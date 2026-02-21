use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    u64,
};

use futures::StreamExt;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::{
    abis::railgun::RailgunSmartWallet,
    account::RailgunAccount,
    caip::AssetId,
    chain_config::ChainConfig,
    crypto::poseidon::poseidon_hash,
    railgun::{
        address::RailgunAddress,
        indexer::{
            indexed_account::IndexedAccount,
            syncer::{NoteSyncer, SyncEvent},
        },
        merkle_tree::{
            MerkleTreeState, MerkleTreeVerifier, TOTAL_LEAVES, UtxoLeafHash, UtxoMerkleTree,
            VerificationError,
        },
        note::utxo::{NoteError, UtxoNote},
    },
};

/// Utxo indexer that maintains the set of UTXO merkle trees and tracks accounts
/// and account notes / balances.
pub struct UtxoIndexer {
    pub utxo_trees: BTreeMap<u32, UtxoMerkleTree>,
    pub synced_block: u64,

    utxo_syncer: Arc<dyn NoteSyncer>,
    utxo_verifier: Arc<dyn MerkleTreeVerifier>,

    accounts: Vec<IndexedAccount>,
}

#[derive(Serialize, Deserialize)]
pub struct UtxoIndexerState {
    pub utxo_trees: BTreeMap<u32, MerkleTreeState>,
    pub synced_block: u64,
    pub accounts: Vec<IndexedAccount>,
}

#[derive(Debug, Error)]
pub enum UtxoIndexerError {
    #[error("Syncer error: {0}")]
    SyncerError(Box<dyn std::error::Error>),
    #[error("Verification error: {0}")]
    VerificationError(#[from] VerificationError),
    #[error("Note error: {0}")]
    NoteError(#[from] NoteError),
}

impl UtxoIndexer {
    pub fn new(
        utxo_syncer: Arc<dyn NoteSyncer>,
        utxo_verifier: Arc<dyn MerkleTreeVerifier>,
    ) -> Self {
        UtxoIndexer {
            utxo_trees: BTreeMap::new(),
            synced_block: 0,
            utxo_syncer,
            utxo_verifier,
            accounts: vec![],
        }
    }

    pub fn from_state(
        utxo_syncer: Arc<dyn NoteSyncer>,
        utxo_verifier: Arc<dyn MerkleTreeVerifier>,
        state: UtxoIndexerState,
    ) -> Self {
        let mut utxo_trees = BTreeMap::new();
        for (number, tree_state) in state.utxo_trees {
            utxo_trees.insert(
                number,
                UtxoMerkleTree::from_state(tree_state).with_verifier(utxo_verifier.clone()),
            );
        }

        UtxoIndexer {
            utxo_trees,
            synced_block: state.synced_block,
            utxo_syncer,
            utxo_verifier,
            accounts: vec![],
        }
    }

    pub fn state(&self) -> UtxoIndexerState {
        let utxo_trees = self
            .utxo_trees
            .iter()
            .map(|(k, v)| (*k, v.state()))
            .collect();

        UtxoIndexerState {
            utxo_trees,
            synced_block: self.synced_block,
            accounts: self.accounts.clone(),
        }
    }

    pub fn synced_block(&self) -> u64 {
        self.synced_block
    }

    /// Adds an account to the indexer. The indexer will track the balance and
    /// transactions for this account as it syncs.
    ///
    /// NOTE: This does not trigger a resync, so it should be called before the
    /// first sync.
    ///
    /// NOTE: Because accounts contain private key material, the indexer
    /// does not persist them. If an indexer is initialized from a saved states,
    /// accounts will need to be re-added before continuing to sync.
    pub fn add_account(&mut self, account: &RailgunAccount) {
        self.accounts.push(account.into());
    }

    /// Returns a list of unspent notes for a given address
    pub fn unspent(&self, address: RailgunAddress) -> Vec<UtxoNote> {
        for account in self.accounts.iter() {
            if account.address() == address {
                return account.unspent();
            }
        }

        vec![]
    }

    /// Returns a list of all unspent notes across all accounts
    pub fn all_unspent(&self) -> Vec<UtxoNote> {
        let mut notes = Vec::new();
        for account in self.accounts.iter() {
            notes.extend(account.unspent());
        }

        notes
    }

    /// Returns the balance of a given address by summing the values of all
    /// unspent notes for that address.
    pub fn balance(&self, address: RailgunAddress) -> HashMap<AssetId, u128> {
        for account in self.accounts.iter() {
            if account.address() == address {
                return account.balance();
            }
        }

        HashMap::new()
    }

    pub async fn sync(&mut self) -> Result<(), UtxoIndexerError> {
        self.sync_to(u64::MAX).await
    }

    #[tracing::instrument(name = "utxo_sync", skip_all)]
    pub async fn sync_to(&mut self, to_block: u64) -> Result<(), UtxoIndexerError> {
        let from_block = self.synced_block + 1;

        let syncer = self.utxo_syncer.clone();
        let latest_block = syncer
            .latest_block()
            .await
            .map_err(UtxoIndexerError::SyncerError)?;
        let to_block = to_block.min(latest_block);

        if from_block > to_block {
            info!("Already synced to block {}", to_block);
            return Ok(());
        }

        // Sync
        let mut stream = syncer
            .sync(from_block, to_block)
            .await
            .map_err(UtxoIndexerError::SyncerError)?;

        while let Some(event) = stream.next().await {
            match event {
                SyncEvent::Shield(shield, block) => self.handle_shield(&shield, block)?,
                SyncEvent::Transact(transact, block) => self.handle_transact(&transact, block)?,
                SyncEvent::Nullified(nullified, block) => self.handle_nullified(&nullified, block),
                SyncEvent::Legacy(legacy, block) => self.handle_legacy(legacy, block),
            }
        }

        // Rebuild
        for tree in self.utxo_trees.values_mut() {
            tree.rebuild();
        }

        // Verify
        self.verify().await?;

        self.synced_block = to_block;
        Ok(())
    }

    fn handle_shield(
        &mut self,
        event: &RailgunSmartWallet::Shield,
        block_number: u64,
    ) -> Result<(), UtxoIndexerError> {
        let leaves: Vec<UtxoLeafHash> = event
            .commitments
            .iter()
            .map(|c| {
                let npk = U256::from_be_bytes(*c.npk);
                let token_id: AssetId = c.token.clone().into();
                let token_id = token_id.hash();
                let value = U256::from(c.value);

                poseidon_hash(&[npk, token_id, value]).unwrap().into()
            })
            .collect();

        insert_utxo_leaves(
            &mut self.utxo_trees,
            event.treeNumber.saturating_to(),
            event.startPosition.saturating_to(),
            &leaves,
            self.utxo_verifier.clone(),
        );

        for account in self.accounts.iter_mut() {
            account.handle_shield_event(event, block_number)?;
        }

        Ok(())
    }

    fn handle_transact(
        &mut self,
        event: &RailgunSmartWallet::Transact,
        block_number: u64,
    ) -> Result<(), UtxoIndexerError> {
        let leaves: Vec<UtxoLeafHash> = event
            .hash
            .iter()
            .map(|h| U256::from_be_bytes(**h).into())
            .collect();

        insert_utxo_leaves(
            &mut self.utxo_trees,
            event.treeNumber.saturating_to(),
            event.startPosition.saturating_to(),
            &leaves,
            self.utxo_verifier.clone(),
        );

        for account in self.accounts.iter_mut() {
            account.handle_transact_event(event, block_number)?;
        }

        Ok(())
    }

    fn handle_nullified(&mut self, event: &RailgunSmartWallet::Nullified, timestamp: u64) {
        for account in self.accounts.iter_mut() {
            account.handle_nullified_event(event, timestamp);
        }
    }

    fn handle_legacy(
        &mut self,
        event: crate::railgun::indexer::syncer::LegacyCommitment,
        _block_number: u64,
    ) {
        insert_utxo_leaves(
            &mut self.utxo_trees,
            event.tree_number,
            event.leaf_index as usize,
            &[event.hash.into()],
            self.utxo_verifier.clone(),
        );

        // TODO: Handle legacy events for accounts.
    }

    async fn verify(&self) -> Result<(), VerificationError> {
        for tree in self.utxo_trees.values() {
            tree.verify().await?;
        }
        Ok(())
    }
}

/// Inserts UTXO leaves into the appropriate tree, handling tree boundaries.
///
/// If the leaves cross a tree boundary, it will fill the first tree, then
/// insert the remaining leaves into the next tree.
fn insert_utxo_leaves(
    trees: &mut BTreeMap<u32, UtxoMerkleTree>,
    tree_number: u32,
    start_position: usize,
    leaves: &[UtxoLeafHash],
    verifier: Arc<dyn MerkleTreeVerifier>,
) {
    let mut remaining = leaves;
    let mut current_tree = tree_number + (start_position / TOTAL_LEAVES) as u32;
    let mut position = start_position % TOTAL_LEAVES;

    while !remaining.is_empty() {
        let space_in_tree = TOTAL_LEAVES - position;
        let to_insert = remaining.len().min(space_in_tree);

        trees
            .entry(current_tree)
            .or_insert_with(|| UtxoMerkleTree::new(current_tree).with_verifier(verifier.clone()))
            .insert_leaves_raw(&remaining[..to_insert], position);

        remaining = &remaining[to_insert..];
        current_tree += 1;
        position = 0;
    }
}
