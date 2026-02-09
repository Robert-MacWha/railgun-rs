use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use alloy::primitives::{ChainId, U256};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use futures::StreamExt;
use poseidon_rust::poseidon_hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::{
    abis::railgun::RailgunSmartWallet,
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, get_chain_config},
    crypto::{
        keys::{fr_to_bytes, fr_to_u256},
        railgun_txid::{Txid, TxidLeafHash, UtxoTreeOut},
        railgun_utxo::Utxo,
    },
    indexer::{
        indexed_account::IndexedAccount,
        notebook::Notebook,
        syncer::{self, SyncEvent, Syncer},
    },
    merkle_trees::merkle_tree::{
        MerkleTree, MerkleTreeState, TreeConfig, TxidMerkleTree, UtxoMerkleTree,
    },
    note::note::NoteError,
    railgun::address::RailgunAddress,
};

pub type CommitmentHash = Fr;
pub type TxIdLeafHash = Fr;

/// The indexer is responsible for syncing the state of the Railgun protocol by
/// consuming events from a Syncer.
pub struct Indexer {
    syncer: Arc<dyn Syncer>,
    chain: ChainConfig,
    /// The latest block number that has been synced
    synced_block: u64,
    utxo_trees: BTreeMap<u32, UtxoMerkleTree>,
    txid_trees: BTreeMap<u32, TxidMerkleTree>,

    /// List of accounts being tracked by the indexer
    accounts: Vec<IndexedAccount>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IndexerState {
    pub chain_id: ChainId,
    pub synced_block: u64,
    pub utxo_trees: BTreeMap<u32, MerkleTreeState>,
    pub txid_trees: BTreeMap<u32, MerkleTreeState>,
    pub accounts: Vec<IndexedAccount>,
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("Error decoding log: {0}")]
    LogDecodeError(#[from] alloy_sol_types::Error),
    #[error("Note error: {0}")]
    NoteError(#[from] NoteError),
    #[error("No Subsquid endpoint configured")]
    MissingSubsquidEndpoint,
    // #[error("Subsquid client error: {0}")]
    // SubsquidClientError(#[from] crate::indexer::subsquid_syncer::SubsquidError),
    #[error("Validation error: {0}")]
    ValidationError(#[from] ValidationError),
    #[error("Syncer error: {0}")]
    SyncerError(Box<dyn std::error::Error>),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Tree {tree_number} root {root:x?} not seen on-chain")]
    NotSeen { tree_number: u32, root: U256 },
    #[error("Contract error: {0}")]
    ContractError(#[from] alloy_contract::Error),
    #[error("Syncer error: {0}")]
    SyncerError(Box<dyn std::error::Error>),
}

pub const TOTAL_LEAVES: usize = 2usize.pow(16);

impl Indexer {
    pub fn new(syncer: Box<dyn Syncer>, chain: ChainConfig) -> Self {
        Indexer {
            syncer: Arc::from(syncer),
            chain,
            synced_block: chain.deployment_block,
            utxo_trees: BTreeMap::new(),
            txid_trees: BTreeMap::new(),
            accounts: Vec::new(),
        }
    }

    pub fn new_with_state(syncer: Box<dyn Syncer>, state: IndexerState) -> Option<Self> {
        let chain = get_chain_config(state.chain_id)?;
        let utxo_trees = state
            .utxo_trees
            .into_iter()
            .map(|(k, v)| (k, MerkleTree::new_from_state(v)))
            .collect();

        let txid_trees = state
            .txid_trees
            .into_iter()
            .map(|(k, v)| (k, MerkleTree::new_from_state(v)))
            .collect();

        Some(Indexer {
            syncer: Arc::from(syncer),
            chain,
            synced_block: state.synced_block,
            utxo_trees,
            txid_trees,
            accounts: state.accounts,
        })
    }

    /// Adds an account to the indexer for tracking
    pub fn add_account(&mut self, account: &RailgunAccount) {
        self.accounts.push(account.into());
    }

    pub fn chain(&self) -> ChainConfig {
        self.chain
    }

    pub fn synced_block(&self) -> u64 {
        self.synced_block
    }

    pub fn utxo_trees(&mut self) -> &mut BTreeMap<u32, UtxoMerkleTree> {
        &mut self.utxo_trees
    }

    pub fn txid_trees(&mut self) -> &mut BTreeMap<u32, TxidMerkleTree> {
        &mut self.txid_trees
    }

    pub fn notebooks(&self, address: RailgunAddress) -> Option<BTreeMap<u32, Notebook>> {
        for account in self.accounts.iter() {
            if account.address() == address {
                return Some(account.notebooks());
            }
        }

        None
    }

    pub fn balance(&self, address: RailgunAddress) -> HashMap<AssetId, u128> {
        for account in self.accounts.iter() {
            if account.address() == address {
                return account.balance();
            }
        }

        HashMap::new()
    }

    pub fn state(&mut self) -> IndexerState {
        let utxo_trees = self
            .utxo_trees
            .iter_mut()
            .map(|(k, v)| (*k, v.state()))
            .collect();

        let txid_trees = self
            .txid_trees
            .iter_mut()
            .map(|(k, v)| (*k, v.state()))
            .collect();

        IndexerState {
            chain_id: self.chain.id,
            synced_block: self.synced_block,
            utxo_trees,
            txid_trees,
            accounts: self.accounts.clone(),
        }
    }

    pub async fn sync(&mut self) -> Result<(), SyncError> {
        let end_block = self
            .syncer
            .latest_block()
            .await
            .map_err(SyncError::SyncerError)?;

        self.sync_to(end_block).await
    }

    pub async fn sync_to(&mut self, block_number: u64) -> Result<(), SyncError> {
        let start_block = self.synced_block + 1;
        let end_block = block_number;

        if start_block > end_block {
            info!("Already synced to block {}, no need to sync", end_block);
            return Ok(());
        }

        info!("Syncing from block {} to {}", start_block, end_block);
        let syncer = self.syncer.clone();
        let mut stream = syncer
            .sync(start_block, end_block)
            .await
            .map_err(SyncError::SyncerError)?;

        let mut i = 0;
        while let Some(event) = stream.next().await {
            i += 1;
            if i % 100 == 0 {
                info!("Processing event #{}", i);
            }

            match event {
                SyncEvent::Shield(shield, block) => self.handle_shield(&shield, block)?,
                SyncEvent::Transact(transact, block) => self.handle_transact(&transact, block)?,
                SyncEvent::Nullified(nullified, block) => self.handle_nullified(&nullified, block),
                SyncEvent::Operation(op) => self.handle_operation(&op),
                SyncEvent::Legacy(legacy, block) => self.handle_legacy(legacy, block),
            }
        }

        self.validate().await?;
        self.synced_block = end_block;
        Ok(())
    }

    /// Validates that all Merkle Tree roots are seen on-chain. If any are not,
    /// returns a ValidationError.
    pub async fn validate(&mut self) -> Result<(), ValidationError> {
        info!("Validating {} trees", self.utxo_trees.len());

        for (i, tree) in self.utxo_trees.iter_mut() {
            let root = tree.root();
            info!("Tree {} root: {}", i, fr_to_u256(&root));

            let seen = self
                .syncer
                .seen(root)
                .await
                .map_err(ValidationError::SyncerError)?;

            if !seen {
                return Err(ValidationError::NotSeen {
                    tree_number: *i,
                    root: fr_to_u256(&root),
                });
            }
        }

        Ok(())
    }

    fn handle_shield(
        &mut self,
        event: &RailgunSmartWallet::Shield,
        block_number: u64,
    ) -> Result<(), SyncError> {
        let leaves: Vec<Utxo> = event
            .commitments
            .iter()
            .map(|c| {
                let npk = Fr::from_be_bytes_mod_order(c.npk.as_slice());
                let token_id: AssetId = c.token.clone().into();
                let token_id = token_id.hash();
                let value: u128 = c.value.saturating_to();
                let value = Fr::from(value);

                poseidon_hash(&[npk, token_id, value]).unwrap().into()
            })
            .collect();

        insert_leaves(
            &mut self.utxo_trees,
            event.treeNumber.saturating_to(),
            event.startPosition.saturating_to(),
            &leaves,
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
    ) -> Result<(), SyncError> {
        // info!("Handling transact: {:#?}", event);

        let leaves: Vec<Utxo> = event
            .hash
            .iter()
            .map(|h| Fr::from_be_bytes_mod_order(h.as_slice()).into())
            .collect();

        insert_leaves(
            &mut self.utxo_trees,
            event.treeNumber.saturating_to(),
            event.startPosition.saturating_to(),
            &leaves,
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

    fn handle_operation(&mut self, event: &syncer::Operation) {
        let txid = Txid::new(
            &event.nullifiers,
            &event.commitment_hashes,
            event.bound_params_hash,
        );

        let txid_leaf_hash = TxidLeafHash::new(
            txid,
            event.utxo_tree_in,
            UtxoTreeOut::included(event.utxo_tree_out, event.utxo_out_start_index),
        );

        // TODO: Consider making a wrapper around a BTreeMap of txid trees that
        // handles this and abstracts away the tree number logic, since it's not as
        // relevant.
        // Position is global sequential based on the tree number and leaf index
        let tree_number = (self.txid_trees.len() as u32).saturating_sub(1);
        let start_position = self
            .txid_trees
            .last_entry()
            .map(|e| e.get().leaves_len())
            .unwrap_or(0);

        insert_leaves(
            &mut self.txid_trees,
            tree_number,
            start_position,
            &[txid_leaf_hash],
        );
    }

    fn handle_legacy(&mut self, event: syncer::LegacyCommitment, _block_number: u64) {
        insert_leaves(
            &mut self.utxo_trees,
            event.tree_number,
            event.leaf_index as usize,
            &[event.hash.into()],
        );
    }
}

/// Inserts leaves into the appropriate Merkle Tree, handling tree boundaries.
///
/// If the leaves cross a tree boundary, it will fill the first tree, then
/// insert the remaining leaves into the next tree.
fn insert_leaves<C: TreeConfig>(
    trees: &mut BTreeMap<u32, MerkleTree<C>>,
    tree_number: u32,
    start_position: usize,
    leaves: &[C::LeafType],
) {
    let mut remaining = leaves;
    let mut current_tree = tree_number + (start_position / TOTAL_LEAVES) as u32;
    let mut position = start_position % TOTAL_LEAVES;

    while !remaining.is_empty() {
        let space_in_tree = TOTAL_LEAVES - position;
        let to_insert = remaining.len().min(space_in_tree);

        trees
            .entry(current_tree)
            .or_insert_with(|| MerkleTree::new(current_tree))
            .insert_leaves(&remaining[..to_insert], position);

        remaining = &remaining[to_insert..];
        current_tree += 1;
        position = 0;
    }
}
