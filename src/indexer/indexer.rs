use std::collections::{BTreeMap, HashMap};

use alloy::{
    primitives::{Address, U256, address},
    providers::Provider,
    rpc::types::{Filter, Log},
};
use alloy_sol_types::SolEvent;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use thiserror::Error;
use tracing::info;

use crate::{
    caip::AssetId,
    chain_config::ChainConfig,
    crypto::poseidon::poseidon_hash,
    indexer::account::IndexerAccount,
    merkle_tree::MerkleTree,
    note::note::NoteError,
    railgun::{address::RailgunAddress, sol::RailgunSmartWallet},
};

pub struct Indexer<P: Provider> {
    provider: P,
    chain: ChainConfig,
    /// The latest block number that has been synced
    synced_block: u64,
    trees: BTreeMap<u64, MerkleTree>,

    /// List of accounts being tracked by the indexer
    accounts: Vec<IndexerAccount>,
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("Error decoding log: {0}")]
    LogDecodeError(#[from] alloy_sol_types::Error),
    #[error("Note error: {0}")]
    NoteError(#[from] NoteError),
}

const BATCH_SIZE: u64 = 1000;
pub const TOTAL_LEAVES: u64 = 2u64.pow(16);

impl<P: Provider> Indexer<P> {
    pub fn new(provider: P, chain: ChainConfig, start_block: u64) -> Self {
        // TODO: Derive railgun address from chain ID
        Indexer {
            provider,
            chain,
            synced_block: start_block,
            trees: BTreeMap::new(),
            accounts: Vec::new(),
        }
    }

    pub fn add_account(&mut self, account: IndexerAccount) {
        self.accounts.push(account);
    }

    pub fn chain(&self) -> ChainConfig {
        self.chain
    }

    pub fn synced_block(&self) -> u64 {
        self.synced_block
    }

    pub fn balance(&self, address: RailgunAddress) -> HashMap<AssetId, u128> {
        for account in self.accounts.iter() {
            if account.address() == address {
                return account.balance();
            }
        }

        HashMap::new()
    }

    /// Syncs the indexer with the blockchain
    pub async fn sync(&mut self) -> Result<(), SyncError> {
        let start_block = self.synced_block + 1;
        let end_block = self.provider.get_block_number().await.unwrap();

        info!("Syncing from block {} to {}", start_block, end_block);

        let mut from_block = start_block;
        while from_block <= end_block {
            let to_block = std::cmp::min(from_block + BATCH_SIZE, end_block);
            let filter = Filter::new()
                .address(self.chain.railgun_smart_wallet)
                .from_block(from_block)
                .to_block(to_block);
            let logs = self.provider.get_logs(&filter).await.unwrap();
            info!(
                "Fetched {} logs from blocks {} to {}",
                logs.len(),
                from_block,
                to_block
            );
            for log in logs {
                self.handle_log(log)?;
            }

            // Advance the from_block for the next iteration
            from_block = to_block + 1;
        }

        Ok(())
    }

    fn handle_log(&mut self, log: Log) -> Result<(), SyncError> {
        let topic0 = log.topics()[0];
        let block_number = log.block_number.unwrap();

        match topic0 {
            RailgunSmartWallet::Shield::SIGNATURE_HASH => {
                let event = RailgunSmartWallet::Shield::decode_log(&log.inner)?;
                self.handle_shield(&event.data, block_number)?;
            }
            RailgunSmartWallet::Transact::SIGNATURE_HASH => {
                let event = RailgunSmartWallet::Transact::decode_log(&log.inner)?;
                self.handle_transact(&event.data, block_number)?;
            }
            RailgunSmartWallet::Nullified::SIGNATURE_HASH => {
                let event = RailgunSmartWallet::Nullified::decode_log(&log.inner)?;
                self.handle_nullified(&event.data);
            }
            _ => {
                println!("Unknown event: {:?}", topic0);
            }
        }

        Ok(())
    }

    fn handle_shield(
        &mut self,
        event: &RailgunSmartWallet::Shield,
        block_number: u64,
    ) -> Result<(), SyncError> {
        let tree_number: u64 = event.treeNumber.saturating_to();

        let leaves: Vec<Fr> = event
            .commitments
            .iter()
            .map(|c| {
                let npk = Fr::from_be_bytes_mod_order(c.npk.as_slice());
                let token_id: AssetId = c.token.clone().into();
                let token_id = token_id.hash();
                let value: u128 = c.value.saturating_to();
                let value = Fr::from(value);

                poseidon_hash(&[npk, token_id, value])
            })
            .collect();

        let is_crossing_tree =
            event.startPosition + U256::from(event.commitments.len()) >= TOTAL_LEAVES;

        let (tree_number, start_position) = if is_crossing_tree {
            (tree_number + 1, 0)
        } else {
            (tree_number, event.startPosition.saturating_to())
        };

        self.trees
            .entry(tree_number)
            .or_insert(MerkleTree::new(tree_number))
            .insert_leaves(&leaves, start_position);

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
        let tree_number: u64 = event.treeNumber.saturating_to();

        let leaves: Vec<Fr> = event
            .hash
            .iter()
            .map(|hash| Fr::from_be_bytes_mod_order(hash.as_slice()))
            .collect();

        let is_crossing_tree = event.startPosition + U256::from(event.hash.len()) >= TOTAL_LEAVES;
        let (tree_number, start_position) = if is_crossing_tree {
            (tree_number + 1, 0)
        } else {
            (tree_number, event.startPosition.saturating_to())
        };

        self.trees
            .entry(tree_number)
            .or_insert(MerkleTree::new(tree_number))
            .insert_leaves(&leaves, start_position);

        for account in self.accounts.iter_mut() {
            account.handle_transact_event(event, block_number)?;
        }

        Ok(())
    }

    fn handle_nullified(&mut self, event: &RailgunSmartWallet::Nullified) {
        let tree_number = event.treeNumber as u64;

        let mut nullifiers: Vec<[u8; 32]> = event.nullifier.iter().map(|&n| n.into()).collect();

        self.trees
            .entry(tree_number)
            .or_insert(MerkleTree::new(tree_number))
            .nullifiers
            .append(&mut nullifiers);
    }
}
