use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

use alloy::{
    primitives::{ChainId, U256},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
};
use alloy_sol_types::SolEvent;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

use crate::{
    abis::railgun::RailgunSmartWallet,
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, get_chain_config},
    crypto::{keys::fr_to_u256, poseidon::poseidon_hash},
    indexer::subsquid_client::SubsquidClient,
    indexer::{account::IndexerAccount, notebook::Notebook},
    merkle_tree::{MerkleTree, MerkleTreeState},
    note::note::NoteError,
    railgun::address::RailgunAddress,
};

pub struct Indexer {
    provider: DynProvider,
    chain: ChainConfig,
    /// The latest block number that has been synced
    synced_block: u64,
    trees: BTreeMap<u32, MerkleTree>,

    /// List of accounts being tracked by the indexer
    accounts: Vec<IndexerAccount>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IndexerState {
    pub chain_id: ChainId,
    pub synced_block: u64,
    pub trees: BTreeMap<u32, MerkleTreeState>,
    pub accounts: Vec<IndexerAccount>,
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("Error decoding log: {0}")]
    LogDecodeError(#[from] alloy_sol_types::Error),
    #[error("Note error: {0}")]
    NoteError(#[from] NoteError),
    #[error("No Subsquid endpoint configured")]
    MissingSubsquidEndpoint,
    #[error("Subsquid client error: {0}")]
    SubsquidClientError(#[from] crate::indexer::subsquid_client::SubsquidError),
    #[error("Validation error: {0}")]
    ValidationError(#[from] ValidationError),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Tree {tree_number} root {root:x?} not seen on-chain")]
    NotSeen { tree_number: u32, root: U256 },
    #[error("Contract error: {0}")]
    ContractError(#[from] alloy_contract::Error),
}

const BATCH_SIZE: u64 = 5;
pub const TOTAL_LEAVES: u32 = 2u32.pow(16);

impl Indexer {
    pub fn new(provider: DynProvider, chain: ChainConfig) -> Self {
        Indexer {
            provider,
            chain,
            synced_block: chain.deployment_block,
            trees: BTreeMap::new(),
            accounts: Vec::new(),
        }
    }

    pub fn new_with_state(provider: DynProvider, state: IndexerState) -> Option<Self> {
        let chain = get_chain_config(state.chain_id)?;
        let trees = state
            .trees
            .into_iter()
            .map(|(k, v)| (k, MerkleTree::new_from_state(v)))
            .collect();

        Some(Indexer {
            provider,
            chain,
            synced_block: state.synced_block,
            trees,
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

    pub fn merkle_trees(&mut self) -> &mut BTreeMap<u32, MerkleTree> {
        &mut self.trees
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
        IndexerState {
            chain_id: self.chain.id,
            synced_block: self.synced_block,
            trees: self
                .trees
                .iter_mut()
                .map(|(k, v)| (*k, v.state()))
                .collect(),
            accounts: self.accounts.clone(),
        }
    }

    /// Sync the indexer with the head of the chain
    ///
    /// Syncs by fetching logs in batches and processing them to update the Merkle
    /// Trees and accounts. The provider must be an archival node to fetch historical
    /// logs.
    ///
    /// TODO: Add error handling for provider log rate batch size limits
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

        self.validate().await?;
        self.synced_block = end_block;
        Ok(())
    }

    /// Quick syncs from Subsquid
    ///
    /// If to_block is None, syncs up to the latest block
    ///
    /// TODO: Make this a generic method so it's only present when subsquid_endpoint is set
    /// TODO: Have this sync full notes so we can track balances
    pub async fn sync_from_subsquid(&mut self, to_block: Option<u64>) -> Result<(), SyncError> {
        let Some(endpoint) = self.chain.subsquid_endpoint else {
            return Err(SyncError::MissingSubsquidEndpoint);
        };

        let to_block = match to_block {
            Some(b) => b,
            None => self.provider.get_block_number().await.unwrap(),
        };

        info!(
            "Syncing from Subsquid from block {} to {:?}",
            self.synced_block, to_block
        );
        let client = SubsquidClient::new(endpoint);
        let commitments = client
            .fetch_all_commitments(self.synced_block, Some(to_block))
            .await?;

        info!("Fetched {} commitments from Subsquid", commitments.len());

        // TODO: Consider sorting commitments and inserting contiguous ranges together
        info!("Grouping commits");
        let mut groups: HashMap<u32, Vec<(usize, Fr)>> = HashMap::new();
        for c in commitments {
            let hash = Fr::from_str(&c.hash).unwrap();
            let global_pos = c.tree_position as u64;

            //? Manually calculate the actual tree number and position because.
            // It seems like subsquid doesn't properly respect tree boundaries
            // so it reports tx
            // 0xb028ffa4f761a91abb09d139cbf466992d65cb60ba02c1f2d9db5400f8bbd497
            // as being in (tree 0 position 65536), which is invalid, instead of
            // (tree 1 position 0).
            //
            // By manually calculating the tree number & position based on the
            // 2^16 leaves per tree, we can work around this issue.
            let actual_tree = (c.tree_number) + (global_pos / 65536) as u32;
            let actual_pos = (global_pos % 65536) as usize;

            groups
                .entry(actual_tree)
                .or_default()
                .push((actual_pos, hash));
        }

        info!("Inserting commits into Merkle Trees");
        for (tree_number, leaves) in groups {
            let tree = self
                .trees
                .entry(tree_number)
                .or_insert(MerkleTree::new(tree_number));

            for (pos, hash) in leaves {
                tree.insert_leaves(&[hash], pos);
            }
        }

        self.synced_block = to_block;

        Ok(())
    }

    /// Validates that all Merkle Tree roots are seen on-chain. If any are not,
    /// returns a ValidationError.
    pub async fn validate(&mut self) -> Result<(), ValidationError> {
        info!("Validating Merkle Tree roots on-chain");
        let contract =
            RailgunSmartWallet::new(self.chain.railgun_smart_wallet, self.provider.clone());

        for (i, tree) in self.trees.iter_mut() {
            let root = fr_to_u256(&tree.root());
            let seen = contract
                .rootHistory(U256::from(*i), root.into())
                .call()
                .await?;

            if !seen {
                return Err(ValidationError::NotSeen {
                    tree_number: *i,
                    root: root.try_into().unwrap(),
                });
            }

            info!("Validated tree {}", i);
        }

        Ok(())
    }

    fn handle_log(&mut self, log: Log) -> Result<(), SyncError> {
        let topic0 = log.topics()[0];
        let block_number = log.block_number.unwrap();
        let block_timestamp = log.block_timestamp.unwrap();

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
                self.handle_nullified(&event.data, block_timestamp);
            }
            RailgunSmartWallet::Unshield::SIGNATURE_HASH => {
                // Unshield events are not needed for indexing. Spent notes are
                // already tracked via Nullified events.
            }
            _ => {
                warn!("Unknown event: {:?}", topic0);
            }
        }

        Ok(())
    }

    // TODO: Combine handle_shield and handle_transact's shared logic
    fn handle_shield(
        &mut self,
        event: &RailgunSmartWallet::Shield,
        block_number: u64,
    ) -> Result<(), SyncError> {
        let tree_number: u32 = event.treeNumber.saturating_to();

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
        let tree_number: u32 = event.treeNumber.saturating_to();

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

    fn handle_nullified(&mut self, event: &RailgunSmartWallet::Nullified, timestamp: u64) {
        for account in self.accounts.iter_mut() {
            account.handle_nullified_event(event, timestamp);
        }
    }
}
