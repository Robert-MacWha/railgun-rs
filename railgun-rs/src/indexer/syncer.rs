use std::pin::Pin;

use ark_bn254::Fr;
use futures::Stream;

use crate::abis::railgun::RailgunSmartWallet;

/// TODO: Consider making types for shield, transact, and nullified so we don't need to use the anvil
/// types if it's more convenient.
pub enum SyncEvent {
    Shield(RailgunSmartWallet::Shield, u64),
    Transact(RailgunSmartWallet::Transact, u64),
    Nullified(RailgunSmartWallet::Nullified, u64),
    Operation(Operation),
    Legacy(LegacyCommitment, u64),
}

pub struct Operation {
    pub nullifiers: Vec<Fr>,
    pub commitment_hashes: Vec<Fr>,
    pub bound_params_hash: Fr,
    pub utxo_tree_in: u32,
    pub utxo_tree_out: u32,
    pub utxo_out_start_index: u32,
}

// TODO: Handle legacy commitments properly, so the indexer can be used for legacy events.
// For now it's much simpler just to populate the UTXO merkle tree while ignoring the
// legacy events for accounts.
pub struct LegacyCommitment {
    pub hash: Fr,
    pub tree_number: u32,
    pub leaf_index: u32,
}

/// Verifies merkle roots against on-chain state.
#[async_trait::async_trait]
pub trait RootVerifier: Send + Sync {
    /// Check if a UTXO merkle root has been seen on-chain for a specific tree.
    async fn seen(
        &self,
        tree_number: u32,
        utxo_merkle_root: Fr,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

#[async_trait::async_trait]
pub trait Syncer: Send + Sync {
    async fn latest_block(&self) -> Result<u64, Box<dyn std::error::Error>>;
    async fn seen(&self, utxo_merkle_root: Fr) -> Result<bool, Box<dyn std::error::Error>>;

    async fn sync(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Pin<Box<dyn Stream<Item = SyncEvent> + Send + '_>>, Box<dyn std::error::Error>>;
}
