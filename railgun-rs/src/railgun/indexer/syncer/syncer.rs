use ruint::aliases::U256;

use super::compat::BoxedSyncStream;
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
    pub nullifiers: Vec<U256>,
    pub commitment_hashes: Vec<U256>,
    pub bound_params_hash: U256,
    pub utxo_tree_in: u32,
    pub utxo_tree_out: u32,
    pub utxo_out_start_index: u32,
}

pub struct LegacyCommitment {
    pub hash: U256,
    pub tree_number: u32,
    pub leaf_index: u32,
}

#[cfg_attr(not(feature = "wasm"), async_trait::async_trait)]
#[cfg_attr(feature = "wasm", async_trait::async_trait(?Send))]
pub trait Syncer: Send + Sync {
    async fn latest_block(&self) -> Result<u64, Box<dyn std::error::Error>>;
    async fn sync(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<BoxedSyncStream<'_>, Box<dyn std::error::Error>>;
}
