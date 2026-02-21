use std::{collections::HashMap, sync::Arc};

use alloy::{primitives::ChainId, providers::Provider};

use crate::{
    caip::AssetId,
    railgun::{
        address::RailgunAddress,
        indexer::{UtxoIndexer, syncer::NoteSyncer},
        merkle_tree::MerkleTreeVerifier,
        signer::Signer,
    },
};

/// Provides access to Railgun interactions
pub struct RailgunProvider {
    provider: Arc<dyn Provider>,
    utxo_indexer: Arc<UtxoIndexer>,
}

/// General provider functions
impl RailgunProvider {
    pub fn new(
        provider: Arc<dyn Provider>,
        utxo_syncer: Arc<dyn NoteSyncer>,
        utxo_verifier: Arc<dyn MerkleTreeVerifier>,
    ) -> Self {
        Self {
            provider,
            utxo_indexer: Arc::new(UtxoIndexer::new(utxo_syncer, utxo_verifier)),
        }
    }

    pub fn register(&self, account: Arc<dyn Signer>) {}

    /// Raw railgun balance
    pub fn balance(&self, address: RailgunAddress) -> HashMap<AssetId, u128> {
        todo!()
    }

    /// Returns a shield builder
    pub fn shield(&self) {
        todo!()
    }

    /// Returns a transact builder
    pub fn transact(&self) {
        todo!()
    }

    /// Manually syncs the provider to the blockchain. This will be called
    /// automatically when needed
    pub fn sync(&mut self) {
        todo!()
    }
}
