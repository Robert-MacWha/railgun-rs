use std::{collections::HashMap, sync::Arc};

use alloy::{
    primitives::ChainId,
    providers::{DynProvider, Provider},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    caip::AssetId,
    chain_config::{ChainConfig, get_chain_config},
    circuit::prover::TransactProver,
    railgun::{
        address::RailgunAddress,
        indexer::{UtxoIndexer, UtxoIndexerError, UtxoIndexerState, syncer::NoteSyncer},
        merkle_tree::MerkleTreeVerifier,
        signer::Signer,
        transaction::{ShieldBuilder, TransactionBuilder},
    },
};

/// Provides access to Railgun interactions
pub struct RailgunProvider {
    chain: ChainConfig,
    provider: DynProvider,
    utxo_indexer: UtxoIndexer,
    prover: Arc<dyn TransactProver>,
}

#[derive(Serialize, Deserialize)]
pub struct RailgunProviderState {
    pub chain_id: ChainId,
    pub indexer: UtxoIndexerState,
}

#[derive(Debug, Error)]
pub enum RailgunProviderError {
    #[error("Unsupported chain ID: {0}")]
    UnsupportedChainId(ChainId),
    #[error("Utxo indexer error: {0}")]
    UtxoIndexer(#[from] UtxoIndexerError),
}

/// General provider functions
impl RailgunProvider {
    pub fn new(
        chain: ChainConfig,
        provider: DynProvider,
        utxo_syncer: Arc<dyn NoteSyncer>,
        utxo_verifier: Arc<dyn MerkleTreeVerifier>,
        prover: Arc<dyn TransactProver>,
    ) -> Self {
        Self {
            chain,
            provider,
            utxo_indexer: UtxoIndexer::new(utxo_syncer, utxo_verifier),
            prover,
        }
    }

    pub fn from_state(
        state: RailgunProviderState,
        provider: DynProvider,
        utxo_syncer: Arc<dyn NoteSyncer>,
        utxo_verifier: Arc<dyn MerkleTreeVerifier>,
        prover: Arc<dyn TransactProver>,
    ) -> Result<Self, RailgunProviderError> {
        let chain = get_chain_config(state.chain_id)
            .ok_or(RailgunProviderError::UnsupportedChainId(state.chain_id))?;

        Ok(Self {
            chain,
            provider,
            utxo_indexer: UtxoIndexer::from_state(utxo_syncer, utxo_verifier, state.indexer),
            prover,
        })
    }

    pub fn state(&self) -> RailgunProviderState {
        RailgunProviderState {
            chain_id: self.chain.id,
            indexer: self.utxo_indexer.state(),
        }
    }

    /// Registers an account with the provider. The provider will track the balance
    /// and transactions for this account as it syncs.
    pub fn register(&mut self, account: Arc<dyn Signer>) {
        self.utxo_indexer.register(account);
    }

    /// Registers an account and resyncs from the specified block. Resyncing is
    /// necessary to initially populate an account's state. Resyncing can be skipped
    ///
    pub async fn register_resync(
        &mut self,
        account: Arc<dyn Signer>,
        from_block: Option<u64>,
    ) -> Result<(), RailgunProviderError> {
        self.utxo_indexer
            .register_resync(account, from_block)
            .await?;
        Ok(())
    }

    /// Raw railgun balance
    pub async fn balance(
        &mut self,
        address: RailgunAddress,
    ) -> Result<HashMap<AssetId, u128>, RailgunProviderError> {
        self.sync().await?;
        Ok(self.utxo_indexer.balance(address))
    }

    /// Returns a shield builder
    pub fn shield(&mut self) -> ShieldBuilder {
        ShieldBuilder::new(self.chain)
    }

    /// Returns a transact builder
    pub fn transact(&self) -> TransactionBuilder<'_> {
        TransactionBuilder::new(&self.utxo_indexer, self.prover.as_ref(), self.chain)
    }

    /// Manually syncs the provider to the blockchain. This will be called
    /// automatically when needed
    pub async fn sync(&mut self) -> Result<(), RailgunProviderError> {
        self.utxo_indexer.sync().await?;
        Ok(())
    }
}
