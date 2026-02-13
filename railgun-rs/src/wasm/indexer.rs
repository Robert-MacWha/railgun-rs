use std::collections::HashMap;

use alloy::{
    network::Ethereum,
    providers::{Provider, ProviderBuilder},
};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use tracing::info;
use wasm_bindgen::{JsError, JsValue, prelude::wasm_bindgen};

use crate::{
    caip::AssetId,
    chain_config::get_chain_config,
    indexer::{
        indexer::{Indexer, IndexerState},
        rpc_syncer::RpcSyncer,
        subsquid_syncer::SubsquidSyncer,
        syncer::Syncer,
    },
    railgun::address::RailgunAddress,
    wasm::JsRailgunAccount,
};

#[wasm_bindgen]
pub struct JsIndexer {
    inner: Indexer,
}

#[wasm_bindgen]
pub struct JsSyncer {
    inner: Box<dyn Syncer>,
}

#[wasm_bindgen]
impl JsSyncer {
    /// Create a syncer with Subsquid (recommended for historical sync)
    #[wasm_bindgen(js_name = "withSubsquid")]
    pub fn with_subsquid(endpoint: &str) -> JsSyncer {
        JsSyncer {
            inner: Box::new(SubsquidSyncer::new(endpoint)),
        }
    }

    #[wasm_bindgen(js_name = "withRpc")]
    pub async fn with_rpc(rpc_url: &str, chain_id: u64) -> Result<JsSyncer, JsError> {
        let provider = ProviderBuilder::new()
            .network::<Ethereum>()
            .connect(rpc_url)
            .await
            .unwrap()
            .erased();

        let chain = get_chain_config(chain_id)
            .ok_or_else(|| JsError::new(&format!("Unsupported chain ID: {}", chain_id)))?;

        Ok(JsSyncer {
            inner: Box::new(RpcSyncer::new(provider, chain)),
        })
    }
}

#[wasm_bindgen]
impl JsIndexer {
    pub fn new(syncer: JsSyncer, chain_id: u64) -> Result<Self, JsError> {
        let chain = get_chain_config(chain_id)
            .ok_or_else(|| JsError::new(&format!("Unsupported chain ID: {}", chain_id)))?;

        Ok(Self {
            inner: Indexer::new(syncer.inner, chain),
        })
    }

    pub async fn from_state(syncer: JsSyncer, state: &[u8]) -> Result<Self, JsError> {
        let state: IndexerState = bitcode::deserialize(state)
            .map_err(|e| JsError::new(&format!("Failed to deserialize state: {}", e)))?;

        let inner = Indexer::from_state(syncer.inner, state)
            .ok_or(JsError::new("Failed to initialize indexer from state"))?;

        Ok(Self { inner })
    }

    pub fn add_account(&mut self, account: &JsRailgunAccount) {
        self.inner.add_account(&account.inner);
    }

    pub async fn sync(&mut self) -> Result<(), JsError> {
        Ok(self.inner.sync().await?)
    }

    pub async fn sync_to(&mut self, block_number: u64) -> Result<(), JsError> {
        Ok(self.inner.sync_to(block_number).await?)
    }

    pub fn balance(&self, address: &str) -> Result<JsValue, JsError> {
        let address: RailgunAddress = address.parse()?;
        info!("Getting balance for address: {}", address);

        let balance: HashMap<String, u128> = self
            .inner
            .balance(address)
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();

        info!("Balance for {}: {:?}", address, balance);
        let serializer = Serializer::new()
            .serialize_large_number_types_as_bigints(true)
            .serialize_maps_as_objects(true);
        balance
            .serialize(&serializer)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    pub async fn export_state(&mut self) -> Vec<u8> {
        let state = self.inner.state();
        bitcode::serialize(&state).unwrap_or_default()
    }
}

// Non-wasm_bindgen helper methods for internal use
impl JsIndexer {
    /// Returns the chain config for this indexer
    pub(crate) fn chain(&self) -> crate::chain_config::ChainConfig {
        self.inner.chain()
    }

    /// Returns a mutable reference to the inner indexer
    pub(crate) fn inner_mut(&mut self) -> &mut Indexer {
        &mut self.inner
    }
}
