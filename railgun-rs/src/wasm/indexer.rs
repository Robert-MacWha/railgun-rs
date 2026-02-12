use std::collections::HashMap;

use wasm_bindgen::{JsError, JsValue, prelude::wasm_bindgen};

use crate::{
    caip::AssetId,
    chain_config::get_chain_config,
    indexer::{
        indexer::{Indexer, IndexerState},
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

    /// Returns balances as a JSON object mapping asset IDs to amounts
    pub fn balance(&self, address: &str) -> Result<JsValue, JsError> {
        let address: RailgunAddress = address.parse()?;
        let balance: HashMap<AssetId, u128> = self.inner.balance(address);
        let balance_map: HashMap<String, String> = balance
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        serde_wasm_bindgen::to_value(&balance_map)
            .map_err(|e| JsError::new(&format!("Failed to serialize balance: {}", e)))
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
