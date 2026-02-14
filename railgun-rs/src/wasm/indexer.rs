use std::collections::HashMap;

use alloy::{
    network::Ethereum,
    providers::{Provider, ProviderBuilder},
};
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
pub struct JsBalanceMap {
    inner: HashMap<AssetId, u128>,
}

#[wasm_bindgen]
impl JsSyncer {
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

    /// Get the balance for a Railgun address.
    ///
    /// @param address - Railgun address (0zk...)
    pub fn balance(&self, address: &str) -> Result<JsBalanceMap, JsError> {
        let address: RailgunAddress = address.parse()?;
        let balance = self.inner.balance(address);
        Ok(JsBalanceMap { inner: balance })
    }

    pub async fn export_state(&mut self) -> Vec<u8> {
        let state = self.inner.state();
        bitcode::serialize(&state).unwrap_or_default()
    }
}

impl JsIndexer {
    pub(crate) fn chain(&self) -> crate::chain_config::ChainConfig {
        self.inner.chain()
    }

    pub(crate) fn inner_mut(&mut self) -> &mut Indexer {
        &mut self.inner
    }
}

#[wasm_bindgen]
impl JsBalanceMap {
    pub fn get(&self, asset_id: &str) -> Option<js_sys::BigInt> {
        let asset_id: AssetId = asset_id.parse().ok()?;
        self.inner
            .get(&asset_id)
            .map(|balance| js_sys::BigInt::from(*balance))
    }

    pub fn keys(&self) -> Vec<String> {
        self.inner
            .keys()
            .map(|asset_id| asset_id.to_string())
            .collect()
    }
}
