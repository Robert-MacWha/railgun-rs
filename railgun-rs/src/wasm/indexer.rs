use std::{collections::HashMap, sync::Arc};

use alloy::{
    network::Ethereum,
    providers::{Provider, ProviderBuilder},
};
use async_trait::async_trait;
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

use crate::{
    caip::AssetId,
    chain_config::{ChainConfig, get_chain_config},
    railgun::{
        address::RailgunAddress,
        indexer::{
            UtxoIndexer, UtxoIndexerState,
            syncer::{ChainedSyncer, NoteSyncer, RpcSyncer, SubsquidSyncer},
        },
        merkle_tree::{MerkleRoot, MerkleTreeVerifier},
    },
    wasm::JsRailgunAccount,
};

/// A no-op verifier used in WASM context where on-chain verification is unavailable.
struct NoopVerifier;

#[async_trait(?Send)]
impl MerkleTreeVerifier for NoopVerifier {
    async fn verify_root(
        &self,
        _tree_number: u32,
        _tree_index: u64,
        _root: MerkleRoot,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(true)
    }
}

#[wasm_bindgen]
pub struct JsIndexer {
    inner: UtxoIndexer,
    chain: ChainConfig,
}

#[wasm_bindgen]
pub struct JsSyncer {
    inner: Box<dyn NoteSyncer>,
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
    pub async fn with_rpc(
        rpc_url: &str,
        chain_id: u64,
        batch_size: u64,
    ) -> Result<JsSyncer, JsError> {
        let provider = ProviderBuilder::new()
            .network::<Ethereum>()
            .connect(rpc_url)
            .await
            .unwrap()
            .erased();

        let chain = get_chain_config(chain_id)
            .ok_or_else(|| JsError::new(&format!("Unsupported chain ID: {}", chain_id)))?;

        Ok(JsSyncer {
            inner: Box::new(RpcSyncer::new(provider, chain).with_batch_size(batch_size)),
        })
    }

    #[wasm_bindgen(js_name = "withChained")]
    pub fn with_chained(syncers: Vec<JsSyncer>) -> JsSyncer {
        let inner = syncers
            .into_iter()
            .map(|js_syncer| js_syncer.inner)
            .collect();
        JsSyncer {
            inner: Box::new(ChainedSyncer::new(inner)),
        }
    }
}

#[wasm_bindgen]
impl JsIndexer {
    pub fn new(syncer: JsSyncer, chain_id: u64) -> Result<Self, JsError> {
        let chain = get_chain_config(chain_id)
            .ok_or_else(|| JsError::new(&format!("Unsupported chain ID: {}", chain_id)))?;

        let syncer: Arc<dyn NoteSyncer> = Arc::from(syncer.inner);
        let verifier: Arc<dyn MerkleTreeVerifier> = Arc::new(NoopVerifier);

        Ok(Self {
            inner: UtxoIndexer::new(syncer, verifier),
            chain,
        })
    }

    pub async fn from_state(
        syncer: JsSyncer,
        chain_id: u64,
        state: &[u8],
    ) -> Result<Self, JsError> {
        let chain = get_chain_config(chain_id)
            .ok_or_else(|| JsError::new(&format!("Unsupported chain ID: {}", chain_id)))?;

        let state: UtxoIndexerState = bitcode::deserialize(state)
            .map_err(|e| JsError::new(&format!("Failed to deserialize state: {}", e)))?;

        let syncer: Arc<dyn NoteSyncer> = Arc::from(syncer.inner);
        let verifier: Arc<dyn MerkleTreeVerifier> = Arc::new(NoopVerifier);

        Ok(Self {
            inner: UtxoIndexer::from_state(syncer, verifier, state),
            chain,
        })
    }

    pub fn add_account(&mut self, account: &JsRailgunAccount) {
        self.inner.add_account(account.inner());
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
    pub fn chain(&self) -> ChainConfig {
        self.chain
    }

    pub fn inner_mut(&mut self) -> &mut UtxoIndexer {
        &mut self.inner
    }

    pub fn inner(&self) -> &UtxoIndexer {
        &self.inner
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
