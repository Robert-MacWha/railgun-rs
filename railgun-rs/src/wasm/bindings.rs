use wasm_bindgen::prelude::*;

use crate::account::RailgunAccount;
use crate::crypto::keys::{ByteKey, SpendingKey, ViewingKey};

#[wasm_bindgen]
pub struct JsRailgunAccount {
    pub(crate) inner: RailgunAccount,
}

#[wasm_bindgen]
impl JsRailgunAccount {
    #[wasm_bindgen(constructor)]
    pub fn new(
        spending_key: &[u8],
        viewing_key: &[u8],
        chain_id: u64,
    ) -> Result<JsRailgunAccount, JsError> {
        if spending_key.len() != 32 {
            return Err(JsError::new("Spending key must be 32 bytes"));
        }
        if viewing_key.len() != 32 {
            return Err(JsError::new("Viewing key must be 32 bytes"));
        }

        let spending_key: [u8; 32] = spending_key.try_into().unwrap();
        let viewing_key: [u8; 32] = viewing_key.try_into().unwrap();

        let spending_key = SpendingKey::from_bytes(spending_key);
        let viewing_key = ViewingKey::from_bytes(viewing_key);

        Ok(JsRailgunAccount {
            inner: RailgunAccount::new(spending_key, viewing_key, chain_id),
        })
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.inner.address().to_string()
    }
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Chain configuration exposed to JS
#[wasm_bindgen]
pub struct JsChainConfig {
    inner: crate::chain_config::ChainConfig,
}

#[wasm_bindgen]
impl JsChainConfig {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> u64 {
        self.inner.id
    }

    #[wasm_bindgen(getter, js_name = "railgunWallet")]
    pub fn railgun_wallet(&self) -> String {
        format!("{:?}", self.inner.railgun_smart_wallet)
    }

    #[wasm_bindgen(getter, js_name = "deploymentBlock")]
    pub fn deployment_block(&self) -> u64 {
        self.inner.deployment_block
    }

    #[wasm_bindgen(getter, js_name = "poiStartBlock")]
    pub fn poi_start_block(&self) -> u64 {
        self.inner.poi_start_block
    }

    #[wasm_bindgen(getter, js_name = "subsquidEndpoint")]
    pub fn subsquid_endpoint(&self) -> Option<String> {
        self.inner.subsquid_endpoint.map(|s| s.to_string())
    }

    #[wasm_bindgen(getter, js_name = "poiEndpoint")]
    pub fn poi_endpoint(&self) -> Option<String> {
        self.inner.poi_endpoint.map(|s| s.to_string())
    }
}

/// Get chain config by chain ID. Returns undefined if chain is not supported.
#[wasm_bindgen]
pub fn get_chain_config(chain_id: u64) -> Option<JsChainConfig> {
    crate::chain_config::get_chain_config(chain_id).map(|inner| JsChainConfig { inner })
}

/// Format an ERC20 address as an asset ID
#[wasm_bindgen]
pub fn erc20_asset(address: &str) -> String {
    format!("erc20:{}", address.to_lowercase())
}
