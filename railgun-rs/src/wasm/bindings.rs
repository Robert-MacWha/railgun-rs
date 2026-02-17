use wasm_bindgen::prelude::*;

use crate::account::RailgunAccount;
use crate::crypto::keys::{ByteKey, SpendingKey, ViewingKey};

/// Parse a 32-byte hex string (with or without 0x prefix)
fn parse_hex_32(s: &str, name: &str) -> Result<[u8; 32], JsError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| JsError::new(&format!("Invalid {name}: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| JsError::new(&format!("{name} must be 32 bytes (64 hex chars)")))
}

#[wasm_bindgen]
pub struct JsRailgunAccount {
    inner: RailgunAccount,
}

#[wasm_bindgen]
impl JsRailgunAccount {
    /// Create a new Railgun account from hex-encoded keys.
    ///
    /// @param spending_key - 32-byte hex string (with or without 0x prefix)
    /// @param viewing_key - 32-byte hex string (with or without 0x prefix)
    /// @param chain_id - The chain ID for this account
    #[wasm_bindgen(constructor)]
    pub fn new(
        spending_key: &str,
        viewing_key: &str,
        chain_id: u64,
    ) -> Result<JsRailgunAccount, JsError> {
        let spending_key = parse_hex_32(spending_key, "spending_key")?;
        let viewing_key = parse_hex_32(viewing_key, "viewing_key")?;

        let spending_key = SpendingKey::from_bytes(spending_key);
        let viewing_key = ViewingKey::from_bytes(viewing_key);

        Ok(JsRailgunAccount {
            inner: RailgunAccount::new(spending_key, viewing_key, chain_id),
        })
    }

    /// The Railgun address (0zk...) for this account
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.inner.address().to_string()
    }
}

impl JsRailgunAccount {
    pub fn inner(&self) -> &RailgunAccount {
        &self.inner
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

    /// The Railgun smart wallet contract address (checksummed 0x...)
    #[wasm_bindgen(getter, js_name = "railgunWallet")]
    pub fn railgun_wallet(&self) -> String {
        self.inner.railgun_smart_wallet.to_checksum(None)
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
