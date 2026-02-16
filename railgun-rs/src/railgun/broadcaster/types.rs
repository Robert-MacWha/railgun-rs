use std::collections::HashMap;

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

#[cfg(feature = "wasm")]
use tsify_next::Tsify;

/// A message received from the Waku network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct WakuMessage {
    /// Message payload as bytes
    pub payload: Vec<u8>,
    /// Content topic the message was received on
    pub content_topic: String,
    /// Optional timestamp in milliseconds
    pub timestamp: Option<u64>,
}

/// Fee message data broadcast by a broadcaster.
///
/// This is the decoded content of a fee message from the Waku network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcasterFeeMessageData {
    /// Map of token address (checksummed) to fee per unit gas (hex string)
    pub fees: HashMap<String, String>,
    /// Unix timestamp when these fees expire
    pub fee_expiration: u64,
    /// Unique identifier for this fee update
    #[serde(rename = "feesID")]
    pub fees_id: String,
    /// Broadcaster's RAILGUN address
    pub railgun_address: String,
    /// Optional human-readable identifier
    pub identifier: Option<String>,
    /// Number of wallets available for broadcasting
    pub available_wallets: u32,
    /// Broadcaster version string (e.g., "8.0.0")
    pub version: String,
    /// Address of the relay adapt contract
    pub relay_adapt: String,
    /// Required POI list keys for this broadcaster
    #[serde(rename = "requiredPOIListKeys")]
    pub required_poi_list_keys: Vec<String>,
    /// Reliability score (0-100)
    pub reliability: f64,
}

/// Fee information for a specific token from a broadcaster.
#[derive(Debug, Clone)]
pub struct TokenFee {
    /// Fee per unit gas in token base units
    pub fee_per_unit_gas: u128,
    /// Unix timestamp when this fee expires
    pub expiration: u64,
    /// Unique identifier for this fee update
    pub fees_id: String,
    /// Number of wallets available for broadcasting
    pub available_wallets: u32,
    /// Address of the relay adapt contract
    pub relay_adapt: Address,
    /// Reliability score (0-100)
    pub reliability: u32,
}

/// Information about a broadcaster and their current fees.
#[derive(Debug, Clone)]
pub struct BroadcasterInfo {
    /// Broadcaster's RAILGUN address
    pub railgun_address: String,
    /// Optional human-readable identifier
    pub identifier: Option<String>,
    /// Broadcaster version string
    pub version: String,
    /// Required POI list keys
    pub required_poi_list_keys: Vec<String>,
    /// Token fees by token address
    pub token_fees: HashMap<Address, TokenFee>,
    /// Last update timestamp
    pub last_seen: u64,
}

impl BroadcasterInfo {
    /// Returns the fee for a specific token, if available and not expired.
    pub fn fee_for_token(&self, token: Address, current_time: u64) -> Option<&TokenFee> {
        self.token_fees
            .get(&token)
            .filter(|f| f.expiration > current_time)
    }
}

/// The expected broadcaster version. Messages from incompatible versions are ignored.
pub const BROADCASTER_VERSION: &str = "8";

/// Waku pubsub topic for RAILGUN
pub const WAKU_RAILGUN_PUB_SUB_TOPIC: &str = "/waku/2/rs/1/1";

/// Generates the content topic for fee messages on a given chain.
pub fn fee_content_topic(chain_id: u64) -> String {
    format!("/railgun/v2/0-{}-fees/json", chain_id)
}

/// Wrapped fee message from the Waku network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcasterFeeMessage {
    /// Hex-encoded JSON data
    pub data: String,
    /// Signature of the data
    pub signature: String,
}
