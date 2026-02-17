use std::sync::Arc;

use alloy::primitives::Address;

use crate::railgun::address::RailgunAddress;

use super::transport::WakuTransport;

/// Fee information for a specific token from a broadcaster.
#[derive(Debug, Clone)]
pub struct Fee {
    /// Address of the ERC-20 token used for fees
    pub token: Address,
    /// Fee per unit gas, where the fee is in the token's base units and the gas
    /// is in units of ether (1e18)
    pub per_unit_gas: u128,
    /// Railgun address of the fee recipient (broadcaster)
    pub recipient: RailgunAddress,
    /// Unix timestamp when this fee expires
    pub expiration: u64,
    /// UUID for this fee offer
    pub fees_id: String,
    /// Number of wallets available for broadcasting
    pub available_wallets: u32,
    /// Address of the relay adapt contract
    pub relay_adapt: Address,
    /// Reliability score (0-100)
    pub reliability: u32,
    /// List keys required by the broadcaster for POI selection
    pub list_keys: Vec<String>,
}

/// Broadcaster instance for a specific fee token.
pub struct Broadcaster {
    transport: Arc<dyn WakuTransport>,
    pub chain_id: u64,
    /// Human-readable identifier for the broadcaster
    pub identifier: Option<String>,
    /// Fee information for the specific token
    pub fee: Fee,
}

impl Broadcaster {
    pub(crate) fn new(
        transport: Arc<dyn WakuTransport>,
        chain_id: u64,
        identifier: Option<String>,
        fee: Fee,
    ) -> Self {
        Self {
            transport,
            chain_id,
            identifier,
            fee,
        }
    }
}
