use std::sync::Arc;

use alloy::primitives::{Address, map::HashMap};

use crate::railgun::{
    address::RailgunAddress, broadcaster::transport::WakuTransport, poi::poi_client::ListKey,
};

pub struct Broadcaster {
    chain_id: u64,
    transport: Arc<dyn WakuTransport>,

    /// Railgun address of the broadcaster
    address: RailgunAddress,
    /// Human-readable identifier for the broadcaster
    identifier: String,
    token_fees: HashMap<Address, TokenFee>,
}

pub struct TokenFee {
    /// Fee per unit gas, where the fee is in the token's base units and the gas
    /// is in units of ether (1e18)
    fee_per_unit_gas: u128,
    /// Unix timestamp when this fee offer expires
    expiration: u64,
    /// UUID for this fee offer
    fees_id: String,
    /// TODO: Not sure what this means
    available_wallets: u32,
    /// Address of the relay adapt contract that can be broadcast to using this
    /// fee offer
    relay_adapt: Address,
    /// Reliability score of the broadcaster for this fee offer, on a scale of
    /// 0-100
    reliability: u32,
    /// Required POI list keys for this fee offer
    list_keys: Vec<ListKey>,
}

/// Fee information for a specific broadcaster and token
pub struct Fee {
    /// Address of the ERC-20 token used for fees
    pub token: Address,
    /// Fee per unit gas, where the fee is in the token's base units and the gas
    /// is in units of ether (1e18)
    pub fee_per_unit_gas: u128,
    /// UUID for this fee offer
    pub fees_id: String,
    /// Address the fee should be paid to
    pub broadcaster_address: RailgunAddress,
    /// Required POI list keys for this fee offer
    pub list_keys: Vec<ListKey>,
}

impl Broadcaster {
    pub fn new(
        chain_id: u64,
        transport: Arc<dyn WakuTransport>,
        address: RailgunAddress,
        identifier: String,
        token_fees: HashMap<Address, TokenFee>,
    ) -> Self {
        Self {
            chain_id,
            transport,
            address,
            identifier,
            token_fees,
        }
    }

    /// Add or update fee information for a given token
    pub fn add_fee(&mut self, token: Address, fee: TokenFee) {
        self.token_fees.insert(token, fee);
    }

    /// Get the fee information for a given token
    pub fn fees_for_token(&self, token: Address) -> Option<Fee> {
        self.token_fees.get(&token).map(|token_fee| Fee {
            token,
            fee_per_unit_gas: token_fee.fee_per_unit_gas,
            fees_id: token_fee.fees_id.clone(),
            broadcaster_address: self.address,
            list_keys: token_fee.list_keys.clone(),
        })
    }

    /// Remove expired fee information
    pub fn remove_expired_fees(&mut self, current_time: u64) {
        self.token_fees
            .retain(|_, fee| fee.expiration > current_time);
    }
}
