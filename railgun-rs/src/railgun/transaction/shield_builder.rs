use alloy::primitives::U256;
use alloy_sol_types::SolCall;

use crate::{
    abis::railgun::{RailgunSmartWallet, ShieldRequest},
    caip::AssetId,
    chain_config::ChainConfig,
    railgun::{
        address::RailgunAddress,
        note::shield::{ShieldError, create_shield_request},
        transaction::tx_data::TxData,
    },
};

/// Basic builder for constructing shield transactions.
pub struct ShieldBuilder {
    chain: ChainConfig,
    shields: Vec<(RailgunAddress, AssetId, u128)>,
}

impl ShieldBuilder {
    pub fn new(chain: ChainConfig) -> Self {
        Self {
            chain,
            shields: Vec::new(),
        }
    }

    /// Adds a shield operation to the transaction builder
    pub fn shield(mut self, recipient: RailgunAddress, asset: AssetId, value: u128) -> Self {
        self.shields.push((recipient, asset, value));
        self
    }

    /// Builds the shield transaction. Shield txns must be self-broadcast.
    pub fn build(self) -> Result<TxData, ShieldError> {
        let shields = self
            .shields
            .into_iter()
            .map(|(r, a, v)| create_shield_request(r, a, v, &mut rand::rng()))
            .collect::<Result<Vec<ShieldRequest>, ShieldError>>()?;

        let call = RailgunSmartWallet::shieldCall {
            _shieldRequests: shields,
        };
        let calldata = call.abi_encode();

        Ok(TxData {
            to: self.chain.railgun_smart_wallet,
            data: calldata,
            value: U256::ZERO,
        })
    }
}
