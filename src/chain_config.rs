use alloy::primitives::{Address, ChainId, address};
use serde::{Deserialize, Serialize};

/// Eip155 Chain Configurations
#[derive(Copy, Clone, Debug)]
pub struct ChainConfig {
    /// EIP-155 Chain ID
    pub id: ChainId,
    /// Railgun Smart Wallet Address on this chain
    pub railgun_smart_wallet: Address,
    /// Block number the railgun smart wallet was deployed at
    pub deployment_block: u64,
    /// Subsquid GraphQL Endpoint for fast syncing
    pub subsquid_endpoint: Option<&'static str>,
}

pub const CHAIN_CONFIGS: &[ChainConfig] = &[MAINNET_CONFIG];

pub const MAINNET_CONFIG: ChainConfig = ChainConfig {
    id: 1,
    railgun_smart_wallet: address!("0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9"),
    deployment_block: 14693013,
    subsquid_endpoint: Some(
        "https://rail-squid.squids.live/squid-railgun-ethereum-v2/v/v1/graphql",
    ),
};

pub const fn get_chain_config(chain_id: ChainId) -> Option<ChainConfig> {
    let mut i = 0;
    while i < CHAIN_CONFIGS.len() {
        if CHAIN_CONFIGS[i].id == chain_id {
            return Some(CHAIN_CONFIGS[i]);
        }
        i += 1;
    }
    None
}
