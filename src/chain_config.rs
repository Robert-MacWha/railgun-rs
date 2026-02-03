use alloy::primitives::{Address, ChainId, address};

/// Eip155 Chain Configurations
#[derive(Copy, Clone, Debug)]
pub struct ChainConfig {
    /// EIP-155 Chain ID
    pub id: ChainId,
    /// Railgun Smart Wallet Address on this chain
    pub railgun_smart_wallet: Address,
}

pub const MAINNET_CONFIG: ChainConfig = ChainConfig {
    id: 1,
    railgun_smart_wallet: address!("0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9"),
};
