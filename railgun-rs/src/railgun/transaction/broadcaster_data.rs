use alloy::primitives::Address;
use ruint::aliases::U256;

use crate::railgun::{
    address::RailgunAddress,
    poi::poi_client::{PreTransactionPoisPerTxidLeafPerList, TxidVersion},
};

/// Serialize to EVM = 0
#[derive(Debug)]
pub enum ChainType {
    EVM,
}

#[derive(Debug)]
pub struct Chain {
    pub chain_type: ChainType,
    /// EIP-155 Chain ID
    pub chain_id: u64,
}

#[derive(Debug)]
pub struct BroadcastData {
    pub txid_version_for_inputs: TxidVersion,
    pub to: Address,
    pub data: Vec<u8>,
    pub broadcaster_railgun_address: RailgunAddress,
    pub broadcaster_fee_id: String,
    pub chain: Chain,
    pub nullifiers: Vec<U256>,
    pub overall_batch_min_gas_price: u128,
    pub use_relay_adapt: bool,
    pub pre_transaction_pois_per_txid_leaf_per_list: PreTransactionPoisPerTxidLeafPerList,
}
