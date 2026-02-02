use alloy::primitives::Address;
use num_bigint::BigInt;

pub struct TxData {
    pub to: Address,
    pub data: Vec<u8>,
    pub value: BigInt,
}
