use alloy::primitives::{Address, Uint};
use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::railgun::{TokenData, TokenType};

#[derive(Debug, Copy, Clone)]
pub enum AssetId {
    Erc20(Address),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainId {
    Eip155(u64),
}

impl AssetId {
    pub fn hash(&self) -> Fr {
        match self {
            AssetId::Erc20(address) => Fr::from_be_bytes_mod_order(address.as_slice()),
        }
    }
}

impl From<AssetId> for TokenData {
    fn from(asset_id: AssetId) -> Self {
        match asset_id {
            AssetId::Erc20(address) => TokenData {
                tokenType: TokenType::ERC20,
                tokenAddress: address,
                tokenSubID: Uint::ZERO,
            },
        }
    }
}
