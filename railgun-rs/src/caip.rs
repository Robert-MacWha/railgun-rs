use std::fmt::Display;

use alloy::primitives::{Address, U256, Uint};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::{
    abis::railgun::{TokenData, TokenType},
    railgun::address::RailgunAddress,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssetId {
    Erc20(Address),
    Erc721(Address, U256),
    Erc1155(Address, U256),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AccountId {
    Eip155(Address),
    Railgun(RailgunAddress),
}

impl AssetId {
    pub fn hash(&self) -> U256 {
        let token_data: TokenData = (*self).into();
        token_data.hash()
    }
}

impl Display for AssetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetId::Erc20(address) => write!(f, "erc20:{:?}", address),
            AssetId::Erc721(address, sub_id) => write!(f, "erc721:{:?}/{}", address, sub_id),
            AssetId::Erc1155(address, sub_id) => write!(f, "erc1155:{:?}/{}", address, sub_id),
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
            AssetId::Erc721(address, sub_id) => TokenData {
                tokenType: TokenType::ERC721,
                tokenAddress: address,
                tokenSubID: sub_id,
            },
            AssetId::Erc1155(address, sub_id) => TokenData {
                tokenType: TokenType::ERC1155,
                tokenAddress: address,
                tokenSubID: sub_id,
            },
        }
    }
}

impl From<TokenData> for AssetId {
    fn from(token_data: TokenData) -> Self {
        match token_data.tokenType {
            TokenType::ERC20 => AssetId::Erc20(token_data.tokenAddress),
            TokenType::ERC721 => AssetId::Erc721(token_data.tokenAddress, token_data.tokenSubID),
            TokenType::ERC1155 => AssetId::Erc1155(token_data.tokenAddress, token_data.tokenSubID),
            _ => unreachable!(),
        }
    }
}
