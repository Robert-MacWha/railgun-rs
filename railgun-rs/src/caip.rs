use std::fmt::Display;

use alloy::primitives::{Address, U256, Uint};
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erc20_hash_snap() {
        let erc20 = AssetId::Erc20(Address::from_slice(&[1u8; 20]));
        let hash = erc20.hash();
        insta::assert_debug_snapshot!(hash);

        let recovered: AssetId = TokenData::from_hash(&hash.to_be_bytes_vec())
            .unwrap()
            .into();
        assert_eq!(recovered, erc20);
    }

    #[test]
    fn test_erc721_hash_snap() {
        let erc721 = AssetId::Erc721(Address::from_slice(&[2u8; 20]), U256::from(123));
        let hash = erc721.hash();
        insta::assert_debug_snapshot!(hash);
    }

    #[test]
    fn test_erc1155_hash_snap() {
        let erc1155 = AssetId::Erc1155(Address::from_slice(&[3u8; 20]), U256::from(456));
        let hash = erc1155.hash();
        insta::assert_debug_snapshot!(hash);
    }
}
