//! Railgun Solidity types.
//!
//! https://github.com/Railgun-Privacy/contract/blob/9ec09123eb140fdaaf3a5ff1f29d634c353630cd/contracts/logic/Globals.sol

use alloy::primitives::{Address, ChainId, U256, aliases::U72};
use alloy_sol_types::{SolValue, sol};
use serde::Deserialize;
use thiserror::Error;

use crate::crypto::hash_to_scalar;

#[derive(Debug, Error)]
pub enum TokenDataError {
    #[error("Invalid token data hash length")]
    InvalidHashLength,
}

impl TokenData {
    pub fn from_hash(hash: &[u8]) -> Result<Self, TokenDataError> {
        if hash.len() == 32 {
            let token_address = Address::from_slice(&hash[12..32]);
            return Ok(TokenData {
                tokenType: TokenType::ERC20,
                tokenAddress: token_address,
                tokenSubID: U256::ZERO,
            });
        }

        if hash.len() != 96 {
            return Err(TokenDataError::InvalidHashLength);
        }

        let token_type = hash[31];
        let token_type = match token_type {
            1 => TokenType::ERC721,
            2 => TokenType::ERC1155,
            _ => unreachable!(),
        };
        let token_address = Address::from_slice(&hash[44..64]);
        let token_sub_id = U256::from_be_bytes::<32>(hash[64..96].try_into().unwrap());

        Ok(TokenData {
            tokenType: token_type,
            tokenAddress: token_address,
            tokenSubID: token_sub_id,
        })
    }

    pub fn hash(&self) -> ruint::aliases::U256 {
        if self.tokenType == TokenType::ERC20 {
            let mut bytes = [0u8; 32];
            bytes[12..].copy_from_slice(self.tokenAddress.as_slice());
            return U256::from_be_bytes(bytes);
        }

        let token_type = self.tokenType as u8;

        // tokenType (32 bytes) | address (32 bytes) | subID (32 bytes)
        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(&[0u8; 31]);
        data.push(token_type);
        data.extend_from_slice(&[0u8; 12]); // pad address to 32 bytes
        data.extend_from_slice(self.tokenAddress.as_slice());
        data.extend_from_slice(&self.tokenSubID.to_be_bytes::<32>());

        // Hash and mod by SNARK_SCALAR_FIELD
        let hash = hash_to_scalar(&data);

        let mut bytes = [0u8; 32];
        let result_bytes = hash.to_be_bytes::<32>();
        bytes[32 - result_bytes.len()..].copy_from_slice(&result_bytes);
        ruint::aliases::U256::from_be_bytes(bytes)
    }
}

impl BoundParams {
    pub fn new(
        tree_number: u16,
        min_gas_price: u128,
        unshield: UnshieldType,
        chain_id: ChainId,
        adapt_contract: Address,
        adapt_input: &[u8; 32],
        commitment_ciphertexts: Vec<CommitmentCiphertext>,
    ) -> Self {
        BoundParams {
            treeNumber: tree_number,
            minGasPrice: U72::saturating_from(min_gas_price),
            unshield,
            chainID: chain_id,
            adaptContract: adapt_contract,
            adaptParams: adapt_input.into(),
            commitmentCiphertext: commitment_ciphertexts,
        }
    }

    pub fn hash(&self) -> U256 {
        let encoded = self.abi_encode();
        hash_to_scalar(&encoded)
    }
}

sol! {
    #[sol(rpc)]
    contract RailgunSmartWallet {
        // Events
        #[derive(Debug)]
        event Transact(
            uint256 treeNumber,
            uint256 startPosition,
            bytes32[] hash,
            CommitmentCiphertext[] ciphertext
        );
        #[derive(Debug)]
        event Shield(
            uint256 treeNumber,
            uint256 startPosition,
            CommitmentPreimage[] commitments,
            ShieldCiphertext[] shieldCiphertext,
            uint256[] fees
        );
        event Unshield(address to, TokenData token, uint256 amount, uint256 fee);
        event Nullified(uint16 treeNumber, bytes32[] nullifier);

        // Public variables
        // Whether the contract has already seen a particular Merkle tree root
        // treeNumber -> root -> seen
        mapping(uint256 => mapping(bytes32 => bool)) public rootHistory;

        // Functions
        function shield(ShieldRequest[] calldata _shieldRequests) external;
        function transact(Transaction[] calldata _transactions) external;
    }

    #[derive(Debug)]
    struct ShieldRequest {
        CommitmentPreimage preimage;
        ShieldCiphertext ciphertext;
    }

    #[derive(Debug, PartialEq, Eq)]
    enum TokenType {
        ERC20,
        ERC721,
        ERC1155
    }

    #[derive(Debug)]
    struct TokenData {
        TokenType tokenType;
        address tokenAddress;
        uint256 tokenSubID;
    }

    #[derive(Debug, Deserialize)]
    struct CommitmentCiphertext {
        bytes32[4] ciphertext; // Ciphertext order: IV & tag (16 bytes each), encodedMPK (senderMPK XOR receiverMPK), random & amount (16 bytes each), token
        bytes32 blindedSenderViewingKey;
        bytes32 blindedReceiverViewingKey;
        bytes annotationData; // Only for sender to decrypt
        bytes memo; // Added to note ciphertext for decryption
    }

    #[derive(Debug)]
    struct ShieldCiphertext {
        bytes32[3] encryptedBundle; // IV shared (16 bytes), tag (16 bytes), random (16 bytes), IV sender (16 bytes), receiver viewing public key (32 bytes)
        bytes32 shieldKey; // Public key to generate shared key from
    }

    #[derive(Debug)]
    enum UnshieldType {
        NONE,
        NORMAL,
        REDIRECT
    }

    #[derive(Debug)]
    struct BoundParams {
        uint16 treeNumber;
        uint72 minGasPrice; // Only for type 0 transactions
        UnshieldType unshield;
        uint64 chainID;
        address adaptContract;
        bytes32 adaptParams;
        // For unshields do not include an element in ciphertext array
        // Ciphertext array length = commitments - unshields
        CommitmentCiphertext[] commitmentCiphertext;
    }

    struct Transaction {
        SnarkProof proof;
        bytes32 merkleRoot;
        bytes32[] nullifiers;
        bytes32[] commitments;
        BoundParams boundParams;
        CommitmentPreimage unshieldPreimage;
    }

    #[derive(Debug)]
    struct CommitmentPreimage {
        bytes32 npk; // Poseidon(Poseidon(spending public key, nullifying key), random)
        TokenData token; // Token field
        uint120 value; // Note value
    }

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    struct VerifyingKey {
        string artifactsIPFSHash;
        G1Point alpha1;
        G2Point beta2;
        G2Point gamma2;
        G2Point delta2;
        G1Point[] ic;
    }

    struct SnarkProof {
        G1Point a;
        G2Point b;
        G1Point c;
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Bytes, FixedBytes, address};
    use ruint::uint;
    use tracing_test::traced_test;

    use crate::abis::railgun::{BoundParams, CommitmentCiphertext, UnshieldType};

    #[test]
    #[traced_test]
    fn test_hash_bound_params() {
        let bound_params = BoundParams::new(
            1,
            10,
            UnshieldType::NONE,
            1,
            address!("0x1234567890123456789012345678901234567890"),
            &[5u8; 32],
            vec![CommitmentCiphertext {
                ciphertext: [
                    FixedBytes::from_slice(&[1u8; 32]),
                    FixedBytes::from_slice(&[1u8; 32]),
                    FixedBytes::from_slice(&[1u8; 32]),
                    FixedBytes::from_slice(&[1u8; 32]),
                ],
                blindedSenderViewingKey: FixedBytes::from_slice(&[2u8; 32]),
                blindedReceiverViewingKey: FixedBytes::from_slice(&[3u8; 32]),
                annotationData: Bytes::from(&[4u8; 50]),
                memo: Bytes::from(&[5u8; 50]),
            }],
        );

        let hash = bound_params.hash();
        let expected =
            uint!(653354349844558206886319240777917397850034746873378410801880094244109558523_U256);

        assert_eq!(hash, expected);
    }
}
