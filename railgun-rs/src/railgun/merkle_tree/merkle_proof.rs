use std::fmt::Display;

use alloy::primitives::FixedBytes;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize, Serializer};
use serde_with::serde_as;

use crate::{crypto::poseidon::poseidon_hash, padded_u256::PaddedU256};

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct MerkleRoot(U256);

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf element
    #[serde_as(as = "PaddedU256")]
    #[serde(rename = "leaf")]
    pub element: U256,
    /// Sibling elements along the proof path
    #[serde_as(as = "Vec<PaddedU256>")]
    pub elements: Vec<U256>,
    /// Bit-packed indices of the proof path
    #[serde_as(as = "PaddedU256")]
    pub indices: U256,
    /// The expected Merkle root
    pub root: MerkleRoot,
}

impl MerkleProof {
    pub fn new(element: U256, elements: Vec<U256>, indices: U256, root: MerkleRoot) -> Self {
        Self {
            element,
            elements,
            indices,
            root,
        }
    }

    /// Creates a deterministic proof for a given Txid leaf. This proof is
    /// used when computing inputs for the POI circuit, where we need a Txid leaf
    /// for a txid that has not yet been submitted on-chain (and consequentially
    /// has not been added to the TXID merkle tree).
    pub fn new_pre_inclusion(element: U256) -> Self {
        Self::new_deterministic(element)
    }

    /// Creates a deterministic proof with a given element where the proof path is all zeros.
    pub fn new_deterministic(element: U256) -> Self {
        let indices = U256::ZERO;
        let elements = [U256::ZERO; 16].to_vec();

        let mut root = element;
        for e in elements.iter() {
            root = hash_left_right(root, *e);
        }

        Self::new(element, elements, indices, root.into())
    }

    pub fn verify(&self) -> bool {
        let mut indices_bits = Vec::new();
        let mut idx: u32 = self.indices.saturating_to();
        for _ in 0..self.elements.len() {
            indices_bits.push(idx & 1);
            idx >>= 1;
        }

        let mut current_hash = self.element;

        for (i, &sibling) in self.elements.iter().enumerate() {
            let is_left_child = indices_bits[i] == 0;
            current_hash = if is_left_child {
                hash_left_right(current_hash, sibling)
            } else {
                hash_left_right(sibling, current_hash)
            };
        }

        let current_hash: MerkleRoot = current_hash.into();
        current_hash == self.root
    }
}

impl From<U256> for MerkleRoot {
    fn from(value: U256) -> Self {
        MerkleRoot(value)
    }
}

impl From<MerkleRoot> for U256 {
    fn from(value: MerkleRoot) -> Self {
        value.0
    }
}

impl From<MerkleRoot> for FixedBytes<32> {
    fn from(value: MerkleRoot) -> Self {
        value.0.into()
    }
}

impl From<FixedBytes<32>> for MerkleRoot {
    fn from(value: FixedBytes<32>) -> Self {
        MerkleRoot(value.into())
    }
}

impl Serialize for MerkleRoot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:064x}", self.0))
    }
}

impl<'de> Deserialize<'de> for MerkleRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = U256::from_str_radix(&s, 16).map_err(serde::de::Error::custom)?;
        Ok(MerkleRoot(value))
    }
}

impl Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:064x}", self.0)
    }
}

fn hash_left_right(left: U256, right: U256) -> U256 {
    poseidon_hash(&[left, right]).unwrap()
}
