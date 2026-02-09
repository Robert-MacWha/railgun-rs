use alloy::primitives::map::HashMap;
use ark_bn254::Fr;

use crate::{
    caip::AssetId, crypto::railgun_utxo::Utxo, merkle_trees::merkle_tree::MerkleProof,
    note::note::Note, poi::client::ListKey,
};

pub struct PoiNote {
    inner: Note,

    /// This note's POI Merkle proofs, keyed by ListKey
    ///
    /// Note POI proofs are fetched from the POI client via `PoiClient::merkle_proofs`
    /// using the note's blinded commitment.
    poi_merkle_proofs: HashMap<ListKey, MerkleProof>,
}

impl PoiNote {
    pub fn new(inner: Note, poi_merkle_proofs: HashMap<ListKey, MerkleProof>) -> Self {
        Self {
            inner,
            poi_merkle_proofs,
        }
    }

    pub fn note(&self) -> &Note {
        &self.inner
    }

    pub fn poi_merkle_proofs(&self) -> &HashMap<ListKey, MerkleProof> {
        &self.poi_merkle_proofs
    }

    pub fn hash(&self) -> Utxo {
        self.inner.hash().into()
    }

    pub fn asset(&self) -> AssetId {
        self.inner.asset
    }

    pub fn value(&self) -> u128 {
        self.inner.value
    }

    pub fn leaf_index(&self) -> u32 {
        self.inner.leaf_index
    }

    pub fn random(&self) -> [u8; 16] {
        self.inner.random
    }

    pub fn nullifier(&self, leaf_index: u32) -> Fr {
        self.inner.nullifier(leaf_index)
    }
}
