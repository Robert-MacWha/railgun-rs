use std::collections::HashMap;

use ruint::aliases::U256;

use crate::{
    caip::AssetId,
    crypto::keys::ViewingPublicKey,
    railgun::{
        merkle_tree::{MerkleProof, UtxoLeafHash},
        note::{IncludedNote, Note, utxo::UtxoNote},
        poi::types::ListKey,
    },
};

#[derive(Debug, Clone)]
pub struct PoiNote {
    inner: UtxoNote,

    /// This note's POI Merkle proofs, keyed by ListKey
    ///
    /// Note POI proofs are fetched from the POI client via `PoiClient::merkle_proofs`
    /// using the note's blinded commitment.
    poi_merkle_proofs: HashMap<ListKey, MerkleProof>,
}

impl PoiNote {
    pub fn new(inner: UtxoNote, poi_merkle_proofs: HashMap<ListKey, MerkleProof>) -> Self {
        Self {
            inner,
            poi_merkle_proofs,
        }
    }

    pub fn note(&self) -> &UtxoNote {
        &self.inner
    }

    pub fn poi_merkle_proofs(&self) -> &HashMap<ListKey, MerkleProof> {
        &self.poi_merkle_proofs
    }

    pub fn blinded_commitment(&self) -> U256 {
        self.inner.blinded_commitment()
    }
}

impl IncludedNote for PoiNote {
    fn tree_number(&self) -> u32 {
        self.inner.tree_number()
    }

    fn leaf_index(&self) -> u32 {
        self.inner.leaf_index()
    }

    fn viewing_pubkey(&self) -> ViewingPublicKey {
        self.inner.viewing_pubkey()
    }

    fn nullifier(&self, leaf_index: U256) -> U256 {
        self.inner.nullifier(leaf_index)
    }

    fn nullifying_key(&self) -> U256 {
        self.inner.nullifying_key()
    }

    fn random(&self) -> [u8; 16] {
        self.inner.random()
    }

    fn sign(&self, inputs: &[U256]) -> [U256; 3] {
        self.inner.sign(inputs)
    }

    fn spending_pubkey(&self) -> [U256; 2] {
        self.inner.spending_pubkey()
    }
}

impl Note for PoiNote {
    fn asset(&self) -> AssetId {
        self.inner.asset()
    }

    fn value(&self) -> u128 {
        self.inner.value()
    }

    fn memo(&self) -> String {
        self.inner.memo()
    }

    fn hash(&self) -> UtxoLeafHash {
        self.inner.hash().into()
    }

    fn note_public_key(&self) -> U256 {
        self.inner.note_public_key()
    }
}
