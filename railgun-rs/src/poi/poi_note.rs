use std::collections::HashMap;

use ark_bn254::Fr;

use crate::{
    caip::AssetId,
    crypto::{keys::fr_to_bytes, railgun_utxo::Utxo},
    merkle_trees::merkle_proof::MerkleProof,
    note::{IncludedNote, Note, utxo::UtxoNote},
    poi::client::{ClientError, ListKey, PoiClient},
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

    pub async fn from_utxo_notes(
        inner: Vec<UtxoNote>,
        client: &PoiClient,
    ) -> Result<Vec<Self>, ClientError> {
        let blinded_commitments = inner
            .iter()
            .map(|n| fr_to_bytes(&n.blinded_commitment()))
            .collect();
        let proofs = client.merkle_proofs(blinded_commitments).await?;

        let mut poi_notes = Vec::new();

        for (i, note) in inner.into_iter().enumerate() {
            let mut note_proofs = HashMap::new();

            for (list_key, proofs) in proofs.iter() {
                let proof = proofs.get(i).unwrap();
                note_proofs.insert(list_key.clone(), proof.clone());
            }

            let poi_note = PoiNote::new(note, note_proofs);
            poi_notes.push(poi_note);
        }

        Ok(poi_notes)
    }

    pub fn note(&self) -> &UtxoNote {
        &self.inner
    }

    pub fn poi_merkle_proofs(&self) -> &HashMap<ListKey, MerkleProof> {
        &self.poi_merkle_proofs
    }

    pub fn random(&self) -> [u8; 16] {
        self.inner.random()
    }

    pub fn nullifier(&self, leaf_index: u32) -> Fr {
        self.inner.nullifier(leaf_index)
    }
}

impl IncludedNote for PoiNote {
    fn tree_number(&self) -> u32 {
        self.inner.tree_number()
    }

    fn leaf_index(&self) -> u32 {
        self.inner.leaf_index()
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

    fn hash(&self) -> Utxo {
        self.inner.hash().into()
    }

    fn note_public_key(&self) -> Fr {
        self.inner.note_public_key()
    }
}
