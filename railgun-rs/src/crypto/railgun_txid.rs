use ark_bn254::Fr;
use poseidon_rust::poseidon_hash;
use tracing::info;

use crate::crypto::railgun_zero::railgun_merkle_tree_zero;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Txid(Fr);

impl Txid {
    pub fn new(nullifiers: &[Fr], commitments: &[Fr], bound_params_hash: Fr) -> Self {
        let max_nullifiers = 13; // Max circuit inputs
        let max_commitments = 13; // Max circuit outputs

        let mut nullifiers_padded = [railgun_merkle_tree_zero(); 13];
        let mut commitments_padded = [railgun_merkle_tree_zero(); 13];

        for (i, &nullifier) in nullifiers.iter().take(max_nullifiers).enumerate() {
            nullifiers_padded[i] = nullifier;
        }
        for (i, &commitment) in commitments.iter().take(max_commitments).enumerate() {
            commitments_padded[i] = commitment;
        }

        let nullifiers_hash = poseidon_hash(&nullifiers_padded).unwrap();
        let commitments_hash = poseidon_hash(&commitments_padded).unwrap();

        poseidon_hash(&[nullifiers_hash, commitments_hash, bound_params_hash])
            .unwrap()
            .into()
    }
}

impl From<Fr> for Txid {
    fn from(value: Fr) -> Self {
        Txid(value)
    }
}

impl Into<Fr> for Txid {
    fn into(self) -> Fr {
        self.0
    }
}
