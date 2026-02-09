use ark_bn254::Fr;

use crate::crypto::poseidon::poseidon_hash;

#[derive(Debug, Clone, Copy)]
pub struct Txid(Fr);

impl Txid {
    pub fn new(nullifiers: &[Fr], commitments: &[Fr], bound_params_hash: Fr) -> Self {
        let max_nullifiers = 13; // Max circuit inputs
        let max_commitments = 13; // Max circuit outputs

        let mut nullifiers_padded = [Fr::from(0); 13];
        let mut commitments_padded = [Fr::from(0); 13];

        for (i, &nullifier) in nullifiers.iter().take(max_nullifiers).enumerate() {
            nullifiers_padded[i] = nullifier;
        }
        for (i, &commitment) in commitments.iter().take(max_commitments).enumerate() {
            commitments_padded[i] = commitment;
        }

        let nullifiers_hash = poseidon_hash(&nullifiers_padded);
        let commitments_hash = poseidon_hash(&commitments_padded);

        poseidon_hash(&[nullifiers_hash, commitments_hash, bound_params_hash]).into()
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
