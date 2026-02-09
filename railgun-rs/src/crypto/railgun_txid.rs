use ark_bn254::Fr;
use poseidon_rust::poseidon_hash;

use crate::{crypto::railgun_zero::railgun_merkle_tree_zero, indexer::indexer::TOTAL_LEAVES};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TxidLeafHash(Fr);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Txid(Fr);

impl TxidLeafHash {
    pub fn new(txid: Txid, utxo_tree_in: u32, utxo_tree_out: u32, start_index: u32) -> Self {
        let global_position = (utxo_tree_out as u64) * (TOTAL_LEAVES as u64) + (start_index as u64);
        poseidon_hash(&[
            txid.into(),
            Fr::from(utxo_tree_in),
            Fr::from(global_position),
        ])
        .unwrap()
        .into()
    }
}

impl From<Fr> for TxidLeafHash {
    fn from(value: Fr) -> Self {
        TxidLeafHash(value)
    }
}

impl Into<Fr> for TxidLeafHash {
    fn into(self) -> Fr {
        self.0
    }
}

impl Txid {
    pub fn new(nullifiers: &[Fr], commitments: &[Fr], bound_params_hash: Fr) -> Self {
        let max_nullifiers = 13; // Max circuit inputs
        let max_commitments = 13; // Max circuit outputs

        // This is deeply unfortunate given the performance implications
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

#[cfg(test)]
mod tests {

    use crate::crypto::keys::{fr_to_bytes, hex_to_fr};

    use super::*;

    #[test]
    fn test_txid() {
        let txid = Txid::new(
            &[
                hex_to_fr("0x1e52cee52f67c37a468458671cddde6b56390dcbdc4cf3b770badc0e78d66401"),
                hex_to_fr("0x0ac9f5ab5bcb5a115a3efdd0475f6c22dc6a6841caf35a52ecf86a802bfce8ee"),
            ],
            &[
                hex_to_fr("0x1afd01a29faf22dcc5678694092a08d38de99fc97d07b9281fa66f956ce43579"),
                hex_to_fr("0x2ffc716d8ae767995961bbde4a208dbae438783065bbd200f51a8d4e97cc2289"),
                hex_to_fr("0x078f9824c86b2488714eb76dc15199c3fa21903517d5f3e19ab2035d264400b6"),
            ],
            hex_to_fr("0x2c72a0bcce4f1169dd988204775483938ded5f5899cec84829b1cc667a683784"),
        );

        assert_eq!(
            hex::encode(fr_to_bytes(&txid.0)),
            "24355ef25433d028ebcc75110e233021e80f6c5fa04bd1b42cdb40c35d8396e8"
        );
    }
}
