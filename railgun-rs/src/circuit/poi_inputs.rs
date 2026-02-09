use ark_bn254::Fr;
use num_bigint::BigInt;
use thiserror::Error;

use crate::{
    crypto::{
        keys::{BigIntKey, NullifyingKey, SpendingPublicKey, bytes_to_bigint, fr_to_bigint},
        railgun_txid::{Txid, TxidLeafHash, UtxoTreeOut},
    },
    merkle_trees::merkle_tree::{MerkleTreeError, TxidMerkleTree, UtxoMerkleTree},
    note::operation::Operation,
    poi::{client::ListKey, poi_note::PoiNote},
};

pub struct PoiCircuitInputs {
    // Public Inputs
    pub railgun_txid_merkle_root_after_transaction: BigInt,
    pub poi_merkle_roots: Vec<BigInt>,

    // Private inputs

    // Railgun Transaction info
    bound_params_hash: BigInt,
    nullifiers: Vec<BigInt>,
    commitments: Vec<BigInt>,

    // Spender wallet info
    spending_public_key: [BigInt; 2],
    nullifying_key: BigInt,

    // Nullified notes data
    token: BigInt,
    randoms_in: Vec<BigInt>,
    values_in: Vec<BigInt>,
    utxo_positions_in: Vec<BigInt>,
    utxo_tree_in: BigInt,

    // Commitment notes data
    npks_out: Vec<BigInt>,
    values_out: Vec<BigInt>,
    utxo_batch_global_start_position_out: BigInt,

    // Unshield data
    railgun_txid_if_has_unshield: BigInt,
    railgun_txid_merkle_proof_indices: BigInt,
    railgun_txid_merkle_proof_path_elements: Vec<BigInt>,

    // POI tree
    poi_in_merkle_proof_indices: Vec<BigInt>,
    poi_in_merkle_proof_path_elements: Vec<Vec<BigInt>>,
}

#[derive(Debug, Error)]
pub enum PoiCircuitInputsError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Merkle tree error")]
    MerkleTree(#[from] MerkleTreeError),
    #[error("Missing POI proofs for list key {0}")]
    MissingPoiProofs(ListKey),
}

impl PoiCircuitInputs {
    pub fn from_inputs(
        spending_pubkey: SpendingPublicKey,
        nullifying_pubkey: NullifyingKey,
        utxo_merkle_tree: &mut UtxoMerkleTree,
        txid_merkle_tree: &mut TxidMerkleTree,
        bound_params_hash: Fr,
        operation: Operation<PoiNote>,
        list_key: ListKey,
    ) -> Result<Self, PoiCircuitInputsError> {
        let utxo_proofs: Vec<_> = operation
            .in_notes()
            .iter()
            .map(|note| utxo_merkle_tree.generate_proof(note.hash()))
            .collect::<Result<_, _>>()?;

        let nullifiers = operation
            .in_notes()
            .iter()
            .zip(utxo_proofs.iter())
            .map(|(note, proof)| note.nullifier(proof.indices))
            .collect::<Vec<Fr>>();
        let commitments: Vec<Fr> = operation
            .out_notes()
            .iter()
            .map(|note| note.hash())
            .collect();

        let txid = Txid::new(&nullifiers, &commitments, bound_params_hash);
        let txid = TxidLeafHash::new(
            txid,
            operation.tree_number(),
            crate::crypto::railgun_txid::UtxoTreeOut::PreInclusion,
        );

        txid_merkle_tree.push_leaf(txid);
        let txid_merkle_root_after_transaction = txid_merkle_tree.root();
        txid_merkle_tree.pop_leaf();

        // Per-note POI proofs
        let poi_proofs = operation
            .in_notes()
            .iter()
            .map(|n| {
                n.poi_merkle_proofs()
                    .get(&list_key)
                    .ok_or(PoiCircuitInputsError::MissingPoiProofs(list_key.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let poi_merkle_roots = poi_proofs
            .iter()
            .map(|proof| fr_to_bigint(&proof.root))
            .collect();
        let poi_in_merkle_proof_indices = poi_proofs
            .iter()
            .map(|proof| BigInt::from(proof.indices))
            .collect();
        let poi_in_merkle_proof_path_elements = poi_proofs
            .iter()
            .map(|proof| proof.elements.iter().map(|e| fr_to_bigint(e)).collect())
            .collect();

        let asset = operation.asset();
        let randoms_in = operation
            .in_notes()
            .iter()
            .map(|n| bytes_to_bigint(&n.random()))
            .collect::<Vec<BigInt>>();
        let values_in = operation
            .in_notes()
            .iter()
            .map(|n| BigInt::from(n.value()))
            .collect::<Vec<BigInt>>();
        let utxo_positions_in = operation
            .in_notes()
            .iter()
            .map(|n| BigInt::from(n.leaf_index()))
            .collect();
        let utxo_tree_in = BigInt::from(operation.tree_number());

        //? Only include output note data for commitment notes. Unshield note
        //? data is included separately.
        let npks_out = operation
            .out_encryptable_notes()
            .iter()
            .map(|n| fr_to_bigint(&n.note_public_key()))
            .collect();
        let values_out = operation
            .out_encryptable_notes()
            .iter()
            .map(|n| BigInt::from(n.value()))
            .collect::<Vec<BigInt>>();

        let txid_if_has_unshield = match &operation.unshield_note() {
            Some(_) => fr_to_bigint(&txid.into()),
            None => BigInt::from(0),
        };

        let txid_merkle_proof = txid_merkle_tree.generate_proof(txid)?;
        let txid_merkle_proof_indices = BigInt::from(txid_merkle_proof.indices);
        let txid_merkle_proof_path_elements = txid_merkle_proof
            .elements
            .iter()
            .map(|e| fr_to_bigint(e))
            .collect();

        Ok(PoiCircuitInputs {
            railgun_txid_merkle_root_after_transaction: fr_to_bigint(
                &txid_merkle_root_after_transaction,
            ),
            poi_merkle_roots,
            bound_params_hash: fr_to_bigint(&bound_params_hash),
            nullifiers: nullifiers.iter().map(|n| fr_to_bigint(n)).collect(),
            commitments: commitments.iter().map(|c| fr_to_bigint(c)).collect(),
            spending_public_key: [spending_pubkey.x_bigint(), spending_pubkey.y_bigint()],
            nullifying_key: nullifying_pubkey.to_bigint(),
            token: fr_to_bigint(&asset.hash()),
            randoms_in,
            values_in,
            utxo_positions_in,
            utxo_tree_in,
            npks_out,
            values_out,
            utxo_batch_global_start_position_out: BigInt::from(
                UtxoTreeOut::PreInclusion.global_index(),
            ),
            railgun_txid_if_has_unshield: txid_if_has_unshield,
            railgun_txid_merkle_proof_indices: txid_merkle_proof_indices,
            railgun_txid_merkle_proof_path_elements: txid_merkle_proof_path_elements,
            poi_in_merkle_proof_indices,
            poi_in_merkle_proof_path_elements,
        })
    }
}
