use std::collections::HashMap;

use ark_bn254::Fr;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::circuit::circuit_input::IntoSignalVec;
use crate::circuit::prover::{PoiProver, Proof};
use crate::{
    circuit_inputs,
    crypto::{
        keys::{BigIntKey, NullifyingKey, SpendingPublicKey, bytes_to_bigint, fr_to_bigint},
        railgun_txid::{Txid, TxidLeafHash, UtxoTreeOut},
        railgun_zero::railgun_merkle_tree_zero,
    },
    merkle_trees::{
        merkle_proof::MerkleProof,
        merkle_tree::{MerkleTreeError, UtxoMerkleTree},
    },
    note::{IncludedNote, Note, operation::Operation},
    poi::{client::ListKey, poi_note::PoiNote},
};

// TODO: Consider making me into an enum with two variants on a generic Inner, so
// the values can be [_; 3] / [_; 13] instead of Vec<_> with padding.
#[derive(Debug, Serialize, Deserialize)]
pub struct PoiCircuitInputs {
    // Public Inputs
    /// A merkle root from the txid merkle tree after this note's
    pub railgun_txid_merkle_root_after_transaction: BigInt,
    pub poi_merkle_roots: Vec<BigInt>,

    // Private inputs

    // Railgun Transaction info
    bound_params_hash: BigInt,

    //? Required for prover
    pub nullifiers: Vec<BigInt>,
    pub commitments: Vec<BigInt>,

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
pub enum PoiCircuitProofError {
    #[error("Invalid circuit inputs: {0}")]
    InvalidCircuitInputs(#[from] PoiCircuitInputsError),
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(Box<dyn std::error::Error>),
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

const POI_MERKLE_PROOF_DEPTH: usize = 16;

/// Determines the circuit size based on the number of nullifiers and commitments.
/// Returns 3 for the "mini" circuit, 13 for the "full" circuit.
fn circuit_size(nullifiers_len: usize, commitments_len: usize) -> usize {
    if nullifiers_len <= 3 && commitments_len <= 3 {
        3
    } else {
        13
    }
}

/// Pads a vector with the railgun merkle tree zero value.
fn pad_with_zero_value(vec: Vec<BigInt>, target_len: usize) -> Vec<BigInt> {
    let zero = fr_to_bigint(&railgun_merkle_tree_zero());
    pad_with_value(vec, target_len, zero)
}

/// Pads a vector with zero (0).
fn pad_with_zero(vec: Vec<BigInt>, target_len: usize) -> Vec<BigInt> {
    pad_with_value(vec, target_len, BigInt::from(0))
}

/// Pads a vector with the given value.
fn pad_with_value(mut vec: Vec<BigInt>, target_len: usize, value: BigInt) -> Vec<BigInt> {
    while vec.len() < target_len {
        vec.push(value.clone());
    }
    vec
}

/// Pads a 2D vector (array of merkle proof paths) to the target length.
fn pad_merkle_proof_paths(mut vec: Vec<Vec<BigInt>>, target_len: usize) -> Vec<Vec<BigInt>> {
    let zero = fr_to_bigint(&railgun_merkle_tree_zero());
    let empty_path: Vec<BigInt> = vec![zero; POI_MERKLE_PROOF_DEPTH];
    while vec.len() < target_len {
        vec.push(empty_path.clone());
    }
    vec
}

impl PoiCircuitInputs {
    pub fn prove<P: PoiProver>(
        prover: P,
        spending_pubkey: SpendingPublicKey,
        nullifying_pubkey: NullifyingKey,
        utxo_merkle_tree: &mut UtxoMerkleTree,
        bound_params_hash: Fr,
        operation: &Operation<PoiNote>,
        list_key: ListKey,
    ) -> Result<Proof, PoiCircuitProofError> {
        let inputs = Self::from_inputs(
            spending_pubkey,
            nullifying_pubkey,
            utxo_merkle_tree,
            bound_params_hash,
            operation,
            list_key,
        )?;

        let proof = prover
            .prove_poi(&inputs)
            .map_err(|e| PoiCircuitProofError::ProofGenerationFailed(e))?;

        Ok(proof)
    }

    pub fn from_inputs(
        spending_pubkey: SpendingPublicKey,
        nullifying_pubkey: NullifyingKey,
        utxo_merkle_tree: &mut UtxoMerkleTree,
        bound_params_hash: Fr,
        operation: &Operation<PoiNote>,
        list_key: ListKey,
    ) -> Result<Self, PoiCircuitInputsError> {
        info!("UTXO proofs");
        let utxo_proofs: Vec<_> = operation
            .in_notes()
            .iter()
            .map(|note| utxo_merkle_tree.generate_proof(note.hash()))
            .collect::<Result<_, _>>()?;

        info!("Nullifiers and commitments");
        let nullifiers = operation
            .in_notes()
            .iter()
            .zip(utxo_proofs.iter())
            .map(|(note, proof)| note.nullifier(proof.indices))
            .collect::<Vec<Fr>>();
        let commitments: Vec<Fr> = operation
            .out_notes()
            .iter()
            .map(|note| note.hash().into())
            .collect();

        let txid = Txid::new(&nullifiers, &commitments, bound_params_hash);
        let txid_leaf_hash = TxidLeafHash::new(
            txid,
            operation.utxo_tree_number(),
            crate::crypto::railgun_txid::UtxoTreeOut::PreInclusion,
        );
        let txid_proof = MerkleProof::new_pre_inclusion(txid_leaf_hash.into());

        // Per-note POI proofs
        info!("POI proofs");
        let poi_proofs = operation
            .in_notes()
            .iter()
            .map(|n| {
                n.poi_merkle_proofs()
                    .get(&list_key)
                    .ok_or(PoiCircuitInputsError::MissingPoiProofs(list_key.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        info!("Assembling circuit inputs");
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
        let utxo_tree_in = BigInt::from(operation.utxo_tree_number());

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

        // Determine circuit size and apply padding
        let max_size = circuit_size(nullifiers.len(), commitments.len());

        let nullifiers: Vec<BigInt> = nullifiers.iter().map(|n| fr_to_bigint(n)).collect();
        let commitments: Vec<BigInt> = commitments.iter().map(|c| fr_to_bigint(c)).collect();

        Ok(PoiCircuitInputs {
            railgun_txid_merkle_root_after_transaction: fr_to_bigint(&txid_proof.root),
            poi_merkle_roots: pad_with_zero_value(poi_merkle_roots, max_size),
            bound_params_hash: fr_to_bigint(&bound_params_hash),
            nullifiers: pad_with_zero_value(nullifiers, max_size),
            commitments: pad_with_zero_value(commitments, max_size),
            spending_public_key: [spending_pubkey.x_bigint(), spending_pubkey.y_bigint()],
            nullifying_key: nullifying_pubkey.to_bigint(),
            token: fr_to_bigint(&asset.hash()),
            randoms_in: pad_with_zero_value(randoms_in, max_size),
            values_in: pad_with_zero(values_in, max_size),
            utxo_positions_in: pad_with_zero_value(utxo_positions_in, max_size),
            utxo_tree_in,
            npks_out: pad_with_zero_value(npks_out, max_size),
            values_out: pad_with_zero(values_out, max_size),
            utxo_batch_global_start_position_out: BigInt::from(
                UtxoTreeOut::PreInclusion.global_index(),
            ),
            railgun_txid_if_has_unshield: txid_if_has_unshield,
            railgun_txid_merkle_proof_indices: BigInt::from(txid_proof.indices),
            railgun_txid_merkle_proof_path_elements: txid_proof
                .elements
                .iter()
                .map(|e| fr_to_bigint(e))
                .collect(),
            poi_in_merkle_proof_indices: pad_with_zero(poi_in_merkle_proof_indices, max_size),
            poi_in_merkle_proof_path_elements: pad_merkle_proof_paths(
                poi_in_merkle_proof_path_elements,
                max_size,
            ),
        })
    }

    circuit_inputs!(
        railgun_txid_merkle_root_after_transaction => "anyRailgunTxidMerklerootAfterTransaction",
        bound_params_hash => "boundParamsHash",
        nullifiers => "nullifiers",
        commitments => "commitmentsOut",
        spending_public_key => "spendingPublicKey",
        nullifying_key => "nullifyingKey",
        token => "token",
        randoms_in => "randomsIn",
        values_in => "valuesIn",
        utxo_positions_in => "utxoPositionsIn",
        utxo_tree_in => "utxoTreeIn",
        npks_out => "npksOut",
        values_out => "valuesOut",
        utxo_batch_global_start_position_out => "utxoBatchGlobalStartPositionOut",
        railgun_txid_if_has_unshield => "railgunTxidIfHasUnshield",
        railgun_txid_merkle_proof_indices => "railgunTxidMerkleProofIndices",
        railgun_txid_merkle_proof_path_elements => "railgunTxidMerkleProofPathElements",
        poi_merkle_roots => "poiMerkleroots",
        poi_in_merkle_proof_indices => "poiInMerkleProofIndices",
        poi_in_merkle_proof_path_elements => "poiInMerkleProofPathElements"
    );

    /// Serialize inputs to JSON for creating test fixtures.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Load inputs from JSON fixture.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::native_prover::NativeProver;

    const TEST_FIXTURE_PATH: &str = "tests/fixtures/poi_03x03_circuit_inputs.json";

    #[tokio::test]
    #[ignore] // Run with: cargo test test_poi_proof_from_fixture -- --ignored
    async fn test_poi_proof_from_fixture() {
        let json = std::fs::read_to_string(TEST_FIXTURE_PATH)
            .expect("Failed to read test fixture. Run a test that generates the fixture first.");

        let inputs = PoiCircuitInputs::from_json(&json).expect("Failed to parse test fixture");

        let prover = NativeProver::new();
        prover.prove_poi(&inputs).expect("Proof generation failed");
    }
}
