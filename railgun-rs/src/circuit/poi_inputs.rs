use std::collections::HashMap;

use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::circuit::circuit_input::IntoSignalVec;
use crate::crypto::keys::U256Key;
use crate::{
    circuit_inputs,
    crypto::{
        keys::{NullifyingKey, SpendingPublicKey},
        railgun_txid::{Txid, TxidLeaf, UtxoTreeOut},
        railgun_zero::railgun_merkle_tree_zero,
    },
    railgun::merkle_tree::{
        merkle_proof::MerkleProof,
        merkle_tree::{MerkleTreeError, UtxoMerkleTree},
    },
    railgun::note::{IncludedNote, Note, operation::Operation},
    railgun::poi::{poi_client::ListKey, poi_note::PoiNote},
};

// TODO: Consider making me into an enum with two variants on a generic Inner, so
// the values can be [_; 3] / [_; 13] instead of Vec<_> with padding.
#[derive(Debug, Serialize, Deserialize)]
pub struct PoiCircuitInputs {
    // Public Inputs
    /// A merkle root from the txid merkle tree after this note's
    pub railgun_txid_merkle_root_after_transaction: U256,
    pub poi_merkle_roots: Vec<U256>,

    // Private inputs

    // Railgun Transaction info
    bound_params_hash: U256,

    //? Required for prover
    pub nullifiers: Vec<U256>,
    pub commitments: Vec<U256>,

    // Spender wallet info
    spending_public_key: [U256; 2],
    nullifying_key: U256,

    // Nullified notes data
    token: U256,
    randoms_in: Vec<U256>,
    values_in: Vec<U256>,
    utxo_positions_in: Vec<U256>,
    utxo_tree_in: U256,

    // Commitment notes data
    npks_out: Vec<U256>,
    values_out: Vec<U256>,
    utxo_batch_global_start_position_out: U256,

    // Unshield data
    railgun_txid_if_has_unshield: U256,
    railgun_txid_merkle_proof_indices: U256,
    railgun_txid_merkle_proof_path_elements: Vec<U256>,

    // POI tree
    poi_in_merkle_proof_indices: Vec<U256>,
    poi_in_merkle_proof_path_elements: Vec<Vec<U256>>,
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
fn pad_with_zero_value(vec: Vec<U256>, target_len: usize) -> Vec<U256> {
    pad_with_value(vec, target_len, railgun_merkle_tree_zero())
}

/// Pads a vector with zero (0).
fn pad_with_zero(vec: Vec<U256>, target_len: usize) -> Vec<U256> {
    pad_with_value(vec, target_len, U256::from(0))
}

/// Pads a vector with the given value.
fn pad_with_value(mut vec: Vec<U256>, target_len: usize, value: U256) -> Vec<U256> {
    while vec.len() < target_len {
        vec.push(value.clone());
    }
    vec
}

/// Pads a 2D vector (array of merkle proof paths) to the target length.
fn pad_merkle_proof_paths(mut vec: Vec<Vec<U256>>, target_len: usize) -> Vec<Vec<U256>> {
    let zero = railgun_merkle_tree_zero();
    let empty_path: Vec<U256> = vec![zero; POI_MERKLE_PROOF_DEPTH];
    while vec.len() < target_len {
        vec.push(empty_path.clone());
    }
    vec
}

impl PoiCircuitInputs {
    pub fn from_inputs(
        spending_pubkey: SpendingPublicKey,
        nullifying_pubkey: NullifyingKey,
        utxo_merkle_tree: &mut UtxoMerkleTree,
        bound_params_hash: U256,
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
        let nullifiers: Vec<U256> = operation
            .in_notes()
            .iter()
            .zip(utxo_proofs.iter())
            .map(|(note, proof)| note.nullifier(proof.indices))
            .collect();
        let commitments: Vec<U256> = operation
            .out_notes()
            .iter()
            .map(|note| note.hash().into())
            .collect();

        let txid = Txid::new(&nullifiers, &commitments, bound_params_hash);
        let txid_leaf_hash = TxidLeaf::new(
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
        let poi_merkle_roots = poi_proofs.iter().map(|p| p.root).collect();
        let poi_in_merkle_proof_indices =
            poi_proofs.iter().map(|p| U256::from(p.indices)).collect();
        let poi_in_merkle_proof_path_elements =
            poi_proofs.iter().map(|p| p.elements.clone()).collect();

        let asset = operation.asset();
        let randoms_in = operation
            .in_notes()
            .iter()
            .map(|n| U256::from_be_slice(&n.random()))
            .collect();
        let values_in = operation
            .in_notes()
            .iter()
            .map(|n| U256::from(n.value()))
            .collect();
        let utxo_positions_in = operation
            .in_notes()
            .iter()
            .map(|n| U256::from(n.leaf_index()))
            .collect();
        let utxo_tree_in = U256::from(operation.utxo_tree_number());

        //? Only include output note data for commitment notes. Unshield note
        //? data is included separately.
        let npks_out = operation
            .out_encryptable_notes()
            .iter()
            .map(|n| n.note_public_key())
            .collect();
        let values_out = operation
            .out_encryptable_notes()
            .iter()
            .map(|n| U256::from(n.value()))
            .collect();

        let txid_if_has_unshield = match &operation.unshield_note() {
            Some(_) => txid.into(),
            None => U256::from(0),
        };

        // Determine circuit size and apply padding
        let max_size = circuit_size(nullifiers.len(), commitments.len());

        Ok(PoiCircuitInputs {
            railgun_txid_merkle_root_after_transaction: txid_proof.root,
            poi_merkle_roots: pad_with_zero_value(poi_merkle_roots, max_size),
            bound_params_hash: bound_params_hash,
            nullifiers: pad_with_zero_value(nullifiers, max_size),
            commitments: pad_with_zero_value(commitments, max_size),
            spending_public_key: [spending_pubkey.x_u256(), spending_pubkey.y_u256()],
            nullifying_key: nullifying_pubkey.to_u256(),
            token: asset.hash(),
            randoms_in: pad_with_zero_value(randoms_in, max_size),
            values_in: pad_with_zero(values_in, max_size),
            utxo_positions_in: pad_with_zero_value(utxo_positions_in, max_size),
            utxo_tree_in,
            npks_out: pad_with_zero_value(npks_out, max_size),
            values_out: pad_with_zero(values_out, max_size),
            utxo_batch_global_start_position_out: U256::from(
                UtxoTreeOut::PreInclusion.global_index(),
            ),
            railgun_txid_if_has_unshield: txid_if_has_unshield,
            railgun_txid_merkle_proof_indices: U256::from(txid_proof.indices),
            railgun_txid_merkle_proof_path_elements: txid_proof.elements,
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
