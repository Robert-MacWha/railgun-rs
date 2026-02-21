use std::collections::HashMap;

use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    circuit::{
        inputs::poi_inputs::{PoiCircuitInputs, PoiCircuitInputsError},
        prover::PoiProver,
    },
    crypto::{
        keys::{NullifyingKey, SpendingPublicKey},
        railgun_txid::Txid,
    },
    railgun::{
        indexer::{TxidIndexer, UtxoIndexer},
        merkle_tree::UtxoTreeIndex,
        note::utxo::UtxoNote,
        poi::{ListKey, PoiClient, PoiClientError, types::TransactProofData},
        transaction::PoiProvedOperation,
    },
};

/// Tracks operations that have been broadcast and are waiting for their on-chain
/// TXID position to become validated so that post-transaction POI proofs can be
/// submitted to the aggregator.
pub struct PendingPoiSubmitter {
    pending: Vec<PendingPoiEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct PendingPoiSubmitterState {
    pending: Vec<PendingPoiEntry>,
}

/// Minimal serializable snapshot needed to re-prove and submit a
/// post-transaction POI proof to the POI aggregator.
///
/// Created by `PendingPoiSubmitter::register()` after a transaction has been
/// broadcast and is waiting for on-chain confirmation.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingPoiEntry {
    /// Txid used to look up the on-chain position in the TXID tree.
    pub txid: Txid,
    pub spending_pubkey: SpendingPublicKey,
    pub nullifying_key: NullifyingKey,
    pub utxo_tree_in: u32,
    pub bound_params_hash: U256,
    /// Input UTXO notes. Fresh POI proofs are re-fetched at process time.
    pub in_notes: Vec<UtxoNote>,
    /// Hashes of all output notes (fee + transfer + unshield, unpadded).
    pub out_commitments: Vec<U256>,
    /// Note public keys of encryptable (non-unshield) output notes.
    pub out_npks: Vec<U256>,
    /// Values of encryptable output notes.
    pub out_values: Vec<U256>,
    pub token: U256,
    pub has_unshield: bool,
    pub list_keys: Vec<ListKey>,
}

#[derive(Debug, Error)]
pub enum PendingPoiError {
    #[error("POI client error: {0}")]
    PoiClient(#[from] PoiClientError),
    #[error("Circuit inputs error: {0}")]
    CircuitInputs(#[from] PoiCircuitInputsError),
    #[error("Prover error: {0}")]
    Prover(Box<dyn std::error::Error>),
    #[error("Missing UTXO tree {0}")]
    MissingUtxoTree(u32),
    #[error("Missing TXID tree {0}")]
    MissingTxidTree(u32),
}

impl PendingPoiSubmitter {
    pub fn new() -> Self {
        PendingPoiSubmitter {
            pending: Vec::new(),
        }
    }

    pub fn from_state(state: PendingPoiSubmitterState) -> Self {
        Self {
            pending: state.pending,
        }
    }

    pub fn state(&self) -> PendingPoiSubmitterState {
        PendingPoiSubmitterState {
            pending: self.pending.clone(),
        }
    }

    /// Returns the pending entries (for persistence).
    pub fn pending(&self) -> &[PendingPoiEntry] {
        &self.pending
    }

    /// Restore from persisted entries.
    pub fn from_pending(pending: Vec<PendingPoiEntry>) -> Self {
        PendingPoiSubmitter { pending }
    }

    /// Register a proved operation for post-transaction POI submission.
    pub fn register(&mut self, op: &PoiProvedOperation) {
        let Some(txid) = op.txid else { return };
        let spending_pubkey = op.operation.from.spending_key().public_key();

        self.pending.push(PendingPoiEntry {
            txid,
            spending_pubkey,
            nullifying_key: op.operation.from.viewing_key().nullifying_key(),
            utxo_tree_in: op.operation.utxo_tree_number,
            bound_params_hash: op.circuit_inputs.bound_params_hash,
            in_notes: op
                .operation
                .in_notes
                .iter()
                .map(|n| n.note().clone())
                .collect(),
            out_commitments: op
                .operation
                .out_notes()
                .iter()
                .map(|n| n.hash().into())
                .collect(),
            out_npks: op
                .operation
                .out_encryptable_notes()
                .iter()
                .map(|n| n.note_public_key())
                .collect(),
            out_values: op
                .operation
                .out_encryptable_notes()
                .iter()
                .map(|n| U256::from(n.value()))
                .collect(),
            token: op.operation.asset.hash(),
            has_unshield: op.operation.unshield_note.is_some(),
            list_keys: op.pois.keys().cloned().collect(),
        });
    }

    /// Process pending entries: for each entry whose txid now has a validated
    /// on-chain position, re-proves with the real TXID Merkle position and
    /// submits to the POI aggregator.
    ///
    /// Returns the txids that were successfully submitted.
    pub async fn process<P: PoiProver>(
        &mut self,
        txid_indexer: &TxidIndexer,
        utxo_indexer: &UtxoIndexer,
        poi_client: &PoiClient,
        prover: &P,
    ) -> Result<Vec<Txid>, PendingPoiError> {
        let mut submitted = Vec::new();
        for i in 0..self.pending.len() {
            let entry = &self.pending[i];

            let Some((tree_number, leaf_index)) = txid_indexer.txid_set.position_of(&entry.txid)
            else {
                continue;
            };

            let txid_tree = txid_indexer
                .txid_set
                .tree(tree_number)
                .ok_or(PendingPoiError::MissingTxidTree(tree_number))?;

            let utxo_tree = utxo_indexer
                .utxo_trees
                .get(&entry.utxo_tree_in)
                .ok_or(PendingPoiError::MissingUtxoTree(entry.utxo_tree_in))?;

            let included = UtxoTreeIndex::included(tree_number, leaf_index);

            // Re-fetch fresh POI merkle proofs from the aggregator.
            let fresh_poi_notes = poi_client
                .note_to_poi_note(entry.in_notes.clone(), &entry.list_keys)
                .await?;

            // Build and submit a proof for each list key.
            let mut proof_data_map = HashMap::new();
            for list_key in &entry.list_keys {
                let inputs = PoiCircuitInputs::from_inputs_included(
                    entry.spending_pubkey,
                    entry.nullifying_key,
                    utxo_tree,
                    entry.utxo_tree_in,
                    entry.bound_params_hash,
                    &fresh_poi_notes,
                    &entry.out_commitments,
                    &entry.out_npks,
                    &entry.out_values,
                    entry.token,
                    entry.has_unshield,
                    list_key.clone(),
                    included,
                    txid_tree,
                )?;

                let (proof, public_inputs) = prover
                    .prove_poi(&inputs)
                    .await
                    .map_err(PendingPoiError::Prover)?;

                let blinded_commitments_out = public_inputs[0..inputs.nullifiers.len()].to_vec();

                proof_data_map.insert(
                    list_key.clone(),
                    TransactProofData {
                        proof,
                        poi_merkleroots: inputs.poi_merkleroots,
                        txid_merkleroot: inputs.railgun_txid_merkleroot_after_transaction,
                        txid_merkleroot_index: leaf_index as u64,
                        blinded_commitments_out,
                        railgun_txid_if_has_unshield: inputs.railgun_txid_if_has_unshield,
                    },
                );
            }

            poi_client.submit_operation(proof_data_map).await?;
            let txid = entry.txid;
            self.pending.remove(i);
            submitted.push(txid);
        }

        Ok(submitted)
    }
}
