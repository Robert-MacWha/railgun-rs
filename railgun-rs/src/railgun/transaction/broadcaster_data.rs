use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
};

use thiserror::Error;

use crate::{
    abis,
    circuit::{
        inputs::{PoiCircuitInputs, PoiCircuitInputsError, TransactCircuitInputs},
        prover::PoiProver,
    },
    railgun::merkle_tree::TxidLeafHash,
    railgun::{
        broadcaster::broadcaster::Fee,
        merkle_tree::UtxoMerkleTree,
        note::{operation::Operation, utxo::UtxoNote},
        poi::{ListKey, PoiNote, PreTransactionPoi},
        transaction::tx_data::TxData,
    },
};

/// A single proved operation (no POI).
pub struct ProvedOperation {
    pub operation: Operation<UtxoNote>,
    pub circuit_inputs: TransactCircuitInputs,
    pub transaction: abis::railgun::Transaction,
}

/// A transaction that has been proven for railgun (no POI).
pub struct ProvedTransaction {
    /// Transaction data to execute this transaction on-chain in railgun.
    pub tx_data: TxData,
    /// The operations included in this transaction alongside their proof data.
    pub proved_operations: Vec<ProvedOperation>,
    pub min_gas_price: u128,
}

/// A proved operation with POI proofs attached for each list key.
#[derive(Debug)]
pub struct PoiProvedOperation {
    pub operation: Operation<PoiNote>,
    pub circuit_inputs: TransactCircuitInputs,
    pub transaction: abis::railgun::Transaction,
    /// POI proofs keyed by list key.
    pub pois: HashMap<ListKey, PreTransactionPoi>,
    /// The txid leaf hash for this operation (same for all list keys).
    /// Computed on first `add_pois` call.
    pub txid_leaf_hash: Option<TxidLeafHash>,
}

/// A transaction with POI proofs for all operations.
#[derive(Debug)]
pub struct PoiProvedTransaction {
    /// Transaction data to execute this transaction on-chain in railgun.
    pub tx_data: TxData,
    /// The operations with their POI proofs.
    pub operations: Vec<PoiProvedOperation>,
    pub min_gas_price: u128,
    /// Optional fee information if this transaction is being sent through a broadcaster.
    pub fee: Option<Fee>,
}

#[derive(Debug, Error)]
pub enum PoiProvedOperationError {
    #[error("Missing UTXO tree for tree number {0}")]
    MissingTree(u32),
    #[error("Circuit Inputs error: {0}")]
    CircuitInputs(#[from] PoiCircuitInputsError),
    #[error("Prover error: {0}")]
    Prover(Box<dyn std::error::Error>),
}

impl PoiProvedOperation {
    /// Add POI proofs to this operation for the provided list keys.
    pub async fn add_pois(
        &mut self,
        prover: &impl PoiProver,
        list_keys: &[ListKey],
        utxo_trees: &BTreeMap<u32, UtxoMerkleTree>,
    ) -> Result<(), PoiProvedOperationError> {
        let utxo_merkle_tree = utxo_trees.get(&self.operation.utxo_tree_number).ok_or(
            PoiProvedOperationError::MissingTree(self.operation.utxo_tree_number),
        )?;

        // Generate a POI proof for each list key and add it to the pois map.
        for list_key in list_keys {
            if self.pois.contains_key(list_key) {
                continue;
            }

            let inputs = PoiCircuitInputs::from_inputs(
                self.operation.from.spending_key().public_key(),
                self.operation.from.viewing_key().nullifying_key(),
                utxo_merkle_tree,
                self.circuit_inputs.bound_params_hash,
                &self.operation,
                list_key.clone(),
            )?;

            // Store txid_leaf_hash (same for all list keys)
            if self.txid_leaf_hash.is_none() {
                self.txid_leaf_hash = Some(inputs.txid_leaf_hash);
            }

            let (proof, public_inputs) = prover
                .prove_poi(&inputs)
                .await
                .map_err(PoiProvedOperationError::Prover)?;

            let pre_transaction_poi = PreTransactionPoi {
                proof,
                txid_merkleroot: inputs.railgun_txid_merkleroot_after_transaction,
                poi_merkleroots: inputs.poi_merkleroots,
                blinded_commitments_out: public_inputs[0..inputs.nullifiers.len()].to_vec(),
                railgun_txid_if_has_unshield: inputs.railgun_txid_if_has_unshield,
            };

            self.pois.insert(list_key.clone(), pre_transaction_poi);
        }

        Ok(())
    }
}

impl Display for ProvedOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProvedOperation({})", self.operation)
    }
}

impl Display for PoiProvedOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PoiProvedOperation({}, pois: {:?})",
            self.operation,
            self.pois.keys()
        )
    }
}
