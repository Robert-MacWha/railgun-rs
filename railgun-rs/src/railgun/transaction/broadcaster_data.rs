use std::collections::{BTreeMap, HashMap};

use ruint::aliases::U256;
use thiserror::Error;

use crate::{
    abis,
    circuit::{
        inputs::{PoiCircuitInputs, PoiCircuitInputsError, TransactCircuitInputs},
        proof::Proof,
        prover::PoiProver,
    },
    railgun::{
        merkle_tree::merkle_tree::UtxoMerkleTree,
        note::{operation::Operation, utxo::UtxoNote},
        poi::{poi_client::ListKey, poi_note::PoiNote},
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

/// POI proof for a single operation, proving that the input notes have valid POI.
pub struct PreTransactionPoi {
    pub snark_proof: Proof,
    pub txid_merkleroot: U256,
    pub poi_merkleroots: Vec<U256>,
    pub blinded_commitments_out: Vec<U256>,
    pub railgun_txid_if_has_unshield: U256,
}

/// A proved operation with POI proofs attached for each list key.
pub struct PoiProvedOperation {
    pub operation: Operation<PoiNote>,
    pub circuit_inputs: TransactCircuitInputs,
    pub transaction: abis::railgun::Transaction,
    /// POI proofs keyed by list key.
    pub pois: HashMap<ListKey, PreTransactionPoi>,
}

/// A transaction with POI proofs for all operations.
pub struct PoiProvedTransaction {
    /// Transaction data to execute this transaction on-chain in railgun.
    pub tx_data: TxData,
    /// The operations with their POI proofs.
    pub operations: Vec<PoiProvedOperation>,
    pub min_gas_price: u128,
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
            let proof = prover
                .prove_poi(&inputs)
                .await
                .map_err(PoiProvedOperationError::Prover)?;

            let pre_transaction_poi = PreTransactionPoi {
                snark_proof: proof,
                txid_merkleroot: inputs.railgun_txid_merkle_root_after_transaction,
                poi_merkleroots: inputs.poi_merkle_roots.clone(),
                blinded_commitments_out: self.operation.blinded_commitments(),
                railgun_txid_if_has_unshield: inputs.railgun_txid_if_has_unshield,
            };

            self.pois.insert(list_key.clone(), pre_transaction_poi);
        }

        Ok(())
    }
}
