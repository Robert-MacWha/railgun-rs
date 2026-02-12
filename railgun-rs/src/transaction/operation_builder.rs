//! Because Railgun's transaction-within-transaction language is confusing, I'm
//! setting some ground rules.
//!
//! A "Note" is an already-on-chain note, which can be used as an input to an Operation.
//!
//! A "Operation" means a single railgun transaction (IE `RailgunSmartWallet.Transaction` object).
//!  - An operation can have many input notes, but they must all be on the same tree and held by the same address.
//!  - An operation may have many output notes, which can be to different addresses and on different trees.
//!  - An operation may only have one unshield note, since the `RailgunSmartWallet.Transaction` struct only
//!
//! A "Transaction" means an EVM transaction.
//!  - A transaction can have many operations across many trees and addresses.

use std::collections::{BTreeMap, HashMap};

use alloy::primitives::Address;
use rand::{Rng, random};
use thiserror::Error;
use tracing::{info, warn};

use crate::{
    abis,
    account::RailgunAccount,
    caip::AssetId,
    chain_config::ChainConfig,
    circuit::{
        prover::TransactProver,
        transact_inputs::{TransactCircuitInputs, TransactCircuitInputsError},
    },
    indexer::indexer::Indexer,
    merkle_trees::merkle_tree::UtxoMerkleTree,
    note::{
        IncludedNote, Note, encrypt::EncryptError, operation::Operation, transfer::TransferNote,
        unshield::UnshieldNote, utxo::UtxoNote,
    },
    railgun::address::RailgunAddress,
    transaction::tx_data::TxData,
};

/// A builder for construction railgun operations (transfers, unshields)
pub struct OperationBuilder {
    transfers: Vec<TransferData>,
    unshields: HashMap<AssetId, UnshieldData>,
}

struct TransferData {
    pub from: RailgunAccount,
    pub to: RailgunAddress,
    pub asset: AssetId,
    pub value: u128,
    pub memo: String,
}

struct UnshieldData {
    pub from: RailgunAccount,
    pub to: Address,
    pub asset: AssetId,
    pub value: u128,
}

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("Multiple unshield operations are not supported")]
    MultipleUnshields,
    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptError),
    #[error("Prover error: {0}")]
    Prover(#[from] Box<dyn std::error::Error>),
    #[error("Missing tree for number {0}")]
    MissingTree(u32),
    #[error("Transact circuit input error: {0}")]
    TransactCircuitInput(#[from] TransactCircuitInputsError),
}

impl OperationBuilder {
    pub fn new() -> Self {
        Self {
            transfers: Vec::new(),
            unshields: HashMap::new(),
        }
    }

    pub fn transfer(
        &mut self,
        from: RailgunAccount,
        to: RailgunAddress,
        asset: AssetId,
        value: u128,
        memo: &str,
    ) {
        let transfer_data = TransferData {
            from,
            to,
            asset,
            value,
            memo: memo.to_string(),
        };
        self.transfers.push(transfer_data);
    }

    pub fn set_unshield(&mut self, from: RailgunAccount, to: Address, asset: AssetId, value: u128) {
        let unshield_data = UnshieldData {
            from,
            to,
            asset,
            value,
        };
        let old = self.unshields.insert(asset, unshield_data);
        if old.is_some() {
            warn!(
                "Overwriting existing unshield data for {}",
                old.unwrap().asset
            );
        }
    }

    /// Builds the operations.
    ///
    /// Groups input notes by (tree_number, asset_id) and creates separate operations
    /// for each group. Creates change notes when input value exceeds output value.
    ///
    /// Preserves the ordering of transfers within and across operations. Does not
    /// guarantee any particular ordering of unshield operations relative to transfers.
    pub fn build<N: IncludedNote>(
        &mut self,
        in_notes: Vec<N>,
    ) -> Result<Vec<Operation<N>>, BuildError> {
        // 1. Group input notes by (tree_number, asset_id)
        let mut grouped: HashMap<(u32, AssetId), Vec<N>> = HashMap::new();
        for note in in_notes {
            let key = (note.tree_number(), note.asset());
            grouped.entry(key).or_default().push(note);
        }

        // 2. Get sender account from first transfer or unshield (needed for change notes)
        let sender = self
            .transfers
            .first()
            .map(|t| &t.from)
            .or_else(|| self.unshields.values().next().map(|u| &u.from));

        // 3. Build operations for each group
        let mut operations = Vec::new();
        for ((tree_number, asset), notes) in grouped {
            let input_sum: u128 = notes.iter().map(|n| n.value()).sum();

            // Filter transfers for this asset
            let mut out_notes: Vec<TransferNote> = self
                .transfers
                .iter()
                .filter(|t| t.asset == asset)
                .map(|t| {
                    TransferNote::new(
                        t.from.viewing_key(),
                        t.to,
                        t.asset,
                        t.value,
                        random(),
                        &t.memo,
                    )
                })
                .collect();

            let transfer_sum: u128 = out_notes.iter().map(|n| n.value()).sum();
            let unshield_value = self.unshields.get(&asset).map(|u| u.value).unwrap_or(0);
            let output_sum = transfer_sum + unshield_value;

            // Add change note if input > output
            if input_sum > output_sum {
                if let Some(sender) = sender {
                    let change_value = input_sum - output_sum;
                    out_notes.push(TransferNote::new(
                        sender.viewing_key(),
                        sender.address(),
                        asset,
                        change_value,
                        random(),
                        "",
                    ));
                }
            }

            let unshield = self
                .unshields
                .get(&asset)
                .map(|u| UnshieldNote::new(u.to, u.asset, u.value));

            operations.push(Operation::new(tree_number, notes, out_notes, unshield));
        }

        Ok(operations)
    }

    pub async fn build_transaction<R: Rng>(
        &mut self,
        prover: &impl TransactProver,
        indexer: &mut Indexer,
        chain: ChainConfig,
        rng: &mut R,
    ) -> Result<TxData, BuildError> {
        let in_notes = indexer.all_unspent();
        let operations = self.build(in_notes)?;
        let utxo_trees = &mut indexer.utxo_trees;
        let transactions = create_transactions(
            prover,
            utxo_trees,
            operations,
            chain,
            0,
            Address::ZERO,
            &[0u8; 32],
            rng,
        )
        .await?;

        Ok(TxData::new(chain.railgun_smart_wallet, transactions))
    }

    pub async fn build_broadcasted<R: Rng>(
        &mut self,
        prover: &impl TransactProver,
        indexer: &mut Indexer,
        chain: ChainConfig,
        rng: &mut R,
    ) -> Result<TxData, BuildError> {
        // let tx_data = self.build_transaction(prover, indexer, chain, rng).await?;
        todo!()
    }
}

async fn create_transactions<R: Rng>(
    prover: &impl TransactProver,
    utxo_trees: &mut BTreeMap<u32, UtxoMerkleTree>,
    operations: Vec<Operation<UtxoNote>>,
    chain: ChainConfig,
    min_gas_price: u128,
    adapt_contract: Address,
    adapt_input: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<abis::railgun::Transaction>, BuildError> {
    let mut transactions = Vec::new();
    for operation in operations {
        let tree_number = operation.utxo_tree_number();
        let mut tree = utxo_trees
            .get_mut(&tree_number)
            .ok_or(BuildError::MissingTree(tree_number))?;

        let transaction = create_transaction(
            prover,
            &mut tree,
            operation,
            chain,
            min_gas_price,
            adapt_contract,
            adapt_input,
            rng,
        )
        .await?;

        transactions.push(transaction);
    }

    Ok(transactions)
}

async fn create_transaction<R: Rng>(
    prover: &impl TransactProver,
    utxo_tree: &mut UtxoMerkleTree,
    operation: Operation<UtxoNote>,
    chain: ChainConfig,
    min_gas_price: u128,
    adapt_contract: Address,
    adapt_input: &[u8; 32],
    rng: &mut R,
) -> Result<abis::railgun::Transaction, BuildError> {
    let notes_in = operation.in_notes();
    let notes_out = operation.out_notes();

    info!("Constructing circuit inputs");
    let unshield_type = operation
        .unshield_note()
        .map(|n| n.unshield_type())
        .unwrap_or_default();

    let commitment_ciphertexts: Vec<abis::railgun::CommitmentCiphertext> = operation
        .out_encryptable_notes()
        .iter()
        .map(|n| n.encrypt(rng))
        .collect::<Result<_, _>>()?;

    let bound_params = abis::railgun::BoundParams::new(
        utxo_tree.number() as u16,
        min_gas_price,
        unshield_type,
        chain.id,
        adapt_contract,
        adapt_input,
        commitment_ciphertexts,
    );

    let inputs =
        TransactCircuitInputs::from_inputs(utxo_tree, bound_params.hash(), notes_in, &notes_out)?;

    info!("Proving transaction");
    let proof = prover.prove_transact(&inputs).await?;

    let transaction = abis::railgun::Transaction {
        proof: proof.into(),
        merkleRoot: inputs.merkle_root.into(),
        nullifiers: inputs.nullifiers.iter().map(|n| n.clone().into()).collect(),
        commitments: inputs
            .commitments_out
            .iter()
            .map(|c| c.clone().into())
            .collect(),
        boundParams: bound_params,
        unshieldPreimage: operation
            .unshield_note()
            .map(|n| n.preimage())
            .unwrap_or_default(),
    };

    Ok(transaction)
}
