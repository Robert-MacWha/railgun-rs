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
use rand::Rng;
use ruint::aliases::U256;
use thiserror::Error;
use tracing::{info, warn};

use crate::{
    abis,
    account::RailgunAccount,
    caip::AssetId,
    chain_config::ChainConfig,
    circuit::{
        inputs::{PoiCircuitInputsError, TransactCircuitInputs, TransactCircuitInputsError},
        prover::{PoiProver, TransactProver},
    },
    crypto::keys::ViewingPublicKey,
    railgun::{
        address::RailgunAddress,
        broadcaster::broadcaster::Fee,
        indexer::indexer::Indexer,
        merkle_tree::{merkle_proof::MerkleRoot, merkle_tree::UtxoMerkleTree},
        note::{
            IncludedNote,
            encrypt::EncryptError,
            operation::{Operation, OperationVerificationError},
            transfer::TransferNote,
            unshield::UnshieldNote,
            utxo::UtxoNote,
        },
        poi::{ListKey, PoiClient, PoiClientError},
        transaction::{
            broadcaster_data::{
                PoiProvedOperation, PoiProvedOperationError, PoiProvedTransaction, ProvedOperation,
                ProvedTransaction,
            },
            gas_estimator::GasEstimator,
            tx_data::TxData,
        },
    },
};

/// A builder for construction railgun operations (transfers, unshields)
#[derive(Clone)]
pub struct OperationBuilder {
    transfers: Vec<TransferData>,
    unshields: BTreeMap<AssetId, UnshieldData>,
    broadcaster_fee: Option<TransferData>,
    accounts: BTreeMap<ViewingPublicKey, RailgunAccount>,
}

#[derive(Clone)]
struct TransferData {
    pub from: RailgunAccount,
    pub to: RailgunAddress,
    pub asset: AssetId,
    pub value: u128,
    pub memo: String,
}

#[derive(Clone)]
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
    Prover(Box<dyn std::error::Error>),
    #[error("Missing tree for number {0}")]
    MissingTree(u32),
    #[error("Transact circuit input error: {0}")]
    TransactCircuitInput(#[from] TransactCircuitInputsError),
    #[error("Poi Client error: {0}")]
    PoiClient(#[from] PoiClientError),
    #[error("Poi Circuit input error: {0}")]
    PoiCircuitInput(#[from] PoiCircuitInputsError),
    #[error("Operation verification error: {0}")]
    OperationVerification(#[from] OperationVerificationError),
    #[error("Estimator error: {0}")]
    Estimator(Box<dyn std::error::Error>),
    #[error("POI Proved Operation error: {0}")]
    PoiProvedOperation(#[from] PoiProvedOperationError),
    #[error("Invalid POI merkleroot for list key {0}: {1}")]
    InvalidPoiMerkleroot(ListKey, MerkleRoot),
}

const FEE_BUFFER: f64 = 1.3;

impl OperationBuilder {
    pub fn new() -> Self {
        Self {
            transfers: Vec::new(),
            unshields: BTreeMap::new(),
            broadcaster_fee: None,
            accounts: BTreeMap::new(),
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
        self.accounts
            .insert(from.viewing_key().public_key(), from.clone());

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
        self.accounts
            .insert(from.viewing_key().public_key(), from.clone());

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

    fn set_broadcaster_fee(
        &mut self,
        from: RailgunAccount,
        to: RailgunAddress,
        asset: AssetId,
        value: u128,
    ) {
        self.accounts
            .insert(from.viewing_key().public_key(), from.clone());
        let fee_data = TransferData {
            from,
            to,
            asset,
            value,
            memo: "fee".to_string(),
        };
        self.broadcaster_fee = Some(fee_data);
    }

    /// Builds and proves a transaction for railgun.
    ///
    /// The resulting transaction can be self-broadcasted, but does not include
    /// any POI proofs.
    pub async fn build<R: Rng>(
        &self,
        indexer: &Indexer,
        prover: &impl TransactProver,
        chain: ChainConfig,
        rng: &mut R,
    ) -> Result<TxData, BuildError> {
        let in_notes = indexer.all_unspent();
        let operations = self.build_operations(in_notes, rng)?;

        let proved = self
            .prove_operations(prover, &indexer.utxo_trees, &operations, chain, 0, rng)
            .await?;

        Ok(proved.tx_data)
    }

    /// Builds and proves a transaction for railgun with POI proofs.
    pub async fn build_with_poi<R: Rng>(
        &self,
        indexer: &mut Indexer,
        prover: &(impl TransactProver + PoiProver),
        poi_client: &PoiClient,
        chain: ChainConfig,
        rng: &mut R,
    ) -> Result<PoiProvedTransaction, BuildError> {
        let in_notes = indexer.all_unspent();
        let operations = self.build_operations(in_notes, rng)?;

        let proved = self
            .prove_operations(prover, &mut indexer.utxo_trees, &operations, chain, 0, rng)
            .await?;

        let list_keys = poi_client.list_keys();
        self.prove_poi(
            prover,
            poi_client,
            proved,
            &mut indexer.utxo_trees,
            &list_keys,
            None,
        )
        .await
    }

    /// Builds a transaction with fee calculation and POI proofs for broadcasting.
    ///
    /// Calculates the broadcaster fee iteratively, proves the transaction,
    /// and generates POI proofs.
    pub async fn build_with_broadcast<R: Rng>(
        &self,
        indexer: &Indexer,
        prover: &(impl TransactProver + PoiProver),
        poi_client: &PoiClient,
        estimator: &impl GasEstimator,
        fee_payer: RailgunAccount,
        fee: &Fee,
        chain: ChainConfig,
        rng: &mut R,
    ) -> Result<PoiProvedTransaction, BuildError> {
        let in_notes = indexer.all_unspent();

        let proved = calculate_fee_to_convergence(
            self,
            &in_notes,
            prover,
            &indexer.utxo_trees,
            estimator,
            fee_payer,
            fee,
            chain,
            rng,
        )
        .await?;

        self.prove_poi(
            prover,
            poi_client,
            proved,
            &indexer.utxo_trees,
            &fee.list_keys,
            Some(fee.clone()),
        )
        .await
    }

    /// Proves the operations and returns a proved transaction that can be
    /// executed in railgun on-chain.
    async fn prove_operations<R: Rng>(
        &self,
        prover: &impl TransactProver,
        utxo_trees: &BTreeMap<u32, UtxoMerkleTree>,
        operations: &[Operation<UtxoNote>],
        chain: ChainConfig,
        min_gas_price: u128,
        rng: &mut R,
    ) -> Result<ProvedTransaction, BuildError> {
        let tx_results = create_transactions(
            prover,
            utxo_trees,
            operations,
            chain,
            min_gas_price,
            Address::ZERO,
            &[0u8; 32],
            rng,
        )
        .await?;

        let proved_operations: Vec<ProvedOperation> = operations
            .iter()
            .zip(tx_results)
            .map(|(op, (ci, tx))| ProvedOperation {
                operation: op.clone(),
                circuit_inputs: ci,
                transaction: tx,
            })
            .collect();

        let transactions: Vec<_> = proved_operations
            .iter()
            .map(|po| po.transaction.clone())
            .collect();
        let tx_data = TxData::from_transactions(chain.railgun_smart_wallet, transactions);

        Ok(ProvedTransaction {
            proved_operations,
            tx_data,
            min_gas_price,
        })
    }

    /// Builds the operations.
    ///
    /// Groups input notes by (tree_number, asset_id, viewing_public_key) and creates
    /// separate operations for each group. This ensures that each operation only
    /// contains notes from the same owner, tree, and asset.
    ///
    /// Creates change notes when input value exceeds output value.
    fn build_operations<N: IncludedNote, R: Rng>(
        &self,
        in_notes: Vec<N>,
        rng: &mut R,
    ) -> Result<Vec<Operation<N>>, BuildError> {
        //? Collect all output notes into draft operations, grouped by (from_address, asset_id).
        let mut draft_operations: HashMap<(RailgunAddress, AssetId), Operation<N>> = HashMap::new();
        for transfer in &self.transfers {
            draft_operations
                .entry((transfer.from.address(), transfer.asset))
                .or_insert(Operation::new_empty(
                    0,
                    transfer.from.clone(),
                    transfer.asset,
                ))
                .out_notes
                .push(TransferNote::new(
                    transfer.from.viewing_key(),
                    transfer.to,
                    transfer.asset,
                    transfer.value,
                    rng.random(),
                    &transfer.memo,
                ));
        }

        for unshield in self.unshields.values() {
            draft_operations
                .entry((unshield.from.address(), unshield.asset))
                .or_insert(Operation::new_empty(
                    0,
                    unshield.from.clone(),
                    unshield.asset,
                ))
                .unshield_note = Some(UnshieldNote::new(
                unshield.to,
                unshield.asset,
                unshield.value,
            ));
        }

        if let Some(fee) = &self.broadcaster_fee {
            draft_operations
                .entry((fee.from.address(), fee.asset))
                .or_insert(Operation::new_empty(0, fee.from.clone(), fee.asset))
                .fee_note = Some(TransferNote::new(
                fee.from.viewing_key(),
                fee.to,
                fee.asset,
                fee.value,
                rng.random(),
                "fee",
            ));
        }

        //? Collect input notes to satisfy each operation's output value.
        draft_operations.values_mut().for_each(|o| {
            o.in_notes = select_in_notes(o.from.address(), o.asset, o.out_value(), in_notes.clone())
        });

        //? Split operations by tree number and add change notes if necessary.
        let operations: Vec<_> = draft_operations
            .into_values()
            .flat_map(|o| split_trees(o))
            .collect();
        let mut operations: Vec<_> = operations
            .into_iter()
            .map(|o| add_change_note(o, rng))
            .collect();

        //? Sort the operations to bring the fee note to the front if it exists
        operations.sort_by(|a, b| {
            let a_fee = a.fee_note().is_some();
            let b_fee = b.fee_note().is_some();
            b_fee.cmp(&a_fee) // fee note first
        });

        Ok(operations)
    }

    /// Attach POI proofs to a proved transaction.
    async fn prove_poi(
        &self,
        poi_prover: &impl PoiProver,
        poi_client: &PoiClient,
        proved: ProvedTransaction,
        utxo_trees: &BTreeMap<u32, UtxoMerkleTree>,
        list_keys: &[ListKey],
        fee: Option<Fee>,
    ) -> Result<PoiProvedTransaction, BuildError> {
        // Rebuild operations with PoiNote inputs (needed for POI merkle proofs)
        let proved_operations = proved.proved_operations;
        let mut poi_operations = Vec::new();
        for operation in proved_operations {
            let op = operation.operation;
            let in_notes = op.in_notes;
            let poi_in_notes = poi_client.note_to_poi_note(in_notes, list_keys).await?;

            //? Need to create a new operation since the generic can't be
            //? trivially cast.
            poi_operations.push(PoiProvedOperation {
                operation: Operation {
                    utxo_tree_number: op.utxo_tree_number,
                    from: op.from,
                    asset: op.asset,
                    in_notes: poi_in_notes,
                    out_notes: op.out_notes,
                    unshield_note: op.unshield_note,
                    fee_note: op.fee_note,
                },
                circuit_inputs: operation.circuit_inputs,
                transaction: operation.transaction,
                pois: HashMap::new(),
                txid_leaf_hash: None,
            });
        }

        // Attach POI proofs to each operation
        for poi_op in poi_operations.iter_mut() {
            poi_op.add_pois(poi_prover, list_keys, utxo_trees).await?;
        }

        // Validate all POI merkle roots
        //? Should always pass, but sanity check to ensure proofs are valid before broadcasting
        #[cfg(debug_assertions)]
        for poi_op in poi_operations.iter() {
            for (list_key, poi) in poi_op.pois.iter() {
                for merkleroot in &poi.poi_merkleroots {
                    let valid = poi_client
                        .validate_poi_merkleroot(list_key.clone(), *merkleroot)
                        .await?;
                    if !valid {
                        return Err(BuildError::InvalidPoiMerkleroot(
                            list_key.clone(),
                            *merkleroot,
                        ));
                    }
                }
            }
        }

        Ok(PoiProvedTransaction {
            tx_data: proved.tx_data,
            operations: poi_operations,
            min_gas_price: proved.min_gas_price,
            fee,
        })
    }
}

/// Selects input notes for an operation.
fn select_in_notes<N: IncludedNote>(
    from: RailgunAddress,
    asset: AssetId,
    value: u128,
    in_notes: Vec<N>,
) -> Vec<N> {
    //? Naive implementation: just takes notes until we have enough value.
    let mut selected = Vec::new();
    let mut total = 0;
    for note in in_notes {
        if note.viewing_pubkey() == from.viewing_pubkey() && note.asset() == asset {
            selected.push(note.clone());
            total += note.value();
            if total >= value {
                break;
            }
        }
    }

    selected
}

/// Splits an operation into multiple operations by tree number if the input notes
/// are from different trees. The outputs are also split accordingly.
fn split_trees<N: IncludedNote>(operation: Operation<N>) -> Vec<Operation<N>> {
    //? Naive impl: Assumes that all in notes are from the same tree, so no need to
    //? split.
    let tree_number = operation
        .in_notes
        .first()
        .map(|n| n.tree_number())
        .unwrap_or_else(|| {
            warn!("Operation has no input notes, defaulting tree number to 0");
            0
        });

    for note in operation.in_notes.iter() {
        if note.tree_number() != tree_number {
            todo!("Implement operation splitting for notes from different trees");
        }
    }

    vec![Operation {
        utxo_tree_number: tree_number,
        ..operation
    }]
}

/// Adds a change note to the operation if required. The change note sends any
/// excess consumed value back to the sender's address.
fn add_change_note<R: Rng, N: IncludedNote>(operation: Operation<N>, rng: &mut R) -> Operation<N> {
    let in_value = operation.in_value();
    let out_value = operation.out_value();
    let change_value = in_value.saturating_sub(out_value);

    if change_value > 0 {
        let change_note = TransferNote::new(
            operation.from.viewing_key(),
            operation.from.address(),
            operation.asset,
            change_value,
            rng.random(),
            "change",
        );
        let mut new_operation = operation.clone();
        new_operation.out_notes.push(change_note);
        new_operation
    } else {
        operation
    }
}

/// Calculate fee iteratively until convergence. It iteratively builds and proves
/// transactions until the fee converges to a stable value.
async fn calculate_fee_to_convergence<R: Rng>(
    builder: &OperationBuilder,
    in_notes: &[UtxoNote],
    prover: &impl TransactProver,
    utxo_trees: &BTreeMap<u32, UtxoMerkleTree>,
    estimator: &impl GasEstimator,
    fee_payer: RailgunAccount,
    fee: &Fee,
    chain: ChainConfig,
    rng: &mut R,
) -> Result<ProvedTransaction, BuildError> {
    const MAX_ITERS: usize = 5;

    let gas_price_wei = estimator
        .gas_price_wei()
        .await
        .map_err(BuildError::Estimator)?;

    let mut fee_builder = builder.clone();
    let mut last_fee: u128 = calculate_fee(1000000, gas_price_wei, fee.per_unit_gas);
    fee_builder.set_broadcaster_fee(
        fee_payer.clone(),
        fee.recipient.clone(),
        AssetId::Erc20(fee.token),
        last_fee,
    );

    let mut proved_operations: Vec<ProvedOperation> = Vec::new();
    let mut tx_data = TxData::new(Address::ZERO, vec![], U256::ZERO);

    for _ in 0..MAX_ITERS {
        let operations = fee_builder.build_operations(in_notes.to_vec(), rng)?;
        let tx_results = create_transactions(
            prover,
            utxo_trees,
            &operations,
            chain,
            0,
            Address::ZERO,
            &[0u8; 32],
            rng,
        )
        .await?;

        proved_operations = operations
            .into_iter()
            .zip(tx_results)
            .map(|(op, (ci, tx))| ProvedOperation {
                operation: op,
                circuit_inputs: ci,
                transaction: tx,
            })
            .collect();

        let transactions: Vec<_> = proved_operations
            .iter()
            .map(|po| po.transaction.clone())
            .collect();
        tx_data = TxData::from_transactions(chain.railgun_smart_wallet, transactions);

        let gas = estimator
            .estimate_gas(&tx_data)
            .await
            .map_err(BuildError::Estimator)?;
        let new_fee = calculate_fee(gas, gas_price_wei, fee.per_unit_gas);

        info!(
            "Estimated gas: {}, gas price (wei): {}, fee: {}",
            gas, gas_price_wei, new_fee
        );
        if new_fee <= last_fee {
            info!("Fee converged at {} after iterations", new_fee);
            break;
        }

        fee_builder.set_broadcaster_fee(
            fee_payer.clone(),
            fee.recipient.clone(),
            AssetId::Erc20(fee.token),
            new_fee,
        );
        last_fee = new_fee;
    }

    Ok(ProvedTransaction {
        proved_operations,
        tx_data,
        min_gas_price: gas_price_wei,
    })
}

/// Creates a list of railgun transactions for a list of operations.
async fn create_transactions<R: Rng, N: IncludedNote>(
    prover: &impl TransactProver,
    utxo_trees: &BTreeMap<u32, UtxoMerkleTree>,
    operations: &[Operation<N>],
    chain: ChainConfig,
    min_gas_price: u128,
    adapt_contract: Address,
    adapt_input: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<(TransactCircuitInputs, abis::railgun::Transaction)>, BuildError> {
    let mut transactions = Vec::new();
    for operation in operations {
        operation.verify()?;

        let tree_number = operation.utxo_tree_number();
        let tree = utxo_trees
            .get(&tree_number)
            .ok_or(BuildError::MissingTree(tree_number))?;

        let tx = create_transaction(
            prover,
            tree,
            operation,
            chain,
            min_gas_price,
            adapt_contract,
            adapt_input,
            rng,
        )
        .await?;

        transactions.push(tx);
    }

    Ok(transactions)
}

/// Creates a railgun transaction for a single operation.
async fn create_transaction<R: Rng, N: IncludedNote>(
    prover: &impl TransactProver,
    utxo_tree: &UtxoMerkleTree,
    operation: &Operation<N>,
    chain: ChainConfig,
    min_gas_price: u128,
    adapt_contract: Address,
    adapt_input: &[u8; 32],
    rng: &mut R,
) -> Result<(TransactCircuitInputs, abis::railgun::Transaction), BuildError> {
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
    let (proof, _) = prover
        .prove_transact(&inputs)
        .await
        .map_err(BuildError::Prover)?;

    let transaction = abis::railgun::Transaction {
        proof: proof.into(),
        merkleRoot: inputs.merkleroot.into(),
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

    Ok((inputs, transaction))
}

/// Calculate the broadcaster's fee based on the estimated gas cost, gas price in wei,
/// broadcaster's fee rate, and a buffer.
fn calculate_fee(gas_cost: u128, gas_price_wei: u128, fee_rate: u128) -> u128 {
    let raw = (gas_cost * gas_price_wei * fee_rate) / 10_u128.pow(18);
    ((raw as f64) * FEE_BUFFER).ceil() as u128
}
