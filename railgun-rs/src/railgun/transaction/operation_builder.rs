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
use ruint::aliases::U256;
use thiserror::Error;
use tracing::{info, warn};

use crate::{
    abis,
    account::RailgunAccount,
    caip::AssetId,
    chain_config::ChainConfig,
    circuit::{
        poi_inputs::{PoiCircuitInputs, PoiCircuitInputsError},
        prover::{PoiProver, TransactProver},
        transact_inputs::{TransactCircuitInputs, TransactCircuitInputsError},
    },
    crypto::keys::ViewingPublicKey,
    railgun::{
        address::RailgunAddress,
        indexer::indexer::Indexer,
        merkle_tree::merkle_tree::UtxoMerkleTree,
        note::{
            IncludedNote, encrypt::EncryptError, operation::Operation, transfer::TransferNote,
            unshield::UnshieldNote, utxo::UtxoNote,
        },
        poi::{
            poi_client::{ListKey, PoiClient, PoiClientError, PreTransactionPoi, TxidVersion},
            poi_note::PoiNote,
        },
        transaction::{
            broadcaster_data::{BroadcastData, Chain, ChainType},
            tx_data::TxData,
        },
    },
};

/// A builder for construction railgun operations (transfers, unshields)
#[derive(Clone)]
pub struct OperationBuilder {
    transfers: Vec<TransferData>,
    unshields: HashMap<AssetId, UnshieldData>,
    broadcaster_fee: Option<TransferData>,
    accounts: HashMap<ViewingPublicKey, RailgunAccount>,
}

#[async_trait::async_trait]
pub trait GasEstimator {
    async fn estimate_gas(&self, tx_data: &TxData) -> Result<u128, Box<dyn std::error::Error>>;
    async fn gas_price_wei(&self) -> Result<u128, Box<dyn std::error::Error>>;
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
    Prover(#[from] Box<dyn std::error::Error>),
    #[error("Missing tree for number {0}")]
    MissingTree(u32),
    #[error("Transact circuit input error: {0}")]
    TransactCircuitInput(#[from] TransactCircuitInputsError),
    #[error("Poi Client error: {0}")]
    PoiClient(#[from] PoiClientError),
    #[error("Poi Circuit input error: {0}")]
    PoiCircuitInput(#[from] PoiCircuitInputsError),
}

impl OperationBuilder {
    pub fn new() -> Self {
        Self {
            transfers: Vec::new(),
            unshields: HashMap::new(),
            broadcaster_fee: None,
            accounts: HashMap::new(),
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

    /// Builds the operations.
    ///
    /// Groups input notes by (tree_number, asset_id, viewing_public_key) and creates
    /// separate operations for each group. This ensures that each operation only
    /// contains notes from the same owner, tree, and asset.
    ///
    /// Creates change notes when input value exceeds output value.
    pub fn build<N: IncludedNote, R: Rng>(
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
        let operations: Vec<Operation<N>> = draft_operations
            .into_values()
            .flat_map(|o| split_trees(o))
            .collect();
        let operations = operations
            .into_iter()
            .map(add_change_note)
            .collect::<Vec<_>>();

        Ok(operations)
    }

    /// Builds the operation into a EVM transaction.
    pub async fn build_transaction<R: Rng>(
        &self,
        indexer: &mut Indexer,
        prover: &impl TransactProver,
        chain: ChainConfig,
        rng: &mut R,
    ) -> Result<TxData, BuildError> {
        let in_notes = indexer.all_unspent();

        let operations = self.build(in_notes, rng)?;
        let utxo_trees = &mut indexer.utxo_trees;
        let transactions = create_transactions(
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
        let transactions = transactions.into_iter().map(|(_, t)| t).collect();

        Ok(TxData::from_transactions(
            chain.railgun_smart_wallet,
            transactions,
        ))
    }

    /// Builds the transaction a broadcast-ready transaction.
    ///
    /// - `fee_payee`: account that pays the broadcaster's fee.
    /// - `fee_token`: asset used to pay the broadcaster's fee.
    /// - `fee_bps`: broadcaster fee rate in basis points of the EVM gas cost.
    /// For example, if `fee_bps` is 100 and the transaction costs 100k gas at a gas price of 10 gwei,
    /// the fee would be 100k * 10 gwei * 1% = 10k gwei.
    /// - `fee_recipient`: address that receives the broadcaster's fee.
    /// - `fee_id`: Unique identifier for the broadcaster's token fee.
    pub async fn prepare_broadcast<R: Rng>(
        &self,
        indexer: &mut Indexer,
        prover: &(impl TransactProver + PoiProver),
        poi_client: &PoiClient,
        estimator: &impl GasEstimator,
        chain: ChainConfig,
        fee_payee: RailgunAccount,
        fee_token: Address,
        fee_bps: u32,
        fee_recipient: RailgunAddress,
        fee_id: String,
        list_keys: Vec<ListKey>,
        rng: &mut R,
    ) -> Result<BroadcastData, BuildError> {
        //? The broadcaster's fee must be paid as the first transfer note in the
        //? first operation. Because adding this note will change the gas cost,
        //? we need to iteratively build the tx until the fee converges.

        const MAX_ITERS: usize = 5;

        //? Initial gas estimate, approximately what a simple transfer would cost.
        let mut last_fee: u128 = 50_000 * 10u128.pow(10) * fee_bps as u128 / 10_000;

        let mut builder = self.clone();
        builder.set_broadcaster_fee(
            fee_payee.clone(),
            fee_recipient,
            AssetId::Erc20(fee_token),
            last_fee,
        );

        let in_notes = indexer.all_unspent();
        let in_notes = PoiNote::from_utxo_notes(in_notes, &poi_client).await?;
        let utxo_trees = &mut indexer.utxo_trees;

        //? Iteratively build transactions until the fee converges.
        let mut operations = Vec::new();
        let mut transactions = Vec::new();
        let mut tx_data = TxData::new(Address::ZERO, vec![], U256::ZERO);
        let gas_price_wei = estimator.gas_price_wei().await?;
        for _ in 0..MAX_ITERS {
            operations = builder.build(in_notes.clone(), rng)?;
            transactions = create_transactions(
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
            let txns = transactions.iter().map(|(_, t)| t.clone()).collect();
            tx_data = TxData::from_transactions(chain.railgun_smart_wallet, txns);

            let gas = estimator.estimate_gas(&tx_data).await?;
            let fee = gas * gas_price_wei * fee_bps as u128 / 10_000;

            if fee == last_fee {
                break;
            }

            builder.set_broadcaster_fee(
                fee_payee.clone(),
                fee_recipient,
                AssetId::Erc20(fee_token),
                fee,
            );
            last_fee = fee;
        }

        // prover.prove_poi(inputs)
        let mut nullifiers = Vec::new();
        let mut pre_transaction_pois_per_txid_leaf_per_list: HashMap<
            ListKey,
            HashMap<String, PreTransactionPoi>,
        > = HashMap::new();
        for list_key in list_keys {
            for (operation, transaction) in operations.iter().zip(transactions.iter()) {
                let tx_circuit_inputs = &transaction.0;
                nullifiers.extend(tx_circuit_inputs.nullifiers.clone());

                let mut utxo_merkle_tree = utxo_trees
                    .get_mut(&operation.utxo_tree_number)
                    .ok_or(BuildError::MissingTree(operation.utxo_tree_number))?;

                let inputs = PoiCircuitInputs::from_inputs(
                    operation.from.spending_key().public_key(),
                    operation.from.viewing_key().nullifying_key(),
                    &mut utxo_merkle_tree,
                    tx_circuit_inputs.bound_params_hash,
                    operation,
                    list_key.clone(),
                )?;

                let poi_proof = prover.prove_poi(&inputs).await?;

                let txid_merkleroot = inputs
                    .railgun_txid_merkle_root_after_transaction
                    .to_string();
                let poi_merkleroots = inputs
                    .poi_merkle_roots
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>();
                let blinded_commitments_out = operation
                    .in_notes
                    .iter()
                    .map(|n| n.blinded_commitment())
                    .map(|bc| bc.to_string())
                    .collect();

                let pre_transaction_poi = PreTransactionPoi {
                    snark_proof: poi_proof.into(),
                    // TODO: Make sure these are stringified correctly AND that they're the right values
                    txid_merkleroot,
                    poi_merkleroots,
                    blinded_commitments_out,
                    railgun_txid_if_has_unshield: inputs.railgun_txid_if_has_unshield.to_string(),
                };
                let txid_leaf_hash: U256 = inputs.txid_leaf_hash.into();
                pre_transaction_pois_per_txid_leaf_per_list
                    .entry(list_key.clone())
                    .or_default()
                    .insert(txid_leaf_hash.to_string(), pre_transaction_poi);
            }
        }

        let data = BroadcastData {
            txid_version_for_inputs: TxidVersion::V2PoseidonMerkle,
            to: tx_data.to,
            data: tx_data.data,
            broadcaster_railgun_address: fee_recipient,
            broadcaster_fee_id: fee_id,
            chain: Chain {
                chain_type: ChainType::EVM,
                chain_id: chain.id,
            },
            nullifiers,
            overall_batch_min_gas_price: gas_price_wei,
            use_relay_adapt: false,
            pre_transaction_pois_per_txid_leaf_per_list,
        };

        Ok(data)
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
fn add_change_note<N: IncludedNote>(operation: Operation<N>) -> Operation<N> {
    let in_value = operation.in_value();
    let out_value = operation.out_value();
    let change_value = in_value.saturating_sub(out_value);

    if change_value > 0 {
        let change_note = TransferNote::new(
            operation.from.viewing_key(),
            operation.from.address(),
            operation.asset,
            change_value,
            random(),
            "change",
        );
        let mut new_operation = operation.clone();
        new_operation.out_notes.push(change_note);
        new_operation
    } else {
        operation
    }
}

// async fn create_pre_transaction_pois_per_txid_leaf_per_list(
//     prover: &impl PoiProver,

// )

async fn create_transactions<R: Rng, N: IncludedNote>(
    prover: &impl TransactProver,
    utxo_trees: &mut BTreeMap<u32, UtxoMerkleTree>,
    operations: &[Operation<N>],
    chain: ChainConfig,
    min_gas_price: u128,
    adapt_contract: Address,
    adapt_input: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<(TransactCircuitInputs, abis::railgun::Transaction)>, BuildError> {
    let mut transactions = Vec::new();
    for operation in operations {
        let tree_number = operation.utxo_tree_number();
        let mut tree = utxo_trees
            .get_mut(&tree_number)
            .ok_or(BuildError::MissingTree(tree_number))?;

        let tx = create_transaction(
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

        transactions.push(tx);
    }

    Ok(transactions)
}

async fn create_transaction<R: Rng, N: IncludedNote>(
    prover: &impl TransactProver,
    utxo_tree: &mut UtxoMerkleTree,
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

    Ok((inputs, transaction))
}
