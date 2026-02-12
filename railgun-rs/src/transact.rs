use std::collections::BTreeMap;

use alloy::primitives::U256;
use alloy::primitives::{Address, FixedBytes, aliases::U120};
use alloy_sol_types::SolCall;

use rand::Rng;
use tracing::info;

use crate::abis::railgun::{BoundParams, RailgunSmartWallet};
use crate::circuit::prover::TransactProver;
use crate::merkle_trees::merkle_tree::UtxoMerkleTree;
use crate::note::Note;
use crate::note::encrypt::EncryptError;
use crate::transaction::tx_data::TxData;
use crate::{
    abis::railgun::{CommitmentCiphertext, CommitmentPreimage, Transaction, UnshieldType},
    caip::AssetId,
    chain_config::ChainConfig,
    circuit::transact_inputs::TransactCircuitInputs,
    note::{operation::Operation, utxo::UtxoNote},
};

pub fn create_txdata<R: Rng>(
    prover: &impl TransactProver,
    merkle_trees: &mut BTreeMap<u32, UtxoMerkleTree>,
    min_gas_price: u128,
    chain: ChainConfig,
    adapt_contract: Address,
    adapt_input: &[u8; 32],
    operations: Vec<Operation<UtxoNote>>,
    rng: &mut R,
) -> Result<TxData, EncryptError> {
    let transactions = create_transactions(
        prover,
        merkle_trees,
        min_gas_price,
        chain,
        adapt_contract,
        adapt_input,
        operations,
        rng,
    )?;

    let call = RailgunSmartWallet::transactCall {
        _transactions: transactions,
    };
    let calldata = call.abi_encode();
    Ok(TxData {
        to: chain.railgun_smart_wallet,
        data: calldata,
        value: U256::ZERO,
    })
}

pub fn create_transactions<R: Rng>(
    prover: &impl TransactProver,
    merkle_trees: &mut BTreeMap<u32, UtxoMerkleTree>,
    min_gas_price: u128,
    chain: ChainConfig,
    adapt_contract: Address,
    adapt_input: &[u8; 32],
    operations: Vec<Operation<UtxoNote>>,
    rng: &mut R,
) -> Result<Vec<Transaction>, EncryptError> {
    let mut transactions = Vec::new();
    for operation in operations {
        info!("Processing tree {}", operation.utxo_tree_number());
        let merkle_tree = merkle_trees.get_mut(&operation.utxo_tree_number()).unwrap();

        let unshield = if operation.unshield_note().is_some() {
            UnshieldType::NORMAL
        } else {
            UnshieldType::NONE
        };

        let notes_in = operation.in_notes();
        let notes_out = operation.out_notes();

        info!("Constructing circuit inputs");
        let commitment_ciphertexts: Vec<CommitmentCiphertext> = operation
            .out_encryptable_notes()
            .iter()
            .map(|n| n.encrypt(rng))
            .collect::<Result<Vec<_>, _>>()?;

        let bound_params = BoundParams::new(
            merkle_tree.number() as u16,
            min_gas_price,
            unshield,
            chain.id,
            adapt_contract,
            adapt_input,
            commitment_ciphertexts,
        );
        let inputs = TransactCircuitInputs::from_inputs(
            merkle_tree,
            bound_params.hash(),
            notes_in,
            &notes_out,
        )
        .unwrap();

        info!("Proving transaction");
        let proof = prover.prove_transact(&inputs).unwrap();
        let transaction = Transaction {
            proof: proof.into(),
            merkleRoot: inputs.merkle_root.into(),
            nullifiers: inputs.nullifiers.iter().map(|n| n.clone().into()).collect(),
            commitments: inputs
                .commitments_out
                .iter()
                .map(|c| c.clone().into())
                .collect(),
            boundParams: bound_params,
            unshieldPreimage: match operation.unshield_note() {
                Some(unshield) => CommitmentPreimage {
                    npk: unshield.note_public_key().into(),
                    token: unshield.asset.into(),
                    value: U120::saturating_from(unshield.value),
                },
                //? If there's no unshield note, the preimage is ignored by the
                //? contract so we can just return a zeroed preimage. Just using
                //? `asset` for convenience.
                None => CommitmentPreimage {
                    npk: FixedBytes::ZERO,
                    token: AssetId::Erc20(Address::ZERO).into(),
                    value: U120::saturating_from(0),
                },
            },
        };

        transactions.push(transaction);
    }

    Ok(transactions)
}
