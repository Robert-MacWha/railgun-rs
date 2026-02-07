use std::collections::BTreeMap;

use alloy::primitives::{Address, FixedBytes, aliases::U120};
use num_bigint::BigInt;
use tracing::info;

use crate::abis::railgun::BoundParams;
use crate::circuit::prover::TransactProver;
use crate::{
    abis::railgun::{
        CommitmentCiphertext, CommitmentPreimage, G1Point, G2Point, SnarkProof, Transaction,
        UnshieldType,
    },
    caip::AssetId,
    chain_config::ChainConfig,
    circuit::transact_inputs::TransactCircuitInputs,
    crypto::keys::{bigint_to_fr, fr_to_u256},
    merkle_tree::MerkleTree,
    note::{
        note::{EncryptError, Note},
        tree_transaction::{TransactNote, TreeTransaction},
    },
};

pub fn create_transaction(
    prover: &Box<dyn TransactProver>,
    merkle_trees: &mut BTreeMap<u32, MerkleTree>,
    min_gas_price: u128,
    chain: ChainConfig,
    adapt_contract: Address,
    adapt_input: &[u8; 32],
    tree_txns: BTreeMap<u32, TreeTransaction>,
) -> Result<Vec<Transaction>, EncryptError> {
    let mut transactions = Vec::new();
    for (tree_number, tree_tx) in tree_txns {
        info!("Processing tree {}", tree_number);
        let merkle_tree = merkle_trees.get_mut(&tree_number).unwrap();

        let unshield = if tree_tx.unshield.is_some() {
            UnshieldType::NORMAL
        } else {
            UnshieldType::NONE
        };

        let notes_in: Vec<Note> = tree_tx.notes_in().clone();
        let notes_out = tree_tx.notes_out();

        info!("Constructing circuit inputs");
        let commitment_ciphertexts: Vec<CommitmentCiphertext> = tree_tx
            .encryptable_notes_out()
            .iter()
            .map(|n| n.encrypt())
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
            notes_out,
        )
        .unwrap();

        info!("Proving transaction");
        let proof = prover.prove_transact(&inputs).unwrap();
        let transaction = Transaction {
            proof: SnarkProof {
                a: G1Point {
                    x: proof.a.x,
                    y: proof.a.y,
                },
                b: G2Point {
                    x: [proof.b.x[1], proof.b.x[0]],
                    y: [proof.b.y[1], proof.b.y[0]],
                },
                c: G1Point {
                    x: proof.c.x,
                    y: proof.c.y,
                },
            },
            merkleRoot: bigint_to_bytes(&inputs.merkle_root),
            nullifiers: inputs.nullifiers.iter().map(bigint_to_bytes).collect(),
            commitments: inputs.commitments_out.iter().map(bigint_to_bytes).collect(),
            boundParams: bound_params,
            unshieldPreimage: match tree_tx.unshield {
                Some(unshield) => {
                    info!(
                        "Unshield npk: {:?}",
                        fr_to_u256(&unshield.note_public_key())
                    );
                    info!(
                        "Unshield token_id: {:?}",
                        fr_to_u256(&unshield.asset.hash())
                    );
                    info!("Unshield value: {:?}", unshield.value);
                    info!("Unshield hash: {:?}", fr_to_u256(&unshield.hash()));
                    info!("Last commitment_out: {:?}", &inputs.commitments_out.last());
                    CommitmentPreimage {
                        npk: fr_to_u256(&unshield.note_public_key()).into(),
                        token: unshield.asset.into(),
                        value: U120::saturating_from(unshield.value),
                    }
                }
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

fn bigint_to_bytes(value: &BigInt) -> FixedBytes<32> {
    fr_to_u256(&bigint_to_fr(value)).into()
}
