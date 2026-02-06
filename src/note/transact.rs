use std::{collections::BTreeMap, fs};

use alloy::primitives::{Address, FixedBytes, aliases::U120};
use alloy_sol_types::SolCall;
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction, read_zkey};
use ark_ec::AffineRepr;
use ark_groth16::{Groth16, ProvingKey, prepare_verifying_key};
use num_bigint::BigInt;
use tracing::info;

use crate::{
    abis::railgun::{
        CommitmentCiphertext, CommitmentPreimage, G1Point, G2Point, SnarkProof, Transaction, UnshieldType,
    },
    caip::AssetId,
    chain_config::ChainConfig,
    circuit::inputs::CircuitInputs,
    crypto::keys::{bigint_to_fr, fq_to_u256, fr_to_u256},
    merkle_tree::MerkleTree,
    note::{
        note::{EncryptError, Note},
        tree_transaction::{TransactNote, TreeTransaction},
    },
};

pub fn create_transaction(
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

        // Load circuit artifacts
        let notes_in: Vec<Note> = tree_tx.notes_in().clone();
        let notes_out = tree_tx.notes_out();
        let (mut builder, params) = load_artifacts(notes_in.len(), notes_out.len());

        // Construct circuit inputs
        let commitment_ciphertexts: Vec<CommitmentCiphertext> = tree_tx
            .encryptable_notes_out()
            .iter()
            .map(|n| n.encrypt())
            .collect::<Result<Vec<_>, _>>()?;
        let inputs = CircuitInputs::format(
            merkle_tree,
            min_gas_price,
            unshield,
            chain.id,
            adapt_contract,
            adapt_input,
            notes_in,
            notes_out,
            commitment_ciphertexts,
        )
        .unwrap();

        // Build the circuit
        info!("Building circuit for tree {}", tree_number);

        for (name, values) in inputs.as_flat_map() {
            for value in values {
                builder.push_input(&name, value);
            }
        }

        let circom = builder.build().unwrap();
        let public_inputs = circom.get_public_inputs().unwrap();

        info!("Generating proof for tree {}", tree_number);

        let mut rng = ark_std::rand::thread_rng();
        let proof = Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
            circom, &params, &mut rng,
        )
        .unwrap();

        info!("Verifying proof for tree {}", tree_number);

        let pvk = prepare_verifying_key(&params.vk);
        let verified =
            Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
        assert!(verified, "Proof verification failed");
        info!("Proof verified successfully for tree {}", tree_number);

        let transaction = Transaction {
            proof: SnarkProof {
                a: G1Point {
                    x: fq_to_u256(&proof.a.x().unwrap()),
                    y: fq_to_u256(&proof.a.y().unwrap()),
                },
                b: G2Point {
                    x: [
                        fq_to_u256(&proof.b.x().unwrap().c1),
                        fq_to_u256(&proof.b.x().unwrap().c0),
                    ],
                    y: [
                        fq_to_u256(&proof.b.y().unwrap().c1),
                        fq_to_u256(&proof.b.y().unwrap().c0),
                    ],
                },
                c: G1Point {
                    x: fq_to_u256(&proof.c.x().unwrap()),
                    y: fq_to_u256(&proof.c.y().unwrap()),
                },
            },
            merkleRoot: bigint_to_bytes(&inputs.merkle_root),
            nullifiers: inputs.nullifiers.iter().map(bigint_to_bytes).collect(),
            commitments: inputs.commitments_out.iter().map(bigint_to_bytes).collect(),
            boundParams: inputs.bound_params,
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

fn load_artifacts(notes_in: usize, notes_out: usize) -> (CircomBuilder<Fr>, ProvingKey<Bn254>) {
    if notes_in != 1 || notes_out != 2 {
        todo!("Only 1 input and 2 output notes are supported currently");
    }

    const WASM_PATH: &str = "artifacts/01x02/01x02.wasm";
    const R1CS_PATH: &str = "artifacts/01x02/01x02.r1cs";
    const ZKEY_PATH: &str = "artifacts/01x02/01x02.zkey";

    let cfg = CircomConfig::<Fr>::new(WASM_PATH, R1CS_PATH).unwrap();
    let builder = CircomBuilder::new(cfg);

    let mut zkey_file = fs::File::open(ZKEY_PATH).unwrap();
    let (params, _matrices) = read_zkey(&mut zkey_file).unwrap();

    (builder, params)
}
