use alloy::primitives::{Address, ChainId, aliases::U72};
use alloy_sol_types::SolValue;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::{BigInt, Sign};

use crate::{
    abis::railgun::{BoundParams, CommitmentCiphertext, UnshieldType},
    crypto::{hash_to_scalar, keys::fr_to_bigint},
    merkle_tree::MerkleTree,
    note::note::Note,
};

pub struct CircuitInputs {
    // Public Inputs
    merkle_root: BigInt,
    bound_params_hash: BigInt,
    nullifiers: Vec<BigInt>,
    commitments_out: Vec<BigInt>,

    // Private Inputs
    token: BigInt,
    public_key: [BigInt; 2],
    signature: [BigInt; 3],
    random_in: Vec<BigInt>,
    value_in: Vec<BigInt>,
    path_elements: Vec<Vec<BigInt>>,
    leaves_indices: Vec<BigInt>,
    nullifying_key: BigInt,
    npk_out: Vec<BigInt>,
    value_out: Vec<BigInt>,
}

impl CircuitInputs {
    pub fn new(
        merkle_root: BigInt,
        bound_params_hash: BigInt,
        nullifiers: Vec<BigInt>,
        commitments_out: Vec<BigInt>,
        token: BigInt,
        public_key: [BigInt; 2],
        signature: [BigInt; 3],
        random_in: Vec<BigInt>,
        value_in: Vec<BigInt>,
        path_elements: Vec<Vec<BigInt>>,
        leaves_indices: Vec<BigInt>,
        nullifying_key: BigInt,
        npk_out: Vec<BigInt>,
        value_out: Vec<BigInt>,
    ) -> Self {
        CircuitInputs {
            merkle_root,
            bound_params_hash,
            nullifiers,
            commitments_out,
            token,
            public_key,
            signature,
            random_in,
            value_in,
            path_elements,
            leaves_indices,
            nullifying_key,
            npk_out,
            value_out,
        }
    }

    pub fn format(
        merkle_tree: &mut MerkleTree,
        min_gas_price: u128,
        unshield: UnshieldType,
        chain_id: ChainId,
        adapt_contract: Address,
        adapt_input: &[u8; 32],
        notes_in: Vec<Note>,
        notes_out: Vec<Note>,
        commitment_ciphertexts: Vec<CommitmentCiphertext>,
    ) -> Result<Self, ()> {
        if notes_in.is_empty() || notes_out.is_empty() {
            return Err(());
        }

        let merkle_root = merkle_tree.root();
        let tree_number = merkle_tree.number();

        let bound_params_hash = hash_bound_params(BoundParams {
            treeNumber: tree_number,
            minGasPrice: U72::saturating_from(min_gas_price),
            unshield,
            chainID: chain_id,
            adaptContract: adapt_contract,
            adaptParams: adapt_input.into(),
            commitmentCiphertext: commitment_ciphertexts,
        });

        let merkle_proofs: Vec<_> = notes_in
            .iter()
            .map(|note| merkle_tree.generate_proof(note.hash()))
            .collect::<Result<_, _>>()
            .unwrap();

        let nullifiers = notes_in
            .iter()
            .zip(merkle_proofs.iter())
            .map(|(note, proof)| note.nullifier(proof.indices))
            .collect::<Vec<Fr>>();

        let commitments_out: Vec<Fr> = notes_out.iter().map(|note| note.hash()).collect();

        let note_zero = notes_in[0].clone();
        let token = fr_to_bigint(&note_zero.token.hash());
        let public_key = note_zero.spending_public_key();
        let public_key = [fr_to_bigint(&public_key.0), fr_to_bigint(&public_key.1)];
        let signature = note_zero.sign_circuit_inputs(
            merkle_root,
            bound_params_hash,
            &nullifiers,
            &commitments_out,
        );
        let signature = [
            fr_to_bigint(&signature[0]),
            fr_to_bigint(&signature[1]),
            fr_to_bigint(&signature[2]),
        ];

        let random_in = notes_in
            .iter()
            .map(|note| BigInt::from_bytes_be(Sign::Plus, &note.random_seed))
            .collect();

        let value_in: Vec<BigInt> = notes_in
            .iter()
            .map(|note| BigInt::from(note.value))
            .collect();

        let path_elements = merkle_proofs
            .iter()
            .map(|proof| {
                proof
                    .elements
                    .iter()
                    .map(|fr| fr_to_bigint(fr))
                    .collect::<Vec<BigInt>>()
            })
            .collect();

        let leaves_indices = merkle_proofs
            .iter()
            .map(|proof| BigInt::from(proof.indices))
            .collect();

        let nullifying_key = note_zero.nullifying_key();
        let npk_out: Vec<Fr> = notes_out
            .iter()
            .map(|note| note.note_public_key())
            .collect();
        let value_out: Vec<BigInt> = notes_out
            .iter()
            .map(|note| BigInt::from(note.value))
            .collect();

        Ok(CircuitInputs::new(
            fr_to_bigint(&merkle_root),
            fr_to_bigint(&bound_params_hash),
            nullifiers.iter().map(fr_to_bigint).collect(),
            commitments_out.iter().map(fr_to_bigint).collect(),
            token,
            public_key,
            signature,
            random_in,
            value_in,
            path_elements,
            leaves_indices,
            fr_to_bigint(&nullifying_key),
            npk_out.iter().map(fr_to_bigint).collect(),
            value_out,
        ))
    }
}

fn hash_bound_params(bounded_params: BoundParams) -> Fr {
    let encoded = bounded_params.abi_encode();
    let hash = hash_to_scalar(&encoded);
    Fr::from_be_bytes_mod_order(&hash.to_be_bytes::<32>())
}

#[cfg(test)]
mod tests {
    use alloy::{
        hex::FromHex,
        primitives::{Bytes, FixedBytes, address, aliases::U72},
    };
    use ark_bn254::Fr;
    use rand::random;
    use tracing_test::traced_test;

    use crate::{
        abis::railgun::{BoundParams, CommitmentCiphertext, UnshieldType},
        circuit::inputs::{CircuitInputs, hash_bound_params},
        crypto::keys::{ByteKey, SpendingKey, ViewingKey},
        hex_to_fr,
        merkle_tree::MerkleTree,
        note::note::Note,
    };

    #[test]
    #[traced_test]
    fn test_hash_bound_params() {
        let bound_params = BoundParams {
            treeNumber: 1,
            minGasPrice: U72::saturating_from(10),
            unshield: UnshieldType::NONE,
            chainID: 1,
            adaptContract: address!("0x1234567890123456789012345678901234567890"),
            adaptParams: [5u8; 32].into(),
            commitmentCiphertext: vec![CommitmentCiphertext {
                ciphertext: [
                    FixedBytes::from_slice(&[1u8; 32]),
                    FixedBytes::from_slice(&[1u8; 32]),
                    FixedBytes::from_slice(&[1u8; 32]),
                    FixedBytes::from_slice(&[1u8; 32]),
                ],
                blindedSenderViewingKey: FixedBytes::from_slice(&[2u8; 32]),
                blindedReceiverViewingKey: FixedBytes::from_slice(&[3u8; 32]),
                annotationData: Bytes::from(&[4u8; 50]),
                memo: Bytes::from(&[5u8; 50]),
            }],
        };

        let hash = hash_bound_params(bound_params);
        let expected =
            hex_to_fr("0x0171c913baef93e5cf6f223442727c680a1a1844b9999032ac789638032822fb");

        assert_eq!(hash, expected);
    }

    #[test]
    #[traced_test]
    fn test_format_circuit_inputs() {
        let spending_key: SpendingKey = random();
        let viewing_key: ViewingKey = random();

        // let note_in = Note::new_test_note(spending_key, viewing_key)

        // let mut merkle_tree = &mut MerkleTree::new(1);
        // merkle_tree.insert_leaves(&[Fr::from(1)], 100);

        // let inputs = CircuitInputs::format(
        //     merkle_tree,
        //     10u128,
        //     UnshieldType::NONE,
        //     1,
        //     address!("0x1234567890123456789012345678901234567890"),
        //     &[5u8; 32],
        //     notes_in,
        //     notes_out,
        //     commitment_ciphertexts,
        // );
    }
}
