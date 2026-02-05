use std::collections::HashMap;

use alloy::primitives::{Address, ChainId, aliases::U72};
use alloy_sol_types::SolValue;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::{BigInt, Sign};

use crate::{
    abis::railgun::{BoundParams, CommitmentCiphertext, UnshieldType},
    crypto::{hash_to_scalar, keys::fr_to_bigint},
    merkle_tree::MerkleTree,
    note::{note::Note, transact::TransactNote},
};

// TODO: Consider replacing me with functional approach, since the struct
// is just a data container.
#[derive(Debug, Clone)]
pub struct CircuitInputs {
    // Public Inputs
    pub merkle_root: BigInt,
    pub bound_params: BoundParams,
    pub bound_params_hash: BigInt,
    pub nullifiers: Vec<BigInt>,
    pub commitments_out: Vec<BigInt>,

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
        bound_params: BoundParams,
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
            bound_params,
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

    // TODO: Pass in pre-computed nullifiers
    pub fn format(
        merkle_tree: &mut MerkleTree,
        min_gas_price: u128,
        unshield: UnshieldType,
        chain_id: ChainId,
        adapt_contract: Address,
        adapt_input: &[u8; 32],
        notes_in: Vec<Note>,
        notes_out: Vec<Box<dyn TransactNote>>,
        commitment_ciphertexts: Vec<CommitmentCiphertext>,
    ) -> Result<Self, ()> {
        if notes_in.is_empty() || notes_out.is_empty() {
            return Err(());
        }

        let merkle_root = merkle_tree.root();
        let tree_number = merkle_tree.number();

        let bound_params = BoundParams {
            treeNumber: tree_number as u16,
            minGasPrice: U72::saturating_from(min_gas_price),
            unshield,
            chainID: chain_id,
            adaptContract: adapt_contract,
            adaptParams: adapt_input.into(),
            commitmentCiphertext: commitment_ciphertexts,
        };
        let bound_params_hash = hash_bound_params(&bound_params);

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
            .map(|note| BigInt::from(note.value()))
            .collect();

        Ok(CircuitInputs::new(
            fr_to_bigint(&merkle_root),
            bound_params,
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

    /// Flattens the circuit inputs into a HashMap suitable for use as zk-SNARK inputs.
    pub fn as_flat_map(&self) -> HashMap<String, Vec<BigInt>> {
        let mut m = HashMap::new();

        m.insert("merkleRoot".into(), vec![self.merkle_root.clone()]);
        m.insert(
            "boundParamsHash".into(),
            vec![self.bound_params_hash.clone()],
        );
        m.insert("nullifiers".into(), self.nullifiers.clone());
        m.insert("commitmentsOut".into(), self.commitments_out.clone());
        m.insert("token".into(), vec![self.token.clone()]);
        m.insert("publicKey".into(), self.public_key.to_vec());
        m.insert("signature".into(), self.signature.to_vec());
        m.insert("randomIn".into(), self.random_in.clone());
        m.insert("valueIn".into(), self.value_in.clone());
        m.insert(
            "pathElements".into(),
            self.path_elements.iter().flatten().cloned().collect(),
        );
        m.insert("leavesIndices".into(), self.leaves_indices.clone());
        m.insert("nullifyingKey".into(), vec![self.nullifying_key.clone()]);
        m.insert("npkOut".into(), self.npk_out.clone());
        m.insert("valueOut".into(), self.value_out.clone());

        m
    }
}

fn hash_bound_params(bound_params: &BoundParams) -> Fr {
    let encoded = bound_params.abi_encode();
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
        caip::AssetId,
        circuit::inputs::{CircuitInputs, hash_bound_params},
        crypto::keys::{ByteKey, SpendingKey, ViewingKey, bytes_to_fr},
        hex_to_fr,
        merkle_tree::MerkleTree,
        note::{note::Note, transact::TransactNote},
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

        let hash = hash_bound_params(&bound_params);
        let expected =
            hex_to_fr("0x0171c913baef93e5cf6f223442727c680a1a1844b9999032ac789638032822fb");

        assert_eq!(hash, expected);
    }
}
