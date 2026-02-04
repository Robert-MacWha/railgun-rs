use alloy::{
    consensus::transaction::from_eip155_value,
    primitives::{Address, ChainId, U256, aliases::U72, keccak256},
};
use alloy_sol_types::{SolValue, abi::token, sol_data::Uint};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::{BigInt, Sign};

use crate::{
    abis::railgun::{BoundParams, CommitmentCiphertext, UnshieldType},
    circuit::inputs::CircuitInputs,
    crypto::{
        hash_to_scalar,
        keys::{bigint_to_fr, fr_to_bigint},
    },
    merkle_tree::MerkleTree,
    note::{self, note::Note},
};

mod inputs;

pub fn format_circuit_inputs(
    merkle_tree: &mut MerkleTree,
    min_gas_price: u128,
    unshield: UnshieldType,
    chain_id: ChainId,
    adapt_contract: Address,
    adapt_input: [u8; 32],
    notes_in: Vec<Note>,
    notes_out: Vec<Note>,
    commitment_ciphertexts: Vec<CommitmentCiphertext>,
) -> Result<CircuitInputs, ()> {
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

fn hash_bound_params(bounded_params: BoundParams) -> Fr {
    let encoded = bounded_params.abi_encode();
    let hash = hash_to_scalar(&encoded);
    Fr::from_be_bytes_mod_order(&hash.to_be_bytes::<32>())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_hash_bound_params() {
        todo!()
    }

    #[test]
    fn test_format_circuit_inputs() {
        todo!()
    }
}
