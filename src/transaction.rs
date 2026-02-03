use alloy::primitives::Address;
use num_bigint::BigInt;

use crate::{merkle_tree::MerkleTree, note::note::Note};

// const MERKLE_TREE_DEPTH: usize = 32;

// pub struct TransactionRequestV2<const INPUTS: usize, const OUTPUTS: usize> {
//     private_inputs: PrivateInputs<INPUTS, OUTPUTS>,
//     public_inputs: PublicInputs<INPUTS, OUTPUTS>,
//     bound_params: BoundParams<OUTPUTS>,
// }

// pub struct PrivateInputs<const INPUTS: usize, const OUTPUTS: usize> {
//     token_address: BigInt,
//     public_key: [BigInt; 2],
//     random_in: [BigInt; INPUTS],
//     value_in: [BigInt; INPUTS],
//     path_elements: [[BigInt; INPUTS]; MERKLE_TREE_DEPTH],
//     leaves_indices: [BigInt; INPUTS],
//     nullifying_key: BigInt,
//     npk_out: [BigInt; OUTPUTS],
//     value_out: [BigInt; OUTPUTS],
// }

// pub struct PublicInputs<const INPUTS: usize, const OUTPUTS: usize> {
//     merkle_root: BigInt,
//     bound_params_hash: BigInt,
//     nullifiers: [BigInt; INPUTS],
//     commitments_out: [BigInt; OUTPUTS],
// }

// pub struct BoundParams<const OUTPUTS: usize> {
//     tree_number: BigInt,
//     min_gas_price: BigInt,
//     unshield: BigInt,
//     chain_id: alloy::primitives::ChainId,
//     adapt_contract: Address,
//     adapt_params: Vec<u8>,
//     commitment_ciphertext: [CommitmentCiphertextStruct; OUTPUTS],
// }

// pub struct CommitmentCiphertextStruct {
//     ciphertext: [Vec<u8>; 4],
//     blinded_sender_viewing_key: Vec<u8>,
//     blinded_receiver_viewing_key: Vec<u8>,
//     annotation_data: Vec<u8>,
//     memo: Vec<u8>,
// }

pub enum UnshieldType {
    None,
    Adapt,
    Direct,
}

pub struct PublicInputs {}

pub fn transact(
    merkle_tree: MerkleTree,
    min_gas_price: BigInt,
    unshield_type: UnshieldType,
    chain_id: alloy::primitives::ChainId,
    adapt_contract: Option<Address>,
    adapt_params: Option<Vec<u8>>,
    notes_in: Vec<Note>,
    notes_out: Vec<Note>,
) -> PublicInputs {
    let artifacts = get_artifacts(notes_in.len() as u8, notes_out.len() as u8);
    // TODO: pass sender info in with arg?
    let sender_viewing_private_key = notes_in[0].viewing_key;

    let commitment_ciphertexts: Vec<_> = notes_out
        .iter()
        .map(|note| note.encrypt(sender_viewing_private_key, false))
        .collect();

    todo!()
}

fn get_artifacts(nullifiers: u8, commitments: u8) -> (String, String, String) {
    if nullifiers != 1 || commitments != 2 {
        panic!("Only 1 input and 2 output artifacts are supported in this example");
    }

    // TODO: Actually return paths based on inputs
    let wasm_path = "artifacts/01x02/01x02.wasm".to_string();
    let r1cs_path = "artifacts/01x02/01x02.r1cs".to_string();
    let zkey_path = "artifacts/01x02/01x02.zkey".to_string();
    (wasm_path, r1cs_path, zkey_path)
}
