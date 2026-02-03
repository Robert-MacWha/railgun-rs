use alloy::primitives::Address;
use num_bigint::BigInt;

use crate::{merkle_tree::MerkleTree, note::note::Note};

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
