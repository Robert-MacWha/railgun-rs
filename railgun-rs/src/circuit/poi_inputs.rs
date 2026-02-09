use num_bigint::BigInt;

pub struct PoiCircuitInputs {
    // Public Inputs
    pub railgun_txid_merkle_root_after_transaction: BigInt,
    pub poi_merkle_roots: Vec<BigInt>,

    // Private inputs

    // Railgun Transaction info
    bound_params_hash: BigInt,
    nullifiers: Vec<BigInt>,
    commitments: Vec<BigInt>,

    // Spender wallet info
    spending_public_key: [BigInt; 2],
    nullifying_key: BigInt,

    // Nullified notes data
    token: BigInt,
    randoms_in: Vec<BigInt>,
    values_in: Vec<BigInt>,
    utxo_positions_in: Vec<BigInt>,
    utxo_tree_in: BigInt,

    // Commitment notes data
    npks_out: Vec<BigInt>,
    values_out: Vec<BigInt>,
    utxo_batch_global_start_position_out: BigInt,

    // Unshield data
    railgun_txid_if_has_unshield: BigInt,
    railgun_txid_merkle_proof_indices: BigInt,
    railgun_txid_merkle_proof_path_elements: Vec<BigInt>,

    // POI tree
    poi_in_merkle_proof_indices: Vec<BigInt>,
    poi_in_merkle_proof_path_elements: Vec<Vec<BigInt>>,
}

// impl PoiCircuitInputs {
//     pub fn from_inputs(
//         railgun_merkle_tree: &mut MerkleTree<>,
//         poi_merkle_tree: &mut MerkleTree,
//         bound_params_hash: Fr,
//         notes_in: Vec<Note>,
//         notes_out: Vec<Box<dyn TransactNote>>,
//     ) -> Result<Self, ()> {
//         if notes_in.is_empty() || notes_out.is_empty() {
//             return Err(());
//         }

//         todo!()
//     }
// }
