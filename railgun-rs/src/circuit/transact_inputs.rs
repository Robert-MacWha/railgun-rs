use std::collections::HashMap;

use ark_bn254::Fr;
use num_bigint::{BigInt, Sign};

use crate::{
    crypto::keys::fr_to_bigint,
    merkle_trees::merkle_tree::UtxoMerkleTree,
    note::{Note, utxo::UtxoNote},
};

#[derive(Debug, Clone)]
pub struct TransactCircuitInputs {
    // Public Inputs
    pub merkle_root: BigInt,
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

impl TransactCircuitInputs {
    pub fn from_inputs(
        merkle_tree: &mut UtxoMerkleTree,
        bound_params_hash: Fr,
        notes_in: &[UtxoNote],
        notes_out: &[Box<dyn Note>],
    ) -> Result<Self, ()> {
        if notes_in.is_empty() || notes_out.is_empty() {
            return Err(());
        }

        let merkle_root = merkle_tree.root();
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
        let commitments: Vec<Fr> = notes_out.iter().map(|note| note.hash().into()).collect();

        let note_zero = &notes_in[0];
        let token = fr_to_bigint(&note_zero.asset().hash());
        let public_key = note_zero.spending_public_key();
        let public_key = [fr_to_bigint(&public_key.0), fr_to_bigint(&public_key.1)];
        let signature = note_zero.sign_circuit_inputs(
            merkle_root.into(),
            bound_params_hash,
            &nullifiers,
            &commitments,
        );
        let signature = [
            fr_to_bigint(&signature[0]),
            fr_to_bigint(&signature[1]),
            fr_to_bigint(&signature[2]),
        ];

        let random_in = notes_in
            .iter()
            .map(|note| BigInt::from_bytes_be(Sign::Plus, &note.random()))
            .collect();

        let value_in: Vec<BigInt> = notes_in
            .iter()
            .map(|note| BigInt::from(note.value()))
            .collect();

        let path_elements = merkle_proofs
            .iter()
            .map(|proof| {
                proof
                    .elements
                    .iter()
                    .map(fr_to_bigint)
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

        Ok(TransactCircuitInputs {
            merkle_root: fr_to_bigint(&merkle_root.into()),
            bound_params_hash: fr_to_bigint(&bound_params_hash),
            nullifiers: nullifiers.iter().map(fr_to_bigint).collect(),
            commitments_out: commitments.iter().map(fr_to_bigint).collect(),
            token,
            public_key,
            signature,
            random_in,
            value_in,
            path_elements,
            leaves_indices,
            nullifying_key: fr_to_bigint(&nullifying_key),
            npk_out: npk_out.iter().map(fr_to_bigint).collect(),
            value_out,
        })
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
