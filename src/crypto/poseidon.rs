use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonHasher};

pub fn poseidon_hash(inputs: &[Fr]) -> Fr {
    let mut poseidon = Poseidon::<Fr>::new_circom(inputs.len()).unwrap();
    poseidon.hash(inputs).unwrap()
}
