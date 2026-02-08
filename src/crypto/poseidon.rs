use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};
use ff_ce::PrimeField as OldPrimeField;
use light_poseidon::PoseidonHasher;

//? Using `light_poseidon` for hashing instead of `poseidon_rs` (which is already
//? a dependency through `babyjubjub_rs` and significantly smaller) because it's
//? like an order of magnitude faster.
pub fn poseidon_hash(inputs: &[Fr]) -> Fr {
    let mut poseidon = light_poseidon::Poseidon::<Fr>::new_circom(inputs.len()).unwrap();
    poseidon.hash(inputs).unwrap()
    // let inputs = inputs.into_iter().map(arkwork_fr_to_poseidon).collect();

    // let poseidon = poseidon_rs::Poseidon::new();
    // let hash = poseidon.hash(inputs).unwrap();
    // poseidon_fr_to_arkworks(&hash)
}

pub fn poseidon_fr_to_arkworks(fr: &poseidon_rs::Fr) -> Fr {
    let repr: [u64; 4] = fr.into_repr().0;
    Fr::from_bigint(BigInt::<4>(repr)).unwrap()
}

pub fn arkwork_fr_to_poseidon(fr: &Fr) -> poseidon_rs::Fr {
    let repr: [u64; 4] = fr.into_bigint().0;
    poseidon_rs::Fr::from_repr(poseidon_rs::FrRepr(repr)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fr_conversion() {
        let original = Fr::from(123456789u64);
        let poseidon_fr = arkwork_fr_to_poseidon(&original);
        let converted_back = poseidon_fr_to_arkworks(&poseidon_fr);
        assert_eq!(original, converted_back);
    }
}
