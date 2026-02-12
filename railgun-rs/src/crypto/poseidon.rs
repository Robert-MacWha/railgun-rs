use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};
use ff_ce::PrimeField as OldPrimeField;
use ruint::aliases::U256;

pub fn poseidon_hash(inputs: &[U256]) -> Result<U256, poseidon_rust::error::Error> {
    let inputs: Vec<Fr> = inputs.iter().map(|i| BigInt::from(i).into()).collect();
    let hash = poseidon_rust::poseidon_hash(&inputs)?;
    Ok(hash.into_bigint().into())
}

pub fn poseidon_fr_to_uint(fr: &poseidon_rs::Fr) -> U256 {
    let repr: [u64; 4] = fr.into_repr().0;
    U256::from_limbs(repr)
}

pub fn arkwork_fr_to_poseidon(fr: &Fr) -> poseidon_rs::Fr {
    let repr: [u64; 4] = fr.into_bigint().0;
    poseidon_rs::Fr::from_repr(poseidon_rs::FrRepr(repr)).unwrap()
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     #[tracing_test::traced_test]
//     fn test_fr_conversion() {
//         let original = Fr::from(123456789u64);
//         let poseidon_fr = arkwork_fr_to_poseidon(&original);
//         let converted_back = poseidon_fr_to_arkworks(&poseidon_fr);
//         assert_eq!(original, converted_back);
//     }
// }
