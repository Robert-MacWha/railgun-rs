use std::str::FromStr;

use alloy::primitives::{U256, utils::keccak256_cached};

pub mod aes;
pub mod keys;
pub mod poseidon;
pub mod railgun_base_37;
pub mod railgun_txid;
pub mod railgun_utxo;
pub mod railgun_zero;

const SNARK_SCALAR_FIELD: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

pub fn concat_arrays<const A: usize, const B: usize, const C: usize>(
    a: &[u8; A],
    b: &[u8; B],
) -> [u8; C] {
    assert_eq!(A + B, C);
    let mut out = [0u8; C];
    out[..A].copy_from_slice(a);
    out[A..].copy_from_slice(b);
    out
}

pub fn concat_arrays_3<const A: usize, const B: usize, const C: usize, const D: usize>(
    a: &[u8; A],
    b: &[u8; B],
    c: &[u8; C],
) -> [u8; D] {
    assert_eq!(A + B + C, D);
    let mut out = [0u8; D];
    out[..A].copy_from_slice(a);
    out[A..A + B].copy_from_slice(b);
    out[A + B..].copy_from_slice(c);
    out
}

pub fn hash_to_scalar(data: &[u8]) -> U256 {
    let hash = keccak256_cached(data);
    let hash_bigint = U256::from_be_bytes::<32>(hash.as_slice().try_into().unwrap());
    let snark_field = U256::from_str(SNARK_SCALAR_FIELD).unwrap();
    hash_bigint % snark_field
}
