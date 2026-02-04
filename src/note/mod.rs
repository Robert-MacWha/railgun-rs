use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

pub mod note;
pub mod shield;
pub mod transact;

pub fn ark_to_solidity_bytes(fr: Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let mut bytes = [0u8; 32];
    bigint.serialize_compressed(&mut bytes[..]).unwrap();
    bytes.reverse();
    bytes
}
