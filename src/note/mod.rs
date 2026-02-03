use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use curve25519_dalek::{Scalar, edwards::CompressedEdwardsY};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

pub mod note;
pub mod shield;
mod transact;

#[derive(Debug, Error)]
pub enum SharedKeyError {
    #[error("Failed to derive shared symmetric key")]
    KeyDerivationFailed,
}

fn shared_symetric_key(
    private_key_a: &[u8; 32],
    blinded_public_key_b: &[u8; 32],
) -> Result<[u8; 32], SharedKeyError> {
    let scalar = private_scalar_from_private_key(private_key_a);

    let public_point = CompressedEdwardsY(*blinded_public_key_b)
        .decompress()
        .ok_or(SharedKeyError::KeyDerivationFailed)?;
    let shared_point = public_point * scalar;
    let digest = Sha256::digest(shared_point.compress().to_bytes());
    return Ok(digest.into());
}

fn private_scalar_from_private_key(private_key: &[u8; 32]) -> Scalar {
    let hash = Sha512::digest(private_key);
    let mut head = [0u8; 32];
    head.copy_from_slice(&hash[..32]);

    // Clamp as per ED25519
    head[0] &= 248;
    head[31] &= 63;
    head[31] |= 64;

    Scalar::from_bytes_mod_order(head)
}

pub fn ark_to_solidity_bytes(fr: Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let mut bytes = [0u8; 32];
    bigint.serialize_compressed(&mut bytes[..]).unwrap();
    bytes.reverse();
    bytes
}
