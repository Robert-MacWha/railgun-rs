use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ed25519_dalek::SigningKey;
use num_bigint::BigInt;

use crate::crypto::eddsa::prv2pub;
use crate::crypto::poseidon::poseidon_hash;

/// Derive the master public key from spending and viewing private keys
pub fn derive_master_public_key(
    spending_private_key: &[u8; 32],
    viewing_private_key: &[u8; 32],
) -> Fr {
    let spending_pubkey = derive_spending_public_key(spending_private_key);
    let nullifying_key = get_nullifying_key(viewing_private_key);
    poseidon_hash(&[spending_pubkey.0, spending_pubkey.1, nullifying_key])
}

/// Helper to convert Fr to bytes in big-endian format
pub fn fr_to_bytes_be(value: &Fr) -> [u8; 32] {
    value.into_bigint().to_bytes_be().try_into().unwrap()
}

/// Helper to convert Fr to BigInt
pub fn fr_to_bigint(fr: &Fr) -> BigInt {
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &fr_to_bytes_be(&fr))
}

pub fn bigint_to_fr(bi: &BigInt) -> Fr {
    let (_sign, bytes) = bi.to_bytes_be();
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Derive the viewing public key using ed25519
pub fn derive_viewing_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let signing_key = SigningKey::from_bytes(private_key);
    let verifying_key = signing_key.verifying_key();
    verifying_key.to_bytes()
}

/// Derive the spending public key using ed25519 babyjubjub
pub fn derive_spending_public_key(private_key: &[u8; 32]) -> (Fr, Fr) {
    let pubkey = prv2pub(private_key);
    (pubkey.0, pubkey.1)
}

fn get_nullifying_key(viewing_private_key: &[u8; 32]) -> Fr {
    let viewing_key_scalar = Fr::from_be_bytes_mod_order(viewing_private_key);
    poseidon_hash(&[viewing_key_scalar])
}
