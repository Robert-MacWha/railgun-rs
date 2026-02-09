use ark_bn254::Fr;
use ark_ff::PrimeField;

pub fn railgun_merkle_tree_zero() -> Fr {
    use alloy::primitives::utils::keccak256_cached;
    let hash = keccak256_cached(b"Railgun");
    Fr::from_be_bytes_mod_order(hash.as_slice())
}
