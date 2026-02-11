use ark_bn254::Fr;
use ark_ff::BigInt;
use ruint::aliases::U256;
use ruint::uint;

const SNARK_PRIME: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

pub fn railgun_merkle_tree_zero() -> Fr {
    use alloy::primitives::utils::keccak256_cached;
    let hash = U256::from_be_bytes(*keccak256_cached(b"Railgun"));
    let hash_mod = hash % SNARK_PRIME;
    Fr::from(BigInt::from(hash_mod))
}

#[cfg(test)]
mod tests {

    use crate::crypto::keys::hex_to_fr;

    use super::*;

    #[test]
    fn test_railgun_merkle_tree_zero() {
        let zero = railgun_merkle_tree_zero();
        let expected = "0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc";
        assert_eq!(zero, hex_to_fr(expected));
    }
}
