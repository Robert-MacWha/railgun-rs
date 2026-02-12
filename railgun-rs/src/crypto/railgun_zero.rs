use ruint::aliases::U256;
use ruint::uint;

const SNARK_PRIME: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

pub fn railgun_merkle_tree_zero() -> U256 {
    use alloy::primitives::utils::keccak256_cached;
    let hash = U256::from_be_bytes(*keccak256_cached(b"Railgun"));
    let hash_mod = hash % SNARK_PRIME;
    hash_mod
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_railgun_merkle_tree_zero() {
        let zero = railgun_merkle_tree_zero();
        let expected = uint!(
            2051258411002736885948763699317990061539314419500486054347250703186609807356_U256
        );
        assert_eq!(zero, expected);
    }
}
