use ark_bn254::Bn254;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::abis;

/// Circuit proof
///
/// Serializes into a SnarkJS-compatible format, with decimal strings for all
/// field elements and arrays for the g1 / g2 points.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "pi_a")]
    pub a: G1Affine,
    #[serde(rename = "pi_b")]
    pub b: G2Affine,
    #[serde(rename = "pi_c")]
    pub c: G1Affine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(into = "[String; 2]")]
pub struct G1Affine {
    pub x: U256,
    pub y: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(into = "[[String; 2]; 2]")]
pub struct G2Affine {
    pub x: [U256; 2],
    pub y: [U256; 2],
}

impl From<ark_groth16::Proof<Bn254>> for Proof {
    fn from(proof: ark_groth16::Proof<Bn254>) -> Self {
        Proof {
            a: G1Affine {
                x: ark_ff::BigInt::from(proof.a.x).into(),
                y: ark_ff::BigInt::from(proof.a.y).into(),
            },
            b: G2Affine {
                x: [
                    ark_ff::BigInt::from(proof.b.x.c0).into(),
                    ark_ff::BigInt::from(proof.b.x.c1).into(),
                ],
                y: [
                    ark_ff::BigInt::from(proof.b.y.c0).into(),
                    ark_ff::BigInt::from(proof.b.y.c1).into(),
                ],
            },
            c: G1Affine {
                x: ark_ff::BigInt::from(proof.c.x).into(),
                y: ark_ff::BigInt::from(proof.c.y).into(),
            },
        }
    }
}

impl From<Proof> for abis::railgun::SnarkProof {
    fn from(proof: Proof) -> Self {
        abis::railgun::SnarkProof {
            a: abis::railgun::G1Point {
                x: proof.a.x,
                y: proof.a.y,
            },
            //? Reversal of x and y for G2 points is required to match the expected format in Solidity
            b: abis::railgun::G2Point {
                x: [proof.b.x[1], proof.b.x[0]],
                y: [proof.b.y[1], proof.b.y[0]],
            },
            c: abis::railgun::G1Point {
                x: proof.c.x,
                y: proof.c.y,
            },
        }
    }
}

impl From<G1Affine> for [String; 2] {
    fn from(point: G1Affine) -> Self {
        [point.x.to_string(), point.y.to_string()]
    }
}

impl From<G2Affine> for [[String; 2]; 2] {
    fn from(point: G2Affine) -> Self {
        [
            [point.x[0].to_string(), point.x[1].to_string()],
            [point.y[0].to_string(), point.y[1].to_string()],
        ]
    }
}

#[cfg(test)]
mod tests {
    use ruint::uint;

    use super::*;

    #[test]
    fn test_proof_serialization() {
        let proof = test_proof();

        let serialized = serde_json::to_string_pretty(&proof).unwrap();
        insta::assert_snapshot!(serialized);
    }

    #[test]
    fn test_proof_to_abi() {
        let proof = test_proof();
        let abi_proof: abis::railgun::SnarkProof = proof.into();

        insta::assert_debug_snapshot!(abi_proof);
    }

    fn test_proof() -> Proof {
        Proof {
            a: G1Affine {
                x: uint!(12345678901234567890_U256),
                y: uint!(98765432109876543210_U256),
            },
            b: G2Affine {
                x: [
                    uint!(11111111111111111111_U256),
                    uint!(22222222222222222222_U256),
                ],
                y: [
                    uint!(33333333333333333333_U256),
                    uint!(44444444444444444444_U256),
                ],
            },
            c: G1Affine {
                x: uint!(55555555555555555555_U256),
                y: uint!(66666666666666666666_U256),
            },
        }
    }
}
