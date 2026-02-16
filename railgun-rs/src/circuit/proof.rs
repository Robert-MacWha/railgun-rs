use ark_bn254::Bn254;
use ruint::aliases::U256;

use crate::{abis, railgun};

#[derive(Clone)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

#[derive(Clone)]
pub struct G1Affine {
    pub x: U256,
    pub y: U256,
}

#[derive(Clone)]
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

impl From<Proof> for railgun::poi::poi_client::SnarkProof {
    fn from(proof: Proof) -> Self {
        railgun::poi::poi_client::SnarkProof {
            pi_a: (proof.a.x.to_string(), proof.a.y.to_string()),
            pi_b: (
                (proof.b.x[0].to_string(), proof.b.x[1].to_string()),
                (proof.b.y[0].to_string(), proof.b.y[1].to_string()),
            ),
            pi_c: (proof.c.x.to_string(), proof.c.y.to_string()),
        }
    }
}
