use alloy::primitives::U256;

use crate::circuit::transact_inputs::TransactCircuitInputs;

pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

pub struct G1Affine {
    pub x: U256,
    pub y: U256,
}

pub struct G2Affine {
    pub x: [U256; 2],
    pub y: [U256; 2],
}

pub trait TransactProver {
    fn prove_transact(
        &self,
        inputs: &TransactCircuitInputs,
    ) -> Result<Proof, Box<dyn std::error::Error>>;
}
