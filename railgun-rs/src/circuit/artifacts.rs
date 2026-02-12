use ark_bn254::{Bn254, Fr};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;

use crate::circuit::witness::CircuitType;

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait ArtifactLoader {
    async fn load_proving_key(&self, circuit: CircuitType) -> Result<ProvingKey<Bn254>, String>;
    async fn load_matrices(&self, circuit: CircuitType) -> Result<ConstraintMatrices<Fr>, String>;
}
