use crate::circuit::{inputs::PoiCircuitInputs, inputs::TransactCircuitInputs, proof::Proof};

#[cfg_attr(not(feature = "wasm"), async_trait::async_trait)]
#[cfg_attr(feature = "wasm", async_trait::async_trait(?Send))]
pub trait TransactProver {
    async fn prove_transact(
        &self,
        inputs: &TransactCircuitInputs,
    ) -> Result<Proof, Box<dyn std::error::Error>>;
}

#[cfg_attr(not(feature = "wasm"), async_trait::async_trait)]
#[cfg_attr(feature = "wasm", async_trait::async_trait(?Send))]
pub trait PoiProver {
    async fn prove_poi(
        &self,
        inputs: &PoiCircuitInputs,
    ) -> Result<Proof, Box<dyn std::error::Error>>;
}
