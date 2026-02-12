use ark_bn254::{Bn254, Fr};
use ark_circom::CircomReduction;
use ark_ff::BigInt;
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_std::rand::random;

use tracing::info;

use crate::circuit::{
    artifacts::ArtifactLoader,
    poi_inputs::PoiCircuitInputs,
    proof::Proof,
    prover::{PoiProver, TransactProver},
    transact_inputs::TransactCircuitInputs,
    witness::{CircuitType, WitnessCalculator},
};

pub struct Groth16Prover<W, A> {
    witness_calculator: W,
    artifact_loader: A,
}

impl<W: WitnessCalculator, A: ArtifactLoader> Groth16Prover<W, A> {
    pub fn new(witness_calculator: W, artifact_loader: A) -> Self {
        Groth16Prover {
            witness_calculator,
            artifact_loader,
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<W: WitnessCalculator + Sync, A: ArtifactLoader + Sync> TransactProver for Groth16Prover<W, A> {
    async fn prove_transact(
        &self,
        inputs: &TransactCircuitInputs,
    ) -> Result<Proof, Box<dyn std::error::Error>> {
        let circuit_type = CircuitType::Transact {
            nullifiers: inputs.nullifiers.len(),
            commitments: inputs.commitments_out.len(),
        };

        info!("Loading artifacts");
        let pk = self.artifact_loader.load_proving_key(circuit_type).await?;
        let matrices = self.artifact_loader.load_matrices(circuit_type).await?;

        info!("Calculating witness");
        let witnesses = self
            .witness_calculator
            .calculate_witness(circuit_type, inputs.as_flat_map())
            .await?;
        let witnesses: Vec<Fr> = witnesses
            .iter()
            .map(|x| Fr::from(BigInt::from(*x)))
            .collect();

        info!("Creating proof");
        let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
            &pk,
            random(),
            random(),
            &matrices,
            matrices.num_instance_variables,
            matrices.num_constraints,
            &witnesses,
        )
        .unwrap();

        info!("Verifying proof");
        let public_inputs = &witnesses[1..matrices.num_instance_variables];
        let pvk = prepare_verifying_key(&pk.vk);
        let verified =
            Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
        assert!(verified, "Proof verification failed");

        info!("Proof verified successfully");
        Ok(proof.into())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<W: WitnessCalculator + Sync, A: ArtifactLoader + Sync> PoiProver for Groth16Prover<W, A> {
    async fn prove_poi(
        &self,
        inputs: &PoiCircuitInputs,
    ) -> Result<Proof, Box<dyn std::error::Error>> {
        let circuit_type = CircuitType::Transact {
            nullifiers: inputs.nullifiers.len(),
            commitments: inputs.commitments.len(),
        };

        info!("Loading artifacts");
        let pk = self.artifact_loader.load_proving_key(circuit_type).await?;
        let matrices = self.artifact_loader.load_matrices(circuit_type).await?;

        info!("Calculating witness");
        let witnesses = self
            .witness_calculator
            .calculate_witness(circuit_type, inputs.as_flat_map())
            .await?;
        let witnesses: Vec<Fr> = witnesses
            .iter()
            .map(|x| Fr::from(BigInt::from(*x)))
            .collect();

        info!("Creating proof");
        let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
            &pk,
            random(),
            random(),
            &matrices,
            matrices.num_instance_variables,
            matrices.num_constraints,
            &witnesses,
        )
        .unwrap();

        info!("Verifying proof");
        let public_inputs = &witnesses[1..matrices.num_instance_variables];
        let pvk = prepare_verifying_key(&pk.vk);
        let verified =
            Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
        assert!(verified, "Proof verification failed");
        info!("Proof verified successfully");

        Ok(proof.into())
    }
}
