use std::fs;

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomReduction, read_zkey};
use ark_groth16::{Groth16, ProvingKey, prepare_verifying_key};
use ark_relations::r1cs::ConstraintMatrices;
use ark_std::rand::random;
use num_bigint::BigInt;
use tracing::info;
use wasmer::Store;

use crate::{
    circuit::{
        poi_inputs::PoiCircuitInputs,
        prover::{G1Affine, G2Affine, PoiProver, Proof, TransactProver},
        transact_inputs::TransactCircuitInputs,
    },
    crypto::keys::{bigint_to_fr, fq_to_u256},
};

pub struct NativeProver {}

struct WitnessCalculator {
    inner: ark_circom::WitnessCalculator,
    store: wasmer::Store,
}

impl NativeProver {
    pub fn new() -> Self {
        NativeProver {}
    }
}

impl TransactProver for NativeProver {
    fn prove_transact(
        &self,
        inputs: &TransactCircuitInputs,
    ) -> Result<Proof, Box<dyn std::error::Error>> {
        info!("Loading artifacts");
        let (pk, matrices, mut calculator) =
            load_railgun_artifacts(inputs.nullifiers.len(), inputs.commitments_out.len());

        info!("Calculating witness");
        let witnesses = calculator.calculate_witness(inputs.as_flat_map())?;

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
        Ok(Proof {
            a: G1Affine {
                x: fq_to_u256(&proof.a.x),
                y: fq_to_u256(&proof.a.y),
            },
            b: G2Affine {
                x: [fq_to_u256(&proof.b.x.c0), fq_to_u256(&proof.b.x.c1)],
                y: [fq_to_u256(&proof.b.y.c0), fq_to_u256(&proof.b.y.c1)],
            },
            c: G1Affine {
                x: fq_to_u256(&proof.c.x),
                y: fq_to_u256(&proof.c.y),
            },
        })
    }
}

impl PoiProver for NativeProver {
    fn prove_poi(&self, inputs: &PoiCircuitInputs) -> Result<Proof, Box<dyn std::error::Error>> {
        info!("Loading artifacts");
        let (pk, matrices, mut calculator) =
            load_poi_artifacts(inputs.nullifiers.len(), inputs.commitments.len());

        info!("Calculating witness");
        let witness = calculator.calculate_witness(inputs.as_flat_map())?;

        info!("Creating proof");
        let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
            &pk,
            random(),
            random(),
            &matrices,
            matrices.num_instance_variables,
            matrices.num_constraints,
            &witness,
        )
        .unwrap();

        info!("Verifying proof");
        let public_inputs = &witness[1..matrices.num_instance_variables];
        let pvk = prepare_verifying_key(&pk.vk);
        let verified =
            Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
        assert!(verified, "Proof verification failed");

        info!("Proof verified successfully");

        todo!()
    }
}

fn load_railgun_artifacts(
    notes_in: usize,
    notes_out: usize,
) -> (ProvingKey<Bn254>, ConstraintMatrices<Fr>, WitnessCalculator) {
    if notes_in != 1 || notes_out != 2 {
        info!(
            "Unsupported number of notes: {} in, {} out",
            notes_in, notes_out
        );
        todo!("Only 1 input and 2 output notes are supported currently");
    }

    const WASM_PATH: &str = "artifacts/01x02.wasm";
    const ZKEY_PATH: &str = "artifacts/01x02.zkey";

    let calculator = WitnessCalculator::new(WASM_PATH).unwrap();

    let mut zkey_file = fs::File::open(ZKEY_PATH).unwrap();
    let (proving_key, matrices) = read_zkey(&mut zkey_file).unwrap();

    (proving_key, matrices, calculator)
}

fn load_poi_artifacts(
    notes_in: usize,
    notes_out: usize,
) -> (ProvingKey<Bn254>, ConstraintMatrices<Fr>, WitnessCalculator) {
    if notes_in > 3 || notes_out > 3 {
        info!(
            "Unsupported number of notes: {} in, {} out",
            notes_in, notes_out
        );
        todo!("Only up to 3 input and 3 output notes are supported currently");
    }

    const WASM_PATH: &str = "artifacts/ppoi/3x3.wasm";
    const ZKEY_PATH: &str = "artifacts/ppoi/3x3.zkey";

    let calculator = WitnessCalculator::new(WASM_PATH).unwrap();

    let mut zkey_file = fs::File::open(ZKEY_PATH).unwrap();
    let (proving_key, matrices) = read_zkey(&mut zkey_file).unwrap();

    (proving_key, matrices, calculator)
}

impl WitnessCalculator {
    fn new(wasm_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut store = Store::default();
        let inner = ark_circom::WitnessCalculator::new(&mut store, wasm_path)?;
        Ok(Self { inner, store })
    }

    fn calculate_witness(
        &mut self,
        inputs: std::collections::HashMap<String, Vec<BigInt>>,
    ) -> Result<Vec<Fr>, Box<dyn std::error::Error>> {
        let witness = self
            .inner
            .calculate_witness(&mut self.store, inputs, true)?;
        Ok(witness.into_iter().map(|b| bigint_to_fr(&b)).collect())
    }
}
