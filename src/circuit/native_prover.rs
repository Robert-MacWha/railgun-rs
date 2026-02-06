use std::fs;

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction, read_zkey};
use ark_groth16::{Groth16, ProvingKey, prepare_verifying_key};
use tracing::info;

use crate::{
    circuit::{
        prover::{G1Affine, G2Affine, Proof, TransactProver},
        transact_inputs::TransactCircuitInputs,
    },
    crypto::keys::fq_to_u256,
};

pub struct NativeProver {}

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
        let (pk, mut builder) =
            self.load_artifacts(inputs.nullifiers.len(), inputs.commitments_out.len());

        // Build the circuit
        for (name, values) in inputs.as_flat_map() {
            for value in values {
                builder.push_input(&name, value);
            }
        }

        let circuit = builder.build().unwrap();
        let public_inputs = circuit.get_public_inputs().unwrap();
        info!("Creating proof");

        let mut rng = ark_std::rand::thread_rng();
        let proof = Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
            circuit, &pk, &mut rng,
        )
        .unwrap();

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

impl NativeProver {
    fn load_artifacts(
        &self,
        notes_in: usize,
        notes_out: usize,
    ) -> (ProvingKey<Bn254>, CircomBuilder<Fr>) {
        if notes_in != 1 || notes_out != 2 {
            todo!("Only 1 input and 2 output notes are supported currently");
        }

        const WASM_PATH: &str = "artifacts/01x02/01x02.wasm";
        const R1CS_PATH: &str = "artifacts/01x02/01x02.r1cs";
        const ZKEY_PATH: &str = "artifacts/01x02/01x02.zkey";

        let cfg = CircomConfig::<Fr>::new(WASM_PATH, R1CS_PATH).unwrap();
        let builder = CircomBuilder::new(cfg);

        let mut zkey_file = fs::File::open(ZKEY_PATH).unwrap();
        let (proving_key, _matrices) = read_zkey(&mut zkey_file).unwrap();

        (proving_key, builder)
    }
}
