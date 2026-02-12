use std::collections::HashMap;

use js_sys::Function;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::circuit::{
    poi_inputs::PoiCircuitInputs,
    proof::{G1Affine, G2Affine, Proof},
    prover::{PoiProver, TransactProver},
    transact_inputs::TransactCircuitInputs,
};

/// Prover that delegates to JavaScript callbacks for proof generation.
///
/// # Example (JS side)
/// ```js
/// import init, { JsProver } from './railgun_rs.js';
///
/// await init();
///
/// const prover = new JsProver(
///     async (circuitName, inputs) => {
///         // Use snarkjs to generate transact proof
///         const { proof } = await snarkjs.groth16.fullProve(inputs, wasmPath, zkeyPath);
///         return formatProof(proof);
///     },
///     async (circuitName, inputs) => {
///         // Use snarkjs to generate POI proof
///         const { proof } = await snarkjs.groth16.fullProve(inputs, wasmPath, zkeyPath);
///         return formatProof(proof);
///     }
/// );
/// ```
#[wasm_bindgen]
pub struct JsProver {
    prove_transact_fn: Function,
    prove_poi_fn: Function,
}

#[wasm_bindgen]
impl JsProver {
    #[wasm_bindgen(constructor)]
    pub fn new(prove_transact_fn: Function, prove_poi_fn: Function) -> Self {
        Self {
            prove_transact_fn,
            prove_poi_fn,
        }
    }
}

/// Proof format expected from JS callbacks.
/// All values should be decimal or hex strings.
#[derive(Deserialize)]
pub struct JsProofResponse {
    pub a: [String; 2],
    pub b: [[String; 2]; 2],
    pub c: [String; 2],
}

fn parse_number(s: &str) -> Result<U256, String> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        U256::from_str_radix(&s[2..], 16).map_err(|e| format!("Failed to parse hex: {}", e))
    } else {
        U256::from_str_radix(s, 10).map_err(|e| format!("Failed to parse decimal: {}", e))
    }
}

impl JsProofResponse {
    pub fn into_proof(self) -> Result<Proof, String> {
        Ok(Proof {
            a: G1Affine {
                x: parse_number(&self.a[0])?,
                y: parse_number(&self.a[1])?,
            },
            b: G2Affine {
                x: [parse_number(&self.b[0][0])?, parse_number(&self.b[0][1])?],
                y: [parse_number(&self.b[1][0])?, parse_number(&self.b[1][1])?],
            },
            c: G1Affine {
                x: parse_number(&self.c[0])?,
                y: parse_number(&self.c[1])?,
            },
        })
    }
}

/// Circuit inputs serialized for JS consumption.
/// Values are converted to decimal strings.
#[derive(Serialize)]
struct JsCircuitInputs {
    #[serde(flatten)]
    inputs: HashMap<String, Vec<String>>,
}

impl From<HashMap<String, Vec<U256>>> for JsCircuitInputs {
    fn from(inputs: HashMap<String, Vec<U256>>) -> Self {
        let inputs = inputs
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(|x| x.to_string()).collect()))
            .collect();
        JsCircuitInputs { inputs }
    }
}

async fn call_js_prover(
    func: &Function,
    circuit_name: &str,
    inputs: HashMap<String, Vec<U256>>,
) -> Result<Proof, Box<dyn std::error::Error>> {
    let js_inputs: JsCircuitInputs = inputs.into();
    let js_value = serde_wasm_bindgen::to_value(&js_inputs)?;

    let this = JsValue::NULL;
    let circuit_name_js = JsValue::from_str(circuit_name);

    let promise = func
        .call2(&this, &circuit_name_js, &js_value)
        .map_err(|e| format!("Failed to call JS prover: {:?}", e))?;

    let promise = js_sys::Promise::from(promise);
    let result = JsFuture::from(promise).await.map_err(|e| {
        e.as_string()
            .unwrap_or_else(|| "Unknown JS error".to_string())
    })?;

    let response: JsProofResponse = serde_wasm_bindgen::from_value(result)?;
    let proof = response.into_proof()?;

    Ok(proof)
}

#[async_trait::async_trait(?Send)]
impl TransactProver for JsProver {
    async fn prove_transact(
        &self,
        inputs: &TransactCircuitInputs,
    ) -> Result<Proof, Box<dyn std::error::Error>> {
        let circuit_name = format!(
            "{:02}x{:02}",
            inputs.nullifiers.len(),
            inputs.commitments_out.len()
        );

        call_js_prover(&self.prove_transact_fn, &circuit_name, inputs.as_flat_map()).await
    }
}

#[async_trait::async_trait(?Send)]
impl PoiProver for JsProver {
    async fn prove_poi(
        &self,
        inputs: &PoiCircuitInputs,
    ) -> Result<Proof, Box<dyn std::error::Error>> {
        let circuit_name = format!(
            "ppoi/{}x{}",
            inputs.nullifiers.len(),
            inputs.commitments.len()
        );

        call_js_prover(&self.prove_poi_fn, &circuit_name, inputs.as_flat_map()).await
    }
}
