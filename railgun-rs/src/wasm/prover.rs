use std::collections::HashMap;

use js_sys::Function;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::circuit::{
    inputs::{PoiCircuitInputs, TransactCircuitInputs},
    proof::{G1Affine, G2Affine, Proof},
    prover::{PoiProver, PublicInputs, TransactProver},
};

/// JavaScript-backed prover that delegates to snarkjs or similar.
///
/// The prove functions must have the signature:
/// ```typescript
/// type ProveFunction = (
///   circuitName: string,  // e.g., "transact/01x02" or "poi/01x02"
///   inputs: Record<string, string[]>  // circuit inputs as decimal strings
/// ) => Promise<ProofResponse>;
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct JsProver {
    prove_transact_fn: Function,
    prove_poi_fn: Function,
}

/// Circuit inputs serialized for JS consumption.
/// Values are converted to decimal strings.
#[derive(Serialize)]
struct JsCircuitInputs {
    #[serde(flatten)]
    inputs: HashMap<String, Vec<String>>,
}

/// Groth16 proof format for JS interop.
/// All coordinate values are decimal strings representing field elements.
#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct JsProofResponse {
    /// G1 point A: [x, y] as decimal strings
    pub a: [String; 2],
    /// G2 point B: [[x0, x1], [y0, y1]] as decimal strings
    pub b: [[String; 2]; 2],
    /// G1 point C: [x, y] as decimal strings
    pub c: [String; 2],
    /// Public inputs as decimal strings
    pub public_inputs: Vec<String>,
}

#[derive(Debug, Error)]
pub enum JsProverError {
    #[error("Serde error: {0}")]
    Serde(#[from] serde_wasm_bindgen::Error),
    #[error("JS Error: {0:?}")]
    Js(JsValue),
    #[error("Proof parsing error: {0}")]
    ProofParse(String),
}

#[wasm_bindgen]
impl JsProver {
    /// Create a new JsProver with the given prove functions.
    ///
    /// @param prove_transact_fn - Function to prove transact circuits
    /// @param prove_poi_fn - Function to prove POI circuits
    ///
    /// Both functions must match the ProveFunction signature:
    /// `(circuitName: string, inputs: Record<string, string[]>) => Promise<ProofResponse>`
    #[wasm_bindgen(constructor)]
    pub fn new(prove_transact_fn: Function, prove_poi_fn: Function) -> Self {
        Self {
            prove_transact_fn,
            prove_poi_fn,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl TransactProver for JsProver {
    async fn prove_transact(
        &self,
        inputs: &TransactCircuitInputs,
    ) -> Result<(Proof, PublicInputs), Box<dyn std::error::Error>> {
        let circuit_name = format!(
            "transact/{:02}x{:02}",
            inputs.nullifiers.len(),
            inputs.commitments_out.len()
        );

        Ok(call_js_prover(&self.prove_transact_fn, &circuit_name, inputs.as_flat_map()).await?)
    }
}

#[async_trait::async_trait(?Send)]
impl PoiProver for JsProver {
    async fn prove_poi(
        &self,
        inputs: &PoiCircuitInputs,
    ) -> Result<(Proof, PublicInputs), Box<dyn std::error::Error>> {
        let circuit_name = format!(
            "poi/{:02}x{:02}",
            inputs.nullifiers.len(),
            inputs.commitments.len()
        );

        Ok(call_js_prover(&self.prove_poi_fn, &circuit_name, inputs.as_flat_map()).await?)
    }
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

impl JsProofResponse {
    fn into_proof_and_inputs(self) -> Result<(Proof, PublicInputs), JsProverError> {
        let proof = Proof {
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
        };

        let public_inputs: Result<Vec<U256>, _> =
            self.public_inputs.iter().map(|s| parse_number(s)).collect();

        Ok((proof, public_inputs?))
    }
}

async fn call_js_prover(
    func: &Function,
    circuit_name: &str,
    inputs: HashMap<String, Vec<U256>>,
) -> Result<(Proof, PublicInputs), JsProverError> {
    let js_inputs: JsCircuitInputs = inputs.into();
    let serializer = serde_wasm_bindgen::Serializer::new()
        .serialize_maps_as_objects(true)
        .serialize_large_number_types_as_bigints(true);
    let js_value = js_inputs.serialize(&serializer)?;

    let this = JsValue::NULL;
    let circuit_name_js = JsValue::from_str(circuit_name);

    let promise = func
        .call2(&this, &circuit_name_js, &js_value)
        .map_err(|e| JsProverError::Js(e))?;

    let promise = js_sys::Promise::from(promise);
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| JsProverError::Js(e))?;

    let response: JsProofResponse = serde_wasm_bindgen::from_value(result)?;
    let (proof, public_inputs) = response.into_proof_and_inputs()?;

    Ok((proof, public_inputs))
}

fn parse_number(s: &str) -> Result<U256, JsProverError> {
    let s = s.trim();
    U256::from_str_radix(s, 10)
        .map_err(|e| JsProverError::ProofParse(format!("Failed to parse decimal: {}", e)))
}
