use std::collections::HashMap;

use js_sys::Function;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::circuit::{
    poi_inputs::PoiCircuitInputs,
    proof::{G1Affine, G2Affine, Proof},
    prover::{PoiProver, TransactProver},
    transact_inputs::TransactCircuitInputs,
};

#[wasm_bindgen]
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

/// Proof format expected from JS callbacks.
/// All values should be decimal strings.
#[derive(Deserialize)]
pub struct JsProofResponse {
    pub a: [String; 2],
    pub b: [[String; 2]; 2],
    pub c: [String; 2],
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
    ) -> Result<Proof, Box<dyn std::error::Error>> {
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
    ) -> Result<Proof, Box<dyn std::error::Error>> {
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

impl TryFrom<JsProofResponse> for Proof {
    type Error = JsProverError;

    fn try_from(value: JsProofResponse) -> Result<Self, Self::Error> {
        Ok(Proof {
            a: G1Affine {
                x: parse_number(&value.a[0])?,
                y: parse_number(&value.a[1])?,
            },
            b: G2Affine {
                x: [parse_number(&value.b[0][0])?, parse_number(&value.b[0][1])?],
                y: [parse_number(&value.b[1][0])?, parse_number(&value.b[1][1])?],
            },
            c: G1Affine {
                x: parse_number(&value.c[0])?,
                y: parse_number(&value.c[1])?,
            },
        })
    }
}

async fn call_js_prover(
    func: &Function,
    circuit_name: &str,
    inputs: HashMap<String, Vec<U256>>,
) -> Result<Proof, JsProverError> {
    let js_inputs: JsCircuitInputs = inputs.into();
    let js_value = serde_wasm_bindgen::to_value(&js_inputs)?;

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
    let proof = response.try_into()?;

    Ok(proof)
}

fn parse_number(s: &str) -> Result<U256, JsProverError> {
    let s = s.trim();
    U256::from_str_radix(s, 10)
        .map_err(|e| JsProverError::ProofParse(format!("Failed to parse decimal: {}", e)))
}
