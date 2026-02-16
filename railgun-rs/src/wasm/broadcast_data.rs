use wasm_bindgen::prelude::wasm_bindgen;

use crate::railgun::transaction::broadcaster_data::BroadcastData;

#[wasm_bindgen]
pub struct JsBroadcastData {
    inner: BroadcastData,
}

impl JsBroadcastData {
    pub fn new(inner: BroadcastData) -> Self {
        Self { inner }
    }
}
