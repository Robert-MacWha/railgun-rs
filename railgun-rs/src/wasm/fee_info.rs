use alloy::primitives::Address;
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

use crate::{
    account::RailgunAccount,
    railgun::{address::RailgunAddress, transaction::operation_builder::FeeInfo},
    wasm::JsRailgunAccount,
};

#[wasm_bindgen]
pub struct JsFeeInfo {
    inner: FeeInfo,
}

#[wasm_bindgen]
impl JsFeeInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        payee: JsRailgunAccount,
        asset: String,
        bps: u32,
        recipient: String,
        id: String,
        list_keys: Vec<String>,
    ) -> Result<Self, JsError> {
        let asset: Address = asset
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid asset address: {}", e)))?;
        let recipient: RailgunAddress = recipient
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid recipient address: {}", e)))?;

        Ok(Self {
            inner: FeeInfo {
                payee: payee.inner.clone(),
                asset,
                bps,
                recipient,
                id,
                list_keys,
            },
        })
    }
}

impl JsFeeInfo {
    pub fn inner(&self) -> &FeeInfo {
        &self.inner
    }
}
