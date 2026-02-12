use wasm_bindgen::prelude::*;

use crate::account::RailgunAccount;
use crate::crypto::keys::{ByteKey, SpendingKey, ViewingKey};

#[wasm_bindgen]
pub struct JsRailgunAccount {
    inner: RailgunAccount,
}

#[wasm_bindgen]
impl JsRailgunAccount {
    #[wasm_bindgen(constructor)]
    pub fn new(spending_key: &[u8], viewing_key: &[u8], chain_id: u64) -> Result<JsRailgunAccount, JsError> {
        if spending_key.len() != 32 {
            return Err(JsError::new("Spending key must be 32 bytes"));
        }
        if viewing_key.len() != 32 {
            return Err(JsError::new("Viewing key must be 32 bytes"));
        }

        let spending_key: [u8; 32] = spending_key.try_into().unwrap();
        let viewing_key: [u8; 32] = viewing_key.try_into().unwrap();

        let spending_key = SpendingKey::from_bytes(spending_key);
        let viewing_key = ViewingKey::from_bytes(viewing_key);

        Ok(JsRailgunAccount {
            inner: RailgunAccount::new(spending_key, viewing_key, chain_id),
        })
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.inner.address().to_string()
    }
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}
