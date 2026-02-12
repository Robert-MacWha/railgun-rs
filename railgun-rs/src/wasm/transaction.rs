use wasm_bindgen::prelude::wasm_bindgen;

use crate::transaction::operation_builder::OperationBuilder;

#[wasm_bindgen]
pub struct JsTransactionBuilder {
    inner: OperationBuilder,
}
