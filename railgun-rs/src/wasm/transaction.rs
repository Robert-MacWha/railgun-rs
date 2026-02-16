use std::cell::RefCell;

use alloy::primitives::{Address, U256};
use alloy_sol_types::SolCall;
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

use crate::{
    abis::railgun::{RailgunSmartWallet, ShieldRequest},
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, get_chain_config},
    railgun::{
        address::RailgunAddress,
        note::shield::create_shield_request,
        transaction::{operation_builder::OperationBuilder, tx_data::TxData},
    },
    wasm::{
        JsBroadcaster, JsProver, JsRailgunAccount, broadcast_data::JsBroadcastData,
        fee_info::JsFeeInfo, indexer::JsIndexer, poi_client::JsPoiClient, provider::JsProvider,
    },
};

/// Transaction data output for EVM submission
#[wasm_bindgen]
pub struct JsTxData {
    inner: TxData,
}

#[wasm_bindgen]
impl JsTxData {
    /// Contract address to send the transaction to (checksummed 0x...)
    #[wasm_bindgen(getter)]
    pub fn to(&self) -> String {
        self.inner.to.to_checksum(None)
    }

    /// Raw calldata bytes
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.inner.data.clone()
    }

    /// ETH value to send (decimal string, usually "0")
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> String {
        self.inner.value.to_string()
    }

    /// Returns 0x-prefixed hex-encoded calldata
    #[wasm_bindgen(getter, js_name = "dataHex")]
    pub fn data_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.inner.data))
    }
}

/// Builder for shield transactions (self-broadcast only, no prover needed)
#[wasm_bindgen]
pub struct JsShieldBuilder {
    chain: ChainConfig,
    shields: Vec<(RailgunAddress, AssetId, u128)>,
}

#[wasm_bindgen]
impl JsShieldBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(chain_id: u64) -> Result<JsShieldBuilder, JsError> {
        let chain = get_chain_config(chain_id)
            .ok_or_else(|| JsError::new(&format!("Unsupported chain ID: {}", chain_id)))?;

        Ok(JsShieldBuilder {
            chain,
            shields: Vec::new(),
        })
    }

    /// Add a shield operation.
    ///
    /// - `recipient`: Railgun address (0zk...)
    /// - `asset`: Asset ID (e.g., "erc20:0x...")
    /// - `amount`: Amount as decimal string
    pub fn shield(&mut self, recipient: &str, asset: &str, amount: &str) -> Result<(), JsError> {
        let recipient: RailgunAddress = recipient
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid recipient address: {}", e)))?;

        let asset: AssetId = asset
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid asset ID: {}", e)))?;

        let amount: u128 = amount
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid amount: {}", e)))?;

        self.shields.push((recipient, asset, amount));
        Ok(())
    }

    /// Build the shield transaction calldata
    pub fn build(&self) -> Result<JsTxData, JsError> {
        let mut rng = rand::rng();

        let shields: Result<Vec<ShieldRequest>, _> = self
            .shields
            .iter()
            .map(|(r, a, v)| create_shield_request(*r, *a, *v, &mut rng))
            .collect();

        let shields = shields
            .map_err(|e| JsError::new(&format!("Failed to create shield request: {}", e)))?;

        let call = RailgunSmartWallet::shieldCall {
            _shieldRequests: shields,
        };
        let calldata = call.abi_encode();

        Ok(JsTxData {
            inner: TxData {
                to: self.chain.railgun_smart_wallet,
                data: calldata,
                value: U256::ZERO,
            },
        })
    }
}

/// Builder for transact transactions (transfers and unshields)
#[wasm_bindgen]
pub struct JsTransactionBuilder {
    account: RailgunAccount,
    inner: RefCell<OperationBuilder>,
}

#[wasm_bindgen]
impl JsTransactionBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(account: &JsRailgunAccount) -> JsTransactionBuilder {
        JsTransactionBuilder {
            account: account.inner.clone(),
            inner: RefCell::new(OperationBuilder::new()),
        }
    }

    /// Add a transfer operation.
    ///
    /// - `to`: Railgun address (0zk...)
    /// - `asset`: Asset ID (e.g., "erc20:0x...")
    /// - `amount`: Amount as decimal string
    /// - `memo`: Optional memo string
    pub fn transfer(
        &mut self,
        to: &str,
        asset: &str,
        amount: &str,
        memo: &str,
    ) -> Result<(), JsError> {
        let to: RailgunAddress = to
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid recipient address: {}", e)))?;

        let asset: AssetId = asset
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid asset ID: {}", e)))?;

        let amount: u128 = amount
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid amount: {}", e)))?;

        self.inner
            .borrow_mut()
            .transfer(self.account.clone(), to, asset, amount, memo);

        Ok(())
    }

    /// Add an unshield operation.
    ///
    /// - `to`: Ethereum address (0x...)
    /// - `asset`: Asset ID (e.g., "erc20:0x...")
    /// - `amount`: Amount as decimal string
    pub fn unshield(&mut self, to: &str, asset: &str, amount: &str) -> Result<(), JsError> {
        let to: Address = to
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid recipient address: {}", e)))?;

        let asset: AssetId = asset
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid asset ID: {}", e)))?;

        let amount: u128 = amount
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid amount: {}", e)))?;

        self.inner
            .borrow_mut()
            .set_unshield(self.account.clone(), to, asset, amount);

        Ok(())
    }

    /// Build the transaction using the provided indexer state and prover.
    /// Returns encoded calldata for RailgunSmartWallet.transact()
    pub async fn build(
        &mut self,
        indexer: &mut JsIndexer,
        prover: &JsProver,
    ) -> Result<JsTxData, JsError> {
        let chain = indexer.chain();
        let mut rng = rand::rng();

        let tx_data = self
            .inner
            .borrow_mut()
            .build_transaction(indexer.inner_mut(), prover, chain, &mut rng)
            .await
            .map_err(|e| JsError::new(&format!("Failed to build transaction: {}", e)))?;

        Ok(JsTxData { inner: tx_data })
    }

    /// Prepares a broadcastable transaction using the provided indexer, prover,
    /// and broadcaster.
    pub async fn prepare_broadcast(
        &mut self,
        indexer: &mut JsIndexer,
        prover: &JsProver,
        broadcaster: &mut JsBroadcaster,
        poi_client: &mut JsPoiClient,
        provider: &mut JsProvider,
        fee_info: &mut JsFeeInfo,
    ) -> Result<JsBroadcastData, JsError> {
        let chain = indexer.chain();
        let mut rng = rand::rng();

        let broadcast_data = self
            .inner
            .borrow_mut()
            .prepare_broadcast(
                indexer.inner_mut(),
                prover,
                poi_client.inner_mut(),
                provider.inner_mut(),
                fee_info.inner().clone(),
                chain,
                &mut rng,
            )
            .await
            .map_err(|e| JsError::new(&format!("Failed to broadcast transaction: {}", e)))?;

        Ok(JsBroadcastData::new(broadcast_data))
    }
}
