use alloy::{providers::Provider, rpc::types::TransactionRequest};
use num_traits::ToPrimitive;

use crate::railgun::transaction::tx_data::TxData;

#[async_trait::async_trait]
pub trait GasEstimator {
    async fn estimate_gas(&self, tx_data: &TxData) -> Result<u128, Box<dyn std::error::Error>>;
    async fn gas_price_wei(&self) -> Result<u128, Box<dyn std::error::Error>>;
}

#[async_trait::async_trait]
impl<T: Provider> GasEstimator for T {
    async fn estimate_gas(&self, tx_data: &TxData) -> Result<u128, Box<dyn std::error::Error>> {
        let request: TransactionRequest = tx_data.clone().into();
        let gas_estimate = self.estimate_gas(request).await?;
        Ok(gas_estimate as u128)
    }

    async fn gas_price_wei(&self) -> Result<u128, Box<dyn std::error::Error>> {
        let gas_price = self.get_gas_price().await?;
        Ok(gas_price)
    }
}
