use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use alloy::primitives::Address;
use light_poseidon::PoseidonError;
use thiserror::Error;

use crate::caip::AssetId;
use crate::chain_config::ChainConfig;
use crate::indexer::account::IndexerAccount;
use crate::indexer::indexer::Indexer;
use crate::note::shield::ShieldRecipient;
use crate::note::shield::create_shield_transaction;
use crate::note::transact::create_transaction;
use crate::railgun::address::RailgunAddress;
use crate::tx_data::TxData;

pub struct RailgunAccount {
    address: RailgunAddress,
    chain: ChainConfig,

    indexer: Arc<Mutex<Indexer>>,

    viewing_private_key: [u8; 32],
    spending_private_key: [u8; 32],
}

const SPENDING_DERIVATION_PATH: &str = "m/44'/1984'/0'/0'/";
const VIEWING_DERIVATION_PATH: &str = "m/420'/1984'/0'/0'/";

#[derive(Debug, Error)]
pub enum TransactError {
    #[error("Insufficient funds for asset: {0:?}")]
    InsufficientFunds(AssetId),
}

impl RailgunAccount {
    /// Creates a new Railgun Account and adds it to the indexer
    pub fn new(
        spending_private_key: [u8; 32],
        viewing_private_key: [u8; 32],
        indexer: Arc<Mutex<Indexer>>,
    ) -> Self {
        let chain = indexer.lock().unwrap().chain();

        let address = RailgunAddress::from_private_keys(
            &spending_private_key,
            &viewing_private_key,
            chain.id,
        );

        indexer.lock().unwrap().add_account(IndexerAccount::new(
            address,
            viewing_private_key,
            spending_private_key,
        ));

        RailgunAccount {
            address,
            chain,
            indexer,
            viewing_private_key,
            spending_private_key,
        }
    }

    pub fn address(&self) -> RailgunAddress {
        self.address
    }

    pub fn balance(&self) -> HashMap<AssetId, u128> {
        self.indexer.lock().unwrap().balance(self.address)
    }

    // TODO: Convert me into a ShieldBuilder factory to support multiple recipients / assets.
    pub fn shield(&self, asset: AssetId, amount: u128) -> Result<TxData, PoseidonError> {
        let recipient = ShieldRecipient::new(asset, self.address, amount);
        let tx = create_shield_transaction(&self.spending_private_key, self.chain, &[recipient])?;
        Ok(tx)
    }

    // TODO: Convert me into a TransactionBuilder factory to support unshield / transfer actions.
    pub fn unshield(
        &self,
        asset: AssetId,
        amount: u128,
        to_address: Address,
    ) -> Result<TxData, TransactError> {
        // TODO: Filter out used notes
        let notes = self.indexer.lock().unwrap().notes(self.address);
        let tx = create_transaction(
            notes,
            &self.address(),
            &self.viewing_private_key,
            &self.spending_private_key,
            asset,
            amount,
            crate::caip::AccountId::Eip155(to_address),
        )
        .unwrap();
        Ok(tx)
    }
}
