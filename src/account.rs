use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use alloy::primitives::Address;
use light_poseidon::PoseidonError;
use thiserror::Error;

use crate::caip::AccountId;
use crate::caip::AssetId;
use crate::chain_config::ChainConfig;
use crate::crypto::keys::SpendingKey;
use crate::crypto::keys::ViewingKey;
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

    viewing_key: ViewingKey,
    spending_key: SpendingKey,
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
        spending_key: SpendingKey,
        viewing_key: ViewingKey,
        indexer: Arc<Mutex<Indexer>>,
    ) -> Self {
        let chain = indexer.lock().unwrap().chain();

        let address = RailgunAddress::from_private_keys(spending_key, viewing_key, chain.id);

        indexer.lock().unwrap().add_account(IndexerAccount::new(
            address,
            spending_key,
            viewing_key,
        ));

        RailgunAccount {
            address,
            chain,
            indexer,
            spending_key,
            viewing_key,
        }
    }

    pub fn address(&self) -> RailgunAddress {
        self.address
    }

    pub fn balance(&self) -> HashMap<AssetId, u128> {
        self.indexer.lock().unwrap().balance(self.address)
    }

    // TODO: Convert me into a ShieldBuilder factory to support multiple recipients / assets.
    pub fn shield(&self, asset: AssetId, value: u128) -> Result<TxData, PoseidonError> {
        let recipient = ShieldRecipient::new(asset, self.address, value);
        let tx = create_shield_transaction(self.chain, &[recipient])?;
        Ok(tx)
    }

    // TODO: Convert me into a TransactionBuilder factory to support unshield / transfer actions.
    pub fn unshield(
        &self,
        asset: AssetId,
        value: u128,
        to_address: Address,
    ) -> Result<TxData, TransactError> {
        // TODO: Filter out used notes
        let mut indexer = self.indexer.lock().unwrap();
        let mut notebook = indexer
            .notebook(self.address)
            .ok_or(TransactError::InsufficientFunds(asset))?;

        let merkle_trees = indexer.merkle_trees();
        let tx = create_transaction(
            merkle_trees,
            0,
            self.chain,
            Address::ZERO,
            &[0u8; 32],
            self.spending_key,
            self.viewing_key,
            &mut notebook,
            asset,
            value,
            AccountId::Eip155(to_address),
        )
        .unwrap();
        Ok(tx)
    }
}
