use std::sync::Arc;
use std::sync::Mutex;

use alloy::providers::Provider;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use light_poseidon::PoseidonError;

use crate::caip::AssetId;
use crate::chain_config::ChainConfig;
use crate::crypto::keys::derive_master_public_key;
use crate::crypto::keys::derive_viewing_public_key;
use crate::crypto::keys::fr_to_bytes_be;
use crate::indexer::account::IndexerAccount;
use crate::indexer::indexer::Indexer;
use crate::note::shield::ShieldRecipient;
use crate::note::shield::create_shield_transaction;
use crate::railgun::address::RailgunAddress;
use crate::tx_data::TxData;

pub struct RailgunAccount<P: Provider> {
    address: RailgunAddress,
    chain: ChainConfig,

    indexer: Arc<Mutex<Indexer<P>>>,

    master_public_key: [u8; 32],
    viewing_private_key: [u8; 32],
    spending_private_key: [u8; 32],
}

const SPENDING_DERIVATION_PATH: &str = "m/44'/1984'/0'/0'/";
const VIEWING_DERIVATION_PATH: &str = "m/420'/1984'/0'/0'/";

impl<P: Provider> RailgunAccount<P> {
    /// Creates a new Railgun Account and adds it to the indexer
    pub fn new(
        spending_private_key: [u8; 32],
        viewing_private_key: [u8; 32],
        indexer: Arc<Mutex<Indexer<P>>>,
    ) -> Self {
        let chain = indexer.lock().unwrap().chain();

        let master_public_key =
            derive_master_public_key(&spending_private_key, &viewing_private_key);
        let viewing_public_key = derive_viewing_public_key(&viewing_private_key);
        let address = RailgunAddress::new(
            &master_public_key
                .into_bigint()
                .to_bytes_be()
                .try_into()
                .unwrap(),
            &viewing_public_key,
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
            master_public_key: fr_to_bytes_be(&master_public_key),
            viewing_private_key,
            spending_private_key,
        }
    }

    pub fn address(&self) -> RailgunAddress {
        self.address
    }

    // TODO: Convert me into a ShieldBuilder factory to support multiple recipients / assets.
    pub fn shield(&self, asset: AssetId, amount: u128) -> Result<TxData, PoseidonError> {
        let recipient = ShieldRecipient::new(asset, self.address, amount);
        let tx = create_shield_transaction(&self.spending_private_key, self.chain, &[recipient])?;
        Ok(tx)
    }
}
