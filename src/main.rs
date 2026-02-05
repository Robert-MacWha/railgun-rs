use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

mod abis;
mod account;
mod caip;
mod chain_config;
mod circuit;
mod crypto;
mod indexer;
mod merkle_tree;
mod note;
mod railgun;
mod tx_data;

use alloy::{
    network::Ethereum,
    primitives::{Address, U256, address},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use tracing::info;

use crate::{
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, MAINNET_CONFIG},
    crypto::keys::{ByteKey, SpendingKey, ViewingKey},
    indexer::indexer::Indexer,
};

// Anvil test private key (0)
const TEST_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const USDC_ADDRESS: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const INDEXER_STATE_PATH: &str = "indexer_state.json";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let spending_private_key = SpendingKey::from_bytes([1u8; 32]);
    let viewing_private_key = ViewingKey::from_bytes([2u8; 32]);

    let latest = 24378760;
    let asset = AssetId::Erc20(USDC_ADDRESS);
    let amount = 100 * 10u128.pow(6); // 100 USDC
    let chain = MAINNET_CONFIG;

    let signer = PrivateKeySigner::from_str(TEST_PRIVATE_KEY).unwrap();
    let address = signer.address();

    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .wallet(signer)
        .connect("http://localhost:8545")
        .await
        .unwrap()
        .erased();

    // sync_indexer(provider, chain, latest).await;
    let indexer = load_indexer_from_state(provider.clone()).await;

    let account = RailgunAccount::new(spending_private_key, viewing_private_key, indexer.clone());
    shield(provider.clone(), &account, asset.clone(), amount).await;

    indexer.lock().unwrap().sync().await.unwrap();
    let balance = account.balance();
    info!("Account Balance: {:?}", balance);

    info!("Unshielding {} of asset {:?}", amount / 2, asset);
    let unshield_tx = account
        .unshield(asset.clone(), amount / 2, address)
        .unwrap();
    let tx = TransactionRequest::default()
        .to(unshield_tx.to)
        .value(unshield_tx.value)
        .input(unshield_tx.data.into());
    provider
        .send_transaction(tx)
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    info!("Unshielded {} of asset {:?}", amount / 2, asset);

    indexer.lock().unwrap().sync().await.unwrap();
    let balance = account.balance();
    info!("Account Balance: {:?}", balance);
}

/// Sync the indexer up to a specific block, saving the state.
async fn sync_indexer(provider: DynProvider, chain: ChainConfig, to_block: u64) {
    info!("Syncing indexer up to block {}", to_block);

    let mut indexer = Indexer::new(provider, chain);
    indexer.sync_from_subsquid(Some(to_block)).await.unwrap();
    indexer.validate().await.unwrap();

    let state = indexer.state();
    let state_json = serde_json::to_string_pretty(&state).unwrap();
    std::fs::write(INDEXER_STATE_PATH, state_json).unwrap();
}

async fn load_indexer_from_state(provider: DynProvider) -> Arc<Mutex<Indexer>> {
    info!("Loading indexer state from {}", INDEXER_STATE_PATH);

    let state_json = std::fs::read_to_string(INDEXER_STATE_PATH).unwrap();
    let state: indexer::indexer::IndexerState = serde_json::from_str(&state_json).unwrap();
    let mut indexer = Indexer::new_with_state(provider, state).unwrap();
    indexer.validate().await.unwrap();
    Arc::new(Mutex::new(indexer))
}

/// Approves and shields a specified asset and amount
async fn shield(provider: DynProvider, account: &RailgunAccount, asset: AssetId, amount: u128) {
    info!("Shielding {} of asset {:?}", amount, asset);

    // Approve
    let erc20_instance = abis::erc20::ERC20::new(
        match asset {
            AssetId::Erc20(addr) => addr,
            _ => panic!("Unsupported asset for shielding"),
        },
        provider.clone(),
    );
    erc20_instance
        .approve(MAINNET_CONFIG.railgun_smart_wallet, U256::from(amount))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Shield
    let shield_tx = account.shield(asset, amount).unwrap();
    let tx = TransactionRequest::default()
        .to(shield_tx.to)
        .value(shield_tx.value)
        .input(shield_tx.data.into());
    provider
        .send_transaction(tx)
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}
