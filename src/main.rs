use std::str::FromStr;

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
mod transaction;

use alloy::{
    network::Ethereum,
    primitives::{Address, U256, address},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use tracing::info;

use crate::{
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, MAINNET_CONFIG},
    crypto::keys::{ByteKey, SpendingKey, ViewingKey},
    indexer::indexer::{Indexer, IndexerState},
    transaction::{shield_builder::ShieldBuilder, tx_builder::TxBuilder},
};

// Anvil test private key (0)
const TEST_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const USDC_ADDRESS: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const INDEXER_STATE_PATH: &str = "indexer_state.bincode";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt::init();

    let spending_private_key = SpendingKey::from_bytes([1u8; 32]);
    let viewing_private_key = ViewingKey::from_bytes([2u8; 32]);

    let latest = 24378760;
    // let latest = 24178760;
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

    // sync_indexer(provider.clone(), chain, latest).await;
    let mut indexer = load_indexer_from_state(provider.clone()).await;

    info!("Shielding to Railgun account");
    let account_1 = RailgunAccount::new(spending_private_key, viewing_private_key, chain.id);
    let account_2 = RailgunAccount::new(
        SpendingKey::from_bytes([3u8; 32]),
        ViewingKey::from_bytes([4u8; 32]),
        chain.id,
    );

    indexer.add_account(account_1.clone());
    indexer.add_account(account_2.clone());
    shield(provider.clone(), &indexer, &account_1, asset, amount).await;

    indexer.sync().await.unwrap();
    let balance_1 = indexer.balance(account_1.address());
    let balance_2 = indexer.balance(account_2.address());
    info!("Railgun account 1 balance: {:?}", balance_1);
    info!("Railgun account 2 balance: {:?}", balance_2);

    info!("Sending transaction");
    let tx = TxBuilder::new(&mut indexer)
        .transfer(&account_1, account_2.address(), asset, 1000, "test memo")
        .unwrap()
        .build()
        .unwrap();
    provider
        .send_transaction(tx.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    indexer.sync().await.unwrap();
    let balance_1 = indexer.balance(account_1.address());
    let balance_2 = indexer.balance(account_2.address());

    info!("Railgun account 1 balance: {:?}", balance_1);
    info!("Railgun account 2 balance: {:?}", balance_2);

    info!("Unshielding from Railgun account");
    let unshield_tx = TxBuilder::new(&mut indexer)
        .set_unshield(&account_2, address, asset, 500)
        .unwrap()
        .build()
        .unwrap();
    provider
        .send_transaction(unshield_tx.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    indexer.sync().await.unwrap();
    let balance_1 = indexer.balance(account_1.address());
    let balance_2 = indexer.balance(account_2.address());
    info!("Railgun account 1 balance: {:?}", balance_1);
    info!("Railgun account 2 balance: {:?}", balance_2);
}

// /// Sync the indexer up to a specific block, saving the state.
// async fn sync_indexer(provider: DynProvider, chain: ChainConfig, to_block: u64) {
//     info!("Syncing indexer up to block {}", to_block);

//     let mut indexer = Indexer::new(provider, chain);
//     indexer.sync_from_subsquid(Some(to_block)).await.unwrap();
//     indexer.validate().await.unwrap();

//     let state = indexer.state();
//     let state_serde = bitcode::serialize(&state).unwrap();
//     std::fs::write(INDEXER_STATE_PATH, state_serde).unwrap();
// }

async fn load_indexer_from_state(provider: DynProvider) -> Indexer {
    info!("Loading indexer state from {}", INDEXER_STATE_PATH);

    let state_serde = std::fs::read(INDEXER_STATE_PATH).unwrap();
    let state: IndexerState = bitcode::deserialize(&state_serde).unwrap();
    let mut indexer = Indexer::new_with_state(provider, state).unwrap();
    indexer.validate().await.unwrap();
    indexer
}

/// Approves and shields a specified asset and amount
async fn shield(
    provider: DynProvider,
    indexer: &Indexer,
    account: &RailgunAccount,
    asset: AssetId,
    amount: u128,
) {
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

    let shield_tx = ShieldBuilder::new(indexer.chain())
        .shield(account.address(), asset, amount / 2)
        .build()
        .unwrap();
    provider
        .send_transaction(shield_tx.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}
