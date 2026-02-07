use std::str::FromStr;

use alloy::{
    network::Ethereum,
    primitives::{Address, address},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use rand::random;
use tracing::info;

use railgun_rs::{
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, MAINNET_CONFIG},
    indexer::indexer::Indexer,
    transaction::{shield_builder::ShieldBuilder, tx_builder::TxBuilder},
};

// Anvil test private key (0)
const TEST_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const FORK_BLOCK: u64 = 24_378_760;
const USDC_ADDRESS: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const USDC: AssetId = AssetId::Erc20(USDC_ADDRESS);
const CHAIN: ChainConfig = MAINNET_CONFIG;

const INDEXER_STATE: &[u8] = include_bytes!("../tests/fixtures/indexer_state.bincode");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt::init();

    let signer = PrivateKeySigner::from_str(TEST_PRIVATE_KEY).unwrap();
    let address = signer.address();

    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .wallet(signer)
        .connect("http://localhost:8545")
        .await
        .unwrap()
        .erased();

    let indexer_state = bitcode::deserialize(INDEXER_STATE).unwrap();
    let mut indexer = Indexer::new_with_state(provider.clone(), indexer_state).unwrap();

    info!("Shielding to Railgun account");
    let account_1 = RailgunAccount::new(random(), random(), CHAIN.id);
    let account_2 = RailgunAccount::new(random(), random(), CHAIN.id);

    indexer.add_account(&account_1);
    indexer.add_account(&account_2);

    info!("Shielding");
    let shield_tx = ShieldBuilder::new(CHAIN)
        .shield(account_1.address(), USDC, 1_000_000)
        .build()
        .unwrap();
    provider
        .send_transaction(shield_tx.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    indexer.sync().await.unwrap();
    let balance_1 = indexer.balance(account_1.address());
    let balance_2 = indexer.balance(account_2.address());
}
