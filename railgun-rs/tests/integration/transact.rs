use std::str::FromStr;

use alloy::{
    network::Ethereum,
    primitives::{Address, address},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use railgun_rs::{
    abis::erc20::ERC20,
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, MAINNET_CONFIG},
    circuit::native::Groth16Prover,
    railgun::indexer::{indexer::Indexer, rpc_syncer::RpcSyncer},
    railgun::transaction::{operation_builder::OperationBuilder, shield_builder::ShieldBuilder},
};
use rand::random;
use tracing::info;
use tracing_subscriber::EnvFilter;

const USDC_ADDRESS: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const USDC: AssetId = AssetId::Erc20(USDC_ADDRESS);
const CHAIN: ChainConfig = MAINNET_CONFIG;

const INDEXER_STATE: &[u8] = include_bytes!("../fixtures/indexer_state.bincode");

#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_transact() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init()
        .ok();

    info!("Setting up prover");
    let prover = Groth16Prover::new_native("./artifacts");

    // Setup provider, indexer, and accounts
    info!("Setting up provider");
    let signer = PrivateKeySigner::from_str(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )
    .unwrap();
    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .wallet(signer)
        .connect("http://localhost:8545")
        .await
        .unwrap()
        .erased();

    let usdc_contract = ERC20::new(USDC_ADDRESS, provider.clone());

    info!("Setting up indexer");
    let rpc_syncer = Box::new(RpcSyncer::new(provider.clone(), CHAIN));
    let indexer_state = bitcode::deserialize(INDEXER_STATE).unwrap();
    let mut indexer = Indexer::from_state(rpc_syncer, indexer_state).unwrap();

    info!("Setting up accounts");
    let account_1 = RailgunAccount::new(random(), random(), CHAIN.id);
    let account_2 = RailgunAccount::new(random(), random(), CHAIN.id);
    indexer.add_account(&account_1);
    indexer.add_account(&account_2);

    // Test Shielding
    info!("Testing shielding");
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

    assert_eq!(balance_1.get(&USDC), Some(&997_500));
    assert_eq!(balance_2.get(&USDC), None);

    // Test Transfer
    info!("Testing transfer");
    let mut builder = OperationBuilder::new();
    builder.transfer(
        account_1.clone(),
        account_2.address(),
        USDC,
        5_000,
        "test transfer",
    );
    let transfer_tx = builder
        .build(&mut indexer, &prover, CHAIN, &mut rand::rng())
        .await
        .unwrap();

    provider
        .send_transaction(transfer_tx.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    indexer.sync().await.unwrap();
    let balance_1 = indexer.balance(account_1.address());
    let balance_2 = indexer.balance(account_2.address());

    assert_eq!(balance_1.get(&USDC), Some(&992500));
    assert_eq!(balance_2.get(&USDC), Some(&5000));

    // Test Unshielding
    info!("Testing unshielding");
    let mut builder = OperationBuilder::new();
    builder.set_unshield(
        account_1.clone(),
        address!("0xe03747a83E600c3ab6C2e16dd1989C9b419D3a86"),
        USDC,
        1_000,
    );
    let unshield_tx = builder
        .build(&mut indexer, &prover, CHAIN, &mut rand::rng())
        .await
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
    let balance_eoa = usdc_contract
        .balanceOf(address!("0xe03747a83E600c3ab6C2e16dd1989C9b419D3a86"))
        .call()
        .await
        .unwrap();

    assert_eq!(balance_1.get(&USDC), Some(&991500));
    assert_eq!(balance_2.get(&USDC), Some(&5000));
    assert_eq!(balance_eoa, 998);
}
