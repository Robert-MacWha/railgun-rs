#![cfg(not(feature = "wasm"))]

use std::{collections::BTreeMap, str::FromStr};

use alloy::{
    network::Ethereum,
    primitives::{Address, U256, address},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use rand::random;
use tracing::info;

use railgun_rs::{
    abis::{
        erc20::ERC20,
        railgun::{BoundParams, CommitmentCiphertext, UnshieldType},
    },
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, SEPOLIA_CONFIG},
    circuit::{
        groth16_prover::Groth16Prover,
        native::{FsArtifactLoader, WasmerWitnessCalculator},
        poi_inputs::PoiCircuitInputs,
        prover::PoiProver,
    },
    crypto::keys::{HexKey, SpendingKey, ViewingKey},
    indexer::{indexer::Indexer, subsquid_syncer::SubsquidSyncer},
    merkle_trees::merkle_tree::TxidMerkleTree,
    poi::{client::PoiClient, poi_note::PoiNote},
    railgun::address::RailgunAddress,
    transaction::{operation_builder::OperationBuilder, shield_builder::ShieldBuilder},
};

const CHAIN: ChainConfig = SEPOLIA_CONFIG;
const USDC_ADDRESS: Address = address!("0x1c7d4b196cb0c7b01d743fbc6116a902379c7238");
const USDC: AssetId = AssetId::Erc20(USDC_ADDRESS);

const PPOI_URL: &str = "https://ppoi-agg.horsewithsixlegs.xyz/";
const INDEXER_STATE: &str = "./indexer_state_11155111.bincode";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let signer_key = std::env::var("DEV_KEY").expect("DEV_KEY must be set");
    let rpc_url = std::env::var("FORK_URL_SEPOLIA").expect("FORK_URL_SEPOLIA must be set");
    let spending_key = std::env::var("DEV_SPENDING_KEY").expect("DEV_SPENDING_KEY must be set");
    let viewing_key = std::env::var("DEV_VIEWING_KEY").expect("DEV_VIEWING_KEY must be set");

    let signer = PrivateKeySigner::from_str(&signer_key).unwrap();
    let address = signer.address();
    info!("Using EOA: {:?}", address);

    let provider = ProviderBuilder::new()
        .network::<Ethereum>()
        .wallet(signer)
        .connect(&rpc_url)
        .await
        .unwrap()
        .erased();
    let usdc_contract = ERC20::new(USDC_ADDRESS, provider.clone());

    let spending_key = SpendingKey::from_hex(&spending_key).unwrap();
    let viewing_key = ViewingKey::from_hex(&viewing_key).unwrap();
    let account = RailgunAccount::new(spending_key, viewing_key, CHAIN.id);

    info!("Creating indexer");
    let subsquid = Box::new(SubsquidSyncer::new(CHAIN.subsquid_endpoint.unwrap()));
    // let mut indexer = Indexer::new(subsquid, CHAIN);
    let indexer_state = bitcode::deserialize(&std::fs::read(INDEXER_STATE).unwrap()).unwrap();
    let mut indexer = Indexer::from_state(subsquid, indexer_state).unwrap();
    indexer.add_account(&account);

    info!("Syncing indexer");
    indexer.sync_to(10217000).await.unwrap();

    // info!("Saving indexer");
    let indexer_state = bitcode::serialize(&indexer.state()).unwrap();
    std::fs::write("./indexer_state_11155111.bincode", indexer_state).unwrap();

    info!("Balance: {:?}", indexer.balance(account.address()));
    let poi_client = PoiClient::new(PPOI_URL, CHAIN.id).await.unwrap();
    verify_trees(&mut indexer.txid_trees, &poi_client).await;

    info!("Creating POI notes");
    let notes = indexer.unspent(account.address()).unwrap();
    let notes = PoiNote::from_utxo_notes(notes, &poi_client).await.unwrap();

    let to_address = RailgunAddress::from_private_keys(random(), random(), CHAIN.id);
    info!("Creating operation");
    let mut builder = OperationBuilder::new();
    builder.transfer(account.clone(), to_address, USDC, 1_000, "");
    let operations = builder.build(notes.clone()).unwrap();
    let operation = &operations[0];

    let commitment_ciphertexts: Vec<CommitmentCiphertext> = operation
        .out_encryptable_notes()
        .iter()
        .map(|n| n.encrypt(&mut rand::rng()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let bound_params = BoundParams::new(
        2,
        0,
        UnshieldType::NONE,
        CHAIN.id,
        Address::ZERO,
        &[0u8; 32],
        commitment_ciphertexts,
    );
    let bound_params_hash = bound_params.hash();

    info!("Creating POI inputs");
    let prover = Groth16Prover::new(
        WasmerWitnessCalculator::new("./artifacts"),
        FsArtifactLoader::new("./artifacts"),
    );
    let list_keys = poi_client.list_keys();
    for key in list_keys {
        let mut utxo_merkle_tree = indexer
            .utxo_trees
            .get_mut(&operation.utxo_tree_number())
            .unwrap();

        let poi_circuit_inputs = PoiCircuitInputs::from_inputs(
            account.spending_key().public_key(),
            account.viewing_key().nullifying_key(),
            &mut utxo_merkle_tree,
            bound_params_hash,
            operation,
            key.clone(),
        )
        .unwrap();

        let proof = prover.prove_poi(&poi_circuit_inputs).await.unwrap();
    }

    // // Creates a transaction builder for our desired set of operations.
    // let tx = TxBuilder::new().set_unshield(address, USDC, 1_000);

    // // Build a new transaction group with the builder's fee
    // let mut estimated_gas = 100;

    // loop {
    //     let builder_fee = builder_fee_per_gas * (estimated_gas as u128);
    //     let mut builder_tx = TxBuilder::new().transfer(
    //         account.clone(),
    //         builder_address,
    //         builder_fee_asset,
    //         builder_fee,
    //         "",
    //     );

    //     for transfer in tx.transfers.iter() {
    //         builder_tx = builder_tx.transfer(
    //             transfer.from.clone(),
    //             transfer.to,
    //             transfer.asset,
    //             transfer.value,
    //             &transfer.memo,
    //         );
    //     }
    //     for unshield in tx.unshields.values() {
    //         builder_tx = builder_tx.set_unshield(unshield.to, unshield.asset, unshield.value);
    //     }

    //     let operations = builder_tx.build(notes.clone()).unwrap();
    //     let tx_data = create_txdata(
    //         prover.as_ref(),
    //         merkle_trees,
    //         0,
    //         CHAIN,
    //         Address::ZERO,
    //         &[0u8; 32],
    //         operations,
    //     )
    //     .unwrap();

    //     let new_estimated_gas = provider.estimate_gas(tx_data.into()).await.unwrap();
    //     if new_estimated_gas == estimated_gas {
    //         break;
    //     }

    //     estimated_gas = new_estimated_gas;
    // }
}

async fn shield_usdc(provider: DynProvider, to: RailgunAddress, amount: u128) {
    info!("Approving USDC");
    let usdc_contract = ERC20::new(USDC_ADDRESS, provider.clone());
    usdc_contract
        .approve(CHAIN.railgun_smart_wallet, U256::from(amount))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    info!("Shielding");
    let shield_tx = ShieldBuilder::new(CHAIN)
        .shield(to, USDC, amount)
        .build()
        .unwrap();
    provider
        .send_transaction(shield_tx.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    info!("Shielded");
}

async fn verify_trees(trees: &mut BTreeMap<u32, TxidMerkleTree>, poi_client: &PoiClient) {
    info!("Verifying TXID trees: {}", trees.len());
    for (tree_number, tree) in trees.iter_mut() {
        let root = tree.root();
        let leaves = tree.leaves_len();
        info!(
            "Tree number: {}, leaves: {}, tree root: {:?}",
            tree_number, leaves, root
        );

        let valid = poi_client
            .validate_txid_merkleroot(*tree_number, leaves as u64 - 1, root.into())
            .await
            .unwrap();
        assert!(valid, "Tree number {} failed validation", tree_number);
        info!("TXID tree {} is valid", tree_number);
    }
}
