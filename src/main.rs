use std::str::FromStr;

use alloy::{
    network::Ethereum,
    primitives::{Address, U256, address},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use ark_bn254::Fr;
use tracing::info;

use railgun_rs::{
    abis::erc20::ERC20,
    account::RailgunAccount,
    caip::AssetId,
    chain_config::{ChainConfig, SEPOLIA_CONFIG},
    circuit::native_prover::NativeProver,
    crypto::{
        keys::{HexKey, SpendingKey, ViewingKey, fr_to_bytes},
        poseidon::poseidon_hash,
    },
    indexer::{indexer::Indexer, subsquid_syncer::SubsquidSyncer},
    note::{note::Note, transact::create_txdata},
    poi::client::{BlindedCommitmentData, BlindedCommitmentType, PoiClient},
    railgun::address::RailgunAddress,
    transaction::{shield_builder::ShieldBuilder, tx_builder::TxBuilder},
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
    // let mut indexer = Indexer::new(provider.clone(), CHAIN);
    // indexer.sync_from_subsquid(Some(10213177)).await.unwrap();
    // let state = indexer.state();
    // std::fs::write(INDEXER_STATE, bitcode::serialize(&state).unwrap()).unwrap();
    let indexer_state = std::fs::read(INDEXER_STATE).unwrap();
    let indexer_state = bitcode::deserialize(&indexer_state).unwrap();
    let subsquid = Box::new(SubsquidSyncer::new(PPOI_URL));
    let mut indexer = Indexer::new_with_state(subsquid, indexer_state).unwrap();
    indexer.add_account(&account);

    info!("Syncing indexer");
    // indexer.sync().await.unwrap();
    info!("Balance: {:?}", indexer.balance(account.address()));

    info!("Saving indexer");
    let indexer_state = bitcode::serialize(&indexer.state()).unwrap();
    std::fs::write("./indexer_state_11155111.bincode", indexer_state).unwrap();

    let poi_client = PoiClient::new(PPOI_URL, CHAIN.id).await.unwrap();

    let mut notes: Vec<Note> = Vec::new();

    let notebooks = indexer.notebooks(account.address()).unwrap();
    for (tree_index, notebook) in notebooks {
        for (leaf_index, note) in notebook.unspent() {
            info!("Unspent note [{}, {}]: {:?}", tree_index, leaf_index, note);

            let commitment_hash = note.hash().into();
            let npk = note.note_public_key();
            let global_tree_position = Fr::from(tree_index * 65536 + leaf_index);
            let blinded_commitment = poseidon_hash(&[commitment_hash, npk, global_tree_position]);

            let pois = poi_client
                .pois(vec![BlindedCommitmentData {
                    blinded_commitment: fr_to_bytes(&blinded_commitment),
                    commitment_type: BlindedCommitmentType::Shield,
                }])
                .await
                .unwrap();

            let merkle_proofs = poi_client
                .merkle_proofs(vec![fr_to_bytes(&blinded_commitment)])
                .await
                .unwrap();

            info!("POIs: {:?}", pois);
            info!("Merkle Proofs: {:?}", merkle_proofs);

            notes.push(note.clone());
        }
    }

    let prover = Box::new(NativeProver::new());
    let merkle_trees = indexer.utxo_trees();

    // Creates a transaction builder for our desired set of operations.
    let tx = TxBuilder::new().set_unshield(address, USDC, 1_000);

    let builder_address = RailgunAddress::from_str("0zk1qyqhtwaa9zj3ug9dmxhfedappvm509w7dr5lgadaehxz38w9u457mrv7j6fe3z53layes62mktxj5kd6reh2kxd39ds2gnpf6wphtw39y5g36lsvukeywfqa8y0").unwrap();
    let builder_fee_asset = USDC;
    let builder_fee_per_gas = 1;

    // Build a new transaction group with the builder's fee
    let mut estimated_gas = 100;

    while true {
        let builder_fee = builder_fee_per_gas * (estimated_gas as u128);
        let mut builder_tx = TxBuilder::new().transfer(
            account.clone(),
            builder_address,
            builder_fee_asset,
            builder_fee,
            "",
        );

        for transfer in tx.transfers.iter() {
            builder_tx = builder_tx.transfer(
                transfer.from.clone(),
                transfer.to,
                transfer.asset,
                transfer.value,
                &transfer.memo,
            );
        }
        for unshield in tx.unshields.values() {
            builder_tx = builder_tx.set_unshield(unshield.to, unshield.asset, unshield.value);
        }

        let operations = builder_tx.build(notes.clone()).unwrap();
        let tx_data = create_txdata(
            prover.as_ref(),
            merkle_trees,
            0,
            CHAIN,
            Address::ZERO,
            &[0u8; 32],
            operations,
        )
        .unwrap();

        let new_estimated_gas = provider.estimate_gas(tx_data.into()).await.unwrap();
        if new_estimated_gas == estimated_gas {
            break;
        }

        estimated_gas = new_estimated_gas;
    }
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
