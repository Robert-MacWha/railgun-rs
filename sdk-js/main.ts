import { readFile } from "node:fs/promises";
import { createPublicClient, createWalletClient, http } from "viem";
import { createProverFunctions } from "./src/prover";
import { initWasm } from "./src/wasm";
import { mainnet } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { createBroadcaster, createBroadcasterFromNode } from "./src/waku-transport";
import { Broadcasters } from "./src/_broadcaster";

const hexKey = (fill: number): string => "0x" + fill.toString(16).padStart(2, "0").repeat(32);

const USDC_ADDRESS = "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238";
const WETH_ADDRESS = "0xfff9976782d46cc05630d1f6ebab18b2324d6b14";
const CHAIN_ID = 11155111n;
const ARTIFACTS_PATH = "../railgun-rs/artifacts";
const INDEXER_STATE_PATH = "../railgun-rs/indexer_state_11155111.bincode";

const RPC_URL = process.env.FORK_URL_SEPOLIA as string;
const SPENDING_KEY = process.env.DEV_SPENDING_KEY as string;
const VIEWING_KEY = process.env.DEV_VIEWING_KEY as string;

async function main() {
    console.log("Initializing WASM");
    const wasm = await initWasm();

    const broadcast_manager = await createBroadcaster(CHAIN_ID);
    broadcast_manager.start();

    let broadcaster = undefined;
    while (!broadcaster) {
        await new Promise((resolve) => setTimeout(resolve, 1000));

        const unix_time = Math.floor(Date.now() / 1000);
        broadcaster = await broadcast_manager.best_broadcaster_for_token(WETH_ADDRESS, BigInt(unix_time));
    }

    console.log("Best broadcaster for WETH:", broadcaster);

    const USDC = wasm.erc20_asset(USDC_ADDRESS);
    const WETH = wasm.erc20_asset(WETH_ADDRESS);

    console.log("Setup")
    const indexerState = new Uint8Array(await readFile(INDEXER_STATE_PATH));
    const syncer = await wasm.JsSyncer.withRpc(
        RPC_URL,
        CHAIN_ID
    );
    const indexer = await wasm.JsIndexer.from_state(syncer, indexerState);

    const { proveTransact, provePoi } = createProverFunctions({
        artifactsPath: ARTIFACTS_PATH,
    });
    const prover = new wasm.JsProver(proveTransact, provePoi);
    const poi_client = await wasm.JsPoiClient.new(CHAIN_ID);
    const provider = await wasm.JsProvider.with_url(RPC_URL);

    const account1 = new wasm.JsRailgunAccount(SPENDING_KEY, VIEWING_KEY, CHAIN_ID);
    console.log("Account 1 address:", account1.address);
    const account2 = new wasm.JsRailgunAccount(hexKey(3), hexKey(4), CHAIN_ID);

    indexer.add_account(account1);
    indexer.add_account(account2);

    console.log("Balance");
    let balance = await indexer.balance(account1.address);
    console.log("USDC: ", balance.get(USDC));
    console.log("WETH: ", balance.get(WETH));

    console.log("Creating transfer transaction");
    const builder = new wasm.JsTransactionBuilder();
    builder.transfer(
        account1,
        account2.address,
        USDC,
        "100",
        ""
    );

    console.log("Preparing transaction for broadcast");
    const prepared = await builder.prepare_broadcast(indexer, prover, poi_client, provider, account1, broadcaster.fee());

    console.log("Prepared transaction");
}

await main();
