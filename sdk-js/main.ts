import { createPublicClient, createWalletClient, http } from "viem";
import { createProverFunctions } from "./src/prover";
import { initWasm } from "./src/wasm";
import { mainnet } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

const hexKey = (fill: number): string => "0x" + fill.toString(16).padStart(2, "0").repeat(32);

const USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const CHAIN_ID = 11155111n;
const ARTIFACTS_PATH = "../railgun-rs/artifacts";
const INDEXER_STATE_PATH = "../railgun-rs/tests/fixtures/indexer_state.bincode";

const RPC_URL = Bun.env.FORK_URL_SEPOLIA as string;
const SPENDING_KEY = Bun.env.DEV_SPENDING_KEY as string;
const VIEWING_KEY = Bun.env.DEV_VIEWING_KEY as string;

async function main() {
    console.log("Initializing WASM");
    const wasm = await initWasm();
    const USDC = wasm.erc20_asset(USDC_ADDRESS);

    console.log("Setup")
    const indexerState = await Bun.file(INDEXER_STATE_PATH).bytes();
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
    console.log("Spending key:", SPENDING_KEY);
    console.log("Viewing key:", VIEWING_KEY);
    const account2 = new wasm.JsRailgunAccount(hexKey(3), hexKey(4), CHAIN_ID);

    indexer.add_account(account1);
    indexer.add_account(account2);

    console.log("Creating transfer transaction");
    const builder = new wasm.JsTransactionBuilder(account1);
    builder.transfer(
        account2.address,
        wasm.erc20_asset("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        "100",
        ""
    );

    console.log("Preparing transaction for broadcast");
    const prepared = await builder.prepare_broadcast(indexer, prover, poi_client, provider, new wasm.JsFeeInfo(
        account1,
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        100,
        account2.address,
        "0",
        ["efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88", "55049dc47b4435bca4a8f8ac27b1858e409f9f72b317fde4a442095cfc454893"]
    ));
}

await main();