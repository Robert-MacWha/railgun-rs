// Integration test mirroring railgun-rs/tests/integration/transact.rs
import { expect, test } from "bun:test";
import {
  checksumAddress,
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { mainnet } from "viem/chains";
import {
  initWasm,
  createProverFunctions,
} from "../src/mod.ts";

// Test constants (matching transact.rs)
const USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const CHAIN_ID = 1n; // mainnet

// Anvil default private key
const TEST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// Path to circuit artifacts
const ARTIFACTS_PATH = "../railgun-rs/artifacts";

// Path to pre-synced indexer state (same fixture as Rust test)
const INDEXER_STATE_PATH = "../railgun-rs/tests/fixtures/indexer_state.bincode";

// ERC20 ABI for balance checks
const erc20Abi = parseAbi([
  "function balanceOf(address) view returns (uint256)",
]);

interface BalanceMap {
  [assetId: string]: bigint;
}

test("transact: shield, transfer, and unshield", async () => {
  // Initialize WASM module
  const wasm = await initWasm();
  const USDC = wasm.erc20_asset(USDC_ADDRESS);

  // Setup prover with snarkjs
  console.log("Setting up prover");
  const { proveTransact, provePoi } = createProverFunctions({
    artifactsPath: ARTIFACTS_PATH,
  });
  const prover = new wasm.JsProver(proveTransact, provePoi);

  // Setup viem clients
  console.log("Setting up provider");
  const account = privateKeyToAccount(TEST_PRIVATE_KEY);

  const publicClient = createPublicClient({
    chain: mainnet,
    transport: http("http://localhost:8545"),
  });

  const walletClient = createWalletClient({
    account,
    chain: mainnet,
    transport: http("http://localhost:8545"),
  });

  // Load indexer state
  console.log("Setting up indexer");
  const indexerState = await Bun.file(INDEXER_STATE_PATH).bytes();
  const syncer = await wasm.JsSyncer.withRpc(
    "http://localhost:8545",
    1n
  );
  const indexer = await wasm.JsIndexer.from_state(syncer, indexerState);

  // Create accounts with random keys
  console.log("Setting up accounts");
  const spendingKey1 = new Uint8Array(32).fill(1);
  const viewingKey1 = new Uint8Array(32).fill(2);
  const account1 = new wasm.JsRailgunAccount(spendingKey1, viewingKey1, CHAIN_ID);

  const spendingKey2 = new Uint8Array(32).fill(3);
  const viewingKey2 = new Uint8Array(32).fill(4);
  const account2 = new wasm.JsRailgunAccount(spendingKey2, viewingKey2, CHAIN_ID);

  indexer.add_account(account1);
  indexer.add_account(account2);

  // Test Shielding
  console.log("Testing shielding");
  const shieldBuilder = new wasm.JsShieldBuilder(CHAIN_ID);
  shieldBuilder.shield(account1.address, USDC, "1000000");
  const shieldTx = shieldBuilder.build();

  const shieldHash = await walletClient.sendTransaction({
    to: shieldTx.to as `0x${string}`,
    data: shieldTx.toHex() as `0x${string}`,
    value: BigInt(shieldTx.value),
  });
  await publicClient.waitForTransactionReceipt({ hash: shieldHash });

  await indexer.sync();
  const balance1AfterShield = indexer.balance(account1.address) as BalanceMap;
  const balance2AfterShield = indexer.balance(account2.address) as BalanceMap;

  // 0.25% shield fee: 1_000_000 * 0.9975 = 997_500
  expect(balance1AfterShield[USDC]).toBe(997500n);
  expect(balance2AfterShield[USDC]).toBeUndefined();

  // Test Transfer
  console.log("Testing transfer");
  const transferBuilder = new wasm.JsTransactionBuilder(account1);
  transferBuilder.transfer(account2.address, USDC, "5000", "test transfer");
  const transferTx = await transferBuilder.build(indexer, prover);

  const transferHash = await walletClient.sendTransaction({
    to: transferTx.to as `0x${string}`,
    data: transferTx.toHex() as `0x${string}`,
    value: BigInt(transferTx.value),
  });
  await publicClient.waitForTransactionReceipt({ hash: transferHash });

  await indexer.sync();
  const balance1AfterTransfer = indexer.balance(account1.address) as BalanceMap;
  const balance2AfterTransfer = indexer.balance(account2.address) as BalanceMap;

  expect(balance1AfterTransfer[USDC]).toBe(992500n);
  expect(balance2AfterTransfer[USDC]).toBe(5000n);

  // Test Unshielding
  console.log("Testing unshielding");
  const unshieldRecipient = checksumAddress("0xe03747a83E600c3ab6C2e16dd1989C9b419D3a86");
  const unshieldBuilder = new wasm.JsTransactionBuilder(account1);
  unshieldBuilder.unshield(unshieldRecipient, USDC, "1000");
  const unshieldTx = await unshieldBuilder.build(indexer, prover);

  const unshieldHash = await walletClient.sendTransaction({
    to: unshieldTx.to as `0x${string}`,
    data: unshieldTx.toHex() as `0x${string}`,
    value: BigInt(unshieldTx.value),
  });
  await publicClient.waitForTransactionReceipt({ hash: unshieldHash });

  await indexer.sync();
  const balance1Final = indexer.balance(account1.address) as BalanceMap;
  const balance2Final = indexer.balance(account2.address) as BalanceMap;

  expect(balance1Final[USDC]).toBe(991500n);
  expect(balance2Final[USDC]).toBe(5000n);

  // Check EOA balance (0.2% unshield fee: 1000 * 0.998 = 998)
  const eoaBalance = await publicClient.readContract({
    address: USDC_ADDRESS as `0x${string}`,
    abi: erc20Abi,
    functionName: "balanceOf",
    args: [unshieldRecipient as `0x${string}`],
  });
  expect(eoaBalance).toBe(998n);

  // Cleanup
  shieldBuilder.free();
  transferBuilder.free();
  unshieldBuilder.free();
  prover.free();
  indexer.free();
  account1.free();
  account2.free();

  console.log("All tests passed!");
}, 60000);

// Simpler unit test that doesn't require anvil
test("wasm: account creation", async () => {
  const wasm = await initWasm();

  const spendingKey = new Uint8Array(32).fill(1);
  const viewingKey = new Uint8Array(32).fill(2);
  const account = new wasm.JsRailgunAccount(spendingKey, viewingKey, 1n);

  // Address should start with "0zk"
  const address = account.address;
  expect(address.startsWith("0zk")).toBe(true);

  account.free();
});

test("wasm: chain config", async () => {
  const wasm = await initWasm();

  const mainnetConfig = wasm.get_chain_config(1n);
  expect(mainnetConfig?.id).toBe(1n);
  expect(mainnetConfig?.railgunWallet.startsWith("0x")).toBe(true);
  expect(mainnetConfig?.subsquidEndpoint !== undefined).toBe(true);

  const sepolia = wasm.get_chain_config(11155111n);
  expect(sepolia?.id).toBe(11155111n);

  const unknown = wasm.get_chain_config(999n);
  expect(unknown).toBeUndefined();
});

test("wasm: shield builder", async () => {
  const wasm = await initWasm();
  const usdc = wasm.erc20_asset(USDC_ADDRESS);

  const spendingKey = new Uint8Array(32).fill(1);
  const viewingKey = new Uint8Array(32).fill(2);
  const account = new wasm.JsRailgunAccount(spendingKey, viewingKey, 1n);

  const builder = new wasm.JsShieldBuilder(1n);
  builder.shield(account.address, usdc, "1000000");
  const txData = builder.build();

  // Should have valid transaction data
  expect(txData.to.startsWith("0x")).toBe(true);
  expect(txData.toHex().startsWith("0x")).toBe(true);
  expect(txData.value).toBe("0");

  txData.free();
  builder.free();
  account.free();
});
