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

// Anvil default private key
const TEST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const CHAIN_ID = 1n;
const ARTIFACTS_PATH = "../railgun-rs/artifacts";
const INDEXER_STATE_PATH = "../railgun-rs/tests/fixtures/indexer_state.bincode";

const erc20Abi = parseAbi([
  "function balanceOf(address) view returns (uint256)",
]);

// Helper to create a 32-byte hex string filled with a single byte value
const hexKey = (fill: number): string => "0x" + fill.toString(16).padStart(2, "0").repeat(32);

test("transact: shield, transfer, and unshield", async () => {
  const wasm = await initWasm();
  const USDC = wasm.erc20_asset(USDC_ADDRESS);

  console.log("Setting up prover");
  const { proveTransact, provePoi } = createProverFunctions({
    artifactsPath: ARTIFACTS_PATH,
  });
  const prover = new wasm.JsProver(proveTransact, provePoi);

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

  console.log("Setting up indexer");
  const indexerState = await Bun.file(INDEXER_STATE_PATH).bytes();
  const syncer = await wasm.JsSyncer.withRpc(
    "http://localhost:8545",
    1n
  );
  const indexer = await wasm.JsIndexer.from_state(syncer, indexerState);

  console.log("Setting up accounts");
  const account1 = new wasm.JsRailgunAccount(hexKey(1), hexKey(2), CHAIN_ID);
  const account2 = new wasm.JsRailgunAccount(hexKey(3), hexKey(4), CHAIN_ID);

  indexer.add_account(account1);
  indexer.add_account(account2);

  console.log("Testing shielding");
  const shieldBuilder = new wasm.JsShieldBuilder(CHAIN_ID);
  shieldBuilder.shield(account1.address, USDC, "1000000");
  const shieldTx = shieldBuilder.build();

  const shieldHash = await walletClient.sendTransaction({
    to: shieldTx.to as `0x${string}`,
    data: shieldTx.dataHex as `0x${string}`,
    value: BigInt(shieldTx.value),
  });
  await publicClient.waitForTransactionReceipt({ hash: shieldHash });

  await indexer.sync();
  {
    const balance1 = indexer.balance(account1.address);
    const balance2 = indexer.balance(account2.address);

    // 0.25% shield fee: 1_000_000 * 0.9975 = 997_500
    expect(balance1.get(USDC)).toBe(997500n);
    expect(balance2.get(USDC)).toBeUndefined();

    balance1.free();
    balance2.free();
  }

  console.log("Testing transfer");
  const transferBuilder = new wasm.JsTransactionBuilder(account1);
  transferBuilder.transfer(account2.address, USDC, "5000", "test transfer");
  const transferTx = await transferBuilder.build(indexer, prover);

  const transferHash = await walletClient.sendTransaction({
    to: transferTx.to as `0x${string}`,
    data: transferTx.dataHex as `0x${string}`,
    value: BigInt(transferTx.value),
  });
  await publicClient.waitForTransactionReceipt({ hash: transferHash });

  await indexer.sync();
  {
    const balance1 = indexer.balance(account1.address);
    const balance2 = indexer.balance(account2.address);

    expect(balance1.get(USDC)).toBe(992500n);
    expect(balance2.get(USDC)).toBe(5000n);

    balance1.free();
    balance2.free();
  }

  console.log("Testing unshielding");
  const unshieldRecipient = checksumAddress("0xe03747a83E600c3ab6C2e16dd1989C9b419D3a86");
  const unshieldBuilder = new wasm.JsTransactionBuilder(account1);
  unshieldBuilder.unshield(unshieldRecipient, USDC, "1000");
  const unshieldTx = await unshieldBuilder.build(indexer, prover);

  const unshieldHash = await walletClient.sendTransaction({
    to: unshieldTx.to as `0x${string}`,
    data: unshieldTx.dataHex as `0x${string}`,
    value: BigInt(unshieldTx.value),
  });
  await publicClient.waitForTransactionReceipt({ hash: unshieldHash });

  await indexer.sync();
  {
    const balance1 = indexer.balance(account1.address);
    const balance2 = indexer.balance(account2.address);

    expect(balance1.get(USDC)).toBe(991500n);
    expect(balance2.get(USDC)).toBe(5000n);

    balance1.free();
    balance2.free();
  }
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

  const account = new wasm.JsRailgunAccount(hexKey(1), hexKey(2), 1n);

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

  const account = new wasm.JsRailgunAccount(hexKey(1), hexKey(2), 1n);

  const builder = new wasm.JsShieldBuilder(1n);
  builder.shield(account.address, usdc, "1000000");
  const txData = builder.build();

  // Should have valid transaction data
  expect(txData.to.startsWith("0x")).toBe(true);
  expect(txData.dataHex.startsWith("0x")).toBe(true);
  expect(txData.value).toBe("0");

  txData.free();
  builder.free();
  account.free();
});
