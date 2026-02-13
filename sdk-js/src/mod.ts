// Railgun SDK for JavaScript/TypeScript
// Main module exports

export {
  initWasm,
  getWasm,
  type WasmModule,
  type ProofResponse,
  type ProveFunction,
  type JsRailgunAccount,
  type JsIndexer,
  type JsSyncer,
  type JsProver,
  type JsShieldBuilder,
  type JsTransactionBuilder,
  type JsTxData,
} from "./wasm.ts";

export {
  createProveFunction,
  createProverFunctions,
  verifyProof,
  type ProverConfig,
  type ArtifactPaths,
} from "./prover.ts";

// After initWasm(), the following are available on the wasm module:
//
//   get_chain_config(chainId: bigint) -> JsChainConfig | undefined
//     Returns chain config with: id, railgunWallet, deploymentBlock,
//     poiStartBlock, subsquidEndpoint, poiEndpoint
//
//   erc20_asset(address: string) -> string
//     Formats an address as "erc20:0x..."
