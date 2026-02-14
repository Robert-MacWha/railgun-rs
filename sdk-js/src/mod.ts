// Railgun SDK for JavaScript/TypeScript
// Main module exports

export {
  initWasm,
  getWasm,
  type WasmModule,
  type ProveFunction,
  type JsRailgunAccount,
  type JsIndexer,
  type JsSyncer,
  type JsProver,
  type JsShieldBuilder,
  type JsTransactionBuilder,
  type JsTxData,
  type JsBalanceMap,
  type JsProofResponse,
} from "./wasm.ts";

export {
  createProveFunction,
  createProverFunctions,
  verifyProof,
  type ProverConfig,
  type ArtifactPaths,
} from "./prover.ts";

