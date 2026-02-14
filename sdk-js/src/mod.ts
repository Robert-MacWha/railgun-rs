// Railgun SDK for JavaScript/TypeScript
// Main module exports

export {
  initWasm,
  getWasm,
} from "./wasm.ts";

export type {
  JsRailgunAccount,
  JsIndexer,
  JsSyncer,
  JsProver,
  JsShieldBuilder,
  JsTransactionBuilder,
  JsTxData,
  JsProofResponse,
  JsBalanceMap,
  InitOutput as WasmModule,
  JsBroadcaster,
  WakuMessage,
} from "../pkg/railgun_rs.d.ts";

export {
  createProveFunction,
  createProverFunctions,
  verifyProof,
  type ProverConfig,
  type ArtifactPaths,
} from "./prover.ts";

export {
  createWakuTransport,
  type SubscribeFn,
  type SendFn,
} from "./waku-transport.ts";
