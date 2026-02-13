// WASM module initialization and re-exports
// Re-exports the wasm-bindgen generated types

export type {
  JsRailgunAccount,
  JsIndexer,
  JsSyncer,
  JsProver,
  JsShieldBuilder,
  JsTransactionBuilder,
  JsTxData,
  InitOutput as WasmModule,
} from "../pkg/railgun_rs.d.ts";

export { default as initWasmModule } from "../pkg/railgun_rs.js";
export { init_panic_hook } from "../pkg/railgun_rs.js";

export type ProveFunction = (
  circuitName: string,
  inputs: Record<string, string[]>
) => Promise<ProofResponse>;

export interface ProofResponse {
  a: [string, string];
  b: [[string, string], [string, string]];
  c: [string, string];
}

// Module state
let wasmInitialized = false;
let wasmExports: typeof import("../pkg/railgun_rs.js") | null = null;

export async function initWasm(wasmPath?: string): Promise<typeof import("../pkg/railgun_rs.js")> {
  if (wasmInitialized && wasmExports) return wasmExports;

  const module = await import("../pkg/railgun_rs.js");

  if (wasmPath) {
    await module.default(wasmPath);
  } else {
    await module.default();
  }

  module.init_panic_hook();
  wasmInitialized = true;
  wasmExports = module;

  return module;
}

export function getWasm(): typeof import("../pkg/railgun_rs.js") {
  if (!wasmInitialized || !wasmExports) {
    throw new Error("WASM module not initialized. Call initWasm() first.");
  }
  return wasmExports;
}
