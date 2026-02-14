// WASM module initialization and re-exports

import type { JsProofResponse } from "../pkg/railgun_rs.d.ts";

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
} from "../pkg/railgun_rs.d.ts";

export { default as initWasmModule } from "../pkg/railgun_rs.js";
export { init_panic_hook } from "../pkg/railgun_rs.js";

/**
 * Function signature for proving circuits.
 * @param circuitName - Circuit identifier, e.g., "transact/01x02" or "poi/01x02"
 * @param inputs - Circuit inputs as decimal strings
 * @returns Groth16 proof with G1/G2 points as decimal strings
 */
export type ProveFunction = (
  circuitName: string,
  inputs: Record<string, string[]>
) => Promise<JsProofResponse>;

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
