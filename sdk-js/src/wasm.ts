// WASM module initialization and re-exports

import type { JsProofResponse } from "../pkg/railgun_rs.d.ts";

export type ProveFunction = (
  circuitName: string,
  inputs: Record<string, string[]>
) => Promise<JsProofResponse>;

let wasmInitialized = false;
let wasmExports: typeof import("../pkg/railgun_rs.js") | null = null;

export async function initWasm(): Promise<typeof import("../pkg/railgun_rs.js")> {
  if (wasmInitialized && wasmExports) return wasmExports;

  const module = await import("../pkg/railgun_rs.js");

  if ("init_panic_hook" in module && typeof module.init_panic_hook === "function") {
    module.init_panic_hook();
  }

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
