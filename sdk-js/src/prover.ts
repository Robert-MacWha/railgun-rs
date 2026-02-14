// snarkjs-based prover implementation
import * as snarkjs from "snarkjs";
import type { ProveFunction } from "./wasm.ts";
import { JsProofResponse } from "../pkg/railgun_rs";

export interface ArtifactPaths {
  wasmPath: string;
  zkeyPath: string;
}

export interface ProverConfig {
  /** Base path to circuit artifacts */
  artifactsPath: string;
  /** Function to resolve artifact paths for a given circuit */
  resolveArtifacts?: (circuitName: string, basePath: string) => ArtifactPaths;
  /** Whether to verify proofs after generation (default: false) */
  verify?: boolean;
}

/**
 * Default artifact resolver.
 * Expects structure: {basePath}/{circuitType}/{NNxMM}.wasm and .zkey
 * e.g., artifacts/railgun/01x02.wasm
 */
function defaultResolveArtifacts(
  circuitName: string,
  basePath: string
): ArtifactPaths {
  // circuitName format: "transact/01x02" or "poi/01x02"
  const [circuitType, size] = circuitName.split("/");
  const folder = circuitType === "transact" ? "railgun" : "ppoi";

  return {
    wasmPath: `${basePath}/${folder}/${size}.wasm`,
    zkeyPath: `${basePath}/${folder}/${size}.zkey`,
  };
}

// Cache for loaded artifacts
const artifactCache = new Map<string, { wasm: Uint8Array; zkey: Uint8Array }>();

async function loadArtifacts(
  wasmPath: string,
  zkeyPath: string
): Promise<{ wasm: Uint8Array; zkey: Uint8Array }> {
  const cacheKey = `${wasmPath}:${zkeyPath}`;
  const cached = artifactCache.get(cacheKey);
  if (cached) return cached;

  const [wasmBuffer, zkeyBuffer] = await Promise.all([
    Bun.file(wasmPath).arrayBuffer(),
    Bun.file(zkeyPath).arrayBuffer(),
  ]);

  const artifacts = {
    wasm: new Uint8Array(wasmBuffer),
    zkey: new Uint8Array(zkeyBuffer),
  };
  artifactCache.set(cacheKey, artifacts);
  return artifacts;
}

/**
 * Creates a prove function for use with JsProver.
 * Uses snarkjs with single-threaded mode for Bun compatibility.
 */
export function createProveFunction(config: ProverConfig): ProveFunction {
  const resolveArtifacts = config.resolveArtifacts ?? defaultResolveArtifacts;
  const shouldVerify = config.verify ?? false;

  return async (
    circuitName: string,
    inputs: Record<string, string[]>
  ): Promise<JsProofResponse> => {
    const { wasmPath, zkeyPath } = resolveArtifacts(
      circuitName,
      config.artifactsPath
    );

    const bigintInputs: Record<string, bigint[]> = {};
    for (const [key, values] of Object.entries(inputs)) {
      bigintInputs[key] = values.map((v) => BigInt(v));
    }

    const { wasm, zkey } = await loadArtifacts(wasmPath, zkeyPath);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      bigintInputs,
      wasm,
      zkey,
      undefined, // logger
      undefined, // wtnsCalcOptions
      { singleThread: true }
    );

    if (shouldVerify) {
      const vkey = await snarkjs.zKey.exportVerificationKey(zkey);
      const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      if (!valid) {
        throw new Error(`Proof verification failed for ${circuitName}`);
      }
    }

    // Convert proof to the expected format (decimal strings)
    return {
      a: [proof.pi_a[0].toString(), proof.pi_a[1].toString()],
      b: [
        [proof.pi_b[0][0].toString(), proof.pi_b[0][1].toString()],
        [proof.pi_b[1][0].toString(), proof.pi_b[1][1].toString()],
      ],
      c: [proof.pi_c[0].toString(), proof.pi_c[1].toString()],
    };
  };
}

/**
 * Creates prover functions for both transact and POI circuits.
 */
export function createProverFunctions(config: ProverConfig): {
  proveTransact: ProveFunction;
  provePoi: ProveFunction;
} {
  const proveFn = createProveFunction(config);
  return {
    proveTransact: proveFn,
    provePoi: proveFn,
  };
}

/**
 * Verify a proof against a circuit's verification key.
 * Extracts the vkey from the zkey, so no separate vkey.json needed.
 */
export async function verifyProof(
  zkeyPath: string,
  publicSignals: string[],
  proof: JsProofResponse
): Promise<boolean> {
  const zkeyBuffer = await Bun.file(zkeyPath).arrayBuffer();
  const zkey = new Uint8Array(zkeyBuffer);

  const vkey = await snarkjs.zKey.exportVerificationKey(zkey);

  // Convert proof back to snarkjs format
  const snarkjsProof = {
    pi_a: [proof.a[0], proof.a[1], "1"],
    pi_b: [
      [proof.b[0][0], proof.b[0][1]],
      [proof.b[1][0], proof.b[1][1]],
      ["1", "0"],
    ],
    pi_c: [proof.c[0], proof.c[1], "1"],
    protocol: "groth16",
    curve: "bn128",
  };

  return await snarkjs.groth16.verify(vkey, publicSignals, snarkjsProof);
}
