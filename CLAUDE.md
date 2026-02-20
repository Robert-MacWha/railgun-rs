# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

### Rust (railgun-rs)
```bash
# Run unit tests
cd railgun-rs && just test

# Run integration tests (requires environment variables)
cd railgun-rs && just integration

# Run specific integration tests
cd railgun-rs && just integration-sync
cd railgun-rs && just integration-transact

# Build for native
cargo build --release --features native --no-default-features

# Build for WASM (from sdk-js directory)
cd sdk-js && just wasm
```

### JavaScript SDK (sdk-js)
```bash
# Build WASM bindings
cd sdk-js && just wasm

# Run tests (requires Anvil fork)
cd sdk-js && just test

# Run main example
cd sdk-js && just run
```

### Environment Setup

**Secret Management**: This project uses [SOPS](https://github.com/getsops/sops) for secret management.

```bash
# Edit secrets
sops secrets/secrets.yaml

# Load secrets
export $(sops -d secrets/secrets.yaml | xargs)
# Or use direnv for automatic loading

# Add a new contributor
# 1. They run: age-keygen -o ~/.config/sops/age/keys.txt
# 2. Add their public key to .sops.yaml
# 3. Run: sops updatekeys secrets/secrets.yaml
```

**Required Environment Variables**:
- `FORK_URL_MAINNET`: Ethereum Mainnet RPC endpoint for integration tests
- Tests use Anvil forking at block 24379760

**Dependencies**:
- `wasm-pack` for WASM builds
- `anvil` (from Foundry) for integration tests
- `just` for task running

## Architecture Overview

### Multi-Language Architecture
This is a **Rust-based privacy protocol** with **TypeScript/JavaScript bindings**:

1. **poseidon-rust** - Standalone Circom-compatible Poseidon hash library for BN254
2. **railgun-rs** - Core Rust implementation of Railgun Protocol (supports both native and WASM targets)
3. **sdk-js** - TypeScript wrapper around WASM-compiled railgun-rs, providing browser/Node.js support

### Protocol Purpose
Railgun is a **privacy-preserving token transfer system** for Ethereum. It enables:
- **Shielding**: Moving ERC20/ERC721/ERC1155 tokens into privacy pools
- **Private Transfers**: Sending tokens between Railgun addresses without revealing amounts or recipients on-chain
- **Unshielding**: Withdrawing tokens from privacy back to public Ethereum addresses

### Core Components (railgun-rs/src)

#### crypto/
Cryptographic primitives layer:
- **keys.rs**: BabyJubJub key derivation (SpendingKey, ViewingKey, nullifier computation)
- **poseidon.rs**: Wrapper around poseidon-rust for Circom-compatible hashing
- **aes.rs**: AES-GCM encryption for note confidentiality (used by viewing keys)
- **railgun_txid.rs**: Transaction ID computation with merkle proofs
- **railgun_utxo.rs**: UTXO commitment hash computation

#### railgun/
Protocol logic layer:

**address.rs**: Bech32-encoded stealth addresses (format: `0zk1...`)

**note/**: Transaction note types with type-state pattern:
- `utxo.rs`: Unspent outputs (on-chain commitments in merkle tree)
- `transfer.rs`: Notes being sent to other Railgun addresses
- `unshield.rs`: Notes being withdrawn to EOAs
- `operation.rs`: Abstract operation trait (validates input/output value constraints)
- `encrypt.rs`: AES-GCM encryption with recipient viewing keys

**merkle_tree/**: Two tree types used by protocol:
- UTXO trees (16-bit depth, stores note commitments)
- TXID trees (stores transaction IDs for POI system)

**indexer/**: Blockchain state synchronization:
- `indexer.rs`: Main indexer tracking UTXO/TXID trees and balances per account
- `indexed_account.rs`: Per-account balance tracking by token
- **syncer/**: Pluggable data source abstraction
  - `syncer.rs`: Trait for sync providers
  - `rpc_syncer.rs`: Direct RPC-based sync
  - `subsquid_syncer.rs`: SubSquid GraphQL indexer
  - `chained_syncer.rs`: Composable pipeline (e.g., SubSquid with RPC fallback)

**poi/**: Proof of Inclusion system (private compliance):
- `poi_client.rs`: GraphQL client for PPOI aggregator API
- `poi_note.rs`: Notes annotated with POI merkle proofs

**broadcaster/**: Transaction relay system:
- `broadcaster.rs`: Fee calculation, encryption, and message broadcasting
- `broadcaster_manager.rs`: Broadcaster selection and fallback logic
- `transport.rs`: Waku P2P network transport abstraction
- `content_topics.rs`: Waku message routing topics

**transaction/**: Transaction construction:
- `operation_builder.rs`: Fluent builder for operations (transfer, shield, unshield)
- `broadcaster_data.rs`: Encrypted payloads for relayers (relayers can't decrypt note details)
- `tx_data.rs`: Final EVM transaction encoding

#### circuit/
Zero-knowledge proof generation:

**inputs/**: Circuit input builders:
- `transact_inputs.rs`: Private transaction circuit inputs
- `poi_inputs.rs`: POI proof circuit inputs

**native/**: Native proving (features = ["native"]):
- `groth16_prover.rs`: Groth16 proof generation using wasmer + ark-circom
- `wasmer_witness_calculator.rs`: WASM witness computation engine

`prover.rs`: Trait definitions (TransactProver, PoiProver)

#### wasm/
JavaScript bindings (features = ["wasm"]):
- WASM-bindgen exports for all major types
- Uses tsify-next for TypeScript type generation

### Key Architectural Patterns

1. **Builder Pattern**: `OperationBuilder` accumulates transfers/unshields, validates constraints, then builds operation
2. **Trait Abstraction**: `Syncer`, `WakuTransport`, `Prover` traits enable swapping implementations
3. **Type-State Pattern**: Different note types (Utxo/Transfer/Unshield) enforce valid state transitions at compile time
4. **Two-Layer Transactions**:
   - Operations (Railgun-level, contains notes)
   - Transactions (EVM-level, can batch multiple operations)
5. **Lazy Merkle Trees**: Proofs generated on-demand, not precomputed
6. **Encrypted Broadcaster Pattern**: Relayers see encrypted payloads only, preventing front-running

### Data Flow: Private Transfer

```
User calls OperationBuilder::transfer()
  ↓
Indexer provides UtxoNotes (available balance)
  ↓
TransferNotes created (encrypted with recipient viewing keys)
  ↓
TransactCircuitInputs generated
  ↓
Prover generates Groth16 proof (proves correctness without revealing amounts)
  ↓
Broadcaster encrypts transaction with relayer viewing key
  ↓
Waku transport broadcasts to P2P network
  ↓
Relayer decrypts, submits on-chain, collects fee
  ↓
Smart contract verifies proof, updates UTXO tree
```

### Feature Flags (railgun-rs)

- **default**: `native` feature enabled
- **native**: Enables native proving (wasmer, ark-circom), rustls for reqwest
- **wasm**: WASM target support (wasm-bindgen, js-sys, serde-wasm-bindgen, tsify-next)

Build for native: `cargo build --features native --no-default-features`
Build for WASM: `wasm-pack build --target nodejs --features wasm --no-default-features`

### Important Files

- **railgun-rs/Cargo.toml**: Main crate with dual native/WASM support
- **Cargo.toml** (workspace root): Shared dependency versions, clippy lints configuration
- **.cargo/config.toml**: WASM target configuration (getrandom backend)
- **railgun-rs/tests/fixtures/state.json**: Anvil state snapshot for integration tests
- **sdk-js/pkg/**: Generated WASM bindings (created by `just wasm`)

### Testing Strategy

1. **Unit Tests**: `cargo test` (fast, no network)
2. **Integration Tests**: `just integration` (requires Anvil fork, marked with `#[ignore]`)
3. **SDK Tests**: `cd sdk-js && just test` (end-to-end WASM tests with Anvil)

Integration tests fork Ethereum Mainnet at a specific block with pre-funded accounts, allowing realistic testing without deploying contracts.

### Linting

The workspace uses Clippy pedantic lints (configured in workspace Cargo.toml):
```bash
cargo clippy
```

## Common Workflows

### Adding a New Note Type
1. Create struct in `railgun/note/`
2. Implement `Operation` trait
3. Add serialization support (serde, bitcode)
4. Update `OperationBuilder` with new method
5. Add circuit input generation in `circuit/inputs/`
6. Export in `wasm/` if needed for JavaScript

### Modifying Cryptographic Primitives
- **Poseidon changes**: Edit `poseidon-rust` crate separately
- **Key derivation**: Modify `crypto/keys.rs`
- **Note encryption**: Update `railgun/note/encrypt.rs`

⚠️ Cryptographic changes may break compatibility with deployed contracts or existing notes.

### Adding a New Syncer Implementation
1. Create module in `railgun/indexer/syncer/`
2. Implement `Syncer` trait
3. Use `ChainedSyncer` to compose with existing syncers (e.g., fallback pattern)

## Debugging Tips

- **WASM panics**: Build with `console_error_panic_hook` feature enabled for readable stack traces
- **Circuit failures**: Check witness calculation logs (witness mismatches indicate input generation bugs)
- **Merkle proof issues**: Verify tree state matches expected root before generating proofs
- **Integration test failures**: Ensure `FORK_URL_MAINNET` points to valid archive node RPC

## External Artifacts

Railgun circuits and PPOI artifacts:
- Circuits repo: https://github.com/Railgun-Privacy/circuits-v2
- Circuits IPFS: https://ipfs-lb.com/ipfs/QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU/circuits/01x02/
- PPOI repo: https://github.com/Railgun-Privacy/circuits-ppoi
- PPOI IPFS: https://ipfs-lb.com/ipfs/QmZrP9zaZw2LwErT2yA6VpMWm65UdToQiKj4DtStVsUJHr/

These are consumed by the prover but not included in this repository.
