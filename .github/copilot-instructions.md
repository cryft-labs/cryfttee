# CryftTEE Workspace Instructions

## Project Overview

This workspace contains **cryfttee** - a Rust-based TEE-style sidecar application that:

- Acts as a host/runtime for arbitrary WASM modules (signing, fraud proofs, policy engines)
- Loads and manages WASM modules from a module directory driven by a signed global manifest
- Exposes a versioned API (`/v1/...`) over UDS (default) or HTTPS
- Provides a kiosk web UI on port 3232 for module management
- Integrates with Web3Signer and cryftgo staking/TLS wiring

## Architecture

### Core Components

- **cryfttee-runtime/**: Main Rust application
  - `src/main.rs` - Application entry point, API listeners, UI server
  - `src/lib.rs` - Core runtime logic exports
  - `src/runtime/` - Module registry, loader, and dispatch
  - `src/wasm_api/` - WASM module traits and ABIs
  - `src/storage/` - Module metadata, hashes, signatures indexing
  - `src/http/` - HTTP/HTTPS server (axum-based)
  - `src/uds/` - Unix Domain Socket listener
  - `src/config/` - Environment and CLI configuration

- **modules/**: WASM module directory
  - `manifest.json` - Global module registry
  - `bls_tls_signer_v1/` - First signing module

- **ui/**: Kiosk web interface assets
- **config/**: Configuration examples

## Key Design Principles

1. **Stateless**: No persistent secrets or database; relies on Web3Signer for durable state
2. **Modular**: All chain-specific logic lives in WASM modules, not in Rust core
3. **Safe**: Module load/unload failures never crash the core; graceful error handling
4. **Auditable**: Runtime hashes and receipts for public verification
5. **Versioned**: Schema-driven compatibility with `minCryftteeVersion` enforcement

## Version Constant

```rust
pub const CRYFTTEE_VERSION: &str = "0.4.0";
```

## API Endpoints

All endpoints available over both UDS and HTTPS:

- `POST /v1/staking/bls/register` - Register BLS key
- `POST /v1/staking/bls/sign` - BLS signing
- `POST /v1/staking/tls/register` - Register TLS key
- `POST /v1/staking/tls/sign` - TLS signing
- `GET /v1/staking/status` - Module and runtime status
- `GET /v1/runtime/attestation` - Runtime hashes and receipts
- `GET /v1/schema/modules` - Module compatibility schema
- `POST /v1/admin/reload-modules` - Reload module registry

## Environment Variables

- `CRYFTTEE_MODULE_DIR` - Root path for modules/
- `CRYFTTEE_MANIFEST_PATH` - Path to manifest.json
- `CRYFTTEE_UI_DIR` - Path to UI static assets
- `CRYFTTEE_TRUST_CONFIG` - Path to trust roots (publisher keys)
- `CRYFTTEE_API_TRANSPORT` - "uds" (default) or "https"
- `CRYFTTEE_UDS_PATH` - UDS socket path (default: /var/run/cryfttee.sock)
- `CRYFTTEE_HTTP_ADDR` - HTTP bind address (default: 0.0.0.0:3232)
- `CRYFTTEE_TLS_CERT` - TLS certificate path
- `CRYFTTEE_TLS_KEY` - TLS private key path
- `CRYFTTEE_VERIFIED_BINARY_HASH` - Externally-verified binary hash (set by cryftgo)

## Binary Attestation (cryftgo Integration)

To ensure the `core_binary_hash` in attestation cannot be faked:

1. **cryftgo** computes the SHA256 hash of the cryfttee binary before launching it
2. **cryftgo** compares against a known-good hash (from release artifacts or Cryft Labs)
3. **cryftgo** sets `CRYFTTEE_VERIFIED_BINARY_HASH=sha256:<hex>` when spawning cryfttee
4. **cryfttee** reports this externally-verified hash in attestation responses
5. **cryftgo** can optionally re-verify `/proc/<pid>/exe` periodically

If `CRYFTTEE_VERIFIED_BINARY_HASH` is not set, cryfttee falls back to self-hashing 
(reading its own binary), which is less secure as a malicious binary could lie.

Example cryftgo launch:
```go
hash := sha256.Sum256(binaryBytes)
env := fmt.Sprintf("CRYFTTEE_VERIFIED_BINARY_HASH=sha256:%x", hash)
cmd := exec.Command(cryftteeePath, args...)
cmd.Env = append(os.Environ(), env)
```

## Module Manifest Format

Each module in `manifest.json` requires:
- `id`, `dir`, `file`, `version`, `minCryftteeVersion`
- `capabilities`, `defaultFor`, `description`
- `publisherId`, `hash`, `signature`

## Development Guidelines

- Use Rust 2021 edition with stable toolchain
- Prefer small, well-structured modules
- Keep secrets out of logs, API responses, and UI
- All WASM loading uses wasmtime
- Signatures use Ed25519/BLS verification
