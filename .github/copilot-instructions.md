# Cryftee Workspace Instructions

## Project Overview

This workspace contains **cryftee** - a Rust-based TEE-style sidecar application that:

- Acts as a host/runtime for arbitrary WASM modules (signing, fraud proofs, policy engines)
- Loads and manages WASM modules from a module directory driven by a signed global manifest
- Exposes a versioned API (`/v1/...`) over UDS (default) or HTTPS
- Provides a kiosk web UI on port 323 for module management
- Integrates with Web3Signer and cryftgo staking/TLS wiring

## Architecture

### Core Components

- **cryftee-runtime/**: Main Rust application
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
5. **Versioned**: Schema-driven compatibility with `minCryfteeVersion` enforcement

## Version Constant

```rust
pub const CRYFTEE_VERSION: &str = "0.4.0";
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

- `CRYFTEE_MODULE_DIR` - Root path for modules/
- `CRYFTEE_MANIFEST_PATH` - Path to manifest.json
- `CRYFTEE_UI_DIR` - Path to UI static assets
- `CRYFTEE_TRUST_CONFIG` - Path to trust roots (publisher keys)
- `CRYFTEE_API_TRANSPORT` - "uds" (default) or "https"
- `CRYFTEE_UDS_PATH` - UDS socket path (default: /var/run/cryftee.sock)
- `CRYFTEE_HTTP_ADDR` - HTTP bind address (default: 0.0.0.0:323)
- `CRYFTEE_TLS_CERT` - TLS certificate path
- `CRYFTEE_TLS_KEY` - TLS private key path

## Module Manifest Format

Each module in `manifest.json` requires:
- `id`, `dir`, `file`, `version`, `minCryfteeVersion`
- `capabilities`, `defaultFor`, `description`
- `publisherId`, `hash`, `signature`

## Development Guidelines

- Use Rust 2021 edition with stable toolchain
- Prefer small, well-structured modules
- Keep secrets out of logs, API responses, and UI
- All WASM loading uses wasmtime
- Signatures use Ed25519/BLS verification
