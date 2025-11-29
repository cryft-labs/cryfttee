# CryftTEE

A Rust-based TEE-style sidecar for WASM module management, designed to integrate with `cryftgo` and Web3Signer.

## Overview

Cryftee is a stateless runtime that:
- Loads and manages signed WASM modules from a manifest
- Provides BLS/TLS staking key operations via modular plugins
- Exposes a versioned API over UDS (Unix Domain Socket) or HTTPS
- Includes a kiosk web UI for module management on port 3232
- Supports per-module GUIs rendered as tabs in the kiosk interface
- Enforces version compatibility and publisher trust

## Architecture

```
cryftee-runtime/           # Rust TEE runtime (v0.4.0)
├── src/
│   ├── main.rs            # Entry point, server bootstrap
│   ├── lib.rs             # Core exports
│   ├── config/            # Configuration parsing
│   ├── http/              # HTTP/HTTPS server (axum)
│   │   ├── api.rs         # JSON API handlers
│   │   └── kiosk.rs       # Kiosk UI endpoints
│   ├── uds/               # Unix Domain Socket server
│   ├── runtime/           # Module registry, loader, dispatch
│   │   ├── registry.rs    # Module tracking and defaults
│   │   ├── loader.rs      # WASM loading with wasmtime
│   │   └── dispatch.rs    # Operation routing to modules
│   ├── signing/           # Blockchain signing operations
│   ├── storage/           # Manifest parsing, hashing, signatures
│   └── wasm_api/          # WASM module traits and types

modules/                   # WASM modules directory
├── manifest.json          # Global module registry
├── bls_tls_signer_v1/     # BLS + TLS signing module
│   ├── src/               # Rust source
│   ├── gui/               # Module web GUI
│   └── module.json        # Module metadata
├── debug_v1/              # Debugging and diagnostics module
│   ├── src/               # Rust source
│   └── gui/               # Module web GUI
└── llm_chat_v1/           # LLM chat interface module
    ├── src/               # Rust source
    └── gui/               # Module web GUI

ui/                        # Kiosk web interface
├── index.html
├── app.js
└── styles.css

config/                    # Configuration examples
├── cryftee.example.toml
└── trust.toml

scripts/                   # Deployment scripts
├── deploy-web3signer.sh   # Linux/macOS Web3Signer setup
└── Deploy-Web3Signer.ps1  # Windows Web3Signer setup
```

## Available Modules

| Module | Description | Capabilities |
|--------|-------------|--------------|
| `bls_tls_signer_v1` | Baseline BLS + TLS staking module with Web3Signer integration | `bls_register`, `bls_sign`, `tls_register`, `tls_sign`, `module_signing` |
| `debug_v1` | Debugging and diagnostics for runtime inspection | `debug_echo`, `debug_info`, `debug_panic` |
| `llm_chat_v1` | Interactive LLM chat interface for runtime assistance | `llm_chat`, `llm_stream` |

All modules include a web GUI accessible from the kiosk interface.

## Quick Start

### Prerequisites

- Rust 1.75+ (stable toolchain)
- Cargo
- **Windows**: Visual Studio Build Tools 2017+ with "Desktop development with C++" workload
  - Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
- **Linux**: gcc, pkg-config, libssl-dev
- **macOS**: Xcode Command Line Tools

### Build

```bash
cd cryftee-runtime
cargo build --release
```

### Build WASM Modules

```bash
# Build all modules
cd modules/bls_tls_signer_v1
cargo build --target wasm32-unknown-unknown --release

cd ../debug_v1
cargo build --target wasm32-unknown-unknown --release

cd ../llm_chat_v1
cargo build --target wasm32-unknown-unknown --release
```

### Run

```bash
# With default settings (UDS transport)
./target/release/cryftee

# With custom module directory
./target/release/cryftee --module-dir ./modules

# With HTTPS transport
./target/release/cryftee \
  --api-transport https \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTEE_MODULE_DIR` | `./modules` | Module directory path |
| `CRYFTEE_MANIFEST_PATH` | `{module_dir}/manifest.json` | Manifest file path |
| `CRYFTEE_UI_DIR` | `./ui` | UI static assets path |
| `CRYFTEE_TRUST_CONFIG` | - | Trust configuration path |
| `CRYFTEE_API_TRANSPORT` | `uds` | API transport: `uds` or `https` |
| `CRYFTEE_UDS_PATH` | `/var/run/cryftee.sock` | UDS socket path |
| `CRYFTEE_HTTP_ADDR` | `0.0.0.0:3232` | HTTP bind address |
| `CRYFTEE_TLS_CERT` | - | TLS certificate path |
| `CRYFTEE_TLS_KEY` | - | TLS private key path |

## API Endpoints

All endpoints are available over both UDS and HTTPS transports.

### Staking Operations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/staking/bls/register` | POST | Register a BLS key |
| `/v1/staking/bls/sign` | POST | Sign with a BLS key |
| `/v1/staking/tls/register` | POST | Register a TLS key |
| `/v1/staking/tls/sign` | POST | Sign with a TLS key |
| `/v1/staking/status` | GET | Get module and runtime status |

### Runtime & Admin

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/runtime/attestation` | GET | Get runtime attestation |
| `/v1/schema/modules` | GET | Get module compatibility schema |
| `/v1/admin/reload-modules` | POST | Reload module registry |

### Module GUIs

| Endpoint | Description |
|----------|-------------|
| `/api/modules/{module_id}/gui/` | Access module-specific web GUI |

### Example: BLS Register

```bash
curl -X POST http://localhost:3232/v1/staking/bls/register \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "ephemeral",
    "ephemeralKeyB64": "...",
    "networkID": 12345
  }'
```

Response:
```json
{
  "keyHandle": "...",
  "blsPubKeyB64": "...",
  "moduleId": "bls_tls_signer_v1",
  "moduleVersion": "1.0.0"
}
```

## Module Manifest Format

```json
{
  "version": 1,
  "modules": [
    {
      "id": "bls_tls_signer_v1",
      "dir": "bls_tls_signer_v1",
      "file": "module.wasm",
      "version": "1.0.0",
      "minCryfteeVersion": "0.4.0",
      "description": "BLS + TLS signing module",
      "capabilities": ["bls_register", "bls_sign", "tls_register", "tls_sign"],
      "defaultFor": { "bls": true, "tls": true },
      "publisherId": "cryft-labs",
      "hash": "sha256:...",
      "signature": "base64...",
      "hasGui": true,
      "guiPath": "gui"
    }
  ]
}
```

### Module Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique module identifier |
| `dir` | Yes | Directory name under `modules/` |
| `file` | Yes | WASM filename (typically `module.wasm`) |
| `version` | Yes | Semantic version string |
| `minCryfteeVersion` | Yes | Minimum compatible runtime version |
| `description` | Yes | Human-readable description |
| `capabilities` | Yes | List of operations the module provides |
| `defaultFor` | Yes | Which operations this module handles by default |
| `publisherId` | Yes | Publisher identity for trust verification |
| `hash` | Yes | SHA256 hash of the WASM file |
| `signature` | Yes | Publisher signature over canonical metadata |
| `hasGui` | No | Whether the module provides a web GUI |
| `guiPath` | No | Path to GUI assets relative to module directory |
| `moduleType` | No | Special module type (e.g., `llm`) |

## Kiosk UI

Access the kiosk web interface at `http://localhost:3232` to:
- View loaded and available modules
- See module status (trusted, compatible, loaded)
- Access module-specific GUIs as tabs
- View runtime attestation hashes
- Reload modules
- Inspect the module schema

## Module GUI Development

Modules can optionally provide a web GUI that renders as a tab in the kiosk interface:

1. Create a `gui/` directory in your module containing static web assets
2. Add `"hasGui": true` and `"guiPath": "gui"` to your manifest entry
3. The GUI is served at `/api/modules/{module_id}/gui/`
4. Main entry point should be `index.html`
5. GUI is sandboxed in an iframe with `allow-scripts allow-same-origin allow-forms`

## Security

- **Stateless**: No secrets stored on disk; relies on Web3Signer
- **Signed Modules**: All modules must be signed by trusted publishers
- **Version Enforcement**: `minCryfteeVersion` prevents incompatible loads
- **Hash Verification**: Module code is verified against manifest hash
- **Graceful Failures**: Module errors never crash the runtime
- **GUI Sandboxing**: Module GUIs run in sandboxed iframes

## Development

### Project Structure

```
cryftee-runtime/src/
├── config/mod.rs          # Configuration types and parsing
├── http/api.rs            # JSON API handlers
├── http/kiosk.rs          # Kiosk UI endpoints
├── runtime/registry.rs    # Module tracking and defaults
├── runtime/loader.rs      # WASM loading with wasmtime
├── runtime/dispatch.rs    # Operation routing to modules
├── signing/               # Blockchain state and signing
├── storage/index.rs       # Hash and signature verification
└── wasm_api/staking.rs    # WASM module traits
```

### Adding a New Module

1. Create a new directory under `modules/`
2. Create a Rust crate targeting `wasm32-unknown-unknown`
3. Implement the required WASM ABI functions
4. Optionally add a `gui/` directory with static web assets
5. Add an entry to `modules/manifest.json`
6. Sign the module with your publisher key
7. Reload via `/v1/admin/reload-modules` or restart

### Building a Module

```bash
cd modules/your_module
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/your_module.wasm ./module.wasm
```

## Scripts

- `scripts/deploy-web3signer.sh` - Deploy Web3Signer on Linux/macOS
- `scripts/Deploy-Web3Signer.ps1` - Deploy Web3Signer on Windows

## License

MIT

## Links

- Repository: https://github.com/cryft-labs/cryfttee
- IPFS Distribution: `gateway.cryft.network/ipns/cryftee`
- Documentation: Coming soon
