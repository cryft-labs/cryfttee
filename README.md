# Cryftee

A Rust-based TEE-style sidecar for WASM module management, designed to integrate with `cryftgo` and Web3Signer.

## Overview

Cryftee is a stateless runtime that:
- Loads and manages signed WASM modules from a manifest
- Provides BLS/TLS staking key operations via modular plugins
- Exposes a versioned API over UDS (Unix Domain Socket) or HTTPS
- Includes a kiosk web UI for module management on port 323
- Enforces version compatibility and publisher trust

## Architecture

```
cryftee-runtime/           # Rust TEE runtime
├── src/
│   ├── main.rs            # Entry point, server bootstrap
│   ├── lib.rs             # Core exports
│   ├── config/            # Configuration parsing
│   ├── http/              # HTTP/HTTPS server (axum)
│   ├── uds/               # Unix Domain Socket server
│   ├── runtime/           # Module registry, loader, dispatch
│   ├── storage/           # Manifest parsing, hashing
│   └── wasm_api/          # WASM module traits and types

modules/                   # WASM modules directory
├── manifest.json          # Global module registry
└── bls_tls_signer_v1/     # First signing module
    ├── module.wasm        # Compiled WASM
    └── module.json        # Module metadata

ui/                        # Kiosk web interface
├── index.html
├── app.js
└── styles.css

config/                    # Configuration examples
├── cryftee.example.toml
└── trust.toml
```

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
| `CRYFTEE_HTTP_ADDR` | `0.0.0.0:323` | HTTP bind address |
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

### Example: BLS Register

```bash
curl -X POST http://localhost:323/v1/staking/bls/register \
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
      "signature": "base64..."
    }
  ]
}
```

## Kiosk UI

Access the kiosk web interface at `http://localhost:323` to:
- View loaded and available modules
- See module status (trusted, compatible, loaded)
- View runtime attestation hashes
- Reload modules
- Inspect the module schema

## Security

- **Stateless**: No secrets stored on disk; relies on Web3Signer
- **Signed Modules**: All modules must be signed by trusted publishers
- **Version Enforcement**: `minCryfteeVersion` prevents incompatible loads
- **Hash Verification**: Module code is verified against manifest hash
- **Graceful Failures**: Module errors never crash the runtime

## Development

### Project Structure

- `runtime/registry.rs` - Module tracking and defaults
- `runtime/loader.rs` - WASM loading with wasmtime
- `runtime/dispatch.rs` - Operation routing to modules
- `http/api.rs` - JSON API handlers
- `http/kiosk.rs` - Kiosk UI endpoints
- `storage/index.rs` - Hash and signature verification

### Adding a New Module

1. Create a new directory under `modules/`
2. Build your WASM module targeting `wasm32-unknown-unknown`
3. Add an entry to `modules/manifest.json`
4. Sign the module with your publisher key
5. Reload via `/v1/admin/reload-modules` or restart

## License

MIT

## Links

- IPFS Distribution: `gateway.cryft.network/ipns/cryftee`
- Documentation: Coming soon
