# CryftTEE

A Rust-based TEE-style sidecar for WASM module management, designed to integrate with `cryftgo` and Web3Signer.

## Overview

CryftTEE is a stateless runtime that:
- Loads and manages signed WASM modules from a manifest
- Provides BLS/TLS staking key operations via modular plugins
- Exposes a versioned API over UDS (Unix Domain Socket) or HTTPS
- Includes a kiosk web UI for module management on port 3232
- Supports per-module GUIs rendered as tabs in the kiosk interface
- Enforces version compatibility and publisher trust

## Architecture

```
cryfttee-runtime/           # Rust TEE runtime (v0.4.0)
├── src/
│   ├── main.rs            # Entry point, server bootstrap
│   ├── lib.rs             # Core exports
│   ├── config/            # Configuration parsing
│   │   ├── mod.rs
│   │   └── types.rs
│   ├── http/              # HTTP/HTTPS server (axum)
│   │   ├── mod.rs
│   │   ├── api.rs         # JSON API handlers
│   │   └── kiosk.rs       # Kiosk UI endpoints
│   ├── uds/               # Unix Domain Socket server
│   │   ├── mod.rs
│   │   └── service.rs
│   ├── runtime/           # Module registry, loader, dispatch
│   │   ├── mod.rs
│   │   ├── registry.rs    # Module tracking and defaults
│   │   ├── loader.rs      # WASM loading with wasmtime
│   │   └── dispatch.rs    # Operation routing to modules
│   ├── signing/           # Blockchain signing operations
│   │   ├── mod.rs
│   │   └── blockchain_state.rs
│   ├── storage/           # Manifest parsing, hashing, signatures
│   │   ├── mod.rs
│   │   └── index.rs
│   └── wasm_api/          # WASM module traits and types
│       ├── mod.rs
│       └── staking.rs

modules/                   # WASM modules directory
├── manifest.json          # Global module registry
├── bls_tls_signer_v1/     # BLS + TLS signing module (v1.2.0)
│   ├── Cargo.toml
│   ├── module.json        # Module metadata
│   ├── module.wasm        # Compiled WASM
│   ├── README.md
│   ├── src/
│   │   └── lib.rs         # Module implementation
│   └── gui/
│       └── index.html     # Module web GUI
├── debug_v1/              # Debugging and diagnostics module
│   ├── Cargo.toml
│   ├── module.json
│   ├── README.md
│   ├── src/
│   │   └── lib.rs
│   └── gui/
│       └── index.html
├── llm_chat_v1/           # LLM chat interface module
│   ├── Cargo.toml
│   ├── module.json
│   ├── src/
│   │   └── lib.rs
│   └── gui/
│       └── index.html
└── ipfs_v1/               # IPFS embedded node module (v2.0.0)
    ├── Cargo.toml
    ├── module.json        # Module metadata
    ├── module.wasm        # Compiled WASM
    ├── README.md
    ├── src/
    │   └── lib.rs         # Embedded IPFS node implementation
    └── gui/               # Modular GUI structure
        ├── index.html     # Main HTML shell
        ├── styles.css     # Shared styles
        └── js/
            ├── config.js  # Configuration constants
            ├── utils.js   # Utility functions
            ├── api.js     # API wrapper
            ├── app.js     # Main application
            └── tabs/      # Tab modules
                ├── node.js     # Node control
                ├── pins.js     # Pin management
                ├── add.js      # Add content
                ├── peers.js    # Peer management
                ├── ipns.js     # IPNS publishing
                └── settings.js # Settings

ui/                        # Kiosk web interface
├── index.html
├── app.js
└── styles.css

config/                    # Configuration examples
├── cryfttee.example.toml
└── trust.toml

scripts/                   # Deployment scripts
├── deploy-web3signer.sh   # Linux/macOS Web3Signer setup
└── Deploy-Web3Signer.ps1  # Windows Web3Signer setup
```

## Available Modules

| Module | Version | Description | Capabilities |
|--------|---------|-------------|--------------|
| `bls_tls_signer_v1` | 1.2.0 | BLS + TLS staking module with Web3Signer integration and module signing | `bls_register`, `bls_sign`, `bls_verify`, `tls_register`, `tls_sign`, `tls_verify`, `module_signing_key`, `sign_module`, `verify_module`, `hash_module` |
| `debug_v1` | 1.0.0 | Debugging and diagnostics for runtime inspection | `debug_echo`, `debug_info`, `debug_panic` |
| `llm_chat_v1` | 1.0.0 | Interactive LLM chat interface for runtime assistance | `llm_chat`, `llm_stream` |
| `ipfs_v1` | 2.0.0 | Standalone embedded IPFS node (Full/Light modes) | `node_init`, `node_start`, `node_stop`, `node_status`, `node_config`, `ipfs_add`, `ipfs_cat`, `ipfs_get`, `ipfs_pin`, `ipfs_unpin`, `ipfs_ls`, `ipfs_stat`, `ipns_publish`, `ipns_resolve`, `ipns_keys`, `peer_connect`, `peer_disconnect`, `peer_list`, `dht_find_peer`, `dht_find_providers`, `dht_provide` |

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
cd cryfttee-runtime
cargo build --release
```

### Build WASM Modules

```bash
# Build all modules
cd modules/bls_tls_signer_v1
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/bls_tls_signer_v1.wasm module.wasm

cd ../debug_v1
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/debug_v1.wasm module.wasm

cd ../llm_chat_v1
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/llm_chat_v1.wasm module.wasm

cd ../ipfs_v1
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/ipfs_v1.wasm module.wasm
```

### Run

```bash
# With default settings (UDS transport)
./target/release/cryfttee

# With custom module directory
./target/release/cryfttee --module-dir ./modules

# With HTTPS transport
./target/release/cryfttee \
  --api-transport https \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTTEE_MODULE_DIR` | `./modules` | Module directory path |
| `CRYFTTEE_MANIFEST_PATH` | `{module_dir}/manifest.json` | Manifest file path |
| `CRYFTTEE_UI_DIR` | `./ui` | UI static assets path |
| `CRYFTTEE_TRUST_CONFIG` | - | Trust configuration path |
| `CRYFTTEE_API_TRANSPORT` | `uds` | API transport: `uds` or `https` |
| `CRYFTTEE_UDS_PATH` | `/tmp/cryfttee.sock` | UDS socket path |
| `CRYFTTEE_HTTP_ADDR` | `0.0.0.0:3232` | HTTP bind address |
| `CRYFTTEE_TLS_CERT` | - | TLS certificate path |
| `CRYFTTEE_TLS_KEY` | - | TLS private key path |

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
      "minCryftteeVersion": "0.4.0",
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
| `minCryftteeVersion` | Yes | Minimum compatible runtime version |
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
- **Version Enforcement**: `minCryftteeVersion` prevents incompatible loads
- **Hash Verification**: Module code is verified against manifest hash
- **Graceful Failures**: Module errors never crash the runtime
- **GUI Sandboxing**: Module GUIs run in sandboxed iframes
- **GitHub Verification**: Modules can be verified via GitHub signatures

## Publisher Trust & GitHub Verification

CryftTEE supports multiple methods to verify module authenticity:

### 1. Traditional Ed25519 Signatures

Publishers sign modules with Ed25519 keys registered in `trust.toml`:

```toml
[[publishers]]
id        = "cryft-labs"
algo      = "ed25519"
publicKey = "BASE64_PUBLIC_KEY_HERE"
```

### 2. GitHub-Based Verification

Verify modules using GitHub's signing infrastructure:

```toml
[[github_publishers]]
id                     = "cryft-labs"
github_org             = "cryft-labs"
allowed_repos          = ["cryfttee-modules"]
require_signed_commits = true      # GPG/SSH signed commits
require_actions_build  = true      # Built by GitHub Actions
allowed_workflows      = ["release.yml"]
allowed_signers        = []        # Empty = any org member
allow_prereleases      = false
```

#### GitHub Verification Methods

| Method | Description | Trust Level |
|--------|-------------|-------------|
| **Signed Commits** | GPG or SSH signature on commit | High - requires verified key |
| **GitHub Actions** | Module built by CI workflow | High - reproducible builds |
| **Attestations** | Sigstore/cosign attestations | Highest - cryptographic provenance |

#### Setting Up GPG Commit Signing

```bash
# Generate GPG key (if needed)
gpg --full-generate-key

# Add key to GitHub
gpg --armor --export YOUR_KEY_ID | pbcopy
# Paste in GitHub Settings > SSH and GPG keys

# Configure Git to sign commits
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true

# Verify a commit is signed
git log --show-signature -1
```

#### Setting Up SSH Commit Signing

```bash
# Use existing SSH key or generate new one
ssh-keygen -t ed25519 -C "your_email@example.com"

# Add to GitHub as a Signing Key (not just Authentication)
# GitHub Settings > SSH and GPG keys > New SSH key > Key type: Signing Key

# Configure Git
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

#### GitHub Actions Workflow for Module Releases

```yaml
# .github/workflows/release.yml
name: Release Module
on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write  # For attestations
      
    steps:
      - uses: actions/checkout@v4
      
      - name: Build WASM module
        run: |
          cargo build --target wasm32-unknown-unknown --release
          
      - name: Compute hash
        run: |
          sha256sum target/wasm32-unknown-unknown/release/*.wasm > checksums.sha256
          
      - name: Create attestation
        uses: actions/attest-build-provenance@v1
        with:
          subject-path: 'target/wasm32-unknown-unknown/release/*.wasm'
          
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            target/wasm32-unknown-unknown/release/*.wasm
            checksums.sha256
```

### Verification Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                    Module Verification                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Load module from manifest.json                              │
│      └─▶ Extract publisherId, hash, signature                    │
│                                                                  │
│   2. Check publisher type                                        │
│      ├─▶ Ed25519: Verify signature against public key            │
│      └─▶ GitHub: Query GitHub API for verification               │
│                                                                  │
│   3. GitHub verification checks:                                 │
│      ├─▶ Repository in allowed list?                             │
│      ├─▶ Commit signature verified by GitHub?                    │
│      ├─▶ Signer in allowed list?                                 │
│      ├─▶ Built by allowed workflow? (if required)                │
│      └─▶ Attestation valid? (if using Sigstore)                  │
│                                                                  │
│   4. Result: Module trusted or rejected                          │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Environment Variables

```bash
# GitHub API token for higher rate limits (optional)
export CRYFTTEE_GITHUB_TOKEN="ghp_xxxxxxxxxxxx"

# For GitHub Enterprise
export CRYFTTEE_GITHUB_API_URL="https://github.mycompany.com/api/v3"
```

## Development

### Project Structure

```
cryfttee-runtime/src/
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
- IPFS Distribution: `gateway.cryft.network/ipns/cryfttee`
- Documentation: Coming soon
