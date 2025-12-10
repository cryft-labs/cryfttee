# CryftTEE Workspace Instructions

## Project Overview

This workspace contains **cryfttee** - a Rust-based TEE-style sidecar application that:

- Acts as a host/runtime for arbitrary WASM modules (signing, fraud proofs, policy engines)
- Loads and manages WASM modules from a module directory driven by a signed global manifest
- Exposes a versioned API (`/v1/...`) over UDS (default) or HTTPS
- Provides a kiosk web UI on port 3232 for module management
- Integrates with Web3Signer and cryftgo staking/TLS wiring
- **Follows Power of Ten rules** for safe, verifiable code

## Architecture

### Core Components

- **cryfttee-runtime/**: Main Rust application
  - `src/main.rs` - Application entry point, API listeners, UI server
  - `src/lib.rs` - Core runtime logic exports
  - `src/limits.rs` - **Power of Ten static bounds for runtime**
  - `src/runtime/` - Module registry, loader, and dispatch
  - `src/wasm_api/` - WASM module traits and ABIs
  - `src/storage/` - Module metadata, hashes, signatures indexing
  - `src/http/` - HTTP/HTTPS server (axum-based)
  - `src/uds/` - Unix Domain Socket listener
  - `src/config/` - Environment and CLI configuration

- **modules/**: WASM module directory
  - `manifest.json` - Global module registry
  - `bls_tls_signer_v1/` - BLS/TLS signing module
  - `debug_v1/` - Debug and diagnostics module
  - `llm_chat_v1/` - LLM chat integration module
  - `ipfs_v1/` - IPFS storage module
  - `redeemable_codes_v1/` - Redeemable codes module

- **ui/**: Kiosk web interface assets
- **config/**: Configuration files
  - `cryftee.example.toml` - Main configuration template
  - `trust.toml` - Publisher trust configuration
- **scripts/**: Build and deployment scripts
  - `build.sh` - Module build script (produces `module.wasm`)

## Key Design Principles

1. **Stateless**: No persistent secrets or database; relies on Web3Signer for durable state
2. **Modular**: All chain-specific logic lives in WASM modules, not in Rust core
3. **Safe**: Module load/unload failures never crash the core; graceful error handling
4. **Auditable**: Runtime hashes and receipts for public verification
5. **Versioned**: Schema-driven compatibility with `minCryftteeVersion` enforcement
6. **Power of Ten Compliant**: Static bounds, no unsafe code, comprehensive linting

## Power of Ten Rules Implementation

CryftTEE implements NASA/JPL's Power of Ten rules for safety-critical code:

### Clippy Lints (Cargo.toml)

```toml
[lints.rust]
unsafe_code = "forbid"          # No unsafe code allowed
missing_docs = "warn"           # Document public APIs

[lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
unwrap_used = "warn"            # Prefer proper error handling
expect_used = "warn"            # Prefer proper error handling  
panic = "warn"                  # No panics in production code
indexing_slicing = "warn"       # Use .get() for safe access
arithmetic_side_effects = "warn" # Check for overflow
cast_possible_truncation = "warn"
cast_sign_loss = "warn"
float_arithmetic = "warn"       # Avoid floats in safety-critical code
```

### Self-Contained Limits Architecture

**Critical Design Decision**: Each component declares its own limits internally:

- **Runtime** (`src/limits.rs`): HTTP, module management, config, backend limits
- **Each WASM Module** (`lib.rs`): Domain-specific limits declared at top of file

The runtime does NOT enforce module-specific limits. Each module is responsible for:
- Input validation against its declared bounds
- Output size limiting
- Resource consumption control

Example from `bls_tls_signer_v1/src/lib.rs`:
```rust
// MODULE LIMITS (Power of Ten Rule 2: Fixed Bounds)
const MAX_BLS_MESSAGE_SIZE: usize = 32 * 1024;
const MAX_TLS_DIGEST_SIZE: usize = 64;
const MAX_KEY_LABEL_LEN: usize = 128;
const MAX_BLS_KEYS: usize = 100;
// ... etc
```

### Key Runtime Limits (`src/limits.rs`)

- `MAX_REQUEST_BODY_SIZE`: 1 MB
- `MAX_WASM_SIZE`: 10 MB
- `MAX_MODULES`: 100
- `MAX_CONFIG_SIZE`: 1 MB
- `WEB3SIGNER_TIMEOUT_SECS`: 30s

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
- `GET /v1/modules` - List available modules
- `POST /v1/modules/{id}/enable` - Enable a module
- `POST /v1/modules/{id}/disable` - Disable a module
- `POST /v1/modules/{id}/invoke` - Invoke module endpoint

## Environment Variables

### Core Configuration
- `CRYFTTEE_MODULE_DIR` - Root path for modules/
- `CRYFTTEE_MANIFEST_PATH` - Path to manifest.json
- `CRYFTTEE_UI_DIR` - Path to UI static assets

### Trust Configuration
- `CRYFTTEE_TRUST_CONFIG` - Path to trust roots (default: `config/trust.toml`)

### Transport Configuration
- `CRYFTTEE_API_TRANSPORT` - "uds" (default) or "https"
- `CRYFTTEE_UDS_PATH` - UDS socket path (default: /var/run/cryfttee.sock)
- `CRYFTTEE_HTTP_ADDR` - HTTP bind address (default: 0.0.0.0:3232)
- `CRYFTTEE_TLS_CERT` - TLS certificate path
- `CRYFTTEE_TLS_KEY` - TLS private key path

### Web3Signer Configuration
- `CRYFTTEE_WEB3SIGNER_URL` - Primary Web3Signer URL (default: http://localhost:9000)
- `CRYFTTEE_WEB3SIGNER_FALLBACK_URLS` - Comma-separated fallback URLs

### Binary Attestation
- `CRYFTTEE_VERIFIED_BINARY_HASH` - Externally-verified binary hash (set by cryftgo)

## Web3Signer Fallback Support

CryftTEE supports automatic failover between Web3Signer instances:

### Configuration

```toml
[web3signer]
url = "http://localhost:9000"
fallback_urls = ["http://100.111.2.1:9000"]
```

### Behavior

1. On startup, runtime checks primary URL health
2. If primary fails, tries each fallback URL in order
3. First healthy URL becomes `web3signer_active_url`
4. Periodic health checks (every 30s) can switch back to primary
5. Status endpoint reports which URL is currently active

### Default Configuration

- Primary: `http://localhost:9000`
- Fallback: `http://100.111.2.1:9000` (Cryft remote signer)

## Trust Configuration

The trust system controls module signature and publisher verification:

### Default Path

`config/trust.toml` (automatically loaded if exists)

### Configuration Options

```toml
[trust_policy]
enforce_known_publishers = false  # Require known publisher IDs
enforce_signatures = false        # Require valid signatures

[publishers]
# Publisher ID to public key mappings
"cryft-labs" = "ed25519:abc123..."
```

### Development Mode

For development, both enforcement flags default to `false`, allowing unsigned modules.

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

Each module directory contains:
- `module.json` - Module metadata
- `module.wasm` - Compiled WASM binary (canonical filename)
- `gui/index.html` - Optional module-specific UI with tile visibility support
- `src/lib.rs` - Rust source with Power of Ten limits

## Module GUI Tile Visibility System

Module GUIs support user-customizable tile visibility to declutter the workspace:

### Features
- **Hide tiles**: Click ✕ button on any card header to hide it
- **Show hidden tiles**: Click chip in toolbar to restore hidden tile
- **Show All**: Button appears when tiles are hidden
- **Reset Layout**: Restores all tiles to visible

### Implementation Pattern
Each card-based module GUI (`gui/index.html`) includes:

1. **CSS**: Tile toolbar, hide button, and hidden state styles
2. **HTML**: Toolbar at top, `data-tile-id` and `data-tile-name` on each card
3. **JavaScript**: `initTileVisibility()` function managing localStorage persistence

### Storage
Hidden tiles are stored per-module in localStorage:
- Key: `cryfttee_hidden_tiles_{module_id}`
- Value: JSON array of hidden tile IDs

### Adding to New Modules
1. Add tile visibility CSS block (see existing modules)
2. Add toolbar HTML before `cards-grid`
3. Add `data-tile-id` and `data-tile-name` to each `.card`
4. Add `tile-hide-btn` button in each `.card-header`
5. Add `initTileVisibility()` JavaScript function

## Module Lifecycle

### Loading
1. Runtime reads `manifest.json`
2. For each module, validates `minCryftteeVersion` compatibility
3. Loads `module.json` from module directory
4. Optionally verifies hash and signature (based on trust config)
5. Loads WASM binary into wasmtime

### Enable/Disable
- `POST /v1/modules/{id}/enable` - Marks module as active
- `POST /v1/modules/{id}/disable` - Marks module as inactive
- State persisted in module registry
- Trust verification re-checked on enable

### Dispatch
- `POST /v1/modules/{id}/invoke` with `{"endpoint": "...", "data": {...}}`
- Runtime routes to correct WASM module
- Module returns JSON response

## Build System

### Building Modules

```bash
./scripts/build.sh [module_name]
```

The build script:
1. Compiles Rust to `wasm32-unknown-unknown`
2. Renames output to canonical `module.wasm`
3. Removes old WASM files if renamed

### Output Convention

All modules produce `module.wasm` (not `module_name.wasm`) for consistency.

## Development Guidelines

### Code Quality
- Use Rust 2021 edition with stable toolchain
- Run `cargo clippy` and fix all warnings before committing
- Follow Power of Ten limits pattern in all modules
- Prefer `.get()` over indexing, `?` over `.unwrap()`

### Module Development
- Declare all limits as `const` at top of `lib.rs`
- Comment limits with Power of Ten rule reference
- Validate all inputs against declared bounds
- Return structured JSON errors, never panic

### Security
- Keep secrets out of logs, API responses, and UI
- All WASM loading uses wasmtime sandboxing
- Signatures use Ed25519/BLS verification
- Trust config controls signature enforcement

### Testing
- Test module load/unload cycles
- Test with both local and remote Web3Signer
- Test trust config enforcement modes
- Verify Power of Ten bounds are enforced
