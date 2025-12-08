# CryftTEE Environment Variables

Complete reference for all environment variables that CryftTEE accepts.

## Overview

**CryftTEE is automatically started by CryftGo during node initialization.** CryftGo manages the cryfttee process lifecycle and sets all necessary environment variables. Manual/standalone startup is supported but only for edge cases (debugging, development, or specialized deployments).

## Configuration Priority

CryftTEE loads configuration in this order (highest to lowest priority):
1. **CLI flags** (`--flag=value`)
2. **Environment variables** (`CRYFTTEE_*`) ← CryftGo sets these automatically
3. **Config file** (if `--config-file` specified)
4. **Default values**

**In normal operation, CryftGo controls cryfttee entirely via environment variables.**

---

## Core Environment Variables

### Instance & Identity

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTTEE_INSTANCE_NAME` | `cryfttee-01` | Instance name for multi-instance deployments |
| `CRYFTTEE_NODE_ID` | (none) | Node ID for key derivation paths (typically cryftgo node ID, e.g., `NodeID-XXX`) |
| `CRYFTTEE_VERIFIED_BINARY_HASH` | (none) | Binary hash verified by cryftgo before launch. Format: `sha256:<hex>`. **Critical for attestation security.** |

### Module Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTTEE_MODULE_DIR` | `modules` | Root path for modules directory |
| `CRYFTTEE_MANIFEST_PATH` | `{module_dir}/manifest.json` | Path to module manifest file |
| `CRYFTTEE_MODULES` | (all) | **Comma-separated list of module IDs to activate on startup**. If not set, all modules from manifest are loaded. Example: `bls_tls_signer_v1,debug_v1` |
| `CRYFTTEE_TRUST_CONFIG` | (none) | Path to `trust.toml` file for publisher verification |

### API Transport

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTTEE_API_TRANSPORT` | `uds` | API transport mode: `uds` (Unix Domain Socket) or `https` |
| `CRYFTTEE_UDS_PATH` | `/tmp/cryfttee.sock` | UDS socket path (when transport=uds) |
| `CRYFTTEE_HTTP_ADDR` | `0.0.0.0:8443` | HTTP/HTTPS bind address for API |
| `CRYFTTEE_TLS_CERT` | (none) | TLS certificate path (required for https transport) |
| `CRYFTTEE_TLS_KEY` | (none) | TLS private key path (required for https transport) |

### UI Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTTEE_UI_DIR` | `ui` | Path to kiosk UI static assets |
| `CRYFTTEE_UI_ADDR` | `0.0.0.0:3232` | Kiosk UI listen address |

### Web3Signer Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTTEE_WEB3SIGNER_URL` | `http://localhost:9000` | Web3Signer API URL |
| `CRYFTTEE_WEB3SIGNER_TIMEOUT` | `30` | Request timeout in seconds |

### Vault Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTTEE_VAULT_URL` | (none) | HashiCorp Vault URL |
| `CRYFTTEE_VAULT_TOKEN` | (none) | Vault authentication token |

### Key Derivation

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTTEE_KEY_SEED` | (none) | Hex-encoded seed for deterministic key derivation. Used by signing modules. |
| `CRYFTTEE_NODE_ID` | (none) | Node ID for key derivation paths. Typically the cryftgo NodeID. |
| `CRYFTTEE_EXPECTED_BLS_PUBKEY` | (none) | Expected BLS public key (hex, with 0x prefix). Set by CryftGo on restart to verify key availability. |
| `CRYFTTEE_EXPECTED_TLS_PUBKEY` | (none) | Expected TLS/ECDSA public key (hex, with 0x prefix). Set by CryftGo on restart to verify key availability. |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTTEE_LOG_LEVEL` | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace` |
| `CRYFTTEE_LOG_JSON` | `false` | Enable JSON structured logging |
| `CRYFTTEE_VERBOSE` | `false` | Enable verbose logging (shorthand for `debug` level) |

### Security & Attestation

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTTEE_REQUIRE_ATTESTATION` | `false` | Require attestation for all module operations |
| `CRYFTTEE_VERIFIED_BINARY_HASH` | (none) | Hash of cryfttee binary, verified by cryftgo before launch |

### Config File (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYFTTEE_CONFIG_FILE` | (none) | Path to config file (JSON/YAML/TOML) |
| `CRYFTTEE_CONFIG_CONTENT` | (none) | Base64-encoded config content (for Kubernetes) |
| `CRYFTTEE_CONFIG_CONTENT_TYPE` | `json` | Config content type: `json`, `yaml`, `toml` |

---

## CryftGo Integration (Default Behavior)

**CryftGo automatically starts and manages cryfttee during node initialization.** You don't need to manually start cryfttee or set environment variables in normal operation.

### Minimum Required Environment Variables

For CryftGo to properly initialize cryfttee, these environment variables **must** be set:

| Variable | Required | Description |
|----------|----------|-------------|
| `CRYFTTEE_NODE_ID` | **Yes** | Node identity (e.g., `NodeID-ABC123...`) |
| `CRYFTTEE_MODULES` | **Yes** | Modules to load (e.g., `bls_tls_signer_v1`) |
| `CRYFTTEE_WEB3SIGNER_URL` | **Yes** | KeyVault Web3Signer endpoint |
| `CRYFTTEE_UDS_PATH` | **Yes** | Unix socket for CryftGo ↔ CryftTEE communication |
| `CRYFTTEE_VERIFIED_BINARY_HASH` | Recommended | Binary hash for attestation security |
| `CRYFTTEE_EXPECTED_BLS_PUBKEY` | Conditional | Expected BLS public key (if known) |
| `CRYFTTEE_EXPECTED_TLS_PUBKEY` | Conditional | Expected TLS public key (if known) |

### Key Initialization Flow

CryftGo follows this flow when initializing cryfttee for validator operations:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CryftGo Startup                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Check if BLS/TLS public keys are saved from previous run    │
│     (stored in CryftGo's node config/state)                     │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌──────────────────────────┐    ┌──────────────────────────────────┐
│  Keys FOUND (restart)    │    │  Keys NOT FOUND (first start)    │
│                          │    │                                  │
│  Set env vars:           │    │  Start cryfttee without          │
│  CRYFTTEE_EXPECTED_      │    │  expected key env vars           │
│    BLS_PUBKEY=0x...      │    │                                  │
│  CRYFTTEE_EXPECTED_      │    │                                  │
│    TLS_PUBKEY=0x...      │    │                                  │
└──────────────────────────┘    └──────────────────────────────────┘
              │                               │
              └───────────────┬───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Start cryfttee subprocess with environment variables        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. CryftTEE connects to Web3Signer, checks available keys      │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌──────────────────────────┐    ┌──────────────────────────────────┐
│  Expected keys MATCH     │    │  Keys NOT available or           │
│  keys in Web3Signer      │    │  no expected keys provided       │
│                          │    │                                  │
│  ✓ Ready for signing     │    │  CryftTEE requests key           │
│                          │    │  generation from Web3Signer      │
└──────────────────────────┘    └──────────────────────────────────┘
                                              │
                                              ▼
                              ┌──────────────────────────────────┐
                              │  4. New keys generated:          │
                              │     - BLS key for staking        │
                              │     - TLS key for node identity  │
                              │                                  │
                              │  CryftTEE returns public keys    │
                              │  to CryftGo via UDS API          │
                              └──────────────────────────────────┘
                                              │
                                              ▼
                              ┌──────────────────────────────────┐
                              │  5. CryftGo SAVES public keys    │
                              │     to node state/config for     │
                              │     future restarts              │
                              └──────────────────────────────────┘
```

### What CryftGo Does Automatically

1. **Computes binary hash** before launch (for attestation security)
2. **Checks for saved public keys** from previous runs
3. **Spawns cryfttee** with appropriate environment variables
4. **Verifies or requests keys** via UDS API
5. **Saves new public keys** if generated (for restart persistence)
6. **Monitors health** and restarts if needed

### Environment Variables Set by CryftGo

**First startup (no saved keys):**

```go
cmd := exec.Command(cryftteeePath)
cmd.Env = append(os.Environ(),
    "CRYFTTEE_VERIFIED_BINARY_HASH="+hashStr,
    "CRYFTTEE_NODE_ID="+nodeID,
    "CRYFTTEE_MODULES=bls_tls_signer_v1",
    "CRYFTTEE_WEB3SIGNER_URL="+web3signerURL,
    "CRYFTTEE_UDS_PATH=/var/run/cryfttee.sock",
    "CRYFTTEE_LOG_JSON=true",
    // No EXPECTED_*_PUBKEY - CryftGo will request key generation
)
```

**Restart (with saved keys):**

```go
cmd := exec.Command(cryftteeePath)
cmd.Env = append(os.Environ(),
    "CRYFTTEE_VERIFIED_BINARY_HASH="+hashStr,
    "CRYFTTEE_NODE_ID="+nodeID,
    "CRYFTTEE_MODULES=bls_tls_signer_v1",
    "CRYFTTEE_WEB3SIGNER_URL="+web3signerURL,
    "CRYFTTEE_UDS_PATH=/var/run/cryfttee.sock",
    "CRYFTTEE_LOG_JSON=true",
    // Pass expected keys so CryftTEE can verify they're available
    "CRYFTTEE_EXPECTED_BLS_PUBKEY="+savedBLSPubkey,
    "CRYFTTEE_EXPECTED_TLS_PUBKEY="+savedTLSPubkey,
)
```

### CryftGo Pseudocode for Key Management

```go
func initializeCryfttee(nodeID string, config CryftGoConfig) error {
    // Step 1: Check for saved keys from previous run
    savedBLS := loadSavedKey("bls_pubkey")
    savedTLS := loadSavedKey("tls_pubkey")
    
    // Step 2: Build environment variables
    env := []string{
        "CRYFTTEE_VERIFIED_BINARY_HASH=" + computeBinaryHash(),
        "CRYFTTEE_NODE_ID=" + nodeID,
        "CRYFTTEE_MODULES=bls_tls_signer_v1",
        "CRYFTTEE_WEB3SIGNER_URL=" + config.Web3SignerURL,
        "CRYFTTEE_UDS_PATH=" + config.UDSPath,
    }
    
    // Step 3: If we have saved keys, tell CryftTEE to expect them
    if savedBLS != "" {
        env = append(env, "CRYFTTEE_EXPECTED_BLS_PUBKEY=" + savedBLS)
    }
    if savedTLS != "" {
        env = append(env, "CRYFTTEE_EXPECTED_TLS_PUBKEY=" + savedTLS)
    }
    
    // Step 4: Start cryfttee
    cmd := exec.Command(cryftteeePath)
    cmd.Env = env
    cmd.Start()
    
    // Step 5: Wait for cryfttee to be ready
    waitForUDS(config.UDSPath)
    
    // Step 6: Get/verify keys via API
    client := NewCryftteeClient(config.UDSPath)
    
    if savedBLS == "" || savedTLS == "" {
        // First run: request key generation
        keys, err := client.GenerateKeys(nodeID)
        if err != nil {
            return err
        }
        
        // CRITICAL: Save keys for future restarts
        saveKey("bls_pubkey", keys.BLSPubkey)
        saveKey("tls_pubkey", keys.TLSPubkey)
        
        log.Info("Generated and saved new keys",
            "bls", keys.BLSPubkey[:16]+"...",
            "tls", keys.TLSPubkey[:16]+"...")
    } else {
        // Restart: verify expected keys are available
        status, err := client.VerifyKeys(savedBLS, savedTLS)
        if err != nil || !status.KeysAvailable {
            return fmt.Errorf("expected keys not available in Web3Signer")
        }
        log.Info("Verified existing keys are available")
    }
    
    return nil
}
```

### CryftGo Configuration

Configure cryfttee behavior in your CryftGo config (e.g., `node.json`):

```json
{
  "cryfttee": {
    "enabled": true,
    "web3signer-url": "http://keyvault:9000",
    "modules": ["bls_tls_signer_v1"],
    "key-seed": "optional-hex-seed-for-deterministic-keys"
  }
}
```

---

## Standalone Startup (Edge Cases Only)

> **Note:** Manual cryfttee startup is only for debugging, development, or specialized deployments. In production, let CryftGo manage cryfttee.

### Basic Standalone Startup

```bash
# Start cryfttee with only the BLS/TLS signer module
export CRYFTTEE_MODULES="bls_tls_signer_v1"
export CRYFTTEE_WEB3SIGNER_URL="http://keyvault:9000"
export CRYFTTEE_NODE_ID="NodeID-ABC123..."
./cryfttee
```

### Full cryftgo Integration

```bash
# All variables cryftgo would set when spawning cryfttee
export CRYFTTEE_VERIFIED_BINARY_HASH="sha256:abc123..."  # Computed by cryftgo
export CRYFTTEE_NODE_ID="NodeID-ABC123..."
export CRYFTTEE_INSTANCE_NAME="cryfttee-validator-01"
export CRYFTTEE_MODULES="bls_tls_signer_v1"
export CRYFTTEE_WEB3SIGNER_URL="http://100.111.2.1:9000"
export CRYFTTEE_KEY_SEED="deadbeef..."  # For deterministic key derivation
export CRYFTTEE_API_TRANSPORT="uds"
export CRYFTTEE_UDS_PATH="/var/run/cryfttee.sock"
export CRYFTTEE_LOG_LEVEL="info"
export CRYFTTEE_LOG_JSON="true"
./cryfttee
```

### With HashiCorp Vault

```bash
export CRYFTTEE_MODULES="bls_tls_signer_v1"
export CRYFTTEE_WEB3SIGNER_URL="http://keyvault:9000"
export CRYFTTEE_VAULT_URL="http://keyvault:8200"
export CRYFTTEE_VAULT_TOKEN="hvs.xxx..."
export CRYFTTEE_NODE_ID="NodeID-ABC123..."
./cryfttee
```

### HTTPS API Mode

```bash
export CRYFTTEE_API_TRANSPORT="https"
export CRYFTTEE_HTTP_ADDR="0.0.0.0:8443"
export CRYFTTEE_TLS_CERT="/etc/cryfttee/tls.crt"
export CRYFTTEE_TLS_KEY="/etc/cryfttee/tls.key"
./cryfttee
```

### Development/Debug Mode (Standalone)

```bash
export CRYFTTEE_MODULES="bls_tls_signer_v1,debug_v1"
export CRYFTTEE_LOG_LEVEL="debug"
export CRYFTTEE_WEB3SIGNER_URL="http://localhost:9000"
./cryfttee
```

---

## Available Modules

The `CRYFTTEE_MODULES` variable controls which modules are loaded:

| Module ID | Description | Required For |
|-----------|-------------|--------------|
| `bls_tls_signer_v1` | BLS/TLS signing via Web3Signer | Validator staking operations |
| `debug_v1` | Debug/testing module | Development only |
| `llm_chat_v1` | LLM chat interface | Optional AI features |

**Default:** When CryftGo starts cryfttee for validator nodes, it enables `bls_tls_signer_v1` automatically.

---

## Config File Format (Alternative to Env Vars)

If you prefer a config file over environment variables:

```json
{
  "api": {
    "transport": "uds",
    "uds-path": "/var/run/cryfttee.sock"
  },
  "modules": {
    "enabled": ["bls_tls_signer_v1"],
    "module-dir": "/opt/cryfttee/modules"
  },
  "web3signer": {
    "url": "http://keyvault:9000",
    "timeout": 30
  },
  "logging": {
    "level": "info",
    "json": true
  }
}
```

Then launch with:
```bash
./cryfttee --config-file=/etc/cryfttee/config.json
```

Or via environment:
```bash
export CRYFTTEE_CONFIG_FILE="/etc/cryfttee/config.json"
./cryfttee
```

---

## Quick Reference

**For CryftGo operators:** Configure in your node config, CryftGo handles the rest.

### Minimum Required for CryftGo Integration

```bash
# REQUIRED - Must be set by CryftGo
CRYFTTEE_NODE_ID=NodeID-XXX                      # Node identity
CRYFTTEE_MODULES=bls_tls_signer_v1               # Signer module
CRYFTTEE_WEB3SIGNER_URL=http://keyvault:9000     # KeyVault endpoint
CRYFTTEE_UDS_PATH=/var/run/cryfttee.sock         # IPC socket

# RECOMMENDED - Security
CRYFTTEE_VERIFIED_BINARY_HASH=sha256:xxx         # Binary attestation

# CONDITIONAL - Set on restart if keys were previously generated
CRYFTTEE_EXPECTED_BLS_PUBKEY=0x...               # Expected BLS key
CRYFTTEE_EXPECTED_TLS_PUBKEY=0x...               # Expected TLS key
```

### Key Lifecycle Summary

| Scenario | Expected Key Vars | CryftGo Action |
|----------|-------------------|----------------|
| **First start** | Not set | Request key generation, save returned pubkeys |
| **Restart** | Set to saved values | Verify keys available in Web3Signer |
| **Key mismatch** | Set but don't match | Error - manual intervention required |

**For standalone/debug:** Set these minimum variables:

```bash
# Minimum for validator signing (standalone)
CRYFTTEE_MODULES=bls_tls_signer_v1
CRYFTTEE_WEB3SIGNER_URL=http://keyvault:9000
CRYFTTEE_NODE_ID=NodeID-XXX
```
