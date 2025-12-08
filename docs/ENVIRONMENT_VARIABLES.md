# CryftTEE Environment Variables

Complete reference for all environment variables that CryftTEE accepts.

## Configuration Priority

CryftTEE loads configuration in this order (highest to lowest priority):
1. **CLI flags** (`--flag=value`)
2. **Environment variables** (`CRYFTTEE_*`) ← cryftgo sets these
3. **Config file** (if `--config-file` specified)
4. **Default values**

By default, **cryftgo controls cryfttee via environment variables**. Config files are optional.

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

## Usage Examples

### Basic Startup with Specific Modules

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

### Development/Debug Mode

```bash
export CRYFTTEE_MODULES="bls_tls_signer_v1,debug_v1"
export CRYFTTEE_LOG_LEVEL="debug"
export CRYFTTEE_WEB3SIGNER_URL="http://localhost:9000"
./cryfttee
```

---

## cryftgo Launch Integration

When cryftgo spawns cryfttee as a subprocess, it should:

1. **Compute binary hash** before launch:
   ```go
   binaryBytes, _ := os.ReadFile(cryftteeePath)
   hash := sha256.Sum256(binaryBytes)
   hashStr := fmt.Sprintf("sha256:%x", hash)
   ```

2. **Set required environment variables**:
   ```go
   cmd := exec.Command(cryftteeePath)
   cmd.Env = append(os.Environ(),
       "CRYFTTEE_VERIFIED_BINARY_HASH="+hashStr,
       "CRYFTTEE_NODE_ID="+nodeID,
       "CRYFTTEE_MODULES=bls_tls_signer_v1",
       "CRYFTTEE_WEB3SIGNER_URL="+web3signerURL,
       "CRYFTTEE_UDS_PATH=/var/run/cryfttee.sock",
       "CRYFTTEE_LOG_JSON=true",
   )
   ```

3. **Communicate via UDS** (default) for API calls

---

## Module-Specific Configuration

The `CRYFTTEE_MODULES` variable controls which modules are loaded:

| Module ID | Description | Required For |
|-----------|-------------|--------------|
| `bls_tls_signer_v1` | BLS/TLS signing via Web3Signer | Validator staking operations |
| `debug_v1` | Debug/testing module | Development only |
| `llm_chat_v1` | LLM chat interface | Optional AI features |

### Example: Validator Node Startup

For a validator node that needs BLS/TLS keys during initialization:

```bash
# Minimum required for validator operation
export CRYFTTEE_MODULES="bls_tls_signer_v1"
export CRYFTTEE_WEB3SIGNER_URL="http://keyvault:9000"
export CRYFTTEE_NODE_ID="NodeID-ABC123..."

# Optional: deterministic key derivation
export CRYFTTEE_KEY_SEED="your-secure-seed-hex"

./cryfttee
```

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

## Quick Reference Card

```bash
# Essential for validator nodes
CRYFTTEE_MODULES=bls_tls_signer_v1
CRYFTTEE_WEB3SIGNER_URL=http://keyvault:9000
CRYFTTEE_NODE_ID=NodeID-XXX

# Security (set by cryftgo)
CRYFTTEE_VERIFIED_BINARY_HASH=sha256:xxx

# API
CRYFTTEE_API_TRANSPORT=uds
CRYFTTEE_UDS_PATH=/var/run/cryfttee.sock

# Logging
CRYFTTEE_LOG_LEVEL=info
CRYFTTEE_LOG_JSON=true
```
