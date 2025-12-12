# BLS/TLS Signing Module v2

This module provides BLS and TLS key management and signing operations with **automatic TLS-first Node ID derivation** for multi-device support.

## Storage Backends

The module supports three storage backends for key persistence:

| Backend | Setting | Description | Password Protection |
|---------|---------|-------------|---------------------|
| **Vault** | `storageBackend: "vault"` | HashiCorp Vault (recommended for production) | N/A (Vault handles auth) |
| **Local Keystore** | `storageBackend: "local"` | EIP-2335 compatible JSON files | Optional password encryption |
| **Memory** | `storageBackend: "memory"` | No persistence (testing only) | N/A |

### Local Keystore Configuration

For environments without Vault access, use local keystore files with optional password protection:

```go
// Initialize with local keystore (password-protected)
result := cryfttee.Invoke("bls_tls_signer_v1", map[string]interface{}{
    "action": "initialize",
    "storageBackend": "local",
    "keystorePath": "/var/lib/cryfttee/keys",
    "keystorePassword": "your-secure-password",  // HIGHLY RECOMMENDED
    "web3signerUrl": "http://web3signer:9000",
    "deviceName": "Validator Node 1",
})
// Creates: /var/lib/cryfttee/keys/NodeID-abc.../tls_node-identity.json
```

**Security Warning**: Without a password, keys are stored in plaintext. Always use password protection in production!

### Local Keystore File Structure

```
{keystorePath}/
├── NodeID-abc123.../
│   ├── tls_node-identity.json    # TLS identity key
│   ├── bls_primary.json          # Primary BLS key
│   └── bls_backup.json           # Backup BLS key
└── NodeID-def456.../
    └── ...
```

### Keystore File Format (EIP-2335 Compatible)

```json
{
  "crypto": {
    "kdf": { "function": "scrypt", "params": { "n": 16384, "r": 8, "p": 1, "salt": "..." } },
    "checksum": { "function": "sha256", "message": "..." },
    "cipher": { "function": "aes-128-ctr", "params": { "iv": "..." }, "message": "..." }
  },
  "pubkey": "02abc123...",
  "uuid": "...",
  "version": 4,
  "keyType": "tls",
  "encrypted": true
}
```

## Auto-Bootstrap on Initialize

The module **automatically generates a TLS key and derives a Node ID** when you call `initialize` without providing an existing identity. This simplifies the setup flow:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Automatic TLS Bootstrap Flow                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  initialize() called with:                                                  │
│    ├── nodeId provided?        → Reconnect with existing identity          │
│    ├── tlsPublicKey provided?  → Derive nodeId from known pubkey           │
│    └── Neither provided?       → AUTO-BOOTSTRAP NEW TLS KEY                │
│                                                                             │
│  Auto-Bootstrap Flow:                                                       │
│  1. Generate TLS keypair (SECP256K1)                                       │
│  2. Derive Node ID: "NodeID-" + SHA256(pubkey)[0:40]                       │
│  3. Store TLS key in Vault (if enabled)                                    │
│  4. Return: { nodeId, tlsPublicKey, isNewBootstrap: true }                 │
│                                                                             │
│  Now BLS keys can be provisioned (ensureBlsKey)                            │
│  Keys are namespaced: cryfttee/data/keys/bls/{NodeID}/{keyName}            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why TLS First?

1. **Node Identity**: The TLS public key uniquely identifies each CryftTEE instance
2. **Multi-Device Support**: Multiple devices can share one Vault, each with its own Node ID namespace
3. **Key Isolation**: Each device's keys are isolated under its Node ID path
4. **Reconnection**: Devices reconnect using their previously derived Node ID or TLS public key

## Usage from cryftgo

### New Device with Vault (Auto-Bootstrap)

```go
// Just call initialize - TLS key is auto-generated if no identity provided
result := cryfttee.Invoke("bls_tls_signer_v1", map[string]interface{}{
    "action": "initialize",
    "storageBackend": "vault",           // or omit for auto-detect
    "vaultUrl": "http://vault:8200",
    "vaultToken": "hvs.xxx",
    "web3signerUrl": "http://web3signer:9000",
    "deviceName": "Validator Node 1",
})
// Returns: {
//   "success": true,
//   "initialized": true,
//   "isNewBootstrap": true,              // indicates TLS was auto-generated
//   "nodeId": "NodeID-a1b2c3d4e5f6...",  // 47 chars total
//   "tlsPublicKey": "02abc123...",       // 33 bytes compressed
//   "storageBackend": "vault",
//   "vaultEnabled": true
// }

// SAVE nodeId OR tlsPublicKey for subsequent sessions!
savedNodeId := result["nodeId"]
savedTlsPublicKey := result["tlsPublicKey"]
```

### New Device with Local Keystore (Password Protected)

```go
// Initialize with local keystore - no Vault needed
result := cryfttee.Invoke("bls_tls_signer_v1", map[string]interface{}{
    "action": "initialize",
    "storageBackend": "local",
    "keystorePath": "/var/lib/cryfttee/keys",
    "keystorePassword": "my-secure-password-123",  // RECOMMENDED
    "web3signerUrl": "http://web3signer:9000",
    "deviceName": "Validator Node 1",
})
// Returns: {
//   "success": true,
//   "initialized": true,
//   "isNewBootstrap": true,
//   "nodeId": "NodeID-a1b2c3d4e5f6...",
//   "storageBackend": "local",
//   "keystorePath": "/var/lib/cryfttee/keys",
//   "keystoreEncrypted": true           // password protection active
// }
```

### Provision BLS Keys

```go
// Generate or ensure BLS key exists
result := cryfttee.Invoke("bls_tls_signer_v1", map[string]interface{}{
    "action": "ensureBlsKey",
    "label": "validator-primary",
    "keyName": "primary",
})
// For local keystore, creates: {keystorePath}/NodeID-abc.../bls_primary.json
// Returns: {
//   "success": true,
//   "action": "generated",
//   "keyId": "NodeID-abc...:bls:primary",
//   "publicKey": "0x1234...",
//   "proofOfPossession": "0xabcd...",   // 96 bytes - required for validator registration
//   "nodeId": "NodeID-abc...",
//   "storageBackend": "local",
//   "keystoreEncrypted": true,
//   "keystoreWritten": true
// }
```

#### Proof of Possession (PoP)

All BLS key generation now follows the **AvalancheGo pattern** by returning a Proof of Possession:

- **What**: A signature of the public key using the BLS PoP ciphersuite
- **Why**: Proves the caller controls the private key without exposing it
- **Used for**: Validator registration on Avalanche and Cryft networks
- **Ciphersuite**: `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`

```go
// The proofOfPossession field is included in all BLS key responses:
// - ensureBlsKey (generated/loaded_from_vault/loaded_from_keystore)
// - generateBlsKey
// - status (for each BLS key listed)

// Use proofOfPossession when registering with the P-Chain:
registrationData := map[string]interface{}{
    "nodeID":            result["nodeId"],
    "blsPublicKey":      result["publicKey"],
    "blsProofOfPossession": result["proofOfPossession"],  // Required!
}
```

### Reconnect Existing Device

```go
// Option 1: Reconnect with Vault storage
result := cryfttee.Invoke("bls_tls_signer_v1", map[string]interface{}{
    "action": "initialize",
    "nodeId": savedNodeId,  // "NodeID-a1b2c3d4e5f6..."
    "storageBackend": "vault",
    "vaultUrl": "http://vault:8200",
    "vaultToken": "hvs.xxx",
    "loadKeysFromVault": true,
})

// Option 2: Reconnect with local keystore (password required if encrypted)
result := cryfttee.Invoke("bls_tls_signer_v1", map[string]interface{}{
    "action": "initialize",
    "nodeId": savedNodeId,
    "storageBackend": "local",
    "keystorePath": "/var/lib/cryfttee/keys",
    "keystorePassword": "my-secure-password-123",  // Required for encrypted keystores
    "loadKeysFromKeystore": true,
})

// Option 3: Reconnect with TLS public key (nodeId is derived)
result := cryfttee.Invoke("bls_tls_signer_v1", map[string]interface{}{
    "action": "initialize",
    "tlsPublicKey": savedTlsPublicKey,  // "02abc123..."
    "storageBackend": "local",
    "keystorePath": "/var/lib/cryfttee/keys",
    "keystorePassword": "my-secure-password-123",
    "loadKeysFromKeystore": true,
})
```
```

## Multi-Device Vault Structure

When multiple CryftTEE instances share a single Vault:

```
cryfttee/data/keys/
├── tls/
│   ├── NodeID-abc123.../
│   │   └── node-identity    # Device 1 TLS key
│   ├── NodeID-def456.../
│   │   └── node-identity    # Device 2 TLS key
│   └── NodeID-789xyz.../
│       └── node-identity    # Device 3 TLS key
└── bls/
    ├── NodeID-abc123.../
    │   ├── primary          # Device 1 primary BLS key
    │   └── backup           # Device 1 backup BLS key
    ├── NodeID-def456.../
    │   └── primary          # Device 2 primary BLS key
    └── NodeID-789xyz.../
        └── primary          # Device 3 primary BLS key
```

## Key Management Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   CryftGo       │────▶│   CryftTEE      │────▶│  Web3Signer     │
│  (Validator)    │     │  (WASM Runtime) │     │  (BLS Signing)  │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                              │                          │
                              │                          ▼
                              │                 ┌─────────────────┐
                              └────────────────▶│ HashiCorp Vault │
                                                │  (Key Storage)  │
                                                │  {NodeID}/keys  │
                                                └─────────────────┘
```

---

## API Reference

### Bootstrap Actions

#### `bootstrapTls` - Generate TLS Identity (Required First Step)

```json
{
  "action": "bootstrapTls",
  "vaultUrl": "http://vault:8200",      // optional
  "vaultToken": "hvs.xxx",              // optional
  "vaultPath": "cryfttee/data/keys",    // optional, default path
  "web3signerUrl": "http://...",        // optional
  "deviceName": "My Validator"          // optional
}
```

Response:
```json
{
  "success": true,
  "nodeId": "NodeID-a1b2c3d4e5f67890...",
  "deviceId": "NodeID-a1b2c3d4e5f67890...",
  "publicKey": "02abc123...",
  "certificate": "-----BEGIN CERTIFICATE-----...",
  "keyId": "NodeID-abc...:tls:node-identity",
  "vaultEnabled": true
}
```

#### `initialize` - Reconnect with Existing Node ID

```json
{
  "action": "initialize",
  "nodeId": "NodeID-a1b2c3d4e5f67890...",  // required
  "vaultUrl": "http://vault:8200",
  "vaultToken": "hvs.xxx",
  "loadKeysFromVault": true                 // optional: reload keys
}
```

### Key Provisioning Actions

#### `ensureBlsKey` - Provision BLS Key

```json
{
  "action": "ensureBlsKey",
  "publicKey": "0x1234...",   // optional: verify existing key
  "label": "validator-1",     // optional: human-readable label
  "keyName": "primary"        // optional: Vault key name
}
```

#### `ensureTlsKey` - Generate Additional TLS Key

```json
{
  "action": "ensureTlsKey",
  "subject": "service.example.com",  // optional
  "keyName": "api-client"            // required: cannot be "node-identity"
}
```

### Status Actions

#### `status` - Get Module Status

```json
{ "action": "status" }
```

Response:
```json
{
  "success": true,
  "nodeId": "NodeID-abc...",
  "isBootstrapped": true,
  "initialized": true,
  "blsKeyCount": 2,
  "tlsKeyCount": 1,
  "deviceCount": 1,
  "web3signerConfigured": true,
  "vaultEnabled": true
}
```

#### `listKeys` - List All Keys

```json
{ "action": "listKeys" }
```

#### `listDevices` - List Registered Devices

```json
{ "action": "listDevices" }
```

---

## Manual Key Generation
#   - keystore-*.json (encrypted private key)
#   - deposit_data-*.json (deposit transaction data)
```

### Option 2: Generate BLS Keys with Teku (Docker)

```bash
# Generate BLS validator keys using Teku
docker run --rm -v $(pwd)/keys:/keys consensys/teku:latest \
  validator generate-keys \
  --output-path=/keys \
  --keys-count=1 \
  --encrypted-keystore-enabled=true \
  --keystore-password-file=/keys/password.txt

# First create a password file
echo "your-secure-password" > keys/password.txt
```

### Option 3: Generate TLS Keys with OpenSSL

```bash
# Generate ECDSA P-256 key pair for TLS
openssl ecparam -name prime256v1 -genkey -noout -out tls-private.pem
openssl ec -in tls-private.pem -pubout -out tls-public.pem

# Convert to PKCS#8 format for Web3Signer
openssl pkcs8 -topk8 -nocrypt -in tls-private.pem -out tls-private.pkcs8.pem

# Generate self-signed certificate (optional)
openssl req -new -x509 -key tls-private.pem -out tls-cert.pem -days 365 \
  -subj "/CN=cryfttee-node/O=CryftLabs"
```

---

## Importing Keys to Web3Signer

### Import BLS Keystore

```bash
# Copy keystore to Web3Signer keys directory
cp validator_keys/keystore-*.json /opt/web3signer/keys/

# Create password file (same name as keystore with .txt extension)
echo "your-keystore-password" > /opt/web3signer/keys/keystore-m_12345.txt

# Restart Web3Signer to load new keys
sudo systemctl restart web3signer
```

### Import via REST API

```bash
# Import BLS keystore via Web3Signer API
curl -X POST http://localhost:9000/eth/v1/keystores \
  -H "Content-Type: application/json" \
  -d '{
    "keystores": ["'"$(cat keystore.json | jq -c)"'"],
    "passwords": ["your-password"]
  }'
```

---

## HashiCorp Vault Integration

Web3Signer supports HashiCorp Vault as a secure key storage backend.
**Important:** Always use AppRole authentication, never root tokens!

### Vault Access Model

CryftTEE uses two separate AppRoles with least-privilege access:

| Role | Purpose | Permissions | TTL |
|------|---------|-------------|-----|
| `web3signer` | Runtime signing | Read-only key access | 1h |
| `cryfttee-admin` | Key import/delete | Read/write key access | 15m |

### Setup Vault Secret Engine

```bash
# Enable KV secrets engine v2
vault secrets enable -path=cryfttee kv-v2

# Store BLS private key (use admin AppRole or root for setup)
vault kv put cryfttee/keys/bls/validator-1 \
  private_key="0x..." \
  public_key="0x..."

# Store TLS private key
vault kv put cryfttee/keys/tls/node-1 \
  private_key="-----BEGIN EC PRIVATE KEY-----..." \
  certificate="-----BEGIN CERTIFICATE-----..."
```

### Create AppRole Policies (Least Privilege)

```bash
# Read-only policy for Web3Signer (signing operations)
vault policy write cryfttee - << 'EOF'
path "cryfttee/data/keys/bls/*" {
  capabilities = ["read", "list"]
}
path "cryfttee/data/keys/tls/*" {
  capabilities = ["read", "list"]
}
EOF

# Admin policy for key management
vault policy write cryfttee-admin - << 'EOF'
path "cryfttee/data/keys/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
```

### Configure AppRole Authentication

```bash
# Enable AppRole auth method
vault auth enable approle

# Create Web3Signer role (read-only, long-lived)
vault write auth/approle/role/web3signer \
    token_policies="cryfttee" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0 \
    secret_id_num_uses=0

# Create Admin role (write access, short-lived)
vault write auth/approle/role/cryfttee-admin \
    token_policies="cryfttee-admin" \
    token_ttl=15m \
    token_max_ttl=1h \
    secret_id_ttl=24h \
    secret_id_num_uses=10

# Get AppRole credentials
vault read auth/approle/role/web3signer/role-id
vault write -f auth/approle/role/web3signer/secret-id
```

### Web3Signer Vault Key Configuration

Create `validator-1.yaml` in `/etc/web3signer/keys/`:

```yaml
type: hashicorp
keyType: BLS
tlsEnabled: true
keyPath: /v1/secret/data/cryfttee/keys/bls/validator-1
serverHost: vault.example.com
serverPort: 8200
timeout: 10000
# AppRole authentication
authFilePath: /etc/web3signer/vault-approle.json
```

### AppRole Credentials File

Create `/etc/web3signer/vault-approle.json`:

```json
{
  "role_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "secret_id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
}
```

### Environment Variables for Vault

```bash
# Only for CLI tools - Web3Signer uses AppRole file
export VAULT_ADDR="https://vault.example.com:8200"
# Never set VAULT_TOKEN in production - use AppRole!
```

### Start Web3Signer with Vault

```bash
web3signer \
  --http-listen-port=9000 \
  eth2 \
  --network=mainnet \
  --key-config-path=/etc/web3signer/keys/
```

---

## Building the Module

The actual WASM module should be compiled from Rust source:

```bash
cd modules/bls_tls_signer_v1/src
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/bls_tls_signer.wasm ../module.wasm
```

## Module ABI

The module must export these functions:

### BLS Operations

- `bls_register(mode, key_ptr, key_len, handle_out, handle_len_out, pubkey_out, pubkey_len_out) -> i32`
- `bls_sign(handle_ptr, handle_len, msg_ptr, msg_len, sig_out, sig_len_out) -> i32`

### TLS Operations

- `tls_register(mode, key_ptr, key_len, handle_out, handle_len_out, cert_out, cert_len_out) -> i32`
- `tls_sign(handle_ptr, handle_len, digest_ptr, digest_len, algo_ptr, algo_len, sig_out, sig_len_out) -> i32`

## Modes

- `0` = Persistent (use existing key from Web3Signer)
- `1` = Ephemeral (in-memory only - NOT SUPPORTED)
- `2` = Import (import existing key material - use Web3Signer import directly)
- `3` = Verify (check if provided public key exists in Web3Signer)
- `4` = Generate (request key generation - use manual generation tools)

## Return Codes

- `0` = Success
- `-1` = Invalid parameter
- `-2` = Key not found
- `-3` = Signing error
- `-4` = Web3Signer communication error

## Optional GUI

Modules can optionally provide a web GUI that will be rendered as a tab in the CryftTEE kiosk UI. To enable this:

1. Create a `gui/` directory in your module directory containing static web assets
2. Add the following to your manifest entry:
   ```json
   {
     "hasGui": true,
     "guiPath": "gui"
   }
   ```

The GUI will be served at `/api/modules/{module_id}/gui/` and automatically get a tab in the kiosk interface.

### GUI Requirements

- Must be static HTML/CSS/JS (no server-side rendering)
- Main entry point should be `index.html`
- Can communicate with the module's API endpoints
- Sandboxed in an iframe with `allow-scripts allow-same-origin allow-forms`

