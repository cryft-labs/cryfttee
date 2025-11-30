# BLS/TLS Signing Module v1

This module provides BLS and TLS key management and signing operations via Web3Signer integration.

## Key Management Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   CryftGo       │────▶│   CryftTEE      │────▶│  Web3Signer     │
│  (Validator)    │     │  (WASM Runtime) │     │  (Key Manager)  │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
                                               ┌─────────────────┐
                                               │ HashiCorp Vault │
                                               │  (Key Storage)  │
                                               └─────────────────┘
```

Keys are stored and managed by **Web3Signer**, which can optionally use **HashiCorp Vault** as a secure key storage backend.

---

## Manual Key Generation

### Option 1: Generate BLS Keys with eth2.0-deposit-cli

```bash
# Install eth2.0-deposit-cli
pip install eth2-deposit-cli

# Generate validator keys
eth2_deposit_cli new-mnemonic --num_validators 1 --chain mainnet

# Output: validator_keys/ directory containing:
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

### Setup Vault Secret Engine

```bash
# Enable KV secrets engine v2
vault secrets enable -path=web3signer kv-v2

# Store BLS private key
vault kv put web3signer/bls/validator-1 \
  private_key="0x..." \
  public_key="0x..."

# Store TLS private key
vault kv put web3signer/tls/node-1 \
  private_key="-----BEGIN EC PRIVATE KEY-----..." \
  certificate="-----BEGIN CERTIFICATE-----..."
```

### Web3Signer Vault Configuration

Create `web3signer-vault.yaml`:

```yaml
type: hashicorp
keyType: BLS
tlsEnabled: true
keyPath: /v1/secret/data/web3signer/bls
token: ${VAULT_TOKEN}
serverHost: vault.example.com
serverPort: 8200
timeout: 10000
```

### Environment Variables for Vault

```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="hvs.xxxxxxxxxxxxx"
export VAULT_NAMESPACE="admin"  # If using Vault Enterprise
```

### Start Web3Signer with Vault

```bash
web3signer \
  --http-listen-port=9000 \
  eth2 \
  --network=mainnet \
  --key-config-path=/etc/web3signer/vault-keys/
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

