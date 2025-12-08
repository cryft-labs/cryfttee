# CryftGo ↔ CryftTEE Integration Checklist

**For CryftGo Codex LLM Implementation**

This document provides a complete checklist for implementing CryftGo's integration with CryftTEE for BLS/TLS key lifecycle management.

---

## ✅ Implementation Checklist

### 1. Binary Management

- [ ] **Locate cryfttee binary** at configured path (default: alongside cryftgo or in `/usr/local/bin/cryfttee`)
- [ ] **Compute SHA256 hash** of binary before launch:
  ```go
  binaryBytes, _ := os.ReadFile(cryftteeePath)
  hash := sha256.Sum256(binaryBytes)
  hashStr := fmt.Sprintf("sha256:%x", hash)
  ```
- [ ] **Optionally verify hash** against known-good release hash from Cryft Labs
- [ ] **Set `CRYFTTEE_VERIFIED_BINARY_HASH`** environment variable when spawning

### 2. Process Lifecycle

- [ ] **Spawn cryfttee subprocess** with environment variables (not CLI flags)
- [ ] **Wait for UDS socket** to become available before making API calls
- [ ] **Implement health monitoring** - check `/v1/staking/status` periodically
- [ ] **Handle process death** - restart cryfttee if it crashes
- [ ] **Graceful shutdown** - send SIGTERM and wait for clean exit

### 3. Key Persistence (CryftGo Responsibility)

- [ ] **Define storage location** for saved public keys (e.g., `~/.cryftgo/keys/` or node state DB)
- [ ] **Implement `loadSavedKey(keyType)`** - returns hex pubkey or empty string
- [ ] **Implement `saveKey(keyType, pubkey)`** - persists pubkey for future restarts
- [ ] **Keys are PUBLIC ONLY** - never store private keys, those stay in Web3Signer

### 4. Environment Variable Setup

**Required variables (always set):**
```go
env := []string{
    "CRYFTTEE_VERIFIED_BINARY_HASH=" + hashStr,
    "CRYFTTEE_NODE_ID=" + nodeID,                    // e.g., "NodeID-ABC123..."
    "CRYFTTEE_MODULES=bls_tls_signer_v1",
    "CRYFTTEE_WEB3SIGNER_URL=" + web3signerURL,      // e.g., "http://keyvault:9000"
    "CRYFTTEE_UDS_PATH=" + udsPath,                  // e.g., "/var/run/cryfttee.sock"
    "CRYFTTEE_LOG_JSON=true",
}
```

**Conditional variables (set on restart if keys exist):**
```go
if savedBLSPubkey != "" {
    env = append(env, "CRYFTTEE_EXPECTED_BLS_PUBKEY=" + savedBLSPubkey)
}
if savedTLSPubkey != "" {
    env = append(env, "CRYFTTEE_EXPECTED_TLS_PUBKEY=" + savedTLSPubkey)
}
```

---

## 📡 API Reference

### Base Configuration

- **Transport:** Unix Domain Socket (UDS)
- **Socket Path:** Value of `CRYFTTEE_UDS_PATH`
- **Content-Type:** `application/json`
- **All endpoints:** Prefix with `/v1/`

### Status Check

```http
GET /v1/staking/status
```

**Response:**
```json
{
  "cryftteeVersion": "0.4.0",
  "modules": [
    {
      "id": "bls_tls_signer_v1",
      "version": "1.0.0",
      "loaded": true,
      "trusted": true,
      "compatible": true
    }
  ],
  "web3Signer": {
    "reachable": true,
    "lastError": null
  }
}
```

**Check Before Proceeding:**
- `web3Signer.reachable` must be `true`
- Module `bls_tls_signer_v1` must have `loaded: true`

---

### BLS Key Registration

#### First Start (No Saved Key) - Generate New Key

```http
POST /v1/staking/bls/register
Content-Type: application/json

{
  "mode": "generate",
  "networkID": 1,
  "nodeLabel": "validator-01"
}
```

**Success Response (201):**
```json
{
  "keyHandle": "0x8a4f3b2c1d...",
  "blsPubKeyB64": "base64-encoded-48-byte-pubkey",
  "moduleId": "bls_tls_signer_v1",
  "moduleVersion": "1.0.0"
}
```

**⚠️ CRITICAL: Save `keyHandle` (the hex pubkey) for future restarts!**

```go
blsPubkey := response.KeyHandle  // This is the hex-encoded public key
saveKey("bls_pubkey", blsPubkey)
```

#### Restart (Saved Key Exists) - Verify Key Available

```http
POST /v1/staking/bls/register
Content-Type: application/json

{
  "mode": "verify",
  "publicKey": "0x8a4f3b2c1d..."
}
```

**Success Response (200):**
```json
{
  "keyHandle": "0x8a4f3b2c1d...",
  "blsPubKeyB64": "base64-encoded-48-byte-pubkey",
  "moduleId": "bls_tls_signer_v1",
  "moduleVersion": "1.0.0"
}
```

**Error Response (404) - Key Not Found:**
```json
{
  "error": "Key not found in Web3Signer",
  "details": "The BLS key 0x8a4f3b... from CryftGo's local store was not found in Web3Signer. This is a critical error..."
}
```

**⚠️ Key not found = FATAL ERROR - node cannot safely start**

---

### TLS Key Registration

#### First Start (No Saved Key) - Generate New Key

```http
POST /v1/staking/tls/register
Content-Type: application/json

{
  "mode": "generate",
  "networkID": 1,
  "nodeLabel": "validator-01"
}
```

**Success Response (201):**
```json
{
  "keyHandle": "0x04a1b2c3d4...",
  "certChainPEM": "-----BEGIN CERTIFICATE-----\n...",
  "moduleId": "bls_tls_signer_v1",
  "moduleVersion": "1.0.0"
}
```

**⚠️ CRITICAL: Save `keyHandle` (the hex pubkey) for future restarts!**

```go
tlsPubkey := response.KeyHandle
saveKey("tls_pubkey", tlsPubkey)
```

#### Restart (Saved Key Exists) - Verify Key Available

```http
POST /v1/staking/tls/register
Content-Type: application/json

{
  "mode": "verify",
  "publicKey": "0x04a1b2c3d4..."
}
```

---

### BLS Signing

```http
POST /v1/staking/bls/sign
Content-Type: application/json

{
  "keyHandle": "0x8a4f3b2c1d...",
  "message": "base64-encoded-message-bytes"
}
```

**Response:**
```json
{
  "signatureB64": "base64-encoded-96-byte-signature",
  "moduleId": "bls_tls_signer_v1",
  "moduleVersion": "1.0.0"
}
```

---

### TLS Signing

```http
POST /v1/staking/tls/sign
Content-Type: application/json

{
  "keyHandle": "0x04a1b2c3d4...",
  "digest": "base64-encoded-32-byte-digest",
  "algorithm": "ECDSA_P256_SHA256"
}
```

**Response:**
```json
{
  "signatureB64": "base64-encoded-signature",
  "moduleId": "bls_tls_signer_v1",
  "moduleVersion": "1.0.0"
}
```

---

## 🔄 Complete Flow Pseudocode

```go
package cryfttee

import (
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "net"
    "net/http"
    "os"
    "os/exec"
    "time"
)

type CryftteeManager struct {
    binaryPath     string
    udsPath        string
    web3signerURL  string
    nodeID         string
    process        *exec.Cmd
    client         *http.Client
}

type KeyStore interface {
    LoadKey(keyType string) (string, error)  // Returns hex pubkey or ""
    SaveKey(keyType string, pubkey string) error
}

// Initialize starts cryfttee and ensures keys are available
func (m *CryftteeManager) Initialize(keyStore KeyStore) error {
    // Step 1: Compute binary hash for attestation
    binaryBytes, err := os.ReadFile(m.binaryPath)
    if err != nil {
        return fmt.Errorf("cannot read cryfttee binary: %w", err)
    }
    hash := sha256.Sum256(binaryBytes)
    hashStr := fmt.Sprintf("sha256:%x", hash)
    
    // Step 2: Check for saved keys from previous run
    savedBLS, _ := keyStore.LoadKey("bls_pubkey")
    savedTLS, _ := keyStore.LoadKey("tls_pubkey")
    
    // Step 3: Build environment
    env := []string{
        "CRYFTTEE_VERIFIED_BINARY_HASH=" + hashStr,
        "CRYFTTEE_NODE_ID=" + m.nodeID,
        "CRYFTTEE_MODULES=bls_tls_signer_v1",
        "CRYFTTEE_WEB3SIGNER_URL=" + m.web3signerURL,
        "CRYFTTEE_UDS_PATH=" + m.udsPath,
        "CRYFTTEE_LOG_JSON=true",
    }
    
    if savedBLS != "" {
        env = append(env, "CRYFTTEE_EXPECTED_BLS_PUBKEY=" + savedBLS)
    }
    if savedTLS != "" {
        env = append(env, "CRYFTTEE_EXPECTED_TLS_PUBKEY=" + savedTLS)
    }
    
    // Step 4: Start cryfttee
    m.process = exec.Command(m.binaryPath)
    m.process.Env = append(os.Environ(), env...)
    if err := m.process.Start(); err != nil {
        return fmt.Errorf("failed to start cryfttee: %w", err)
    }
    
    // Step 5: Wait for UDS to be ready
    if err := m.waitForUDS(30 * time.Second); err != nil {
        return fmt.Errorf("cryfttee did not become ready: %w", err)
    }
    
    // Step 6: Verify status
    status, err := m.GetStatus()
    if err != nil {
        return fmt.Errorf("cannot get cryfttee status: %w", err)
    }
    if !status.Web3Signer.Reachable {
        return fmt.Errorf("Web3Signer not reachable")
    }
    
    // Step 7: Handle BLS key
    if savedBLS == "" {
        // First run: generate new BLS key
        blsKey, err := m.RegisterBLSKey("generate", "")
        if err != nil {
            return fmt.Errorf("failed to generate BLS key: %w", err)
        }
        if err := keyStore.SaveKey("bls_pubkey", blsKey.KeyHandle); err != nil {
            return fmt.Errorf("failed to save BLS pubkey: %w", err)
        }
        log.Info("Generated new BLS key", "pubkey", blsKey.KeyHandle[:20]+"...")
    } else {
        // Restart: verify existing BLS key
        _, err := m.RegisterBLSKey("verify", savedBLS)
        if err != nil {
            return fmt.Errorf("BLS key verification failed - key may be lost: %w", err)
        }
        log.Info("Verified existing BLS key", "pubkey", savedBLS[:20]+"...")
    }
    
    // Step 8: Handle TLS key (same pattern)
    if savedTLS == "" {
        tlsKey, err := m.RegisterTLSKey("generate", "")
        if err != nil {
            return fmt.Errorf("failed to generate TLS key: %w", err)
        }
        if err := keyStore.SaveKey("tls_pubkey", tlsKey.KeyHandle); err != nil {
            return fmt.Errorf("failed to save TLS pubkey: %w", err)
        }
        log.Info("Generated new TLS key", "pubkey", tlsKey.KeyHandle[:20]+"...")
    } else {
        _, err := m.RegisterTLSKey("verify", savedTLS)
        if err != nil {
            return fmt.Errorf("TLS key verification failed - key may be lost: %w", err)
        }
        log.Info("Verified existing TLS key", "pubkey", savedTLS[:20]+"...")
    }
    
    log.Info("CryftTEE initialization complete")
    return nil
}

func (m *CryftteeManager) waitForUDS(timeout time.Duration) error {
    deadline := time.Now().Add(timeout)
    for time.Now().Before(deadline) {
        conn, err := net.Dial("unix", m.udsPath)
        if err == nil {
            conn.Close()
            return nil
        }
        time.Sleep(100 * time.Millisecond)
    }
    return fmt.Errorf("timeout waiting for UDS socket")
}

func (m *CryftteeManager) RegisterBLSKey(mode, publicKey string) (*BLSRegisterResponse, error) {
    body := map[string]interface{}{
        "mode": mode,
    }
    if publicKey != "" {
        body["publicKey"] = publicKey
    }
    
    var resp BLSRegisterResponse
    if err := m.post("/v1/staking/bls/register", body, &resp); err != nil {
        return nil, err
    }
    return &resp, nil
}

func (m *CryftteeManager) RegisterTLSKey(mode, publicKey string) (*TLSRegisterResponse, error) {
    body := map[string]interface{}{
        "mode": mode,
    }
    if publicKey != "" {
        body["publicKey"] = publicKey
    }
    
    var resp TLSRegisterResponse
    if err := m.post("/v1/staking/tls/register", body, &resp); err != nil {
        return nil, err
    }
    return &resp, nil
}

func (m *CryftteeManager) SignBLS(keyHandle string, message []byte) ([]byte, error) {
    body := map[string]interface{}{
        "keyHandle": keyHandle,
        "message":   base64.StdEncoding.EncodeToString(message),
    }
    
    var resp BLSSignResponse
    if err := m.post("/v1/staking/bls/sign", body, &resp); err != nil {
        return nil, err
    }
    return base64.StdEncoding.DecodeString(resp.SignatureB64)
}

func (m *CryftteeManager) SignTLS(keyHandle string, digest []byte, algorithm string) ([]byte, error) {
    body := map[string]interface{}{
        "keyHandle": keyHandle,
        "digest":    base64.StdEncoding.EncodeToString(digest),
        "algorithm": algorithm,
    }
    
    var resp TLSSignResponse
    if err := m.post("/v1/staking/tls/sign", body, &resp); err != nil {
        return nil, err
    }
    return base64.StdEncoding.DecodeString(resp.SignatureB64)
}
```

---

## ⚠️ Error Handling

### Fatal Errors (Node Cannot Start)

| Error | Meaning | Action |
|-------|---------|--------|
| Key verification failed (404) | Expected key not in Web3Signer | Manual intervention - check Web3Signer/Vault |
| Web3Signer not reachable | KeyVault stack down | Start KeyVault stack first |
| Module not loaded | bls_tls_signer_v1 failed | Check cryfttee logs |

### Recoverable Errors

| Error | Meaning | Action |
|-------|---------|--------|
| Signing timeout | Web3Signer slow | Retry with backoff |
| Connection refused to UDS | CryftTEE process died | Restart cryfttee |

### Critical Invariants

1. **Never generate new keys if saved keys exist** - this would change node identity
2. **Always verify keys on restart** - ensures consistency with Web3Signer
3. **Save pubkeys immediately after generation** - before any staking operations
4. **Binary hash must be computed by CryftGo** - cryfttee self-hash is less secure

---

## 🧪 Testing Checklist

- [ ] **First start flow:** No saved keys → generate → save → verify saved
- [ ] **Restart flow:** Load saved keys → verify → success
- [ ] **Key loss detection:** Delete key from Web3Signer → restart → verify fails
- [ ] **Web3Signer down:** Start without KeyVault → status shows unreachable
- [ ] **Process recovery:** Kill cryfttee → CryftGo restarts it
- [ ] **Signing operations:** Generate key → sign message → verify signature externally

---

## 📋 Summary

### What CryftGo Must Implement

1. **Binary hash computation** before launch
2. **Process management** (spawn, monitor, restart)
3. **Key persistence** (save/load public keys to node state)
4. **UDS client** for API calls
5. **Key lifecycle logic** (generate vs verify based on saved state)

### What CryftTEE Provides

1. **WASM module runtime** with bls_tls_signer_v1
2. **Web3Signer integration** for actual key operations
3. **UDS/HTTPS API** for CryftGo communication
4. **Key verification** against Web3Signer
5. **Attestation** of runtime and binary hashes

### API Modes Quick Reference

| Mode | When to Use | publicKey Field |
|------|-------------|-----------------|
| `generate` | First start (no saved keys) | Not needed |
| `verify` | Restart (have saved keys) | **Required** - the saved pubkey |
| `persistent` | Alias for generate | Not needed |
| `ephemeral` | Testing only | Not needed |

---

**Document Version:** 1.0.0  
**CryftTEE Version:** 0.4.0  
**Last Updated:** 2025-01-XX
