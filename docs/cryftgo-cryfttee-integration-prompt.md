# CryftGo ↔ CryftTEE Integration Prompt

## Overview

You are implementing the integration between **cryftgo** (the Cryft blockchain node) and **cryfttee** (a TEE-style sidecar that manages cryptographic keys via WASM modules). CryftGo communicates with CryftTEE over a Unix Domain Socket (UDS) to:

1. Initialize node identity (generate or retrieve BLS and TLS keys)
2. Sign staking transactions (BLS signatures for consensus)
3. Sign TLS certificates (SECP256k1/ECDSA for node identity)
4. Verify runtime attestation (ensure CryftTEE is running trusted code)

---

## Connection Defaults Contract

Both cryftgo and cryfttee MUST use these matching defaults:

| Setting | Default Value | CryftTEE Env Var | CryftGo Flag |
|---------|---------------|------------------|--------------|
| **Transport** | `uds` | `CRYFTTEE_API_TRANSPORT` | `--cryfttee-transport` |
| **Socket Path** | `/tmp/cryfttee.sock` | `CRYFTTEE_UDS_PATH` | `--cryfttee-socket` |
| **HTTP Fallback** | `127.0.0.1:8443` | `CRYFTTEE_HTTP_ADDR` | `--cryfttee-http-addr` |
| **API Base Path** | `/v1` | N/A | N/A |

### CryftGo Default Constants

```go
const (
    DefaultCryftteeTransport  = "uds"
    DefaultCryftteeSocketPath = "/tmp/cryfttee.sock"
    DefaultCryftteeHTTPAddr   = "127.0.0.1:8443"
    DefaultCryftteeAPIBase    = "/v1"
)
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CRYFTGO                                     │
│                         (Blockchain Node)                                │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │   Staking    │  │     TLS      │  │  Consensus   │                   │
│  │   Manager    │  │   Manager    │  │    Engine    │                   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                   │
│         │                 │                 │                            │
│         └────────────┬────┴────────────────┘                            │
│                      │                                                   │
│              ┌───────▼───────┐                                          │
│              │  CryftTEE     │                                          │
│              │    Client     │                                          │
│              └───────┬───────┘                                          │
└──────────────────────┼──────────────────────────────────────────────────┘
                       │
                       │ Unix Domain Socket
                       │ /tmp/cryfttee.sock
                       │
┌──────────────────────┼──────────────────────────────────────────────────┐
│                      ▼                                                   │
│              ┌───────────────┐                                          │
│              │   UDS API     │                                          │
│              │   /v1/*       │                                          │
│              └───────┬───────┘                                          │
│                      │                                                   │
│              ┌───────▼───────┐                                          │
│              │    Router     │                                          │
│              │   Dispatch    │                                          │
│              └───────┬───────┘                                          │
│                      │                                                   │
│    ┌─────────────────┼─────────────────┐                                │
│    │                 │                 │                                │
│    ▼                 ▼                 ▼                                │
│ ┌──────┐       ┌──────────┐     ┌──────────┐                           │
│ │ BLS  │       │   TLS    │     │  Debug   │                           │
│ │Signer│       │  Signer  │     │  Module  │                           │
│ │Module│       │  Module  │     │          │                           │
│ └──┬───┘       └────┬─────┘     └──────────┘                           │
│    │                │                                                   │
│    └────────┬───────┘                                                   │
│             │                                                           │
│     ┌───────▼───────┐                                                   │
│     │  Web3Signer   │  (Key Storage Backend)                           │
│     │  localhost:   │                                                   │
│     │     9000      │                                                   │
│     └───────────────┘                                                   │
│                                                                          │
│                           CRYFTTEE                                       │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Complete Node Initialization Flow

When cryftgo starts, it must initialize its identity by communicating with cryfttee. This is a multi-step process:

### Step 1: Connect to CryftTEE

```go
type CryftteeClient struct {
    socketPath string
    httpAddr   string
    transport  string
    httpClient *http.Client
}

func NewCryftteeClient(cfg *CryftteeConfig) (*CryftteeClient, error) {
    client := &CryftteeClient{
        socketPath: cfg.SocketPath,
        httpAddr:   cfg.HTTPAddr,
        transport:  cfg.Transport,
    }
    
    if cfg.Transport == "uds" {
        // Create HTTP client that uses Unix socket
        client.httpClient = &http.Client{
            Transport: &http.Transport{
                DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
                    return net.Dial("unix", cfg.SocketPath)
                },
            },
            Timeout: 30 * time.Second,
        }
    } else {
        client.httpClient = &http.Client{
            Timeout: 30 * time.Second,
            // Configure TLS if using HTTPS
        }
    }
    
    return client, nil
}

func (c *CryftteeClient) baseURL() string {
    if c.transport == "uds" {
        return "http://localhost" // Host is ignored for UDS
    }
    return fmt.Sprintf("https://%s", c.httpAddr)
}
```

### Step 2: Verify CryftTEE Health and Attestation

Before trusting cryfttee, verify it's running expected code:

```go
type AttestationResponse struct {
    CoreBinaryHash  string    `json:"core_binary_hash"`
    ManifestHash    string    `json:"manifest_hash"`
    CryftteeVersion string    `json:"cryfttee_version"`
    Timestamp       time.Time `json:"timestamp"`
    ModuleHashes    map[string]string `json:"module_hashes"`
}

func (c *CryftteeClient) VerifyAttestation(expectedHash string) error {
    resp, err := c.httpClient.Get(c.baseURL() + "/v1/runtime/attestation")
    if err != nil {
        return fmt.Errorf("failed to get attestation: %w", err)
    }
    defer resp.Body.Close()
    
    var attestation AttestationResponse
    if err := json.NewDecoder(resp.Body).Decode(&attestation); err != nil {
        return fmt.Errorf("failed to decode attestation: %w", err)
    }
    
    // Verify binary hash matches expected (from release artifacts)
    if expectedHash != "" && attestation.CoreBinaryHash != expectedHash {
        return fmt.Errorf("cryfttee binary hash mismatch: got %s, expected %s",
            attestation.CoreBinaryHash, expectedHash)
    }
    
    log.Info("CryftTEE attestation verified",
        "version", attestation.CryftteeVersion,
        "hash", attestation.CoreBinaryHash[:16]+"...")
    
    return nil
}
```

### Step 3: Check Module Status

Verify the required signer module is loaded and ready:

```go
type StatusResponse struct {
    CryftteeVersion string `json:"cryfttee_version"`
    Modules         []ModuleStatus `json:"modules"`
    Defaults        struct {
        BLS string `json:"bls"`
        TLS string `json:"tls"`
    } `json:"defaults"`
    Keys struct {
        BLS *KeyInfo `json:"bls,omitempty"`
        TLS *KeyInfo `json:"tls,omitempty"`
    } `json:"keys"`
}

type ModuleStatus struct {
    ID           string   `json:"id"`
    Version      string   `json:"version"`
    Loaded       bool     `json:"loaded"`
    Enabled      bool     `json:"enabled"`
    Capabilities []string `json:"capabilities"`
}

type KeyInfo struct {
    Available bool   `json:"available"`
    PublicKey string `json:"public_key,omitempty"`
    KeyHandle string `json:"key_handle,omitempty"`
}

func (c *CryftteeClient) GetStatus() (*StatusResponse, error) {
    resp, err := c.httpClient.Get(c.baseURL() + "/v1/staking/status")
    if err != nil {
        return nil, fmt.Errorf("failed to get status: %w", err)
    }
    defer resp.Body.Close()
    
    var status StatusResponse
    if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
        return nil, fmt.Errorf("failed to decode status: %w", err)
    }
    
    return &status, nil
}

func (c *CryftteeClient) WaitForSignerModule(timeout time.Duration) error {
    deadline := time.Now().Add(timeout)
    
    for time.Now().Before(deadline) {
        status, err := c.GetStatus()
        if err != nil {
            time.Sleep(500 * time.Millisecond)
            continue
        }
        
        // Check if BLS signer module is loaded
        for _, mod := range status.Modules {
            if contains(mod.Capabilities, "bls_sign") && mod.Loaded && mod.Enabled {
                log.Info("Signer module ready", "module", mod.ID, "version", mod.Version)
                return nil
            }
        }
        
        time.Sleep(500 * time.Millisecond)
    }
    
    return fmt.Errorf("signer module not ready after %v", timeout)
}
```

### Step 4: Initialize Keys (Verify Existing or Generate New)

**Key Initialization Rules:**
- CryftGo maintains a local key store at `/var/lib/cryftgo/staking/`
- If keys exist locally → use `verify` mode to confirm they exist in Web3Signer
- If keys don't exist locally → use `generate` mode to create new keys
- If verify fails → **FATAL ERROR** - node cannot start with missing keys

```go
// Register Request - same structure for BLS and TLS
type RegisterRequest struct {
    Mode      string `json:"mode"`               // "verify", "generate", "ephemeral", "import"
    PublicKey string `json:"publicKey,omitempty"` // Required for "verify" mode
    // ... other optional fields
}

// Register Response
type RegisterResponse struct {
    KeyHandle     string `json:"keyHandle"`
    BlsPubKeyB64  string `json:"blsPubKeyB64"`  // Base64-encoded public key
    ModuleID      string `json:"moduleId"`
    ModuleVersion string `json:"moduleVersion"`
}

func (c *CryftteeClient) InitializeNodeIdentity() (*NodeIdentity, error) {
    identity := &NodeIdentity{}
    
    // Load existing keys from CryftGo's local store
    savedBLSPubkey := loadSavedPubkey("/var/lib/cryftgo/staking/bls_pubkey")
    savedTLSPubkey := loadSavedPubkey("/var/lib/cryftgo/staking/tls_pubkey")
    
    // ═══════════════════════════════════════════════════════════════════════
    // BLS KEY: Verify existing or generate new
    // ═══════════════════════════════════════════════════════════════════════
    if savedBLSPubkey != "" {
        // Key exists locally - VERIFY it exists in Web3Signer
        log.Info("Verifying existing BLS key", "pubkey", savedBLSPubkey[:20]+"...")
        
        resp, err := c.RegisterKey("/v1/staking/bls/register", &RegisterRequest{
            Mode:      "verify",
            PublicKey: savedBLSPubkey,
        })
        if err != nil {
            // FATAL: Key in local store but NOT in Web3Signer = key loss
            return nil, fmt.Errorf(
                "FATAL: BLS key %s from local store not found in Web3Signer. "+
                "This may indicate key loss or Web3Signer misconfiguration. "+
                "Node cannot start safely. Error: %w",
                savedBLSPubkey[:20], err)
        }
        
        identity.BLSPublicKey = savedBLSPubkey
        identity.BLSKeyHandle = resp.KeyHandle
        log.Info("✓ BLS key verified in Web3Signer")
        
    } else {
        // No key locally - generate new one
        log.Info("No BLS key in local store, generating new key...")
        
        resp, err := c.RegisterKey("/v1/staking/bls/register", &RegisterRequest{
            Mode: "generate",
        })
        if err != nil {
            return nil, fmt.Errorf("BLS key generation failed: %w", err)
        }
        
        identity.BLSPublicKey = resp.PublicKey
        identity.BLSKeyHandle = resp.KeyHandle
        
        // IMPORTANT: Save to local store for future verifications
        savePubkey("/var/lib/cryftgo/staking/bls_pubkey", resp.PublicKey)
        log.Info("✓ Generated new BLS key", "pubkey", resp.PublicKey[:20]+"...")
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // TLS KEY: Same pattern as BLS
    // ═══════════════════════════════════════════════════════════════════════
    if savedTLSPubkey != "" {
        log.Info("Verifying existing TLS key", "pubkey", savedTLSPubkey[:20]+"...")
        
        resp, err := c.RegisterKey("/v1/staking/tls/register", &RegisterRequest{
            Mode:      "verify",
            PublicKey: savedTLSPubkey,
        })
        if err != nil {
            return nil, fmt.Errorf(
                "FATAL: TLS key %s from local store not found in Web3Signer. "+
                "Node ID would change if we regenerated - this is not safe. "+
                "Error: %w",
                savedTLSPubkey[:20], err)
        }
        
        identity.TLSPublicKey = savedTLSPubkey
        identity.TLSKeyHandle = resp.KeyHandle
        identity.NodeID = deriveNodeID(savedTLSPubkey)
        log.Info("✓ TLS key verified in Web3Signer")
        
    } else {
        log.Info("No TLS key in local store, generating new key...")
        
        resp, err := c.RegisterKey("/v1/staking/tls/register", &RegisterRequest{
            Mode: "generate",
        })
        if err != nil {
            return nil, fmt.Errorf("TLS key generation failed: %w", err)
        }
        
        identity.TLSPublicKey = resp.PublicKey
        identity.TLSKeyHandle = resp.KeyHandle
        identity.NodeID = deriveNodeID(resp.PublicKey)
        
        savePubkey("/var/lib/cryftgo/staking/tls_pubkey", resp.PublicKey)
        log.Info("✓ Generated new TLS key", "nodeID", identity.NodeID)
    }
    
    return identity, nil
}

func (c *CryftteeClient) RegisterKey(endpoint string, req *RegisterRequest) (*RegisterResponse, error) {
    body, _ := json.Marshal(req)
    resp, err := c.httpClient.Post(
        c.baseURL()+endpoint,
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == http.StatusNotFound {
        // Key not found in Web3Signer - this is a verification failure
        var errResp struct {
            Error   string `json:"error"`
            Details string `json:"details"`
        }
        json.NewDecoder(resp.Body).Decode(&errResp)
        return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Details)
    }
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
    }
    
    var result RegisterResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    return &result, nil
}
```

---

## Signing Operations

### BLS Signing (for Staking/Consensus)

```go
type BLSSignRequest struct {
    KeyHandle string `json:"key_handle"`
    Message   []byte `json:"message"` // Raw message bytes to sign
}

type BLSSignResponse struct {
    Success   bool   `json:"success"`
    Signature string `json:"signature"` // Hex-encoded BLS signature
    Error     string `json:"error,omitempty"`
}

func (c *CryftteeClient) SignBLS(keyHandle string, message []byte) ([]byte, error) {
    req := BLSSignRequest{
        KeyHandle: keyHandle,
        Message:   message,
    }
    body, _ := json.Marshal(req)
    
    resp, err := c.httpClient.Post(
        c.baseURL()+"/v1/staking/bls/sign",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        return nil, fmt.Errorf("BLS sign request failed: %w", err)
    }
    defer resp.Body.Close()
    
    var result BLSSignResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("failed to decode BLS sign response: %w", err)
    }
    
    if !result.Success {
        return nil, fmt.Errorf("BLS signing failed: %s", result.Error)
    }
    
    return hex.DecodeString(result.Signature)
}
```

### TLS Signing (for Node Identity/Certificates)

```go
type TLSSignRequest struct {
    KeyHandle string `json:"key_handle"`
    Digest    []byte `json:"digest"`    // SHA256 hash to sign
    Algorithm string `json:"algorithm"` // "ecdsa-sha256"
}

type TLSSignResponse struct {
    Success   bool   `json:"success"`
    Signature string `json:"signature"` // Hex-encoded ECDSA signature
    Error     string `json:"error,omitempty"`
}

func (c *CryftteeClient) SignTLS(keyHandle string, digest []byte) ([]byte, error) {
    req := TLSSignRequest{
        KeyHandle: keyHandle,
        Digest:    digest,
        Algorithm: "ecdsa-sha256",
    }
    body, _ := json.Marshal(req)
    
    resp, err := c.httpClient.Post(
        c.baseURL()+"/v1/staking/tls/sign",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        return nil, fmt.Errorf("TLS sign request failed: %w", err)
    }
    defer resp.Body.Close()
    
    var result TLSSignResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("failed to decode TLS sign response: %w", err)
    }
    
    if !result.Success {
        return nil, fmt.Errorf("TLS signing failed: %s", result.Error)
    }
    
    return hex.DecodeString(result.Signature)
}
```

---

## Complete Integration Example

### CryftGo Startup Flow

```go
type NodeIdentity struct {
    NodeID       string // Cryft Node ID (derived from TLS public key)
    BLSPublicKey string
    BLSKeyHandle string
    TLSPublicKey string
    TLSKeyHandle string
}

type CryftNode struct {
    cryftteeClient *CryftteeClient
    identity       *NodeIdentity
}

func (n *CryftNode) Initialize(cfg *Config) error {
    // Step 1: Create CryftTEE client
    cryftteeClient, err := NewCryftteeClient(&CryftteeConfig{
        Transport:  cfg.CryftteeTransport,  // Default: "uds"
        SocketPath: cfg.CryftteeSocketPath, // Default: "/tmp/cryfttee.sock"
        HTTPAddr:   cfg.CryftteeHTTPAddr,   // Default: "127.0.0.1:8443"
    })
    if err != nil {
        return fmt.Errorf("failed to create cryfttee client: %w", err)
    }
    n.cryftteeClient = cryftteeClient
    
    // Step 2: Verify CryftTEE attestation (optional but recommended)
    if cfg.CryftteeExpectedHash != "" {
        if err := cryftteeClient.VerifyAttestation(cfg.CryftteeExpectedHash); err != nil {
            return fmt.Errorf("cryfttee attestation failed: %w", err)
        }
    }
    
    // Step 3: Wait for signer module to be ready
    if err := cryftteeClient.WaitForSignerModule(30 * time.Second); err != nil {
        return fmt.Errorf("signer module not ready: %w", err)
    }
    
    // Step 4: Initialize node identity (keys)
    identity, err := cryftteeClient.InitializeNodeIdentity()
    if err != nil {
        return fmt.Errorf("failed to initialize identity: %w", err)
    }
    n.identity = identity
    
    log.Info("Node initialized",
        "nodeID", identity.NodeID,
        "blsPubKey", identity.BLSPublicKey[:16]+"...",
        "tlsPubKey", identity.TLSPublicKey[:16]+"...")
    
    return nil
}
```

### Staking Transaction Signing

```go
func (n *CryftNode) SignStakingTransaction(tx *StakingTx) ([]byte, error) {
    // Serialize transaction for signing
    message := tx.SigningBytes()
    
    // Sign with BLS key via CryftTEE
    signature, err := n.cryftteeClient.SignBLS(n.identity.BLSKeyHandle, message)
    if err != nil {
        return nil, fmt.Errorf("failed to sign staking tx: %w", err)
    }
    
    return signature, nil
}
```

### TLS Certificate Signing

```go
func (n *CryftNode) SignTLSCertificate(certDER []byte) ([]byte, error) {
    // Hash the certificate data
    digest := sha256.Sum256(certDER)
    
    // Sign with TLS key via CryftTEE
    signature, err := n.cryftteeClient.SignTLS(n.identity.TLSKeyHandle, digest[:])
    if err != nil {
        return nil, fmt.Errorf("failed to sign TLS cert: %w", err)
    }
    
    return signature, nil
}
```

---

## API Reference Summary

### CryftTEE Endpoints (via UDS `/tmp/cryfttee.sock`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/staking/status` | GET | Get module status and key availability |
| `/v1/staking/bls/register` | POST | Generate or import BLS key |
| `/v1/staking/bls/sign` | POST | Sign message with BLS key |
| `/v1/staking/tls/register` | POST | Generate or import TLS/SECP256k1 key |
| `/v1/staking/tls/sign` | POST | Sign digest with TLS key |
| `/v1/runtime/attestation` | GET | Get runtime attestation (hashes, version) |
| `/v1/runtime/connection` | GET | Get CryftGo↔CryftTEE connection status |
| `/v1/schema/modules` | GET | Get module compatibility schema |
| `/v1/admin/reload-modules` | POST | Reload module registry |
| `/v1/modules/{id}/status-panel` | GET | Get module-rendered status panel content |

---

## CryftGo ↔ CryftTEE Real-Time Connection Status

CryftTEE provides a dedicated endpoint for CryftGo to monitor the bidirectional connection health in real-time.

### Connection Status Endpoint

```go
// GET /v1/runtime/connection
type ConnectionStatusResponse struct {
    // Connection state
    Connected       bool      `json:"connected"`
    Transport       string    `json:"transport"`        // "uds" or "https"
    Endpoint        string    `json:"endpoint"`         // socket path or HTTP addr
    LastSeen        time.Time `json:"last_seen"`        // Last successful request from CryftGo
    Latency         int64     `json:"latency_ms"`       // Round-trip latency in ms
    
    // CryftGo client info (populated after first request)
    CryftGoVersion  string    `json:"cryftgo_version,omitempty"`
    CryftGoNodeID   string    `json:"cryftgo_node_id,omitempty"`
    
    // Health metrics
    RequestCount    uint64    `json:"request_count"`    // Total requests received
    ErrorCount      uint64    `json:"error_count"`      // Total errors
    LastError       string    `json:"last_error,omitempty"`
    LastErrorTime   time.Time `json:"last_error_time,omitempty"`
    
    // Signer module status
    SignerReady     bool      `json:"signer_ready"`
    SignerModuleID  string    `json:"signer_module_id,omitempty"`
}
```

### CryftGo Connection Heartbeat

CryftGo should send periodic heartbeats so CryftTEE can track connection health:

```go
// POST /v1/runtime/heartbeat
type HeartbeatRequest struct {
    CryftGoVersion string `json:"cryftgo_version"`
    NodeID         string `json:"node_id"`
    Timestamp      int64  `json:"timestamp"`
}

type HeartbeatResponse struct {
    Acknowledged    bool   `json:"acknowledged"`
    CryftteeVersion string `json:"cryfttee_version"`
    SignerReady     bool   `json:"signer_ready"`
    Timestamp       int64  `json:"timestamp"`
}

func (c *CryftteeClient) SendHeartbeat(nodeID string) error {
    req := HeartbeatRequest{
        CryftGoVersion: version.Version,
        NodeID:         nodeID,
        Timestamp:      time.Now().UnixMilli(),
    }
    body, _ := json.Marshal(req)
    
    resp, err := c.httpClient.Post(
        c.baseURL()+"/v1/runtime/heartbeat",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        return fmt.Errorf("heartbeat failed: %w", err)
    }
    defer resp.Body.Close()
    
    var result HeartbeatResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return fmt.Errorf("failed to decode heartbeat response: %w", err)
    }
    
    if !result.Acknowledged {
        return fmt.Errorf("heartbeat not acknowledged")
    }
    
    return nil
}

// Start heartbeat goroutine during initialization
func (n *CryftNode) startHeartbeat() {
    go func() {
        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()
        
        for {
            select {
            case <-ticker.C:
                if err := n.cryftteeClient.SendHeartbeat(n.identity.NodeID); err != nil {
                    log.Warn("CryftTEE heartbeat failed", "error", err)
                }
            case <-n.shutdownCh:
                return
            }
        }
    }()
}
```

---

## Module Status Panel Rendering

Modules can provide dynamic content for the CryftTEE status panel. This allows the signer module to display Web3Signer-managed public keys and other runtime information.

### Module Status Panel Interface

Each module can implement a `get_status_panel` export to render custom status content:

```rust
// WASM Module Export (Rust)
#[no_mangle]
pub extern "C" fn get_status_panel() -> *const u8 {
    let panel = StatusPanel {
        title: "BLS/TLS Signer".to_string(),
        sections: vec![
            StatusSection {
                heading: "Managed Keys".to_string(),
                items: get_managed_keys(),
            },
            StatusSection {
                heading: "Web3Signer Connection".to_string(),
                items: vec![
                    StatusItem::KeyValue("Endpoint".into(), WEB3SIGNER_URL.into()),
                    StatusItem::KeyValue("Status".into(), get_web3signer_status()),
                    StatusItem::KeyValue("Key Count".into(), get_key_count().to_string()),
                ],
            },
            StatusSection {
                heading: "Signing Statistics".to_string(),
                items: vec![
                    StatusItem::KeyValue("BLS Signs".into(), BLS_SIGN_COUNT.to_string()),
                    StatusItem::KeyValue("TLS Signs".into(), TLS_SIGN_COUNT.to_string()),
                    StatusItem::KeyValue("Last Sign".into(), format_timestamp(LAST_SIGN_TIME)),
                ],
            },
        ],
    };
    
    serialize_to_memory(&panel)
}

fn get_managed_keys() -> Vec<StatusItem> {
    let keys = query_web3signer_keys();
    keys.iter().map(|k| {
        StatusItem::PublicKey {
            key_type: k.key_type.clone(),     // "BLS" or "TLS"
            public_key: k.public_key.clone(), // Hex-encoded
            label: k.label.clone(),           // Optional friendly name
            created: k.created_at,
        }
    }).collect()
}
```

### Status Panel JSON Schema

```json
{
  "module_id": "bls_tls_signer_v1",
  "module_version": "1.0.0",
  "title": "BLS/TLS Signer",
  "sections": [
    {
      "heading": "Managed Keys",
      "items": [
        {
          "type": "public_key",
          "key_type": "BLS",
          "public_key": "0x8a4f3b2c1d...",
          "label": "Primary Staking Key",
          "created": "2025-11-29T10:30:00Z"
        },
        {
          "type": "public_key", 
          "key_type": "TLS",
          "public_key": "0x04a1b2c3d4...",
          "label": "Node Identity",
          "created": "2025-11-29T10:30:05Z"
        }
      ]
    },
    {
      "heading": "Web3Signer Connection",
      "items": [
        {"type": "key_value", "key": "Endpoint", "value": "http://localhost:9000"},
        {"type": "key_value", "key": "Status", "value": "Connected"},
        {"type": "key_value", "key": "Key Count", "value": "2"}
      ]
    },
    {
      "heading": "Signing Statistics",
      "items": [
        {"type": "key_value", "key": "BLS Signs", "value": "1,247"},
        {"type": "key_value", "key": "TLS Signs", "value": "89"},
        {"type": "key_value", "key": "Last Sign", "value": "2 seconds ago"}
      ]
    }
  ]
}
```

### CryftTEE Runtime: Aggregating Module Panels

```rust
// CryftTEE runtime aggregates all module status panels
async fn get_aggregated_status() -> FullStatusResponse {
    let mut module_panels = Vec::new();
    
    for module in registry.loaded_modules() {
        if let Some(panel) = module.call_get_status_panel() {
            module_panels.push(ModuleStatusPanel {
                module_id: module.id.clone(),
                enabled: module.enabled,
                panel: panel,
            });
        }
    }
    
    FullStatusResponse {
        cryfttee_version: CRYFTTEE_VERSION.to_string(),
        connection: get_cryftgo_connection_status(),
        modules: module_panels,
    }
}
```

### CryftGo: Fetching Module Status Panels

```go
// GET /v1/modules/{id}/status-panel
type ModuleStatusPanel struct {
    ModuleID      string          `json:"module_id"`
    ModuleVersion string          `json:"module_version"`
    Title         string          `json:"title"`
    Sections      []StatusSection `json:"sections"`
}

type StatusSection struct {
    Heading string       `json:"heading"`
    Items   []StatusItem `json:"items"`
}

type StatusItem struct {
    Type      string `json:"type"` // "key_value", "public_key", "status_indicator"
    
    // For key_value
    Key       string `json:"key,omitempty"`
    Value     string `json:"value,omitempty"`
    
    // For public_key
    KeyType   string `json:"key_type,omitempty"`   // "BLS", "TLS"
    PublicKey string `json:"public_key,omitempty"`
    Label     string `json:"label,omitempty"`
    Created   string `json:"created,omitempty"`
    
    // For status_indicator
    Status    string `json:"status,omitempty"`     // "ok", "warning", "error"
    Message   string `json:"message,omitempty"`
}

func (c *CryftteeClient) GetModuleStatusPanel(moduleID string) (*ModuleStatusPanel, error) {
    resp, err := c.httpClient.Get(
        c.baseURL() + "/v1/modules/" + moduleID + "/status-panel",
    )
    if err != nil {
        return nil, fmt.Errorf("failed to get module status panel: %w", err)
    }
    defer resp.Body.Close()
    
    var panel ModuleStatusPanel
    if err := json.NewDecoder(resp.Body).Decode(&panel); err != nil {
        return nil, fmt.Errorf("failed to decode status panel: %w", err)
    }
    
    return &panel, nil
}

// Get all module panels
func (c *CryftteeClient) GetAllModuleStatusPanels() ([]ModuleStatusPanel, error) {
    status, err := c.GetStatus()
    if err != nil {
        return nil, err
    }
    
    var panels []ModuleStatusPanel
    for _, mod := range status.Modules {
        if mod.Loaded && mod.Enabled {
            panel, err := c.GetModuleStatusPanel(mod.ID)
            if err != nil {
                log.Warn("Failed to get status panel", "module", mod.ID, "error", err)
                continue
            }
            panels = append(panels, *panel)
        }
    }
    
    return panels, nil
}
```

---

## Full Status Response (Unified View)

CryftGo can fetch a complete status view including connection health and all module panels:

```go
// GET /v1/staking/status (enhanced)
type FullStatusResponse struct {
    // Runtime info
    CryftteeVersion string `json:"cryfttee_version"`
    Uptime          int64  `json:"uptime_seconds"`
    
    // CryftGo connection status
    Connection ConnectionStatus `json:"connection"`
    
    // Loaded modules with their status panels
    Modules []ModuleWithPanel `json:"modules"`
    
    // Quick access to key availability
    Keys struct {
        BLS *KeyInfo `json:"bls,omitempty"`
        TLS *KeyInfo `json:"tls,omitempty"`
    } `json:"keys"`
}

type ConnectionStatus struct {
    Connected      bool      `json:"connected"`
    Transport      string    `json:"transport"`
    Endpoint       string    `json:"endpoint"`
    LastHeartbeat  time.Time `json:"last_heartbeat"`
    Latency        int64     `json:"latency_ms"`
    CryftGoVersion string    `json:"cryftgo_version,omitempty"`
    CryftGoNodeID  string    `json:"cryftgo_node_id,omitempty"`
}

type ModuleWithPanel struct {
    ID           string            `json:"id"`
    Version      string            `json:"version"`
    Loaded       bool              `json:"loaded"`
    Enabled      bool              `json:"enabled"`
    Capabilities []string          `json:"capabilities"`
    StatusPanel  *ModuleStatusPanel `json:"status_panel,omitempty"`
}
```

### Example Full Status Response

```json
{
  "cryfttee_version": "0.4.0",
  "uptime_seconds": 3600,
  "connection": {
    "connected": true,
    "transport": "uds",
    "endpoint": "/tmp/cryfttee.sock",
    "last_heartbeat": "2025-11-29T15:30:00Z",
    "latency_ms": 2,
    "cryftgo_version": "1.2.0",
    "cryftgo_node_id": "NodeID-P7oB2McjBGgW2NXXWVYjV8JEDFoW9xDE5"
  },
  "modules": [
    {
      "id": "bls_tls_signer_v1",
      "version": "1.0.0",
      "loaded": true,
      "enabled": true,
      "capabilities": ["bls_sign", "tls_sign", "key_gen"],
      "status_panel": {
        "title": "BLS/TLS Signer",
        "sections": [
          {
            "heading": "Managed Keys",
            "items": [
              {
                "type": "public_key",
                "key_type": "BLS",
                "public_key": "0x8a4f3b2c1d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
                "label": "Primary Staking Key",
                "created": "2025-11-29T10:30:00Z"
              },
              {
                "type": "public_key",
                "key_type": "TLS",
                "public_key": "0x04a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                "label": "Node Identity",
                "created": "2025-11-29T10:30:05Z"
              }
            ]
          },
          {
            "heading": "Web3Signer Connection",
            "items": [
              {"type": "key_value", "key": "Endpoint", "value": "http://localhost:9000"},
              {"type": "status_indicator", "status": "ok", "message": "Connected"},
              {"type": "key_value", "key": "Key Count", "value": "2"}
            ]
          }
        ]
      }
    }
  ],
  "keys": {
    "bls": {
      "available": true,
      "public_key": "0x8a4f3b2c1d5e6f7a8b9c...",
      "key_handle": "bls-key-001"
    },
    "tls": {
      "available": true,
      "public_key": "0x04a1b2c3d4e5f6a7b8c9...",
      "key_handle": "tls-key-001"
    }
  }
}
```

---

## Key Persistence Model

**CRITICAL: CryftGo's local key store is the source of truth for key existence.**

CryftGo maintains a local store of public keys at `/var/lib/cryftgo/staking/`:
- `bls_pubkey` - The BLS public key (hex-encoded)
- `tls_pubkey` - The TLS public key (hex-encoded)

The initialization flow follows these rules:

1. **If CryftGo has keys in local store** → Use `verify` mode to confirm they exist in Web3Signer
2. **If CryftGo has no keys** → Use `generate` mode to create new keys
3. **If verify fails (key not in Web3Signer)** → FATAL ERROR, node cannot start

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    KEY INITIALIZATION FLOW                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   CryftGo                  CryftTEE                    Web3Signer       │
│      │                        │                            │            │
│      │  1. Check local store  │                            │            │
│      │  (/var/lib/cryftgo/    │                            │            │
│      │   staking/bls_pubkey)  │                            │            │
│      │                        │                            │            │
│   ┌──┴──────────────────────┐ │                            │            │
│   │ IF keys exist locally:  │ │                            │            │
│   └──┬──────────────────────┘ │                            │            │
│      │                        │                            │            │
│      │  POST /bls/register    │                            │            │
│      │  {mode: "verify",      │                            │            │
│      │   publicKey: "0x..."}  │                            │            │
│      │───────────────────────>│  GET /api/v1/eth2/pubkeys  │            │
│      │                        │───────────────────────────>│            │
│      │                        │    [list of pubkeys]       │            │
│      │                        │<───────────────────────────│            │
│      │                        │                            │            │
│      │                        │  ┌───────────────────────┐ │            │
│      │                        │  │ Check if submitted    │ │            │
│      │                        │  │ pubkey exists in list │ │            │
│      │                        │  └───────────────────────┘ │            │
│      │                        │                            │            │
│      │   IF FOUND: 200 OK     │                            │            │
│      │<───────────────────────│                            │            │
│      │                        │                            │            │
│      │   IF NOT FOUND: 404    │                            │            │
│      │   "Key not found in    │                            │            │
│      │    Web3Signer - key    │                            │            │
│      │    loss detected"      │                            │            │
│      │<───────────────────────│                            │            │
│      │                        │                            │            │
│      │   *** FATAL ERROR ***  │                            │            │
│      │   Node MUST NOT start  │                            │            │
│      │   with missing keys    │                            │            │
│      │                        │                            │            │
│   ┌──┴──────────────────────┐ │                            │            │
│   │ IF no keys locally:     │ │                            │            │
│   └──┬──────────────────────┘ │                            │            │
│      │                        │                            │            │
│      │  POST /bls/register    │                            │            │
│      │  {mode: "generate"}    │                            │            │
│      │───────────────────────>│  POST /eth2/keystores     │            │
│      │                        │───────────────────────────>│            │
│      │                        │    {new key generated}     │            │
│      │                        │<───────────────────────────│            │
│      │                        │                            │            │
│      │   {publicKey: "0x.."   │                            │            │
│      │    keyHandle: "..."}   │                            │            │
│      │<───────────────────────│                            │            │
│      │                        │                            │            │
│   ┌──┴──┐                     │                            │            │
│   │SAVE │ pubkey to           │                            │            │
│   │local│ /var/lib/cryftgo/   │                            │            │
│   └──┬──┘ staking/bls_pubkey  │                            │            │
│      │                        │                            │            │
└──────┴────────────────────────┴────────────────────────────┴────────────┘
```

### Request/Response Types

```go
// BLS/TLS Register Request
type RegisterRequest struct {
    // Mode: "verify", "generate", "ephemeral", "persistent", "import"
    Mode      string `json:"mode"`
    
    // Required for "verify" mode - the pubkey from CryftGo's local store
    PublicKey string `json:"publicKey,omitempty"`
    
    // For "import" mode only
    EphemeralKeyB64 string `json:"ephemeralKeyB64,omitempty"`
    
    // Optional
    NetworkID uint64 `json:"networkID,omitempty"`
    NodeLabel string `json:"nodeLabel,omitempty"`
    ModuleID  string `json:"moduleId,omitempty"`
}

// Register Response
type RegisterResponse struct {
    KeyHandle     string `json:"keyHandle"`
    BlsPubKeyB64  string `json:"blsPubKeyB64"`  // or certChainPEM for TLS
    ModuleID      string `json:"moduleId"`
    ModuleVersion string `json:"moduleVersion"`
}
```

### CryftGo Implementation

```go
func (m *CryftteeManager) InitKeys() (*BLSKeyInfo, *TLSKeyInfo, error) {
    // Load any previously saved pubkeys from local store
    savedBLSPubkey := m.loadSavedBLSPubkey()
    savedTLSPubkey := m.loadSavedTLSPubkey()
    
    var blsKey *BLSKeyInfo
    var tlsKey *TLSKeyInfo
    
    // ═══════════════════════════════════════════════════════════════════════
    // BLS KEY LOGIC
    // ═══════════════════════════════════════════════════════════════════════
    if savedBLSPubkey != "" {
        // We have a key locally - VERIFY it exists in Web3Signer
        log.Printf("Verifying existing BLS key: %s...", savedBLSPubkey[:20])
        
        resp, err := m.callAPI("POST", "/v1/staking/bls/register", map[string]interface{}{
            "mode":      "verify",
            "publicKey": savedBLSPubkey,
        })
        if err != nil {
            return nil, nil, fmt.Errorf(
                "FATAL: BLS key %s from local store not found in Web3Signer. "+
                "This indicates key loss - the node cannot start safely. "+
                "Error: %w", savedBLSPubkey, err)
        }
        
        blsKey = &BLSKeyInfo{PublicKey: savedBLSPubkey}
        log.Printf("✓ BLS key verified in Web3Signer")
        
    } else {
        // No key locally - generate new one
        log.Println("No BLS key in local store, generating new key...")
        
        resp, err := m.callAPI("POST", "/v1/staking/bls/register", map[string]interface{}{
            "mode": "generate",
        })
        if err != nil {
            return nil, nil, fmt.Errorf("BLS key generation failed: %w", err)
        }
        
        blsKey = &BLSKeyInfo{PublicKey: resp.PublicKey}
        m.saveBLSPubkey(resp.PublicKey) // Persist to local store
        log.Printf("✓ Generated new BLS key: %s", resp.PublicKey[:20])
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // TLS KEY LOGIC (same pattern)
    // ═══════════════════════════════════════════════════════════════════════
    if savedTLSPubkey != "" {
        log.Printf("Verifying existing TLS key: %s...", savedTLSPubkey[:20])
        
        resp, err := m.callAPI("POST", "/v1/staking/tls/register", map[string]interface{}{
            "mode":      "verify",
            "publicKey": savedTLSPubkey,
        })
        if err != nil {
            return nil, nil, fmt.Errorf(
                "FATAL: TLS key %s from local store not found in Web3Signer. "+
                "Node ID would change if we generated a new key - this is not safe. "+
                "Error: %w", savedTLSPubkey, err)
        }
        
        tlsKey = &TLSKeyInfo{PublicKey: savedTLSPubkey}
        log.Printf("✓ TLS key verified in Web3Signer")
        
    } else {
        log.Println("No TLS key in local store, generating new key...")
        
        resp, err := m.callAPI("POST", "/v1/staking/tls/register", map[string]interface{}{
            "mode": "generate",
        })
        if err != nil {
            return nil, nil, fmt.Errorf("TLS key generation failed: %w", err)
        }
        
        tlsKey = &TLSKeyInfo{
            PublicKey: resp.PublicKey,
            NodeID:    deriveNodeID(resp.PublicKey),
        }
        m.saveTLSPubkey(resp.PublicKey)
        log.Printf("✓ Generated new TLS key, NodeID: %s", tlsKey.NodeID)
    }
    
    return blsKey, tlsKey, nil
}
```

### Key Points:

1. **CryftGo's local store is authoritative** - if a key exists there, it MUST exist in Web3Signer
2. **CryftTEE never auto-generates** - it only generates when explicitly asked with mode="generate"
3. **Verify failures are FATAL** - the node cannot start if keys are missing from Web3Signer
4. **No silent key regeneration** - this would change Node ID and break staking
5. **Web3Signer persists keys** - in HashiCorp Vault, filesystem, or cloud KMS

---

## CLI Flags for CryftGo

```go
var cryftteeFlags = []cli.Flag{
    &cli.StringFlag{
        Name:    "cryfttee-transport",
        Usage:   "CryftTEE transport: 'uds' or 'https'",
        Value:   "uds",
        EnvVars: []string{"CRYFTTEE_TRANSPORT"},
    },
    &cli.StringFlag{
        Name:    "cryfttee-socket",
        Usage:   "CryftTEE UDS socket path",
        Value:   "/tmp/cryfttee.sock",
        EnvVars: []string{"CRYFTTEE_SOCKET_PATH"},
    },
    &cli.StringFlag{
        Name:    "cryfttee-http-addr",
        Usage:   "CryftTEE HTTP address (for https transport)",
        Value:   "127.0.0.1:8443",
        EnvVars: []string{"CRYFTTEE_HTTP_ADDR"},
    },
    &cli.StringFlag{
        Name:    "cryfttee-expected-hash",
        Usage:   "Expected CryftTEE binary hash for attestation verification",
        Value:   "",
        EnvVars: []string{"CRYFTTEE_EXPECTED_HASH"},
    },
}
```

---

## Error Handling

CryftGo should handle these CryftTEE failure modes:

1. **Connection refused**: CryftTEE not running - wait and retry
2. **Module not loaded**: Signer module disabled - check manifest/trust config
3. **Key not found**: Key handle invalid - re-register key
4. **Signing failed**: Backend error - log and retry with backoff
5. **Attestation mismatch**: Untrusted CryftTEE - refuse to proceed

```go
func (c *CryftteeClient) withRetry(operation func() error) error {
    backoff := 100 * time.Millisecond
    maxBackoff := 5 * time.Second
    maxAttempts := 10
    
    for attempt := 1; attempt <= maxAttempts; attempt++ {
        err := operation()
        if err == nil {
            return nil
        }
        
        if attempt == maxAttempts {
            return fmt.Errorf("operation failed after %d attempts: %w", maxAttempts, err)
        }
        
        log.Warn("CryftTEE operation failed, retrying",
            "attempt", attempt,
            "error", err,
            "backoff", backoff)
        
        time.Sleep(backoff)
        backoff = min(backoff*2, maxBackoff)
    }
    
    return nil
}
```

---

## Summary Checklist

For CryftGo integration, implement:

### Core Client
- [ ] `CryftteeClient` with UDS transport support
- [ ] Connection to `/tmp/cryfttee.sock` by default
- [ ] Retry logic with exponential backoff
- [ ] CLI flags for CryftTEE configuration

### Attestation & Health
- [ ] `VerifyAttestation()` - verify CryftTEE binary hash
- [ ] `GetStatus()` - check module and key status
- [ ] `WaitForSignerModule()` - wait for signer to be ready
- [ ] `GetConnectionStatus()` - real-time connection health

### Key Management
- [ ] `RegisterBLSKey()` - generate/import BLS key
- [ ] `RegisterTLSKey()` - generate/import TLS key, get Node ID
- [ ] Key handle persistence in node config
- [ ] Check status before generating new keys

### Signing Operations
- [ ] `SignBLS()` - sign staking transactions
- [ ] `SignTLS()` - sign TLS certificates

### Connection Monitoring
- [ ] `SendHeartbeat()` - periodic heartbeat to CryftTEE
- [ ] Start heartbeat goroutine on initialization
- [ ] Track connection latency and errors
- [ ] Handle connection loss gracefully

### Module Status Panels
- [ ] `GetModuleStatusPanel()` - fetch module-rendered content
- [ ] `GetAllModuleStatusPanels()` - aggregate all module panels
- [ ] Display Web3Signer-managed public keys
- [ ] Show module-specific statistics (sign counts, etc.)
