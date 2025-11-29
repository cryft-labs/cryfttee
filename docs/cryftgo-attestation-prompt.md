# Cryftgo Binary Attestation Implementation Prompt

## Context

The cryfttee sidecar is a WASM module host that provides staking/signing services. For security accountability, cryfttee exposes attestation data at `/v1/runtime/attestation` that includes a `core_binary_hash` field. However, if cryfttee computes its own hash, a malicious binary could simply report a fake hash.

**Solution**: cryftgo (the parent process) must:
1. Compute the SHA256 hash of the cryfttee binary BEFORE launching it
2. Optionally verify this hash against a known-good value (from release artifacts or Cryft Labs)
3. Pass the verified hash to cryfttee via the `CRYFTTEE_VERIFIED_BINARY_HASH` environment variable
4. Optionally re-verify the running binary periodically via `/proc/<pid>/exe` (Linux) or equivalent

---

## ⚠️ CRITICAL: Cryftgo ↔ CryftTEE Connection Defaults

**Both cryftgo and cryfttee MUST use the same defaults to ensure connectivity.**

### Default Connection Settings

| Setting | Default Value | Environment Variable | CLI Flag |
|---------|---------------|---------------------|----------|
| **Transport** | `uds` (Unix Domain Socket) | `CRYFTTEE_API_TRANSPORT` | `--cryfttee-transport` |
| **Socket Path** | `/var/run/cryfttee.sock` | `CRYFTTEE_UDS_PATH` | `--cryfttee-socket` |
| **HTTP Address** | `127.0.0.1:8787` (only if transport=http) | `CRYFTTEE_HTTP_ADDR` | `--cryfttee-http-addr` |

### Connection Contract

```go
// ═══════════════════════════════════════════════════════════════════════════
// SHARED DEFAULTS - These MUST match between cryftgo and cryfttee
// ═══════════════════════════════════════════════════════════════════════════

const (
    // Transport: UDS is default, HTTP requires explicit opt-in
    DefaultTransport = "uds"
    
    // UDS socket path - used when transport=uds (default)
    DefaultSocketPath = "/var/run/cryfttee.sock"
    
    // HTTP address - only used when transport=http (explicit)
    DefaultHTTPAddr = "127.0.0.1:8787"
    
    // Web3Signer URL - where cryfttee connects for key operations
    DefaultWeb3SignerURL = "http://localhost:9000"
)
```

### Cryftgo Configuration (Go)

```go
// Cryftgo must configure these to match cryfttee
type CryftteeConnectionConfig struct {
    // Transport: "uds" (default) or "http" (explicit)
    Transport string `json:"transport" default:"uds"`
    
    // UDS socket path - must match cryfttee's CRYFTTEE_UDS_PATH
    SocketPath string `json:"socket_path" default:"/var/run/cryfttee.sock"`
    
    // HTTP address - must match cryfttee's CRYFTTEE_HTTP_ADDR (if using HTTP)
    HTTPAddr string `json:"http_addr" default:"127.0.0.1:8787"`
}

// NewCryftteeConnection creates a connection with proper defaults
func NewCryftteeConnection(cfg CryftteeConnectionConfig) (*http.Client, error) {
    // Apply defaults
    if cfg.Transport == "" {
        cfg.Transport = "uds" // DEFAULT: Unix Domain Socket
    }
    if cfg.SocketPath == "" {
        cfg.SocketPath = "/var/run/cryfttee.sock" // DEFAULT socket path
    }
    if cfg.HTTPAddr == "" {
        cfg.HTTPAddr = "127.0.0.1:8787" // DEFAULT HTTP address
    }
    
    switch cfg.Transport {
    case "uds":
        // DEFAULT: Connect via Unix Domain Socket
        return &http.Client{
            Timeout: 30 * time.Second,
            Transport: &http.Transport{
                DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
                    return net.Dial("unix", cfg.SocketPath)
                },
            },
        }, nil
        
    case "http":
        // EXPLICIT: Connect via HTTP (requires --cryfttee-transport=http)
        return &http.Client{
            Timeout: 30 * time.Second,
        }, nil
        
    default:
        return nil, fmt.Errorf("unknown transport: %s (must be 'uds' or 'http')", cfg.Transport)
    }
}
```

### CryftTEE Configuration (Rust)

```rust
// CryftTEE reads these from environment or uses defaults
// These MUST match cryftgo's defaults

const DEFAULT_TRANSPORT: &str = "uds";
const DEFAULT_SOCKET_PATH: &str = "/var/run/cryfttee.sock";
const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:8787";

fn load_transport_config() -> TransportConfig {
    let transport = std::env::var("CRYFTTEE_API_TRANSPORT")
        .unwrap_or_else(|_| DEFAULT_TRANSPORT.to_string());
    
    match transport.as_str() {
        "uds" => TransportConfig::UDS {
            path: std::env::var("CRYFTTEE_UDS_PATH")
                .unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string()),
        },
        "http" => TransportConfig::HTTP {
            addr: std::env::var("CRYFTTEE_HTTP_ADDR")
                .unwrap_or_else(|_| DEFAULT_HTTP_ADDR.to_string()),
        },
        _ => panic!("Unknown transport: {}", transport),
    }
}
```

### Launch Sequence with Correct Defaults

```go
// Cryftgo launches cryfttee with matching transport config
func (m *CryftteeManager) Start(config *CryftgoConfig) error {
    // ─────────────────────────────────────────────────────────────────────
    // STEP 1: Apply defaults (MUST match cryfttee's defaults)
    // ─────────────────────────────────────────────────────────────────────
    transport := config.Transport
    if transport == "" {
        transport = "uds" // DEFAULT
    }
    
    socketPath := config.CryftteeSocketPath
    if socketPath == "" {
        socketPath = "/var/run/cryfttee.sock" // DEFAULT
    }
    
    httpAddr := config.CryftteeHTTPAddr
    if httpAddr == "" {
        httpAddr = "127.0.0.1:8787" // DEFAULT
    }
    
    // ─────────────────────────────────────────────────────────────────────
    // STEP 2: Build environment for cryfttee (pass same values)
    // ─────────────────────────────────────────────────────────────────────
    env := append(os.Environ(),
        fmt.Sprintf("CRYFTTEE_VERIFIED_BINARY_HASH=%s", m.verifiedHash),
        fmt.Sprintf("CRYFTTEE_API_TRANSPORT=%s", transport),
    )
    
    if transport == "uds" {
        env = append(env, fmt.Sprintf("CRYFTTEE_UDS_PATH=%s", socketPath))
    } else {
        env = append(env, fmt.Sprintf("CRYFTTEE_HTTP_ADDR=%s", httpAddr))
    }
    
    if config.Web3SignerURL != "" {
        env = append(env, fmt.Sprintf("CRYFTTEE_WEB3SIGNER_URL=%s", config.Web3SignerURL))
    }
    
    // ─────────────────────────────────────────────────────────────────────
    // STEP 3: Launch cryfttee
    // ─────────────────────────────────────────────────────────────────────
    m.process = exec.Command(m.config.BinaryPath)
    m.process.Env = env
    
    if err := m.process.Start(); err != nil {
        return fmt.Errorf("failed to start cryfttee: %w", err)
    }
    
    log.Printf("Started cryfttee (PID %d) with transport=%s", 
        m.process.Process.Pid, transport)
    
    // ─────────────────────────────────────────────────────────────────────
    // STEP 4: Initialize client with SAME transport settings
    // ─────────────────────────────────────────────────────────────────────
    m.transport = transport
    m.socketPath = socketPath
    m.httpAddr = httpAddr
    m.initHTTPClient() // Uses same values
    
    return nil
}
```

### Verification: Ensure Connection Works

```go
// After starting cryfttee, verify connectivity before proceeding
func (m *CryftteeManager) verifyConnection() error {
    // Wait for socket/port to be available
    deadline := time.Now().Add(30 * time.Second)
    
    for time.Now().Before(deadline) {
        switch m.transport {
        case "uds":
            // Check if socket file exists
            if _, err := os.Stat(m.socketPath); err == nil {
                // Try to connect
                conn, err := net.Dial("unix", m.socketPath)
                if err == nil {
                    conn.Close()
                    log.Printf("✓ UDS connection verified: %s", m.socketPath)
                    return nil
                }
            }
        case "http":
            // Try HTTP health check
            resp, err := http.Get(fmt.Sprintf("http://%s/v1/staking/status", m.httpAddr))
            if err == nil {
                resp.Body.Close()
                log.Printf("✓ HTTP connection verified: %s", m.httpAddr)
                return nil
            }
        }
        time.Sleep(500 * time.Millisecond)
    }
    
    return fmt.Errorf("failed to connect to cryfttee via %s after 30s", m.transport)
}
```

### CLI Flags Summary

```go
// Cryftgo CLI flags - defaults MUST match cryfttee
var (
    CryftteeTransportFlag = cli.StringFlag{
        Name:   "cryfttee-transport",
        Usage:  "Transport for cryfttee connection: 'uds' (default) or 'http'",
        Value:  "uds",  // ← DEFAULT: UDS
        EnvVar: "CRYFTGO_CRYFTTEE_TRANSPORT",
    }
    
    CryftteeSocketFlag = cli.StringFlag{
        Name:   "cryfttee-socket",
        Usage:  "Path to cryfttee UDS socket (when transport=uds)",
        Value:  "/var/run/cryfttee.sock",  // ← DEFAULT socket path
        EnvVar: "CRYFTGO_CRYFTTEE_SOCKET",
    }
    
    CryftteeHTTPAddrFlag = cli.StringFlag{
        Name:   "cryfttee-http-addr",
        Usage:  "HTTP address for cryfttee (when transport=http)",
        Value:  "127.0.0.1:8787",  // ← DEFAULT HTTP address
        EnvVar: "CRYFTGO_CRYFTTEE_HTTP_ADDR",
    }
    
    CryftteeSignerFlag = cli.BoolFlag{
        Name:   "cryfttee-signer",
        Usage:  "Enable cryfttee TEE signer for BLS/TLS key management",
        EnvVar: "CRYFTGO_CRYFTTEE_SIGNER",
    }
    
    CryftteeBinaryFlag = cli.StringFlag{
        Name:   "cryfttee-binary",
        Usage:  "Path to cryfttee binary",
        Value:  "/usr/local/bin/cryfttee",
        EnvVar: "CRYFTGO_CRYFTTEE_BINARY",
    }
    
    Web3SignerURLFlag = cli.StringFlag{
        Name:   "web3signer-url",
        Usage:  "URL of Web3Signer instance",
        Value:  "http://localhost:9000",  // ← DEFAULT Web3Signer URL
        EnvVar: "CRYFTGO_WEB3SIGNER_URL",
    }
)
```

---

## Communication: UDS (Default) vs HTTP (Optional)

**IMPORTANT**: cryftgo and cryfttee communicate via **Unix Domain Socket (UDS) by default**. HTTP/HTTPS is only used when explicitly configured.

### Default: Unix Domain Socket

```go
// Default UDS path
const DefaultCryftteeSocketPath = "/var/run/cryfttee.sock"

// Connect to cryfttee via UDS
func dialCryftteeUDS(socketPath string) (*http.Client, error) {
    return &http.Client{
        Transport: &http.Transport{
            DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
                return net.Dial("unix", socketPath)
            },
        },
    }, nil
}

// Make request via UDS (use "http://localhost" as placeholder, actual routing is via socket)
func (m *CryftteeManager) callAPI(endpoint string) (*http.Response, error) {
    return m.udsClient.Get("http://localhost" + endpoint)
}
```

### Optional: HTTP/HTTPS (Explicit Configuration Only)

HTTP transport should only be enabled via explicit configuration:

```go
type CryftteeTransport string

const (
    TransportUDS   CryftteeTransport = "uds"    // Default
    TransportHTTP  CryftteeTransport = "http"   // Requires explicit config
    TransportHTTPS CryftteeTransport = "https"  // Requires explicit config + TLS
)

type CryftteeConfig struct {
    Transport  CryftteeTransport `json:"transport"`   // Default: "uds"
    SocketPath string           `json:"socket_path"` // Default: /var/run/cryfttee.sock
    HTTPAddr   string           `json:"http_addr"`   // Only if transport=http/https
    TLSCert    string           `json:"tls_cert"`    // Only if transport=https
    TLSKey     string           `json:"tls_key"`     // Only if transport=https
}
```

---

## Signing Services: BLS and TLS Keys

CryftTEE integrates with **Web3Signer** (backed by HashiCorp Vault) for key management:

### Key Types

| Key Type | Algorithm | Purpose | Web3Signer API |
|----------|-----------|---------|----------------|
| **BLS** | BLS12-381 | ETH2 consensus signing (attestations, proposals, sync committees) | `/api/v1/eth2/sign/{pubkey}` |
| **SECP256k1** | ECDSA | ETH1 execution signing, TLS certificates | `/api/v1/eth1/sign/{pubkey}` |

### CryftTEE Staking API Endpoints (via UDS or HTTP)

```
POST /v1/staking/bls/register   - Register a BLS public key
POST /v1/staking/bls/sign       - Sign with BLS key (attestations, blocks, etc.)
POST /v1/staking/tls/register   - Register a TLS/SECP256k1 public key  
POST /v1/staking/tls/sign       - Sign with TLS key (certificates, auth tokens)
GET  /v1/staking/status         - Get signing module status and loaded keys
```

### Example: BLS Signing Flow

```go
// Sign an attestation via cryfttee (which proxies to Web3Signer)
func (m *CryftteeManager) SignAttestation(pubkey string, attestation []byte) ([]byte, error) {
    req := SignRequest{
        PublicKey: pubkey,
        Data:      attestation,
        Type:      "ATTESTATION",
    }
    
    body, _ := json.Marshal(req)
    resp, err := m.callAPI("/v1/staking/bls/sign", "POST", body)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result SignResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return result.Signature, nil
}
```

### Example: TLS Certificate Signing

```go
// Sign a TLS CSR via cryfttee
func (m *CryftteeManager) SignTLSCertificate(pubkey string, csr []byte) ([]byte, error) {
    req := SignRequest{
        PublicKey: pubkey,
        Data:      csr,
        Type:      "TLS_CSR",
    }
    
    body, _ := json.Marshal(req)
    resp, err := m.callAPI("/v1/staking/tls/sign", "POST", body)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result SignResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return result.Signature, nil
}
```

---

## Implementation Requirements

### 1. Binary Hash Computation (Pre-Launch)

Before spawning cryfttee, compute the SHA256 hash of the binary:

```go
import (
    "crypto/sha256"
    "fmt"
    "os"
)

func computeBinaryHash(binaryPath string) (string, error) {
    data, err := os.ReadFile(binaryPath)
    if err != nil {
        return "", fmt.Errorf("failed to read cryfttee binary: %w", err)
    }
    
    hash := sha256.Sum256(data)
    return fmt.Sprintf("sha256:%x", hash), nil
}
```

### 2. Optional: Verify Against Known-Good Hash

Compare the computed hash against expected values. This could come from:
- A hardcoded constant for each release version
- A signed manifest downloaded from Cryft Labs
- A configuration file with pinned hashes

```go
type CryftteeRelease struct {
    Version string `json:"version"`
    Hash    string `json:"hash"`
    // Optional: signature from Cryft Labs
    Signature string `json:"signature,omitempty"`
}

func verifyBinaryIntegrity(computedHash string, expectedReleases []CryftteeRelease, version string) error {
    for _, release := range expectedReleases {
        if release.Version == version && release.Hash == computedHash {
            return nil // Hash matches expected
        }
    }
    return fmt.Errorf("binary hash %s does not match any known release", computedHash)
}
```

### 3. Launch CryftTEE with Verified Hash

Pass the externally-verified hash via environment variable:

```go
func launchCryfttee(binaryPath string, args []string) (*exec.Cmd, error) {
    // Compute hash BEFORE launching
    hash, err := computeBinaryHash(binaryPath)
    if err != nil {
        return nil, err
    }
    
    // Optional: verify against known releases
    // if err := verifyBinaryIntegrity(hash, knownReleases, targetVersion); err != nil {
    //     return nil, err
    // }
    
    cmd := exec.Command(binaryPath, args...)
    cmd.Env = append(os.Environ(), 
        fmt.Sprintf("CRYFTTEE_VERIFIED_BINARY_HASH=%s", hash),
    )
    
    // Capture stdout/stderr, set up process group, etc.
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    
    if err := cmd.Start(); err != nil {
        return nil, fmt.Errorf("failed to start cryfttee: %w", err)
    }
    
    log.Printf("Launched cryfttee (PID %d) with verified hash: %s", cmd.Process.Pid, hash)
    return cmd, nil
}
```

### 4. Optional: Periodic Re-Verification (Linux)

On Linux, the original binary is accessible via `/proc/<pid>/exe`. This catches:
- Binary replacement while running (unlikely with proper permissions)
- Provides ongoing verification for long-running processes

```go
func verifyRunningBinary(pid int, expectedHash string) error {
    exePath := fmt.Sprintf("/proc/%d/exe", pid)
    
    // Read the actual running binary
    data, err := os.ReadFile(exePath)
    if err != nil {
        return fmt.Errorf("failed to read running binary: %w", err)
    }
    
    actualHash := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
    if actualHash != expectedHash {
        return fmt.Errorf("running binary hash mismatch: expected %s, got %s", expectedHash, actualHash)
    }
    
    return nil
}
```

### 5. Verify Attestation Response

After cryfttee starts, verify the attestation endpoint returns the correct hash:

```go
func verifyAttestation(cryftteeAddr string, expectedHash string) error {
    resp, err := http.Get(fmt.Sprintf("http://%s/v1/runtime/attestation", cryftteeAddr))
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    var attestation struct {
        CoreBinaryHash string `json:"core_binary_hash"`
        ManifestHash   string `json:"manifest_hash"`
        CryftteeVersion string `json:"cryfttee_version"`
    }
    
    if err := json.NewDecoder(resp.Body).Decode(&attestation); err != nil {
        return err
    }
    
    if attestation.CoreBinaryHash != expectedHash {
        return fmt.Errorf("attestation hash mismatch: expected %s, got %s", 
            expectedHash, attestation.CoreBinaryHash)
    }
    
    log.Printf("Attestation verified: cryfttee %s, binary %s", 
        attestation.CryftteeVersion, attestation.CoreBinaryHash)
    return nil
}
```

---

## Integration Points

### CryftTEE Behavior (Already Implemented)

CryftTEE handles the environment variable as follows:

1. **On startup**, checks for `CRYFTTEE_VERIFIED_BINARY_HASH` env var
2. **If set**: Uses this hash directly in attestation responses (trusted)
3. **If not set**: Falls back to self-hashing via `std::env::current_exe()` and logs a warning

```rust
// From cryfttee config/mod.rs
if let Ok(hash) = std::env::var("CRYFTTEE_VERIFIED_BINARY_HASH") {
    if !hash.is_empty() {
        info!("Using externally-verified binary hash from cryftgo");
        config.verified_binary_hash = Some(hash);
    }
}
if config.verified_binary_hash.is_none() {
    warn!("No CRYFTTEE_VERIFIED_BINARY_HASH set - attestation will use self-reported hash (less secure)");
}
```

### Hash Format

The hash format is: `sha256:<64-char-hex>`

Example: `sha256:a1b2c3d4e5f6...`

---

## Complete Integration Example

```go
package cryfttee

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "net/http"
    "os"
    "os/exec"
    "time"
)

type TransportType string

const (
    TransportUDS   TransportType = "uds"   // Default - Unix Domain Socket
    TransportHTTP  TransportType = "http"  // Optional - requires explicit config
    TransportHTTPS TransportType = "https" // Optional - requires explicit config + TLS
)

type CryftteeConfig struct {
    BinaryPath string        `json:"binary_path"`
    Transport  TransportType `json:"transport"`    // Default: "uds"
    SocketPath string        `json:"socket_path"`  // Default: /var/run/cryfttee.sock
    HTTPAddr   string        `json:"http_addr"`    // Only used if transport=http/https
}

type CryftteeManager struct {
    config       CryftteeConfig
    verifiedHash string
    process      *exec.Cmd
    httpClient   *http.Client
}

func NewCryftteeManager(config CryftteeConfig) *CryftteeManager {
    // Set defaults
    if config.Transport == "" {
        config.Transport = TransportUDS
    }
    if config.SocketPath == "" {
        config.SocketPath = "/var/run/cryfttee.sock"
    }
    
    return &CryftteeManager{config: config}
}

func (m *CryftteeManager) Start(args []string) error {
    // Step 1: Compute binary hash BEFORE launching
    data, err := os.ReadFile(m.config.BinaryPath)
    if err != nil {
        return fmt.Errorf("failed to read cryfttee binary: %w", err)
    }
    m.verifiedHash = fmt.Sprintf("sha256:%x", sha256.Sum256(data))
    
    // Step 2: Build environment with verified hash and transport config
    env := append(os.Environ(),
        fmt.Sprintf("CRYFTTEE_VERIFIED_BINARY_HASH=%s", m.verifiedHash),
        fmt.Sprintf("CRYFTTEE_API_TRANSPORT=%s", m.config.Transport),
    )
    
    if m.config.Transport == TransportUDS {
        env = append(env, fmt.Sprintf("CRYFTTEE_UDS_PATH=%s", m.config.SocketPath))
    } else {
        env = append(env, fmt.Sprintf("CRYFTTEE_HTTP_ADDR=%s", m.config.HTTPAddr))
    }
    
    // Step 3: Launch cryfttee
    m.process = exec.Command(m.config.BinaryPath, args...)
    m.process.Env = env
    m.process.Stdout = os.Stdout
    m.process.Stderr = os.Stderr
    
    if err := m.process.Start(); err != nil {
        return fmt.Errorf("failed to start cryfttee: %w", err)
    }
    
    log.Printf("Started cryfttee (PID %d) with hash: %s, transport: %s", 
        m.process.Process.Pid, m.verifiedHash, m.config.Transport)
    
    // Step 4: Initialize HTTP client based on transport
    m.initHTTPClient()
    
    // Step 5: Wait for startup and verify attestation
    if err := m.waitForReady(30 * time.Second); err != nil {
        m.process.Process.Kill()
        return fmt.Errorf("cryfttee failed to start: %w", err)
    }
    
    if err := m.VerifyAttestation(); err != nil {
        m.process.Process.Kill()
        return fmt.Errorf("attestation verification failed: %w", err)
    }
    
    return nil
}

func (m *CryftteeManager) initHTTPClient() {
    switch m.config.Transport {
    case TransportUDS:
        // Unix Domain Socket transport (default)
        m.httpClient = &http.Client{
            Timeout: 30 * time.Second,
            Transport: &http.Transport{
                DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
                    return net.Dial("unix", m.config.SocketPath)
                },
            },
        }
    case TransportHTTP, TransportHTTPS:
        // Standard HTTP/HTTPS transport
        m.httpClient = &http.Client{
            Timeout: 30 * time.Second,
        }
    }
}

// callAPI makes a request to cryfttee via configured transport
func (m *CryftteeManager) callAPI(method, endpoint string, body []byte) (*http.Response, error) {
    var url string
    
    switch m.config.Transport {
    case TransportUDS:
        // For UDS, use http://localhost as placeholder (socket handles routing)
        url = "http://localhost" + endpoint
    case TransportHTTP:
        url = "http://" + m.config.HTTPAddr + endpoint
    case TransportHTTPS:
        url = "https://" + m.config.HTTPAddr + endpoint
    }
    
    var req *http.Request
    var err error
    
    if body != nil {
        req, err = http.NewRequest(method, url, bytes.NewReader(body))
    } else {
        req, err = http.NewRequest(method, url, nil)
    }
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/json")
    return m.httpClient.Do(req)
}

func (m *CryftteeManager) waitForReady(timeout time.Duration) error {
    deadline := time.Now().Add(timeout)
    
    for time.Now().Before(deadline) {
        resp, err := m.callAPI("GET", "/v1/staking/status", nil)
        if err == nil {
            resp.Body.Close()
            if resp.StatusCode == 200 {
                return nil
            }
        }
        time.Sleep(500 * time.Millisecond)
    }
    
    return fmt.Errorf("timeout waiting for cryfttee to be ready")
}

func (m *CryftteeManager) VerifyAttestation() error {
    resp, err := m.callAPI("GET", "/v1/runtime/attestation", nil)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    var attestation struct {
        CoreBinaryHash string `json:"core_binary_hash"`
        CryftteeVersion string `json:"cryfttee_version"`
        ManifestHash   string `json:"manifest_hash"`
    }
    
    if err := json.NewDecoder(resp.Body).Decode(&attestation); err != nil {
        return err
    }
    
    if attestation.CoreBinaryHash != m.verifiedHash {
        return fmt.Errorf("hash mismatch: expected %s, got %s",
            m.verifiedHash, attestation.CoreBinaryHash)
    }
    
    log.Printf("✓ Attestation verified: cryfttee %s", attestation.CryftteeVersion)
    return nil
}

// BLS Signing (ETH2 consensus)
func (m *CryftteeManager) SignBLS(pubkey string, data []byte, sigType string) ([]byte, error) {
    req := map[string]interface{}{
        "pubkey": pubkey,
        "data":   data,
        "type":   sigType, // ATTESTATION, BLOCK, SYNC_COMMITTEE, etc.
    }
    body, _ := json.Marshal(req)
    
    resp, err := m.callAPI("POST", "/v1/staking/bls/sign", body)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result struct {
        Signature []byte `json:"signature"`
    }
    json.NewDecoder(resp.Body).Decode(&result)
    return result.Signature, nil
}

// TLS/SECP256k1 Signing
func (m *CryftteeManager) SignTLS(pubkey string, data []byte) ([]byte, error) {
    req := map[string]interface{}{
        "pubkey": pubkey,
        "data":   data,
    }
    body, _ := json.Marshal(req)
    
    resp, err := m.callAPI("POST", "/v1/staking/tls/sign", body)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result struct {
        Signature []byte `json:"signature"`
    }
    json.NewDecoder(resp.Body).Decode(&result)
    return result.Signature, nil
}

func (m *CryftteeManager) Wait() error {
    return m.process.Wait()
}

func (m *CryftteeManager) Stop() error {
    if m.process != nil && m.process.Process != nil {
        return m.process.Process.Signal(os.Interrupt)
    }
    return nil
}
```

---

## Cryftgo ↔ CryftTEE Coordination

### Responsibility Split

| Component | Responsibility |
|-----------|----------------|
| **cryftgo** | Decides WHEN to generate keys, WHICH pubkey to use, stores pubkey reference |
| **cryfttee** | Provides Web3Signer proxy, exposes available pubkeys, handles signing requests |
| **Web3Signer** | Generates keys, stores private keys (via Vault), performs actual signing |

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    COMPONENT RESPONSIBILITIES                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────────────────────┐  │
│  │   CRYFTGO   │      │   CRYFTTEE   │      │   WEB3SIGNER + VAULT        │  │
│  │             │      │             │      │                             │  │
│  │ • Start/stop│      │ • UDS API   │      │ • Key generation            │  │
│  │   cryfttee   │      │ • Proxy to  │      │ • Private key storage       │  │
│  │ • Check     │      │   Web3Signer│      │ • BLS/SECP256k1 signing     │  │
│  │   pubkeys   │      │ • Expose    │      │ • Keystore management       │  │
│  │ • Decide to │      │   pubkeys   │      │                             │  │
│  │   generate  │      │ • Attestation│     │                             │  │
│  │ • Save      │      │             │      │                             │  │
│  │   pubkey ref│      │             │      │                             │  │
│  │ • Sign reqs │      │             │      │                             │  │
│  └──────┬──────┘      └──────┬──────┘      └──────────────┬──────────────┘  │
│         │                    │                            │                 │
│         │    UDS Socket      │      HTTP (internal)       │                 │
│         └────────────────────┴────────────────────────────┘                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Generation Coordination

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         KEY GENERATION FLOW                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  CRYFTGO                      CRYFTTEE                      WEB3SIGNER        │
│  ───────                      ───────                      ──────────        │
│     │                            │                             │             │
│     │ 1. GET /v1/staking/status  │                             │             │
│     │───────────────────────────>│ 2. GET /eth/v1/keystores    │             │
│     │                            │────────────────────────────>│             │
│     │                            │    {bls: [], tls: []}       │             │
│     │    {bls_pubkeys: [],       │<────────────────────────────│             │
│     │     tls_pubkeys: []}       │                             │             │
│     │<───────────────────────────│                             │             │
│     │                            │                             │             │
│     │ 3. [DECISION: pubkeys empty, need to generate]           │             │
│     │                            │                             │             │
│     │ 4. POST /v1/staking/bls/register                         │             │
│     │    {action: "generate"}    │                             │             │
│     │───────────────────────────>│ 5. POST /eth/v1/keystores   │             │
│     │                            │    {type: "bls"}            │             │
│     │                            │────────────────────────────>│             │
│     │                            │                             │ 6. Generate │
│     │                            │                             │    BLS key  │
│     │                            │                             │    Store in │
│     │                            │    {pubkey: "0xabc123..."}  │    Vault    │
│     │                            │<────────────────────────────│             │
│     │    {pubkey: "0xabc123..."} │                             │             │
│     │<───────────────────────────│                             │             │
│     │                            │                             │             │
│     │ 7. [CRYFTGO saves pubkey to /var/lib/cryftgo/staking/bls_pubkey]      │
│     │                            │                             │             │
│     │ 8. POST /v1/staking/tls/register                         │             │
│     │    {action: "generate"}    │                             │             │
│     │───────────────────────────>│ ... (same flow for TLS)     │             │
│     │                            │                             │             │
│     │ 9. [CRYFTGO derives NodeID from TLS pubkey]              │             │
│     │                            │                             │             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Usage Coordination (Signing)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           KEY USAGE FLOW (SIGNING)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  CRYFTGO                      CRYFTTEE                      WEB3SIGNER        │
│  ───────                      ───────                      ──────────        │
│     │                            │                             │             │
│     │ [Validator needs to sign attestation]                    │             │
│     │                            │                             │             │
│     │ 1. POST /v1/staking/bls/sign                             │             │
│     │    {                       │                             │             │
│     │      pubkey: "0xabc123..", │                             │             │
│     │      data: <attestation>,  │                             │             │
│     │      type: "ATTESTATION"   │                             │             │
│     │    }                       │                             │             │
│     │───────────────────────────>│                             │             │
│     │                            │ 2. Validate request         │             │
│     │                            │    Check pubkey is known    │             │
│     │                            │                             │             │
│     │                            │ 3. POST /api/v1/eth2/sign/0xabc123..     │
│     │                            │    {                        │             │
│     │                            │      type: "ATTESTATION",   │             │
│     │                            │      data: <attestation>    │             │
│     │                            │    }                        │             │
│     │                            │────────────────────────────>│             │
│     │                            │                             │ 4. Retrieve │
│     │                            │                             │    key from │
│     │                            │                             │    Vault    │
│     │                            │                             │             │
│     │                            │                             │ 5. Sign     │
│     │                            │                             │    data     │
│     │                            │    {signature: "0xdef..."}  │             │
│     │                            │<────────────────────────────│             │
│     │    {signature: "0xdef..."} │                             │             │
│     │<───────────────────────────│                             │             │
│     │                            │                             │             │
│     │ 6. [CRYFTGO broadcasts signed attestation to network]    │             │
│     │                            │                             │             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### API Contract

#### CryftTEE Exposes (via UDS `/var/run/cryfttee.sock`)

```yaml
# Status & Key Discovery
GET /v1/staking/status
Response:
  ready: bool
  web3signer_url: string
  web3signer_connected: bool
  bls_pubkeys: []string      # Available BLS pubkeys from Web3Signer
  tls_pubkeys: []string      # Available TLS/SECP256k1 pubkeys
  capabilities: []string     # ["bls_signing", "tls_signing", "key_generation"]

# Key Generation (cryftgo decides when to call)
POST /v1/staking/bls/register
Request:  {action: "generate"}
Response: {pubkey: "0x..."}

POST /v1/staking/tls/register  
Request:  {action: "generate"}
Response: {pubkey: "0x...", certificate: "..."}

# Signing (cryftgo provides pubkey to use)
POST /v1/staking/bls/sign
Request:  {pubkey: "0x...", data: bytes, type: "ATTESTATION"|"BLOCK"|...}
Response: {signature: "0x..."}

POST /v1/staking/tls/sign
Request:  {pubkey: "0x...", data: bytes}
Response: {signature: "0x..."}
```

#### Cryftgo Stores Locally (`/var/lib/cryftgo/staking/`)

```
/var/lib/cryftgo/staking/
├── bls_pubkey          # Single file containing BLS pubkey (e.g., "0xabc123...")
├── tls_pubkey          # Single file containing TLS pubkey
└── node_id             # Derived from TLS pubkey: "NodeID-abc123..."
```

### Coordination Rules

1. **Cryftgo is the orchestrator** - It decides when keys need to be generated based on:
   - `bls_pubkeys`/`tls_pubkeys` being empty in status response
   - Mismatch between saved pubkey and available pubkeys

2. **CryftTEE is stateless** - It just proxies to Web3Signer:
   - Doesn't decide when to generate keys
   - Doesn't store pubkey preferences
   - Exposes what Web3Signer has

3. **Web3Signer owns the keys** - Private keys never leave Web3Signer/Vault:
   - Cryftgo and cryfttee only see public keys
   - Signing happens inside Web3Signer

4. **Pubkey is the coordination handle** - All signing requests include the pubkey:
   - Cryftgo remembers which pubkey is "ours"
   - Passes pubkey in every sign request
   - CryftTEE/Web3Signer uses pubkey to find the right key

---

## Node Initialization Flow

All attestation, key generation, and identity setup happens during **node initialization**. This is a single, atomic startup sequence:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NODE INITIALIZATION SEQUENCE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Check --cryfttee-signer flag (skip TEE if disabled)                      │
│  2. Compute cryfttee binary hash                                              │
│  3. Launch cryfttee with CRYFTTEE_VERIFIED_BINARY_HASH                        │
│  4. Wait for cryfttee ready (UDS socket available)                           │
│  5. Verify attestation response matches computed hash                        │
│  6. Verify Web3Signer module is connected and ready                         │
│  7. Check Web3Signer for existing BLS key → generate if not found           │
│  8. Check Web3Signer for existing TLS key → generate if not found           │
│  9. Derive Node ID from TLS public key                                      │
│ 10. Node ready for network participation                                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Persistence Model

**Keys are persisted in Web3Signer/Vault. CryftTEE exposes available public keys via `/v1/staking/status`.**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           KEY DISCOVERY FLOW                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   cryftgo                  cryfttee                   Web3Signer/Vault        │
│   ───────                  ───────                   ─────────────────       │
│      │                        │                            │                 │
│      │  GET /v1/staking/status│                            │                 │
│      │───────────────────────>│  GET /eth/v1/keystores     │                 │
│      │                        │───────────────────────────>│                 │
│      │                        │                            │                 │
│      │                        │  {pubkeys: ["0xabc..."]}   │                 │
│      │  {                     │<───────────────────────────│                 │
│      │    bls_pubkeys: [...], │                            │                 │
│      │    tls_pubkeys: [...], │                            │                 │
│      │    web3signer_ok: true │                            │                 │
│      │  }                     │                            │                 │
│      │<───────────────────────│                            │                 │
│      │                        │                            │                 │
│      │  [Decision Point]      │                            │                 │
│      │  ┌─────────────────────┴────────────────────────┐   │                 │
│      │  │ IF bls_pubkeys is EMPTY:                     │   │                 │
│      │  │   → Generate new BLS key                     │   │                 │
│      │  │ IF tls_pubkeys is EMPTY:                     │   │                 │
│      │  │   → Generate new TLS key                     │   │                 │
│      │  │ IF expected_pubkey != actual_pubkey:         │   │                 │
│      │  │   → ERROR: Key mismatch (possible tampering) │   │                 │
│      │  └──────────────────────────────────────────────┘   │                 │
│      │                        │                            │                 │
│      │ [If generating new key]│                            │                 │
│      │ POST /v1/staking/bls/register                       │                 │
│      │───────────────────────>│  POST /eth/v1/keystores    │                 │
│      │                        │───────────────────────────>│                 │
│      │                        │  (Web3Signer generates key)│                 │
│      │                        │  {pubkey: "0xnew..."}      │  ┌────────────┐ │
│      │  {pubkey: "0xnew..."}  │<───────────────────────────│  │ Vault KV   │ │
│      │<───────────────────────│                            │  │ stores     │ │
│      │                        │                            │  │ private key│ │
│      │  [Save pubkey locally] │                            │  └────────────┘ │
│      │                        │                            │                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### CryftTEE `/v1/staking/status` Response

CryftTEE queries Web3Signer and exposes the available public keys:

```go
// CryftTEE response from GET /v1/staking/status
type StakingStatus struct {
    Ready         bool     `json:"ready"`
    
    // Web3Signer connection status
    Web3SignerURL string   `json:"web3signer_url"`
    Web3SignerOK  bool     `json:"web3signer_connected"`
    
    // Available public keys from Web3Signer
    BLSPubkeys    []string `json:"bls_pubkeys"`    // BLS12-381 public keys available for signing
    TLSPubkeys    []string `json:"tls_pubkeys"`    // SECP256k1 public keys available for signing
    
    // Module info
    ModuleVersion string   `json:"module_version"`
    Capabilities  []string `json:"capabilities"`
}
```

### Key Generation Logic

```go
// InitKeys checks Web3Signer for existing keys, generates if not found
func (m *CryftteeManager) InitKeys(status *StakingStatus) (*BLSKeyInfo, *TLSKeyInfo, error) {
    var blsKey *BLSKeyInfo
    var tlsKey *TLSKeyInfo
    var err error
    
    // Load any previously saved pubkey (from last successful init)
    savedBLSPubkey := m.loadSavedBLSPubkey()
    savedTLSPubkey := m.loadSavedTLSPubkey()
    
    // ═══════════════════════════════════════════════════════════════════════
    // BLS KEY LOGIC
    // ═══════════════════════════════════════════════════════════════════════
    if len(status.BLSPubkeys) == 0 {
        // No keys in Web3Signer - generate new one
        log.Println("No BLS keys available in Web3Signer, generating new key...")
        blsKey, err = m.generateBLSKey()
        if err != nil {
            return nil, nil, fmt.Errorf("BLS key generation failed: %w", err)
        }
        // Save the new pubkey for future reference
        m.saveBLSPubkey(blsKey.PublicKey)
        log.Printf("✓ Generated new BLS key: %s", blsKey.PublicKey)
        
    } else if savedBLSPubkey != "" {
        // We have a saved pubkey - verify it exists in Web3Signer
        found := false
        for _, pk := range status.BLSPubkeys {
            if pk == savedBLSPubkey {
                found = true
                break
            }
        }
        if !found {
            // CRITICAL: Our expected key is missing from Web3Signer!
            return nil, nil, fmt.Errorf("BLS key mismatch: expected %s but not found in Web3Signer (available: %v). "+
                "This could indicate key loss or tampering", savedBLSPubkey, status.BLSPubkeys)
        }
        blsKey = &BLSKeyInfo{PublicKey: savedBLSPubkey}
        log.Printf("✓ Using existing BLS key: %s", blsKey.PublicKey)
        
    } else {
        // Web3Signer has keys but we don't have a saved reference
        // Use the first available key (likely from manual import or previous node)
        blsKey = &BLSKeyInfo{PublicKey: status.BLSPubkeys[0]}
        m.saveBLSPubkey(blsKey.PublicKey)
        log.Printf("✓ Adopting existing BLS key from Web3Signer: %s", blsKey.PublicKey)
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // TLS KEY LOGIC (same pattern)
    // ═══════════════════════════════════════════════════════════════════════
    if len(status.TLSPubkeys) == 0 {
        // No keys in Web3Signer - generate new one
        log.Println("No TLS keys available in Web3Signer, generating new key...")
        tlsKey, err = m.generateTLSKey()
        if err != nil {
            return nil, nil, fmt.Errorf("TLS key generation failed: %w", err)
        }
        m.saveTLSPubkey(tlsKey.PublicKey)
        log.Printf("✓ Generated new TLS key, NodeID: %s", tlsKey.NodeID)
        
    } else if savedTLSPubkey != "" {
        // Verify expected key exists
        found := false
        for _, pk := range status.TLSPubkeys {
            if pk == savedTLSPubkey {
                found = true
                break
            }
        }
        if !found {
            return nil, nil, fmt.Errorf("TLS key mismatch: expected %s but not found in Web3Signer. "+
                "Node ID would change - this could indicate key loss", savedTLSPubkey)
        }
        tlsKey = &TLSKeyInfo{
            PublicKey: savedTLSPubkey,
            NodeID:    deriveNodeID(savedTLSPubkey),
        }
        log.Printf("✓ Using existing TLS key, NodeID: %s", tlsKey.NodeID)
        
    } else {
        // Adopt first available key
        pubkey := status.TLSPubkeys[0]
        tlsKey = &TLSKeyInfo{
            PublicKey: pubkey,
            NodeID:    deriveNodeID(pubkey),
        }
        m.saveTLSPubkey(pubkey)
        log.Printf("✓ Adopting existing TLS key from Web3Signer, NodeID: %s", tlsKey.NodeID)
    }
    
    return blsKey, tlsKey, nil
}

// Local pubkey storage (just the public key, not secrets)
const KeyDataDir = "/var/lib/cryftgo/staking"

func (m *CryftteeManager) saveBLSPubkey(pubkey string) error {
    os.MkdirAll(KeyDataDir, 0700)
    return os.WriteFile(filepath.Join(KeyDataDir, "bls_pubkey"), []byte(pubkey), 0600)
}

func (m *CryftteeManager) loadSavedBLSPubkey() string {
    data, err := os.ReadFile(filepath.Join(KeyDataDir, "bls_pubkey"))
    if err != nil {
        return ""
    }
    return strings.TrimSpace(string(data))
}

func (m *CryftteeManager) saveTLSPubkey(pubkey string) error {
    os.MkdirAll(KeyDataDir, 0700)
    return os.WriteFile(filepath.Join(KeyDataDir, "tls_pubkey"), []byte(pubkey), 0600)
}

func (m *CryftteeManager) loadSavedTLSPubkey() string {
    data, err := os.ReadFile(filepath.Join(KeyDataDir, "tls_pubkey"))
    if err != nil {
        return ""
    }
    return strings.TrimSpace(string(data))
}
```

### Key States and Actions

| Web3Signer Keys | Saved Pubkey | Action |
|-----------------|--------------|--------|
| Empty | Empty | **Generate new key** (first boot) |
| Empty | Has pubkey | **ERROR**: Key was lost from Web3Signer |
| Has keys | Empty | **Adopt** first available key (migration/manual import) |
| Has keys | Has pubkey (matches) | **Use existing** key |
| Has keys | Has pubkey (no match) | **ERROR**: Key mismatch, possible tampering |

### Key Generation Flow

#### Pre-flight: Verify Web3Signer Module is Enabled

Before generating keys, cryftgo must verify that cryfttee has the Web3Signer module loaded and configured:

```go
// CryftgoConfig holds cryftgo node configuration
type CryftgoConfig struct {
    // ... other config
    EnableCryftteeSigner bool   `json:"enable_cryfttee_signer"` // --cryfttee-signer flag
    CryftteeSocketPath   string `json:"cryfttee_socket_path"`
    Web3SignerURL       string `json:"web3signer_url"`        // e.g., http://localhost:9000
}

// VerifySignerReady checks that cryfttee has Web3Signer module enabled and connected
func (m *CryftteeManager) VerifySignerReady() (*StakingStatus, error) {
    resp, err := m.callAPI("GET", "/v1/staking/status", nil)
    if err != nil {
        return nil, fmt.Errorf("failed to get staking status: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("staking module not available (HTTP %d)", resp.StatusCode)
    }
    
    var status StakingStatus
    if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
        return nil, fmt.Errorf("failed to parse staking status: %w", err)
    }
    
    // Verify module is ready
    if !status.Ready {
        return nil, fmt.Errorf("staking module not ready")
    }
    
    // Verify Web3Signer connection
    if !status.Web3SignerOK {
        return nil, fmt.Errorf("Web3Signer not connected (url: %s)", status.Web3SignerURL)
    }
    
    // Verify required capabilities
    requiredCaps := []string{"bls_signing", "tls_signing", "key_generation"}
    for _, req := range requiredCaps {
        found := false
        for _, cap := range status.Capabilities {
            if cap == req {
                found = true
                break
            }
        }
        if !found {
            return nil, fmt.Errorf("missing required capability: %s", req)
        }
    }
    
    log.Printf("✓ Web3Signer ready: %s (module v%s)", status.Web3SignerURL, status.ModuleVersion)
    return &status, nil
}
```

#### Conditional Initialization Based on Cryftgo Flag

```go
// InitializeNode performs the complete node initialization sequence
// Cryftgo orchestrates everything - cryfttee just proxies to Web3Signer
func (m *CryftteeManager) InitializeNode(config *CryftgoConfig) (*NodeIdentity, error) {
    log.Println("=== Starting Node Initialization ===")
    
    // ─────────────────────────────────────────────────────────────────────
    // Step 1: Check if cryfttee signer is enabled (cryftgo decision)
    // ─────────────────────────────────────────────────────────────────────
    if !config.EnableCryftteeSigner {
        log.Println("CryftTEE signer disabled (--cryfttee-signer=false)")
        return nil, nil // Node will use local keystore instead
    }
    
    // ─────────────────────────────────────────────────────────────────────
    // Step 2-3: Start cryfttee with attestation verification
    // ─────────────────────────────────────────────────────────────────────
    log.Println("[1/6] Starting cryfttee with binary attestation...")
    if err := m.Start(config); err != nil {
        return nil, fmt.Errorf("failed to start cryfttee: %w", err)
    }
    
    if err := m.waitForReady(30 * time.Second); err != nil {
        m.Stop()
        return nil, fmt.Errorf("cryfttee failed to start: %w", err)
    }
    
    if err := m.VerifyAttestation(); err != nil {
        m.Stop()
        return nil, fmt.Errorf("attestation verification failed: %w", err)
    }
    log.Printf("[2/6] ✓ Attestation verified: %s", m.verifiedHash)
    
    // ─────────────────────────────────────────────────────────────────────
    // Step 4: Query cryfttee for available pubkeys from Web3Signer
    // ─────────────────────────────────────────────────────────────────────
    log.Println("[3/6] Querying available keys from Web3Signer...")
    status, err := m.VerifySignerReady()
    if err != nil {
        m.Stop()
        return nil, fmt.Errorf("Web3Signer not ready: %w", err)
    }
    log.Printf("[3/6] ✓ Web3Signer connected: %s", status.Web3SignerURL)
    log.Printf("       BLS keys available: %d, TLS keys available: %d", 
        len(status.BLSPubkeys), len(status.TLSPubkeys))
    
    // ─────────────────────────────────────────────────────────────────────
    // Step 5: Cryftgo decides whether to generate or use existing keys
    // ─────────────────────────────────────────────────────────────────────
    log.Println("[4/6] Initializing keys (cryftgo decides, cryfttee executes)...")
    blsKey, tlsKey, err := m.InitKeys(status)
    if err != nil {
        m.Stop()
        return nil, fmt.Errorf("key initialization failed: %w", err)
    }
    log.Printf("[5/6] ✓ Keys ready:")
    log.Printf("       BLS: %s", blsKey.PublicKey)
    log.Printf("       TLS: %s", tlsKey.PublicKey)
    log.Printf("       NodeID: %s", tlsKey.NodeID)
    
    // ─────────────────────────────────────────────────────────────────────
    // Step 6: Build identity and return
    // ─────────────────────────────────────────────────────────────────────
    attestation, err := m.GetAttestation()
    if err != nil {
        m.Stop()
        return nil, fmt.Errorf("attestation fetch failed: %w", err)
    }
    
    identity := &NodeIdentity{
        NodeID:        tlsKey.NodeID,
        BLSKey:        blsKey,
        TLSKey:        tlsKey,
        Attestation:   attestation,
        InitializedAt: time.Now().Unix(),
    }
    
    log.Println("[6/6] ✓ Node initialization complete")
    log.Println("=== Node Identity ===")
    log.Printf("  Node ID:  %s", identity.NodeID)
    log.Printf("  BLS Key:  %s", identity.BLSKey.PublicKey)
    log.Printf("  TLS Key:  %s", identity.TLSKey.PublicKey)
    log.Printf("  CryftTEE:  %s", attestation.CryftteeVersion)
    
    return identity, nil
}

// SignAttestation - cryftgo calls this during validation duties
// Cryftgo provides the pubkey, cryfttee proxies to Web3Signer
func (m *CryftteeManager) SignAttestation(blsPubkey string, attestation []byte) ([]byte, error) {
    req := map[string]interface{}{
        "pubkey": blsPubkey,  // Cryftgo specifies which key to use
        "data":   attestation,
        "type":   "ATTESTATION",
    }
    body, _ := json.Marshal(req)
    
    resp, err := m.callAPI("POST", "/v1/staking/bls/sign", body)
    if err != nil {
        return nil, fmt.Errorf("signing failed: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("signing failed (HTTP %d): %s", resp.StatusCode, string(bodyBytes))
    }
    
    var result struct {
        Signature []byte `json:"signature"`
    }
    json.NewDecoder(resp.Body).Decode(&result)
    return result.Signature, nil
}

// SignBlock - cryftgo calls this when proposing a block
func (m *CryftteeManager) SignBlock(blsPubkey string, blockRoot []byte) ([]byte, error) {
    req := map[string]interface{}{
        "pubkey": blsPubkey,
        "data":   blockRoot,
        "type":   "BLOCK",
    }
    body, _ := json.Marshal(req)
    
    resp, err := m.callAPI("POST", "/v1/staking/bls/sign", body)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result struct {
        Signature []byte `json:"signature"`
    }
    json.NewDecoder(resp.Body).Decode(&result)
    return result.Signature, nil
}
```

#### Cryftgo CLI Flag Definition

```go
// In cryftgo cmd/flags.go or similar
var (
    CryftteeSignerFlag = cli.BoolFlag{
        Name:   "cryfttee-signer",
        Usage:  "Enable cryfttee TEE signer for BLS/TLS key management (requires Web3Signer)",
        EnvVar: "CRYFTGO_CRYFTTEE_SIGNER",
    }
    
    CryftteeSocketFlag = cli.StringFlag{
        Name:   "cryfttee-socket",
        Usage:  "Path to cryfttee UDS socket",
        Value:  "/var/run/cryfttee.sock",
        EnvVar: "CRYFTGO_CRYFTTEE_SOCKET",
    }
    
    CryftteeBinaryFlag = cli.StringFlag{
        Name:   "cryfttee-binary",
        Usage:  "Path to cryfttee binary",
        Value:  "/usr/local/bin/cryfttee",
        EnvVar: "CRYFTGO_CRYFTTEE_BINARY",
    }
    
    Web3SignerURLFlag = cli.StringFlag{
        Name:   "web3signer-url",
        Usage:  "URL of Web3Signer instance (for cryfttee)",
        Value:  "http://localhost:9000",
        EnvVar: "CRYFTGO_WEB3SIGNER_URL",
    }
)

// Usage:
// cryftgo node --cryfttee-signer --web3signer-url=http://keyvault:9000
```

#### BLS Key Generation (ETH2 consensus identity)

BLS keys are used for ETH2-style consensus: signing attestations, blocks, and sync committee messages.

```go
// BLS key generation during node init
type BLSKeyInfo struct {
    PublicKey  string `json:"pubkey"`      // 0x-prefixed 48-byte compressed pubkey
    SecretPath string `json:"secret_path"` // Path in Vault or keystore
    CreatedAt  int64  `json:"created_at"`
}

func (m *CryftteeManager) generateBLSKey() (*BLSKeyInfo, error) {
    // Generate new BLS key via cryfttee -> Web3Signer -> Vault
    req := map[string]interface{}{
        "key_type": "BLS",
        "purpose":  "validator",
    }
    body, _ := json.Marshal(req)
    
    resp, err := m.callAPI("POST", "/v1/staking/bls/register", body)
    if err != nil {
        return nil, fmt.Errorf("BLS key generation failed: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 && resp.StatusCode != 201 {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("BLS key generation failed (HTTP %d): %s", resp.StatusCode, string(bodyBytes))
    }
    
    var result struct {
        PublicKey  string `json:"pubkey"`
        SecretPath string `json:"secret_path"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    
    keyInfo := &BLSKeyInfo{
        PublicKey:  result.PublicKey,
        SecretPath: result.SecretPath,
        CreatedAt:  time.Now().Unix(),
    }
    
    // Persist key info locally (pubkey only, not secret)
    if err := m.saveBLSKeyInfo(keyInfo); err != nil {
        return nil, err
    }
    
    log.Printf("Generated new BLS key: %s", keyInfo.PublicKey)
    return keyInfo, nil
}
```

#### TLS Key Generation (Node Network Identity)

TLS/SECP256k1 keys are used for:
- Node-to-node TLS connections
- Staking certificate signing
- **Node ID derivation** (Node ID = hash of TLS public key)

```go
// TLS key generation during node init
type TLSKeyInfo struct {
    PublicKey   string `json:"pubkey"`       // 0x-prefixed compressed SECP256k1 pubkey
    NodeID      string `json:"node_id"`      // Derived from public key hash
    SecretPath  string `json:"secret_path"`  // Path in Vault or keystore
    Certificate string `json:"certificate"`  // Self-signed or CA-signed cert
    CreatedAt   int64  `json:"created_at"`
}

func (m *CryftteeManager) generateTLSKey() (*TLSKeyInfo, error) {
    // Generate new TLS key via cryfttee -> Web3Signer -> Vault
    req := map[string]interface{}{
        "key_type": "SECP256K1",
        "purpose":  "node_tls",
    }
    body, _ := json.Marshal(req)
    
    resp, err := m.callAPI("POST", "/v1/staking/tls/register", body)
    if err != nil {
        return nil, fmt.Errorf("TLS key generation failed: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 && resp.StatusCode != 201 {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("TLS key generation failed (HTTP %d): %s", resp.StatusCode, string(bodyBytes))
    }
    
    var result struct {
        PublicKey   string `json:"pubkey"`
        SecretPath  string `json:"secret_path"`
        Certificate string `json:"certificate"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    
    // Derive Node ID from TLS public key
    nodeID := deriveNodeID(result.PublicKey)
    
    keyInfo := &TLSKeyInfo{
        PublicKey:   result.PublicKey,
        NodeID:      nodeID,
        SecretPath:  result.SecretPath,
        Certificate: result.Certificate,
        CreatedAt:   time.Now().Unix(),
    }
    
    // Persist key info locally
    if err := m.saveTLSKeyInfo(keyInfo); err != nil {
        return nil, err
    }
    
    log.Printf("Generated new TLS key, NodeID: %s", keyInfo.NodeID)
    return keyInfo, nil
}

// Node ID is derived from the TLS public key
func deriveNodeID(pubkeyHex string) string {
    // Remove 0x prefix if present
    pubkey := strings.TrimPrefix(pubkeyHex, "0x")
    pubkeyBytes, _ := hex.DecodeString(pubkey)
    
    // Node ID = first 20 bytes of SHA256(compressed_pubkey)
    hash := sha256.Sum256(pubkeyBytes)
    nodeID := fmt.Sprintf("NodeID-%s", hex.EncodeToString(hash[:20]))
    
    return nodeID
}
```

### Node Identity Types and Attestation Helper

```go
// NodeIdentity holds all cryptographic identities for the node
type NodeIdentity struct {
    NodeID        string       `json:"node_id"`
    BLSKey        *BLSKeyInfo  `json:"bls_key"`
    TLSKey        *TLSKeyInfo  `json:"tls_key"`
    Attestation   *Attestation `json:"attestation"`
    InitializedAt int64        `json:"initialized_at"`
}

// Attestation response from cryfttee
type Attestation struct {
    CoreBinaryHash string   `json:"core_binary_hash"`
    CryftteeVersion string   `json:"cryfttee_version"`
    ManifestHash   string   `json:"manifest_hash"`
    LoadedModules  []string `json:"loaded_modules"`
}

func (m *CryftteeManager) GetAttestation() (*Attestation, error) {
    resp, err := m.callAPI("GET", "/v1/runtime/attestation", nil)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var attestation Attestation
    if err := json.NewDecoder(resp.Body).Decode(&attestation); err != nil {
        return nil, err
    }
    return &attestation, nil
}
```

### Key Persistence and Recovery

Keys are stored in Web3Signer/Vault, but cryftgo maintains local metadata:

```go
const (
    KeyDataDir = "/var/lib/cryftgo/keys"
)

func (m *CryftteeManager) saveBLSKeyInfo(key *BLSKeyInfo) error {
    data, _ := json.MarshalIndent(key, "", "  ")
    return os.WriteFile(filepath.Join(KeyDataDir, "bls_key.json"), data, 0600)
}

func (m *CryftteeManager) loadExistingBLSKey() (*BLSKeyInfo, error) {
    data, err := os.ReadFile(filepath.Join(KeyDataDir, "bls_key.json"))
    if err != nil {
        return nil, err
    }
    var key BLSKeyInfo
    if err := json.Unmarshal(data, &key); err != nil {
        return nil, err
    }
    
    // Verify key still exists in Web3Signer
    resp, err := m.callAPI("GET", "/v1/staking/status", nil)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var status struct {
        BLSKeys []string `json:"bls_keys"`
    }
    json.NewDecoder(resp.Body).Decode(&status)
    
    for _, k := range status.BLSKeys {
        if k == key.PublicKey {
            return &key, nil // Key exists
        }
    }
    
    return nil, fmt.Errorf("BLS key %s no longer exists in Web3Signer", key.PublicKey)
}

func (m *CryftteeManager) saveTLSKeyInfo(key *TLSKeyInfo) error {
    data, _ := json.MarshalIndent(key, "", "  ")
    return os.WriteFile(filepath.Join(KeyDataDir, "tls_key.json"), data, 0600)
}

func (m *CryftteeManager) loadExistingTLSKey() (*TLSKeyInfo, error) {
    data, err := os.ReadFile(filepath.Join(KeyDataDir, "tls_key.json"))
    if err != nil {
        return nil, err
    }
    var key TLSKeyInfo
    if err := json.Unmarshal(data, &key); err != nil {
        return nil, err
    }
    return &key, nil
}
```

### Usage Example

```go
func main() {
    // ═══════════════════════════════════════════════════════════════════════
    // CONFIGURATION (from CLI flags)
    // ═══════════════════════════════════════════════════════════════════════
    config := &CryftgoConfig{
        EnableCryftteeSigner: true,                        // --cryfttee-signer
        CryftteeSocketPath:   "/var/run/cryfttee.sock",     // --cryfttee-socket
        Web3SignerURL:       "http://keyvault:9000",      // --web3signer-url
    }
    
    cryftteeConfig := CryftteeConfig{
        BinaryPath: "/usr/local/bin/cryfttee",             // --cryfttee-binary
        Transport:  TransportUDS,
        SocketPath: config.CryftteeSocketPath,
    }
    
    manager := NewCryftteeManager(cryftteeConfig)
    
    // ═══════════════════════════════════════════════════════════════════════
    // INITIALIZATION (happens once at node startup)
    // Cryftgo orchestrates: start cryfttee → check keys → generate if needed
    // ═══════════════════════════════════════════════════════════════════════
    identity, err := manager.InitializeNode(config)
    if err != nil {
        log.Fatalf("Node initialization failed: %v", err)
    }
    
    if identity == nil {
        log.Println("Running without cryfttee signer (using local keystore)")
        return
    }
    
    log.Printf("Node %s initialized successfully", identity.NodeID)
    
    // ═══════════════════════════════════════════════════════════════════════
    // RUNTIME SIGNING (happens during validator duties)
    // Cryftgo provides pubkey → cryfttee proxies to Web3Signer → returns sig
    // ═══════════════════════════════════════════════════════════════════════
    
    // Example: Sign an attestation
    attestationData := []byte{...} // Attestation to sign
    sig, err := manager.SignAttestation(identity.BLSKey.PublicKey, attestationData)
    if err != nil {
        log.Printf("Failed to sign attestation: %v", err)
    } else {
        log.Printf("Signed attestation: %x", sig)
        // Broadcast to network...
    }
    
    // Example: Sign a block proposal
    blockRoot := []byte{...} // Block root to sign
    blockSig, err := manager.SignBlock(identity.BLSKey.PublicKey, blockRoot)
    if err != nil {
        log.Printf("Failed to sign block: %v", err)
    } else {
        log.Printf("Signed block: %x", blockSig)
        // Propose block to network...
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // KEY COORDINATION SUMMARY:
    // - identity.BLSKey.PublicKey is saved locally by cryftgo
    // - Every sign request includes this pubkey
    // - CryftTEE doesn't store preferences, just proxies with the given pubkey
    // - Web3Signer looks up the private key by pubkey and signs
    // ═══════════════════════════════════════════════════════════════════════
    
    // Wait for shutdown
    manager.Wait()
}
```

---

## Summary Checklist

### ⚠️ Connection Defaults (MUST Match)

| Setting | Cryftgo Default | CryftTEE Default | Must Match |
|---------|-----------------|-----------------|------------|
| Transport | `uds` | `uds` | ✓ |
| Socket Path | `/var/run/cryfttee.sock` | `/var/run/cryfttee.sock` | ✓ |
| HTTP Address | `127.0.0.1:8787` | `127.0.0.1:8787` | ✓ |
| Web3Signer URL | `http://localhost:9000` | `http://localhost:9000` | ✓ |

### Cryftgo CLI Flags
- `--cryfttee-signer` - Enable cryfttee TEE signer (default: false)
- `--cryfttee-transport` - Transport type: `uds` (default) or `http`
- `--cryfttee-socket` - UDS socket path (default: `/var/run/cryfttee.sock`)
- `--cryfttee-http-addr` - HTTP address (default: `127.0.0.1:8787`, only if transport=http)
- `--cryfttee-binary` - Path to cryfttee binary (default: `/usr/local/bin/cryfttee`)
- `--web3signer-url` - Web3Signer URL (default: `http://localhost:9000`)

### Node Initialization (Single Atomic Sequence)
- [ ] Check `--cryfttee-signer` flag; skip if disabled (use local keystore)
- [ ] Compute SHA256 of cryfttee binary before launching
- [ ] Set `CRYFTTEE_VERIFIED_BINARY_HASH=sha256:<hex>` environment variable
- [ ] Launch cryfttee with `--web3signer-url` argument
- [ ] Wait for cryfttee UDS socket to become available
- [ ] Verify `/v1/runtime/attestation` returns matching `core_binary_hash`
- [ ] Call `/v1/staking/status` to get available pubkeys from Web3Signer
- [ ] **Key Decision Logic**:
  - If `bls_pubkeys` empty → generate new BLS key via `/v1/staking/bls/register`
  - If `tls_pubkeys` empty → generate new TLS key via `/v1/staking/tls/register`
  - If saved pubkey exists but not in Web3Signer → **ERROR** (key loss)
  - If pubkey matches saved → use existing key
- [ ] Derive Node ID from TLS public key (SHA256 hash, first 20 bytes)
- [ ] Save pubkeys locally for future verification
- [ ] Log all steps for audit trail

### Key States Reference
| Web3Signer Keys | Saved Pubkey | Action |
|-----------------|--------------|--------|
| Empty | Empty | Generate new key (first boot) |
| Empty | Has pubkey | ERROR: Key was lost |
| Has keys | Empty | Adopt first available key |
| Has keys | Matches | Use existing key |
| Has keys | No match | ERROR: Key mismatch |

### Runtime Operations
- [ ] Sign attestations/blocks via `/v1/staking/bls/sign`
- [ ] Sign TLS certificates via `/v1/staking/tls/sign`
- [ ] Optionally implement periodic re-verification via `/proc/<pid>/exe`

---

## Security Notes

1. **Why this matters**: A malicious cryfttee binary could fake its own hash. By having cryftgo compute the hash externally, we establish a chain of trust.

2. **Why consensus makes this mostly moot for validators**: The blockchain consensus verifies all outputs. A malicious signer would be detected and slashed. This attestation is primarily for:
   - Compliance/audit requirements
   - Insurance purposes
   - Debugging/incident response
   - Defense in depth

3. **True security for keys**: Use Web3Signer with HSM integration. The sidecar should never have direct access to signing keys.
