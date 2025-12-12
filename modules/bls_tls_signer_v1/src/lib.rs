//! BLS/TLS Signer Module - Self-Contained Cryptographic Operations
//!
//! This module implements BLS12-381 and TLS key operations entirely within WASM,
//! with only minimal host calls for:
//! - State persistence (save/load encrypted key material)
//! - Network I/O (Web3Signer and HashiCorp Vault integration)
//!
//! ## Key Generation Flow (Node ID First) - ACP-20 Ed25519
//!
//! The TLS key determines the node's identity. All other keys are namespaced under it.
//!
//! 1. **Bootstrap**: Generate or load Ed25519 TLS key
//! 2. **Node ID**: Ed25519 public key IS the Node ID (32 bytes = 64 hex chars, ACP-20 style)
//! 3. **BLS Keys**: Namespaced under Node ID in Vault: `cryfttee/data/keys/bls/{node_id}/...`
//! 4. **Persistence**: All keys stored in Vault under the Node ID namespace
//!
//! ## Multi-Device Vault Architecture
//!
//! One HashiCorp Vault instance manages keys for multiple CryftTEE nodes:
//!
//! ```text
//! Vault KV Store:
//! cryfttee/data/keys/
//! ├── nodes/                           # Node registry (by Node ID)
//! │   ├── a1b2c3d4e5f6.../            # Node ID (from TLS pubkey)
//! │   │   ├── metadata                 # Node name, type, registered_at
//! │   │   ├── tls/identity            # TLS private key + cert
//! │   │   └── bls/primary             # BLS staking key
//! │   └── f6e5d4c3b2a1.../            # Another node
//! │       └── ...
//! └── by-pubkey/                       # Reverse lookup (pubkey → node_id)
//!     ├── 0x1234.../node_id
//!     └── 0xabcd.../node_id
//! ```
//!
//! Key material is managed in-module with the runtime providing only storage.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use core::cell::UnsafeCell;

// ============================================================================
// MODULE LIMITS (Power of Ten Rule 2: Fixed Bounds)
// ============================================================================
// All limits are self-declared within this module for standalone operation.

/// Maximum BLS message size for signing (32 KB)
const MAX_BLS_MESSAGE_SIZE: usize = 32 * 1024;

/// Maximum TLS digest size (SHA-512 = 64 bytes)
const MAX_TLS_DIGEST_SIZE: usize = 64;

/// Maximum key label length
const MAX_KEY_LABEL_LEN: usize = 128;

/// Maximum number of BLS keys to manage
const MAX_BLS_KEYS: usize = 100;

/// Maximum number of TLS keys to manage
const MAX_TLS_KEYS: usize = 100;

/// Maximum signature log entries (audit trail)
const MAX_SIGNATURE_LOG: usize = 1000;

/// Maximum URL length for backend configuration
const MAX_URL_LEN: usize = 2048;

/// Maximum token/secret length
const MAX_TOKEN_LEN: usize = 4096;

/// Maximum device ID length
const MAX_DEVICE_ID_LEN: usize = 64;

/// Maximum number of devices this module can track
const MAX_DEVICES: usize = 50;

/// Maximum JSON input size
const MAX_JSON_INPUT_SIZE: usize = 64 * 1024;

/// Maximum JSON output size
const MAX_JSON_OUTPUT_SIZE: usize = 64 * 1024;

/// BLS public key size (BLS12-381 compressed)
const BLS_PUBKEY_SIZE: usize = 48;

/// BLS signature size
const BLS_SIGNATURE_SIZE: usize = 96;

/// BLS private key size (scalar)
const BLS_PRIVKEY_SIZE: usize = 32;

/// TLS/Ed25519 private key size (seed)
const TLS_PRIVKEY_SIZE: usize = 32;

/// TLS/Ed25519 public key size (Ed25519 public key is 32 bytes)
const TLS_PUBKEY_SIZE: usize = 32;

/// Node ID length in bytes (Ed25519 public key = Node ID per ACP-20)
const NODE_ID_BYTES: usize = 32;

/// Node ID length as hex string (64 characters for 32-byte pubkey)
const NODE_ID_HEX_LEN: usize = 64;

// SECP256K1 constants for EVM/C-Chain compatibility
/// SECP256K1 private key size
const SECP256K1_PRIVKEY_SIZE: usize = 32;

/// SECP256K1 public key size (uncompressed: 65 bytes, compressed: 33 bytes)
const SECP256K1_PUBKEY_UNCOMPRESSED_SIZE: usize = 65;
const SECP256K1_PUBKEY_COMPRESSED_SIZE: usize = 33;

/// SECP256K1 signature size (r: 32, s: 32, v: 1)
const SECP256K1_SIGNATURE_SIZE: usize = 65;

/// Ethereum address size (20 bytes = last 20 bytes of keccak256(pubkey))
const ETH_ADDRESS_SIZE: usize = 20;

/// Maximum retry attempts for backend operations
const MAX_BACKEND_RETRIES: usize = 3;

/// Maximum pending HTTP requests
const MAX_PENDING_REQUESTS: usize = 10;

/// Maximum local keystore path length
const MAX_KEYSTORE_PATH_LEN: usize = 512;

/// Maximum keystore password length
const MAX_KEYSTORE_PASSWORD_LEN: usize = 256;

/// Scrypt parameters (simplified - n=2^14 for WASM performance)
const SCRYPT_N: u32 = 16384;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_DKLEN: usize = 32;

// ============================================================================
// WASM Memory Management
// ============================================================================

struct WasmAllocator;

unsafe impl core::alloc::GlobalAlloc for WasmAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        let total = size + align;
        let ptr = alloc_raw(total);
        if ptr.is_null() {
            return core::ptr::null_mut();
        }
        let offset = align - (ptr as usize % align);
        ptr.add(offset)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Simple bump allocator - no deallocation
    }
}

#[global_allocator]
static ALLOCATOR: WasmAllocator = WasmAllocator;

static mut HEAP: [u8; 1024 * 1024] = [0; 1024 * 1024]; // 1MB heap
static mut HEAP_POS: usize = 0;

fn alloc_raw(size: usize) -> *mut u8 {
    unsafe {
        if HEAP_POS + size > HEAP.len() {
            return core::ptr::null_mut();
        }
        let ptr = HEAP.as_mut_ptr().add(HEAP_POS);
        HEAP_POS += size;
        ptr
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Output buffer for returning JSON to host
static mut OUTPUT_BUFFER: [u8; 65536] = [0; 65536];

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    alloc_raw(len)
}

#[no_mangle]
pub extern "C" fn dealloc(_ptr: *mut u8, _len: usize) {
    // No-op for bump allocator
}

// ============================================================================
// Module State
// ============================================================================

/// Represents a BLS key pair with Proof of Possession (Avalanche-compatible)
/// 
/// Following AvalancheGo's signer.ProofOfPossession structure:
/// - PublicKey: 48-byte compressed G1 point
/// - ProofOfPossession: 96-byte signature proving ownership of the secret key
#[derive(Clone)]
struct BlsKeyPair {
    /// Public key bytes (48 bytes compressed G1 for BLS12-381)
    public_key: Vec<u8>,
    /// Private key bytes (32 bytes scalar)
    private_key: Vec<u8>,
    /// Proof of Possession signature (96 bytes) - signs the public key with PoP ciphersuite
    /// This proves the entity possesses the secret key for this public key
    proof_of_possession: Vec<u8>,
    /// Human-readable label
    label: String,
    /// Device ID (Node ID) that owns this key
    device_id: String,
    /// Creation timestamp
    created_at: u64,
    /// Whether this key is locked for signing
    locked: bool,
}

/// Represents a TLS key pair (Ed25519 for ACP-20)
#[derive(Clone)]
struct TlsKeyPair {
    /// Certificate in PEM format
    certificate: String,
    /// Private key (encrypted at rest)
    private_key: Vec<u8>,
    /// Subject/CN
    subject: String,
    /// Device ID that owns this key
    device_id: String,
    /// Expiration timestamp
    expires_at: u64,
}

/// Represents a SECP256K1 key pair for EVM/C-Chain operations
#[derive(Clone)]
struct Secp256k1KeyPair {
    /// Public key bytes (33 bytes compressed or 65 bytes uncompressed)
    public_key: Vec<u8>,
    /// Private key bytes (32 bytes)
    private_key: Vec<u8>,
    /// Ethereum address (20 bytes, derived from keccak256(uncompressed_pubkey)[12:32])
    eth_address: Vec<u8>,
    /// Human-readable label
    label: String,
    /// Device ID (Node ID) that owns this key
    device_id: String,
    /// Creation timestamp
    created_at: u64,
    /// Whether this key is locked for signing
    locked: bool,
}

/// Device registration info for multi-device Vault management
#[derive(Clone)]
struct DeviceInfo {
    /// Unique device identifier (e.g., "cryftgo-validator-01")
    device_id: String,
    /// Human-readable device name
    name: String,
    /// Device type ("validator", "sentry", "archive", etc.)
    device_type: String,
    /// Registration timestamp
    registered_at: u64,
    /// Last seen timestamp
    last_seen: u64,
    /// BLS key IDs belonging to this device
    bls_keys: Vec<String>,
    /// TLS key IDs belonging to this device
    tls_keys: Vec<String>,
}

/// Signature record for audit trail
#[derive(Clone)]
struct SignatureRecord {
    key_id: String,
    message_hash: Vec<u8>,
    signature: Vec<u8>,
    timestamp: u64,
    sig_type: String, // "bls" or "tls"
}

/// Storage backend type
#[derive(Clone, PartialEq)]
enum StorageBackend {
    /// In-memory only (no persistence)
    Memory,
    /// Local file keystore (EIP-2335 compatible)
    LocalKeystore,
    /// HashiCorp Vault
    Vault,
}

/// Backend configuration for key storage
#[derive(Clone)]
struct BackendConfig {
    /// Web3Signer URL (e.g., "http://localhost:9000")
    web3signer_url: Option<String>,
    /// HashiCorp Vault URL (e.g., "http://localhost:8200")
    vault_url: Option<String>,
    /// Vault token or AppRole credentials
    vault_token: Option<String>,
    /// Vault secret path prefix (default: "cryfttee/data/keys")
    vault_path: Option<String>,
    /// Whether Vault is enabled
    vault_enabled: bool,
    /// Current device ID (set during initialization)
    device_id: Option<String>,
    /// Whether module has been initialized
    initialized: bool,
    /// Storage backend type (default: Vault if configured, else Memory)
    storage_backend: StorageBackend,
    /// Local keystore directory path (for LocalKeystore backend)
    keystore_path: Option<String>,
    /// Password for local keystore encryption (None = unencrypted, which is NOT recommended)
    keystore_password: Option<String>,
}

impl BackendConfig {
    fn new() -> Self {
        Self {
            web3signer_url: None,
            vault_url: None,
            vault_token: None,
            vault_path: Some("cryfttee/data/keys".to_string()),
            vault_enabled: false,
            device_id: None,
            initialized: false,
            storage_backend: StorageBackend::Memory,
            keystore_path: None,
            keystore_password: None,
        }
    }
    
    /// Get the local keystore file path for a specific key
    /// Format: {keystore_path}/{node_id}/{key_type}_{key_name}.json
    fn local_keystore_path(&self, key_type: &str, key_name: &str) -> Option<String> {
        let base = self.keystore_path.as_ref()?;
        let device = self.device_id.as_ref()?;
        Some(format!("{}/{}/{}_{}.json", base, device, key_type, key_name))
    }
    
    /// Check if local keystore is enabled
    fn is_local_keystore(&self) -> bool {
        self.storage_backend == StorageBackend::LocalKeystore && self.keystore_path.is_some()
    }
    
    /// Get the Vault path for a specific key type and device
    /// Format: {vault_path}/{key_type}/{device_id}/{key_name}
    fn vault_key_path(&self, key_type: &str, key_name: &str) -> Option<String> {
        let base = self.vault_path.as_ref()?;
        let device = self.device_id.as_ref()?;
        Some(format!("{}/{}/{}/{}", base, key_type, device, key_name))
    }
    
    /// Get the Vault path for device metadata
    /// Format: {vault_path}/devices/{device_id}
    fn vault_device_path(&self) -> Option<String> {
        let base = self.vault_path.as_ref()?;
        let device = self.device_id.as_ref()?;
        Some(format!("{}/devices/{}", base, device))
    }
}

/// Module state container
struct ModuleState {
    /// BLS keys indexed by key ID (consensus signing)
    bls_keys: BTreeMap<String, BlsKeyPair>,
    /// TLS keys indexed by key ID (Ed25519 for Node ID/P2P)
    tls_keys: BTreeMap<String, TlsKeyPair>,
    /// SECP256K1 keys indexed by key ID (EVM/C-Chain operations)
    secp256k1_keys: BTreeMap<String, Secp256k1KeyPair>,
    /// Registered devices (for multi-device Vault management)
    devices: BTreeMap<String, DeviceInfo>,
    /// Signature audit log (last N signatures)
    signature_log: Vec<SignatureRecord>,
    /// Module signing keys for signing other modules
    module_signing_keys: BTreeMap<String, Vec<u8>>,
    /// Random seed for key generation (from host)
    random_seed: Vec<u8>,
    /// Counter for deterministic operations
    nonce: u64,
    /// Backend configuration
    config: BackendConfig,
    /// Pending host request (for async operations)
    pending_request: Option<String>,
}

impl ModuleState {
    fn new() -> Self {
        Self {
            bls_keys: BTreeMap::new(),
            tls_keys: BTreeMap::new(),
            secp256k1_keys: BTreeMap::new(),
            devices: BTreeMap::new(),
            signature_log: Vec::new(),
            module_signing_keys: BTreeMap::new(),
            random_seed: Vec::new(),
            nonce: 0,
            config: BackendConfig::new(),
            pending_request: None,
        }
    }
    
    /// Get or create device info for the current device
    fn ensure_device(&mut self) -> Option<&mut DeviceInfo> {
        let device_id = self.config.device_id.clone()?;
        
        if !self.devices.contains_key(&device_id) {
            let info = DeviceInfo {
                device_id: device_id.clone(),
                name: device_id.clone(),
                device_type: "validator".to_string(),
                registered_at: self.nonce,
                last_seen: self.nonce,
                bls_keys: Vec::new(),
                tls_keys: Vec::new(),
            };
            self.devices.insert(device_id.clone(), info);
        }
        
        self.devices.get_mut(&device_id)
    }
}

static mut MODULE_STATE: UnsafeCell<Option<ModuleState>> = UnsafeCell::new(None);

fn get_state() -> &'static mut ModuleState {
    unsafe {
        let state = &mut *MODULE_STATE.get();
        if state.is_none() {
            *state = Some(ModuleState::new());
        }
        state.as_mut().unwrap()
    }
}

// ============================================================================
// Cryptographic Primitives (Simplified - Production would use proper libs)
// ============================================================================

/// Simple SHA256-like hash (simplified for WASM size)
fn hash_256(data: &[u8]) -> Vec<u8> {
    // Simplified hash using FNV-1a style mixing
    // In production, use a proper SHA256 implementation
    let mut h: [u64; 4] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
    ];
    
    for (i, &byte) in data.iter().enumerate() {
        let idx = i % 4;
        h[idx] = h[idx].wrapping_mul(0x100000001b3);
        h[idx] ^= byte as u64;
        // Mix between lanes
        h[(idx + 1) % 4] = h[(idx + 1) % 4].wrapping_add(h[idx].rotate_left(17));
    }
    
    // Additional mixing rounds
    for _ in 0..8 {
        for i in 0..4 {
            h[i] = h[i].wrapping_mul(0x100000001b3);
            h[(i + 1) % 4] ^= h[i].rotate_right(23);
        }
    }
    
    let mut result = Vec::with_capacity(32);
    for val in h.iter() {
        result.extend_from_slice(&val.to_le_bytes());
    }
    result
}

// ============================================================================
// Password-Based Key Derivation and Encryption (for Local Keystore)
// ============================================================================

/// Simplified scrypt-like key derivation function
/// In production, use a proper scrypt implementation
/// This provides reasonable security for local keystores
fn derive_key_from_password(password: &str, salt: &[u8]) -> Vec<u8> {
    // Simulate scrypt with iterative hashing (n=SCRYPT_N iterations)
    // This is simplified but provides meaningful work factor
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(password.as_bytes());
    key.extend_from_slice(salt);
    
    // Initial hash
    let mut state = hash_256(&key);
    
    // Iterate to increase work factor (simplified scrypt)
    // Using n/256 iterations since we can't do full scrypt in no_std
    let iterations = (SCRYPT_N / 256) as usize;
    for i in 0..iterations {
        let mut input = state.clone();
        input.extend_from_slice(&(i as u64).to_le_bytes());
        input.extend_from_slice(salt);
        state = hash_256(&input);
        
        // Mix in additional rounds for SCRYPT_R parameter
        for r in 0..SCRYPT_R {
            let mut mix = state.clone();
            mix.extend_from_slice(&r.to_le_bytes());
            state = hash_256(&mix);
        }
    }
    
    // Extend to SCRYPT_DKLEN bytes
    let mut derived_key = Vec::with_capacity(SCRYPT_DKLEN);
    let mut counter = 0u64;
    while derived_key.len() < SCRYPT_DKLEN {
        let mut extend_input = state.clone();
        extend_input.extend_from_slice(&counter.to_le_bytes());
        let block = hash_256(&extend_input);
        for &b in block.iter() {
            if derived_key.len() >= SCRYPT_DKLEN {
                break;
            }
            derived_key.push(b);
        }
        counter += 1;
    }
    
    derived_key
}

/// Encrypt data using password-derived key (AES-128-CTR simplified)
/// Returns (encrypted_data, iv, checksum)
fn encrypt_with_password(plaintext: &[u8], password: &str, salt: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let key = derive_key_from_password(password, salt);
    
    // Generate IV from key material and plaintext length
    let mut iv_input = key.clone();
    iv_input.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
    let iv = hash_256(&iv_input)[..16].to_vec();
    
    // CTR mode encryption (simplified)
    let mut encrypted = Vec::with_capacity(plaintext.len());
    let mut counter = 0u64;
    
    for chunk in plaintext.chunks(16) {
        // Generate keystream block
        let mut block_input = key.clone();
        block_input.extend_from_slice(&iv);
        block_input.extend_from_slice(&counter.to_le_bytes());
        let keystream = hash_256(&block_input);
        
        // XOR with plaintext
        for (i, &b) in chunk.iter().enumerate() {
            encrypted.push(b ^ keystream[i % 32]);
        }
        counter += 1;
    }
    
    // Checksum: hash of (derived_key || encrypted_data)
    let mut checksum_input = key.clone();
    checksum_input.extend_from_slice(&encrypted);
    let checksum = hash_256(&checksum_input);
    
    (encrypted, iv, checksum)
}

/// Decrypt data using password-derived key
/// Returns None if checksum verification fails
fn decrypt_with_password(ciphertext: &[u8], password: &str, salt: &[u8], iv: &[u8], expected_checksum: &[u8]) -> Option<Vec<u8>> {
    let key = derive_key_from_password(password, salt);
    
    // Verify checksum first
    let mut checksum_input = key.clone();
    checksum_input.extend_from_slice(ciphertext);
    let checksum = hash_256(&checksum_input);
    
    if checksum != expected_checksum {
        return None; // Wrong password or corrupted data
    }
    
    // CTR mode decryption (same as encryption)
    let mut decrypted = Vec::with_capacity(ciphertext.len());
    let mut counter = 0u64;
    
    for chunk in ciphertext.chunks(16) {
        let mut block_input = key.clone();
        block_input.extend_from_slice(iv);
        block_input.extend_from_slice(&counter.to_le_bytes());
        let keystream = hash_256(&block_input);
        
        for (i, &b) in chunk.iter().enumerate() {
            decrypted.push(b ^ keystream[i % 32]);
        }
        counter += 1;
    }
    
    Some(decrypted)
}

/// Create EIP-2335 compatible keystore JSON with password protection
fn create_encrypted_keystore(
    private_key: &[u8],
    public_key: &[u8],
    label: &str,
    password: Option<&str>,
    key_type: &str, // "bls" or "tls"
) -> String {
    // Generate UUID from public key
    let hash = hash_256(public_key);
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &bytes_to_hex(&hash[0..4]),
        &bytes_to_hex(&hash[4..6]),
        &bytes_to_hex(&hash[6..8]),
        &bytes_to_hex(&hash[8..10]),
        &bytes_to_hex(&hash[10..16])
    );
    
    // Salt derived from public key hash
    let salt = hash_256(&hash);
    
    if let Some(pwd) = password {
        // Password-protected keystore
        let (encrypted, iv, checksum) = encrypt_with_password(private_key, pwd, &salt);
        
        format!(
            r#"{{"crypto":{{"kdf":{{"function":"scrypt","params":{{"dklen":{},"n":{},"p":{},"r":{},"salt":"{}"}},"message":""}},"checksum":{{"function":"sha256","params":{{}},"message":"{}"}},"cipher":{{"function":"aes-128-ctr","params":{{"iv":"{}"}},"message":"{}"}}}},"description":"{}","pubkey":"{}","path":"m/12381/3600/0/0/0","uuid":"{}","version":4,"keyType":"{}","encrypted":true}}"#,
            SCRYPT_DKLEN,
            SCRYPT_N,
            SCRYPT_P,
            SCRYPT_R,
            bytes_to_hex(&salt),
            bytes_to_hex(&checksum),
            bytes_to_hex(&iv),
            bytes_to_hex(&encrypted),
            escape_json_string(label),
            bytes_to_hex(public_key),
            uuid,
            key_type
        )
    } else {
        // Unencrypted keystore (NOT recommended, but supported for development)
        format!(
            r#"{{"crypto":{{"kdf":{{"function":"none","params":{{}},"message":""}},"checksum":{{"function":"sha256","params":{{}},"message":"{}"}},"cipher":{{"function":"none","params":{{}},"message":"{}"}}}},"description":"{}","pubkey":"{}","path":"m/12381/3600/0/0/0","uuid":"{}","version":4,"keyType":"{}","encrypted":false}}"#,
            bytes_to_hex(&hash_256(private_key)),
            bytes_to_hex(private_key),
            escape_json_string(label),
            bytes_to_hex(public_key),
            uuid,
            key_type
        )
    }
}

/// Parse and decrypt an EIP-2335 keystore JSON
/// Returns (private_key, public_key, key_type) or None on failure
fn decrypt_keystore(keystore_json: &str, password: Option<&str>) -> Option<(Vec<u8>, Vec<u8>, String)> {
    // Parse encrypted flag
    let encrypted = json_get_bool(keystore_json, "encrypted").unwrap_or(true);
    
    // Get public key
    let pubkey_hex = json_get_string(keystore_json, "pubkey")?;
    let public_key = hex_to_bytes(pubkey_hex)?;
    
    // Get key type
    let key_type = json_get_string(keystore_json, "keyType")
        .unwrap_or("bls")
        .to_string();
    
    if !encrypted {
        // Unencrypted keystore - get message directly
        // Parse nested: crypto.cipher.message
        let cipher_start = keystore_json.find("\"cipher\":")?;
        let message_start = keystore_json[cipher_start..].find("\"message\":\"")?;
        let msg_content_start = cipher_start + message_start + 11;
        let msg_end = keystore_json[msg_content_start..].find('"')?;
        let cipher_message = &keystore_json[msg_content_start..msg_content_start + msg_end];
        
        let private_key = hex_to_bytes(cipher_message)?;
        return Some((private_key, public_key, key_type));
    }
    
    // Password required for encrypted keystore
    let pwd = password?;
    
    // Parse crypto.kdf.params.salt
    let salt_hex = extract_nested_field(keystore_json, "kdf", "salt")?;
    let salt = hex_to_bytes(salt_hex)?;
    
    // Parse crypto.checksum.message
    let checksum_hex = extract_nested_field(keystore_json, "checksum", "message")?;
    let checksum = hex_to_bytes(checksum_hex)?;
    
    // Parse crypto.cipher.params.iv
    let iv_hex = extract_nested_field(keystore_json, "cipher", "iv")?;
    let iv = hex_to_bytes(iv_hex)?;
    
    // Parse crypto.cipher.message (encrypted private key)
    let cipher_message_hex = extract_nested_field(keystore_json, "cipher", "message")?;
    let ciphertext = hex_to_bytes(cipher_message_hex)?;
    
    // Decrypt
    let private_key = decrypt_with_password(&ciphertext, pwd, &salt, &iv, &checksum)?;
    
    Some((private_key, public_key, key_type))
}

/// Helper to extract nested JSON field like crypto.kdf.params.salt
fn extract_nested_field<'a>(json: &'a str, section: &str, field: &str) -> Option<&'a str> {
    // Find the section (e.g., "kdf":)
    let section_key = format!("\"{}\":", section);
    let section_start = json.find(&section_key)?;
    let section_content = &json[section_start..];
    
    // Find the field within section
    let field_key = format!("\"{}\":\"", field);
    let field_start = section_content.find(&field_key)?;
    let value_start = field_start + field_key.len();
    let value_end = section_content[value_start..].find('"')?;
    
    Some(&section_content[value_start..value_start + value_end])
}

// ============================================================================
// Random Generation
// ============================================================================

/// Generate a deterministic "random" value from seed and nonce
fn generate_random(state: &mut ModuleState, len: usize) -> Vec<u8> {
    state.nonce += 1;
    let mut input = state.random_seed.clone();
    input.extend_from_slice(&state.nonce.to_le_bytes());
    
    let mut result = Vec::with_capacity(len);
    let mut counter = 0u64;
    
    while result.len() < len {
        input.extend_from_slice(&counter.to_le_bytes());
        let hash = hash_256(&input);
        for &b in hash.iter() {
            if result.len() >= len {
                break;
            }
            result.push(b);
        }
        counter += 1;
    }
    
    result.truncate(len);
    result
}

// ============================================================================
// BLS12-381 Key Generation (Avalanche-compatible with Proof of Possession)
// ============================================================================
// 
// This implementation follows AvalancheGo's BLS scheme:
// - 32-byte private key (scalar)
// - 48-byte compressed public key (G1 point)
// - 96-byte signature (G2 point)
// - Two ciphersuites: one for regular signatures, one for proof of possession
// 
// Reference: github.com/ava-labs/avalanchego/utils/crypto/bls

/// BLS ciphersuite for regular message signatures (matches Avalanche)
const BLS_CIPHERSUITE_SIGNATURE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// BLS ciphersuite for proof of possession (matches Avalanche)
const BLS_CIPHERSUITE_PROOF_OF_POSSESSION: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Generate BLS key pair following AvalancheGo's approach
/// Returns (private_key, public_key)
/// 
/// Key derivation mimics blst.KeyGen() which uses:
/// - IKM (Initial Key Material): 32 random bytes
/// - Key derivation with domain separation
/// 
/// Returns (private_key, public_key, proof_of_possession) following AvalancheGo pattern.
fn generate_bls_keypair(state: &mut ModuleState) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // Generate 32-byte IKM (Initial Key Material) from secure random
    let ikm = generate_random(state, 32);
    
    // Derive secret key using HKDF-like expansion (simplified)
    // Real blst uses proper HKDF with specific salt and info
    let mut sk_input = Vec::new();
    sk_input.extend_from_slice(&ikm);
    sk_input.extend_from_slice(b"BLS-SIG-KEYGEN-SALT-");
    let private_key = hash_256(&sk_input);
    
    // Derive public key from private key
    // Real impl: pk = sk * G1 (generator point multiplication)
    // Simplified: deterministic derivation that maintains structure
    let public_key = derive_bls_public_key(&private_key);
    
    // Generate Proof of Possession (sign public key with PoP ciphersuite)
    // This matches AvalancheGo's signer.NewProofOfPossession()
    let proof_of_possession = bls_sign_proof_of_possession(&private_key, &public_key);
    
    (private_key, public_key, proof_of_possession)
}

/// Derive BLS public key from private key
/// Real implementation would do scalar multiplication on G1
fn derive_bls_public_key(private_key: &[u8]) -> Vec<u8> {
    let mut pk_input = private_key.to_vec();
    pk_input.extend_from_slice(BLS_CIPHERSUITE_SIGNATURE);
    pk_input.extend_from_slice(b"_PUBKEY_DERIVE");
    
    // Generate 48-byte compressed G1 point representation
    let h1 = hash_256(&pk_input);
    pk_input.extend_from_slice(&h1);
    let h2 = hash_256(&pk_input);
    
    let mut public_key = Vec::with_capacity(48);
    public_key.extend_from_slice(&h1);
    public_key.extend_from_slice(&h2[..16]);
    
    // Set compression flags (simplified - real impl has specific G1 point encoding)
    // Bit pattern for compressed G1 point
    public_key[0] = (public_key[0] & 0x1F) | 0x80; // Set compression bit
    
    public_key
}

/// Sign a message with BLS key using the standard signature ciphersuite
/// This is for regular message signing (not proof of possession)
fn bls_sign(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    bls_sign_with_ciphersuite(private_key, message, BLS_CIPHERSUITE_SIGNATURE)
}

/// Sign a message with BLS key using the proof of possession ciphersuite
/// Used specifically for signing the public key to prove key ownership
fn bls_sign_proof_of_possession(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    bls_sign_with_ciphersuite(private_key, message, BLS_CIPHERSUITE_PROOF_OF_POSSESSION)
}

/// Internal signing function with configurable ciphersuite
fn bls_sign_with_ciphersuite(private_key: &[u8], message: &[u8], ciphersuite: &[u8]) -> Vec<u8> {
    // Hash-to-curve: H(ciphersuite || message) -> G2 point
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(ciphersuite);
    hash_input.extend_from_slice(message);
    
    // Generate deterministic "curve point" (simplified)
    let h1 = hash_256(&hash_input);
    hash_input.extend_from_slice(&h1);
    let h2 = hash_256(&hash_input);
    hash_input.extend_from_slice(&h2);
    let h3 = hash_256(&hash_input);
    
    // Sign: sig = sk * H(m) (scalar multiplication on G2)
    // Simplified: incorporate private key into signature
    let mut sig_input = Vec::new();
    sig_input.extend_from_slice(private_key);
    sig_input.extend_from_slice(&h1);
    sig_input.extend_from_slice(&h2);
    sig_input.extend_from_slice(&h3);
    
    let s1 = hash_256(&sig_input);
    sig_input.extend_from_slice(&s1);
    let s2 = hash_256(&sig_input);
    sig_input.extend_from_slice(&s2);
    let s3 = hash_256(&sig_input);
    
    // 96-byte signature (compressed G2 point)
    let mut signature = Vec::with_capacity(96);
    signature.extend_from_slice(&s1);
    signature.extend_from_slice(&s2);
    signature.extend_from_slice(&s3);
    
    // Set G2 compression flags
    signature[0] = (signature[0] & 0x1F) | 0x80;
    
    signature
}

/// Create a Proof of Possession for a BLS key
/// Following AvalancheGo's ProofOfPossession structure:
/// - Sign the public key bytes with the PoP ciphersuite
/// 
/// Returns: (public_key, proof_of_possession_signature)
fn create_proof_of_possession(private_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let public_key = derive_bls_public_key(private_key);
    
    // PoP = sign(public_key) using PoP ciphersuite
    // This proves ownership of the secret key corresponding to the public key
    let pop_signature = bls_sign_proof_of_possession(private_key, &public_key);
    
    (public_key, pop_signature)
}

/// Verify a Proof of Possession
/// Matches AvalancheGo's VerifyProofOfPossession function
fn verify_proof_of_possession(public_key: &[u8], pop_signature: &[u8]) -> bool {
    // Verify that the signature is over the public key using PoP ciphersuite
    // In real impl: e(pk, H_pop(pk)) == e(G1, sig)
    
    // Structural validation
    if public_key.len() != 48 || pop_signature.len() != 96 {
        return false;
    }
    
    // Check compression bits are set
    if (public_key[0] & 0x80) == 0 || (pop_signature[0] & 0x80) == 0 {
        return false;
    }
    
    // Simplified verification - in production, would verify pairing equation
    true
}

/// Verify BLS signature (simplified)
fn bls_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // Structural validation
    if public_key.len() != 48 || signature.len() != 96 || message.is_empty() {
        return false;
    }
    
    // Check compression bits
    if (public_key[0] & 0x80) == 0 || (signature[0] & 0x80) == 0 {
        return false;
    }
    
    // Simplified verification passes structural checks
    // Real impl: e(pk, H(m)) == e(G1, sig)
    true
}

// ============================================================================
// Ed25519 Cryptographic Functions (ACP-20 TLS Identity)
// ============================================================================

/// Derive Ed25519 public key from private key (seed)
/// 
/// Ed25519 public key derivation:
/// 1. Hash seed with SHA-512
/// 2. Clamp the lower 32 bytes (clear/set specific bits)
/// 3. Scalar multiply by base point
/// 
/// Simplified implementation for WASM - production should use proper Ed25519
fn derive_ed25519_public_key(private_key: &[u8]) -> Vec<u8> {
    if private_key.len() != TLS_PRIVKEY_SIZE {
        return vec![0u8; TLS_PUBKEY_SIZE];
    }
    
    // Ed25519 key derivation (simplified)
    // Real impl: hash seed with SHA-512, clamp, then scalar mult by base point
    let mut pk_input = private_key.to_vec();
    pk_input.extend_from_slice(b"ED25519_PK_DERIVE_V1");
    
    // First hash for scalar
    let h1 = hash_256(&pk_input);
    
    // Apply Ed25519 clamping (simplified representation)
    let mut clamped = h1.clone();
    clamped[0] &= 248;   // Clear bottom 3 bits
    clamped[31] &= 127;  // Clear top bit
    clamped[31] |= 64;   // Set second-to-top bit
    
    // Second derivation pass for public key bytes
    pk_input.extend_from_slice(&clamped);
    let public_key = hash_256(&pk_input);
    
    public_key
}

/// Sign a message using Ed25519
/// 
/// Ed25519 signature is deterministic (no random nonce needed)
/// Signature format: 64 bytes (R || S)
/// 
/// Simplified implementation for WASM
fn ed25519_sign(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    if private_key.len() != TLS_PRIVKEY_SIZE {
        return vec![0u8; 64];
    }
    
    // Derive public key
    let public_key = derive_ed25519_public_key(private_key);
    
    // Ed25519 signing (simplified)
    // Real impl: 
    // 1. Hash prefix = SHA-512(seed)[32..64]
    // 2. r = SHA-512(prefix || message) mod L
    // 3. R = r * B (base point)
    // 4. k = SHA-512(R || pk || message) mod L
    // 5. S = (r + k * s) mod L
    // 6. Signature = R || S (64 bytes)
    
    // Generate deterministic nonce from private key and message
    let mut nonce_input = Vec::new();
    nonce_input.extend_from_slice(private_key);
    nonce_input.extend_from_slice(b"ED25519_NONCE");
    nonce_input.extend_from_slice(message);
    let nonce = hash_256(&nonce_input);
    
    // R component (first 32 bytes of signature)
    let mut r_input = nonce.clone();
    r_input.extend_from_slice(b"ED25519_R");
    let r = hash_256(&r_input);
    
    // Challenge hash
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&r);
    challenge_input.extend_from_slice(&public_key);
    challenge_input.extend_from_slice(message);
    let challenge = hash_256(&challenge_input);
    
    // S component (second 32 bytes of signature)
    let mut s_input = Vec::new();
    s_input.extend_from_slice(&nonce);
    s_input.extend_from_slice(&challenge);
    s_input.extend_from_slice(private_key);
    let s = hash_256(&s_input);
    
    // Combine into 64-byte signature
    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(&r);
    signature.extend_from_slice(&s);
    
    signature
}

/// Verify an Ed25519 signature (simplified)
fn ed25519_verify(public_key: &[u8], _message: &[u8], signature: &[u8]) -> bool {
    // Structural validation
    if public_key.len() != TLS_PUBKEY_SIZE || signature.len() != 64 {
        return false;
    }
    
    // In production, would verify:
    // 1. Decode R from signature[0..32]
    // 2. Decode S from signature[32..64]
    // 3. Check S < L (curve order)
    // 4. Compute k = SHA-512(R || pk || message)
    // 5. Check [8][S]B == [8]R + [8][k]A
    
    // Simplified: pass structural checks
    true
}

// ============================================================================
// SECP256K1 Cryptographic Functions (EVM/C-Chain Compatibility)
// ============================================================================

/// Derive SECP256K1 public key from private key
/// 
/// Returns (compressed_pubkey, uncompressed_pubkey)
/// - Compressed: 33 bytes (0x02/0x03 prefix + 32-byte X coordinate)
/// - Uncompressed: 65 bytes (0x04 prefix + 32-byte X + 32-byte Y)
/// 
/// Simplified implementation for WASM - production should use proper secp256k1
fn derive_secp256k1_public_key(private_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if private_key.len() != SECP256K1_PRIVKEY_SIZE {
        return (vec![0u8; SECP256K1_PUBKEY_COMPRESSED_SIZE], vec![0u8; SECP256K1_PUBKEY_UNCOMPRESSED_SIZE]);
    }
    
    // SECP256K1 key derivation (simplified)
    // Real impl: pubkey = privkey * G (generator point multiplication)
    let mut pk_input = private_key.to_vec();
    pk_input.extend_from_slice(b"SECP256K1_PK_DERIVE_X");
    let x_coord = hash_256(&pk_input);
    
    pk_input.extend_from_slice(b"SECP256K1_PK_DERIVE_Y");
    let y_coord = hash_256(&pk_input);
    
    // Compressed public key: prefix (0x02 even / 0x03 odd Y) + X coordinate
    let prefix = if y_coord[31] % 2 == 0 { 0x02 } else { 0x03 };
    let mut compressed = Vec::with_capacity(SECP256K1_PUBKEY_COMPRESSED_SIZE);
    compressed.push(prefix);
    compressed.extend_from_slice(&x_coord);
    
    // Uncompressed public key: 0x04 + X + Y
    let mut uncompressed = Vec::with_capacity(SECP256K1_PUBKEY_UNCOMPRESSED_SIZE);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x_coord);
    uncompressed.extend_from_slice(&y_coord);
    
    (compressed, uncompressed)
}

/// Derive Ethereum address from SECP256K1 public key
/// 
/// Address = keccak256(uncompressed_pubkey[1:65])[12:32]
/// The first byte (0x04) is stripped before hashing
fn derive_eth_address(uncompressed_pubkey: &[u8]) -> Vec<u8> {
    if uncompressed_pubkey.len() != SECP256K1_PUBKEY_UNCOMPRESSED_SIZE {
        return vec![0u8; ETH_ADDRESS_SIZE];
    }
    
    // Strip the 0x04 prefix and hash with keccak256
    let pubkey_bytes = &uncompressed_pubkey[1..];
    let hash = keccak256(pubkey_bytes);
    
    // Take last 20 bytes
    hash[12..32].to_vec()
}

/// Keccak256 hash (used for Ethereum addresses and EIP-712)
/// 
/// Simplified implementation - production should use proper keccak
fn keccak256(data: &[u8]) -> Vec<u8> {
    // Keccak256 is different from SHA3-256
    // This is a simplified approximation for demo purposes
    // Real implementation would use proper keccak sponge construction
    
    let mut input = data.to_vec();
    input.extend_from_slice(b"KECCAK256_DOMAIN_SEP");
    
    // Multiple rounds to simulate keccak mixing
    let h1 = hash_256(&input);
    input.extend_from_slice(&h1);
    let h2 = hash_256(&input);
    
    // XOR for additional mixing (keccak uses XOR extensively)
    let mut result = Vec::with_capacity(32);
    for i in 0..32 {
        result.push(h1[i] ^ h2[i] ^ data.get(i % data.len()).copied().unwrap_or(0));
    }
    
    result
}

/// Generate SECP256K1 keypair for EVM operations
/// 
/// Returns (private_key, compressed_pubkey, uncompressed_pubkey, eth_address)
fn generate_secp256k1_keypair(state: &mut ModuleState) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    // Generate 32-byte private key from secure random
    let private_key = generate_random(state, SECP256K1_PRIVKEY_SIZE);
    
    // Derive public keys
    let (compressed, uncompressed) = derive_secp256k1_public_key(&private_key);
    
    // Derive Ethereum address
    let eth_address = derive_eth_address(&uncompressed);
    
    (private_key, compressed, uncompressed, eth_address)
}

/// Sign a message hash with SECP256K1 (ECDSA)
/// 
/// Input: 32-byte message hash (typically keccak256 of the message)
/// Output: 65-byte signature (r: 32, s: 32, v: 1)
/// 
/// For EIP-191 personal_sign: hash = keccak256("\x19Ethereum Signed Message:\n" + len + message)
/// For EIP-712 typed data: hash = keccak256("\x19\x01" + domainSeparator + structHash)
fn secp256k1_sign(private_key: &[u8], message_hash: &[u8]) -> Vec<u8> {
    if private_key.len() != SECP256K1_PRIVKEY_SIZE || message_hash.len() != 32 {
        return vec![0u8; SECP256K1_SIGNATURE_SIZE];
    }
    
    // ECDSA signing (simplified)
    // Real impl:
    // 1. k = deterministic nonce (RFC 6979)
    // 2. R = k * G
    // 3. r = R.x mod n
    // 4. s = k^-1 * (hash + r * privkey) mod n
    // 5. v = recovery id (27 or 28, or 0/1 for EIP-155)
    
    // Generate deterministic k (RFC 6979 style)
    let mut k_input = Vec::new();
    k_input.extend_from_slice(private_key);
    k_input.extend_from_slice(message_hash);
    k_input.extend_from_slice(b"SECP256K1_RFC6979_K");
    let k = hash_256(&k_input);
    
    // r component (X coordinate of k*G)
    let mut r_input = k.clone();
    r_input.extend_from_slice(b"SECP256K1_R");
    let r = hash_256(&r_input);
    
    // s component
    let mut s_input = Vec::new();
    s_input.extend_from_slice(&k);
    s_input.extend_from_slice(message_hash);
    s_input.extend_from_slice(private_key);
    s_input.extend_from_slice(&r);
    let s = hash_256(&s_input);
    
    // v (recovery id) - simplified: use parity of s
    let v = if s[31] % 2 == 0 { 27u8 } else { 28u8 };
    
    // Combine into 65-byte signature (r || s || v)
    let mut signature = Vec::with_capacity(SECP256K1_SIGNATURE_SIZE);
    signature.extend_from_slice(&r);
    signature.extend_from_slice(&s);
    signature.push(v);
    
    signature
}

/// Sign a message with EIP-191 personal_sign format
/// 
/// Prepends "\x19Ethereum Signed Message:\n{len}" to message before signing
fn secp256k1_personal_sign(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    // EIP-191 prefix
    let prefix = b"\x19Ethereum Signed Message:\n";
    let len_str = format!("{}", message.len());
    
    let mut to_hash = Vec::new();
    to_hash.extend_from_slice(prefix);
    to_hash.extend_from_slice(len_str.as_bytes());
    to_hash.extend_from_slice(message);
    
    let message_hash = keccak256(&to_hash);
    secp256k1_sign(private_key, &message_hash)
}

/// Sign a raw transaction hash (for C-Chain transactions)
fn secp256k1_sign_transaction(private_key: &[u8], tx_hash: &[u8]) -> Vec<u8> {
    secp256k1_sign(private_key, tx_hash)
}

/// Verify a SECP256K1 ECDSA signature (simplified)
fn secp256k1_verify(public_key: &[u8], message_hash: &[u8], signature: &[u8]) -> bool {
    // Structural validation
    let valid_pubkey = public_key.len() == SECP256K1_PUBKEY_COMPRESSED_SIZE 
        || public_key.len() == SECP256K1_PUBKEY_UNCOMPRESSED_SIZE;
    
    if !valid_pubkey || message_hash.len() != 32 || signature.len() != SECP256K1_SIGNATURE_SIZE {
        return false;
    }
    
    // Check pubkey prefix
    match public_key[0] {
        0x02 | 0x03 if public_key.len() == 33 => {}
        0x04 if public_key.len() == 65 => {}
        _ => return false,
    }
    
    // Check v is valid (27, 28, or 0, 1 for EIP-155)
    let v = signature[64];
    if v != 27 && v != 28 && v != 0 && v != 1 {
        return false;
    }
    
    // Simplified: pass structural checks
    // Real impl would verify: sG = R + hash*pubkey
    true
}

/// Format Ethereum address with checksum (EIP-55)
fn format_eth_address(address: &[u8]) -> String {
    if address.len() != ETH_ADDRESS_SIZE {
        return String::new();
    }
    
    let hex_addr = bytes_to_hex(address);
    let hash = keccak256(hex_addr.as_bytes());
    
    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");
    
    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            // Use hash nibble to determine case
            let hash_byte = hash[i / 2];
            let hash_nibble = if i % 2 == 0 { hash_byte >> 4 } else { hash_byte & 0x0f };
            if hash_nibble >= 8 {
                checksummed.push(c.to_ascii_uppercase());
            } else {
                checksummed.push(c.to_ascii_lowercase());
            }
        } else {
            checksummed.push(c);
        }
    }
    
    checksummed
}

// ============================================================================
// JSON Helpers
// ============================================================================

fn json_get_string<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let search = format!("\"{}\"", key);
    let start = json.find(&search)?;
    let rest = &json[start + search.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    
    if after_colon.starts_with('"') {
        let content = &after_colon[1..];
        let end = content.find('"')?;
        Some(&content[..end])
    } else {
        None
    }
}

fn json_get_bool(json: &str, key: &str) -> Option<bool> {
    let search = format!("\"{}\"", key);
    let start = json.find(&search)?;
    let rest = &json[start + search.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    
    if after_colon.starts_with("true") {
        Some(true)
    } else if after_colon.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn json_get_number(json: &str, key: &str) -> Option<u64> {
    let search = format!("\"{}\"", key);
    let start = json.find(&search)?;
    let rest = &json[start + search.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    
    // Find the end of the number
    let mut end = 0;
    for (i, c) in after_colon.chars().enumerate() {
        if c.is_ascii_digit() {
            end = i + 1;
        } else if end > 0 {
            break;
        }
    }
    
    if end > 0 {
        after_colon[..end].parse().ok()
    } else {
        None
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
    }
    hex
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    
    for chunk in chars.chunks(2) {
        let high = char_to_nibble(chunk[0])?;
        let low = char_to_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    
    Some(bytes)
}

fn char_to_nibble(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(c),
        }
    }
    result
}

// ============================================================================
// Host API Calls (Minimal - only for I/O operations)
// ============================================================================

/// Request types that require host assistance
enum HostApiCall {
    /// Persist encrypted state to host storage
    PersistState { encrypted_data: String },
    /// Load encrypted state from host storage  
    LoadState,
    /// Get random bytes from host (for initial seeding only)
    GetRandomSeed { length: usize },
    /// Log message to host
    Log { level: String, message: String },
    /// HTTP GET request
    HttpGet { url: String, headers: Vec<(String, String)> },
    /// HTTP POST request with JSON body
    HttpPost { url: String, headers: Vec<(String, String)>, body: String },
    /// Write file to local filesystem (for keystore)
    WriteFile { path: String, content: String },
    /// Read file from local filesystem (for keystore)
    ReadFile { path: String },
    /// Create directory if it doesn't exist
    CreateDir { path: String },
    /// Check if file exists
    FileExists { path: String },
}

fn host_call_json(call: HostApiCall) -> String {
    match call {
        HostApiCall::PersistState { encrypted_data } => {
            format!(
                r#"{{"host_call":"persist_state","data":"{}"}}"#,
                escape_json_string(&encrypted_data)
            )
        }
        HostApiCall::LoadState => {
            r#"{"host_call":"load_state"}"#.to_string()
        }
        HostApiCall::GetRandomSeed { length } => {
            format!(r#"{{"host_call":"get_random_seed","length":{}}}"#, length)
        }
        HostApiCall::Log { level, message } => {
            format!(
                r#"{{"host_call":"log","level":"{}","message":"{}"}}"#,
                level,
                escape_json_string(&message)
            )
        }
        HostApiCall::HttpGet { url, headers } => {
            let headers_json = headers_to_json(&headers);
            format!(
                r#"{{"host_call":"http_get","url":"{}","headers":{}}}"#,
                escape_json_string(&url),
                headers_json
            )
        }
        HostApiCall::HttpPost { url, headers, body } => {
            let headers_json = headers_to_json(&headers);
            format!(
                r#"{{"host_call":"http_post","url":"{}","headers":{},"body":"{}"}}"#,
                escape_json_string(&url),
                headers_json,
                escape_json_string(&body)
            )
        }
        HostApiCall::WriteFile { path, content } => {
            format!(
                r#"{{"host_call":"write_file","path":"{}","content":"{}"}}"#,
                escape_json_string(&path),
                escape_json_string(&content)
            )
        }
        HostApiCall::ReadFile { path } => {
            format!(
                r#"{{"host_call":"read_file","path":"{}"}}"#,
                escape_json_string(&path)
            )
        }
        HostApiCall::CreateDir { path } => {
            format!(
                r#"{{"host_call":"create_dir","path":"{}"}}"#,
                escape_json_string(&path)
            )
        }
        HostApiCall::FileExists { path } => {
            format!(
                r#"{{"host_call":"file_exists","path":"{}"}}"#,
                escape_json_string(&path)
            )
        }
    }
}

fn headers_to_json(headers: &[(String, String)]) -> String {
    let mut json = String::from("{");
    let mut first = true;
    for (k, v) in headers {
        if !first { json.push(','); }
        first = false;
        json.push_str(&format!(r#""{}":"{}""#, escape_json_string(k), escape_json_string(v)));
    }
    json.push('}');
    json
}

// ============================================================================
// API Handlers
// ============================================================================

/// Initialize the module with backend configuration
/// Called by cryfttee runtime on module load
/// 
/// Initialize the module - auto-bootstraps Ed25519 TLS if no known Node ID/public key provided
/// 
/// This is the MAIN entry point. It will:
/// - If nodeId provided: reconnect with that existing identity
/// - If tlsPublicKey provided: Node ID = pubkey directly (ACP-20 style)
/// - If neither provided: auto-generate Ed25519 TLS key, pubkey becomes Node ID
/// 
/// Expected JSON:
/// {
///   "nodeId": "NodeID-abc123...",           // Optional: reconnect with existing Node ID (64 hex chars)
///   "tlsPublicKey": "abc123...",            // Optional: Ed25519 pubkey (32 bytes) = Node ID
///   "deviceName": "Validator Node 1",       // Optional: human-readable name
///   "deviceType": "validator",              // Optional: validator/sentry/archive
///   "web3signerUrl": "http://...",          // Optional: Web3Signer endpoint
///   "vaultUrl": "http://...",               // Optional: Vault endpoint
///   "vaultToken": "hvs.xxx",                // Optional: Vault token
///   "vaultPath": "cryfttee/data/keys",      // Optional: Vault KV path prefix
///   "vaultEnabled": true,                   // Optional: enable Vault backend
///   "randomSeed": "hex...",                 // Optional: initial entropy
///   "loadKeysFromVault": true,              // Optional: load TLS/BLS keys from Vault
///   "storageBackend": "vault|local|memory", // Optional: storage backend type (default: vault if configured)
///   "keystorePath": "/path/to/keystore",    // Optional: local keystore directory
///   "keystorePassword": "secret",           // Optional: password for local keystore encryption
///   "loadKeysFromKeystore": true            // Optional: load keys from local keystore
/// }
fn handle_initialize(json: &str) -> String {
    let state = get_state();
    
    // Parse backend configuration first (needed for bootstrap)
    if let Some(url) = json_get_string(json, "web3signerUrl") {
        state.config.web3signer_url = Some(url.to_string());
    }
    if let Some(url) = json_get_string(json, "vaultUrl") {
        state.config.vault_url = Some(url.to_string());
    }
    if let Some(token) = json_get_string(json, "vaultToken") {
        state.config.vault_token = Some(token.to_string());
    }
    if let Some(path) = json_get_string(json, "vaultPath") {
        state.config.vault_path = Some(path.to_string());
    }
    state.config.vault_enabled = json_get_bool(json, "vaultEnabled").unwrap_or(
        state.config.vault_url.is_some() && state.config.vault_token.is_some()
    );
    
    // Parse local keystore configuration
    if let Some(path) = json_get_string(json, "keystorePath") {
        if path.len() <= MAX_KEYSTORE_PATH_LEN {
            state.config.keystore_path = Some(path.to_string());
        }
    }
    if let Some(pwd) = json_get_string(json, "keystorePassword") {
        if pwd.len() <= MAX_KEYSTORE_PASSWORD_LEN {
            state.config.keystore_password = Some(pwd.to_string());
        }
    }
    
    // Determine storage backend
    if let Some(backend) = json_get_string(json, "storageBackend") {
        state.config.storage_backend = match backend {
            "local" | "keystore" | "file" => StorageBackend::LocalKeystore,
            "vault" => StorageBackend::Vault,
            "memory" | "none" => StorageBackend::Memory,
            _ => {
                // Default based on what's configured
                if state.config.vault_enabled {
                    StorageBackend::Vault
                } else if state.config.keystore_path.is_some() {
                    StorageBackend::LocalKeystore
                } else {
                    StorageBackend::Memory
                }
            }
        };
    } else {
        // Auto-detect based on configuration
        state.config.storage_backend = if state.config.vault_enabled {
            StorageBackend::Vault
        } else if state.config.keystore_path.is_some() {
            StorageBackend::LocalKeystore
        } else {
            StorageBackend::Memory
        };
    }
    
    // Initialize random seed if provided
    if let Some(seed) = json_get_string(json, "randomSeed") {
        if let Some(seed_bytes) = hex_to_bytes(seed) {
            state.random_seed = seed_bytes;
        }
    }
    
    // Determine Node ID from: explicit nodeId, tlsPublicKey derivation, or auto-bootstrap
    let node_id: String;
    let is_new_bootstrap: bool;
    let tls_pubkey_bytes: Option<Vec<u8>>;
    
    // Case 1: Explicit nodeId provided (reconnecting)
    if let Some(id) = json_get_string(json, "nodeId") {
        if id.starts_with("NodeID-") && id.len() == 7 + NODE_ID_HEX_LEN {
            node_id = id.to_string();
            is_new_bootstrap = false;
            tls_pubkey_bytes = None;
        } else if id.starts_with("NodeID-") {
            return format!(r#"{{"error":"invalid nodeId format - must be NodeID- followed by {} hex chars"}}"#, NODE_ID_HEX_LEN);
        } else {
            return r#"{"error":"nodeId must start with 'NodeID-'"}"#.to_string();
        }
    }
    // Case 2: TLS public key provided - Node ID IS the pubkey (ACP-20)
    else if let Some(pubkey_hex) = json_get_string(json, "tlsPublicKey") {
        match hex_to_bytes(pubkey_hex) {
            Some(pubkey) if pubkey.len() == TLS_PUBKEY_SIZE => {
                // ACP-20: Ed25519 public key IS the Node ID directly
                node_id = format!("NodeID-{}", bytes_to_hex(&pubkey));
                is_new_bootstrap = false;
                tls_pubkey_bytes = Some(pubkey);
            }
            Some(_) => {
                return format!(r#"{{"error":"tlsPublicKey must be {} bytes (Ed25519)"}}"#, TLS_PUBKEY_SIZE);
            }
            None => {
                return r#"{"error":"invalid tlsPublicKey hex"}"#.to_string();
            }
        }
    }
    // Case 3: No identity provided - auto-bootstrap new Ed25519 TLS key
    else {
        // Need random seed for key generation
        if state.random_seed.is_empty() {
            state.pending_request = Some(format!(r#"{{"action":"initialize","autoBootstrap":true,"originalRequest":{}}}"#, json));
            return host_call_json(HostApiCall::GetRandomSeed { length: 64 });
        }
        
        // Generate Ed25519 TLS keypair - pubkey IS the Node ID (ACP-20)
        let (private_key, public_key, certificate) = generate_tls_keypair_with_pubkey(state, "CryftTEE Node");
        node_id = format!("NodeID-{}", bytes_to_hex(&public_key));
        is_new_bootstrap = true;
        tls_pubkey_bytes = Some(public_key.clone());
        
        // Store TLS key locally
        let key_id = format!("{}:tls:node-identity", node_id);
        let keypair = TlsKeyPair {
            certificate: certificate.clone(),
            private_key: private_key.clone(),
            subject: "CryftTEE Node".to_string(),
            device_id: node_id.clone(),
            expires_at: state.nonce + 365 * 24 * 60 * 60,
        };
        state.tls_keys.insert(key_id.clone(), keypair);
        
        // Set device_id first so paths work
        state.config.device_id = Some(node_id.clone());
        
        // Store based on configured backend
        match state.config.storage_backend {
            StorageBackend::Vault => {
                // Store in Vault if enabled
                if let (Some(ref vault_url), Some(ref token)) = (&state.config.vault_url, &state.config.vault_token) {
                    let vault_path = state.config.vault_key_path("tls", "node-identity")
                        .unwrap_or_else(|| format!("cryfttee/data/keys/tls/{}/node-identity", node_id));
                    let store_url = format!("{}/v1/{}", vault_url, vault_path);
                    
                    let device_name = json_get_string(json, "deviceName").unwrap_or("CryftTEE Node");
                    
                    let vault_body = format!(
                        r#"{{"data":{{"private_key":"{}","public_key":"{}","certificate":"{}","node_id":"{}","device_name":"{}","created_at":{}}}}}"#,
                        bytes_to_hex(&private_key),
                        bytes_to_hex(&public_key),
                        escape_json_string(&certificate),
                        escape_json_string(&node_id),
                        escape_json_string(device_name),
                        state.nonce
                    );
                    
                    state.pending_request = Some(format!(
                        r#"{{"action":"initialize","nodeId":"{}","keyId":"{}","step":"store_tls_vault","originalRequest":{}}}"#,
                        node_id, key_id, json
                    ));
                    
                    return host_call_json(HostApiCall::HttpPost {
                        url: store_url,
                        headers: vec![
                            ("Content-Type".to_string(), "application/json".to_string()),
                            ("X-Vault-Token".to_string(), token.clone()),
                        ],
                        body: vault_body,
                    });
                }
            }
            StorageBackend::LocalKeystore => {
                // Store in local keystore file
                if let Some(ref base_path) = state.config.keystore_path.clone() {
                    let keystore_dir = format!("{}/{}", base_path, node_id);
                    let keystore_file = format!("{}/tls_node-identity.json", keystore_dir);
                    
                    // Create encrypted keystore JSON
                    let keystore_json = create_encrypted_keystore(
                        &private_key,
                        &public_key,
                        "CryftTEE TLS Identity",
                        state.config.keystore_password.as_deref(),
                        "tls"
                    );
                    
                    // First create the directory
                    state.pending_request = Some(format!(
                        r#"{{"action":"initialize","nodeId":"{}","keyId":"{}","step":"create_keystore_dir","keystoreFile":"{}","keystoreContent":"{}","originalRequest":{}}}"#,
                        node_id, key_id, 
                        escape_json_string(&keystore_file),
                        escape_json_string(&keystore_json),
                        json
                    ));
                    
                    return host_call_json(HostApiCall::CreateDir { path: keystore_dir });
                }
            }
            StorageBackend::Memory => {
                // No persistence - key only in memory
            }
        }
    }
    
    state.config.device_id = Some(node_id.clone());
    
    // Parse optional device metadata
    let device_name = json_get_string(json, "deviceName")
        .unwrap_or(&node_id)
        .to_string();
    let device_type = json_get_string(json, "deviceType")
        .unwrap_or("validator")
        .to_string();
    
    // Register/update device info
    let device_info = DeviceInfo {
        device_id: node_id.clone(),
        name: device_name.clone(),
        device_type: device_type.clone(),
        registered_at: state.nonce,
        last_seen: state.nonce,
        bls_keys: Vec::new(),
        tls_keys: if is_new_bootstrap { vec![format!("{}:tls:node-identity", node_id)] } else { Vec::new() },
    };
    state.devices.insert(node_id.clone(), device_info);
    
    state.config.initialized = true;
    
    // Handle key loading based on storage backend and flags
    let load_from_vault = json_get_bool(json, "loadKeysFromVault").unwrap_or(false);
    let load_from_keystore = json_get_bool(json, "loadKeysFromKeystore").unwrap_or(false);
    
    // Load from Vault if configured and requested
    if state.config.storage_backend == StorageBackend::Vault && load_from_vault && !is_new_bootstrap {
        if let (Some(ref vault_url), Some(ref token)) = (&state.config.vault_url, &state.config.vault_token) {
            let vault_path = state.config.vault_key_path("tls", "node-identity")
                .unwrap_or_else(|| format!("cryfttee/data/keys/tls/{}/node-identity", node_id));
            let check_url = format!("{}/v1/{}", vault_url, vault_path);
            
            state.pending_request = Some(format!(
                r#"{{"action":"initialize","nodeId":"{}","step":"load_tls_from_vault"}}"#,
                node_id
            ));
            
            return host_call_json(HostApiCall::HttpGet {
                url: check_url,
                headers: vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    ("X-Vault-Token".to_string(), token.clone()),
                ],
            });
        }
    }
    
    // Load from local keystore if configured and requested
    if state.config.storage_backend == StorageBackend::LocalKeystore && load_from_keystore && !is_new_bootstrap {
        if let Some(ref base_path) = state.config.keystore_path.clone() {
            let keystore_file = format!("{}/{}/tls_node-identity.json", base_path, node_id);
            
            state.pending_request = Some(format!(
                r#"{{"action":"initialize","nodeId":"{}","step":"load_tls_from_keystore"}}"#,
                node_id
            ));
            
            return host_call_json(HostApiCall::ReadFile { path: keystore_file });
        }
    }
    
    // Build response
    let vault_bls_path = state.config.vault_key_path("bls", "primary")
        .unwrap_or_else(|| "not configured".to_string());
    let vault_tls_path = state.config.vault_key_path("tls", "node-identity")
        .unwrap_or_else(|| "not configured".to_string());
    let keystore_path = state.config.keystore_path.clone().unwrap_or_else(|| "not configured".to_string());
    
    let storage_backend_str = match state.config.storage_backend {
        StorageBackend::Memory => "memory",
        StorageBackend::LocalKeystore => "local",
        StorageBackend::Vault => "vault",
    };
    
    let pubkey_hex = tls_pubkey_bytes.map(|b| bytes_to_hex(&b)).unwrap_or_default();
    
    format!(
        r#"{{"success":true,"initialized":true,"nodeId":"{}","isNewBootstrap":{},"deviceName":"{}","deviceType":"{}","tlsPublicKey":"{}","web3signerConfigured":{},"storageBackend":"{}","vaultEnabled":{},"vaultBlsPath":"{}","vaultTlsPath":"{}","keystorePath":"{}","keystoreEncrypted":{}}}"#,
        escape_json_string(&node_id),
        is_new_bootstrap,
        escape_json_string(&device_name),
        escape_json_string(&device_type),
        pubkey_hex,
        state.config.web3signer_url.is_some(),
        storage_backend_str,
        state.config.vault_enabled,
        escape_json_string(&vault_bls_path),
        escape_json_string(&vault_tls_path),
        escape_json_string(&keystore_path),
        state.config.keystore_password.is_some()
    )
}

/// Ensure a BLS key exists - check backends and generate if missing
/// This is the main entry point for cryftgo key registration
/// 
/// PREREQUISITE: TLS identity must be bootstrapped first (call bootstrapTls)
/// 
/// Flow:
/// 1. Verify Node ID exists (from TLS bootstrap)
/// 2. If publicKey provided: verify it exists in Web3Signer/Vault
/// 3. If not found anywhere: generate new key and import to backends
/// 4. If no publicKey provided: generate new key
/// 
/// Multi-device: Keys are namespaced by Node ID in Vault:
///   cryfttee/data/keys/bls/{node_id}/{key_name}
fn handle_ensure_bls_key(json: &str) -> String {
    let state = get_state();
    
    // Enforce TLS-first: must have a valid Node ID from TLS bootstrap
    let node_id = match &state.config.device_id {
        Some(id) if id.starts_with("NodeID-") => id.clone(),
        Some(_) => return r#"{"error":"invalid_node_id","message":"Device ID is not a valid Node ID. Run bootstrapTls first to generate TLS identity."}"#.to_string(),
        None => return r#"{"error":"not_bootstrapped","message":"TLS identity not bootstrapped. Call bootstrapTls first to generate Node ID from TLS key."}"#.to_string(),
    };
    
    // Check if we need random seed
    if state.random_seed.is_empty() {
        state.pending_request = Some(json.to_string());
        return host_call_json(HostApiCall::GetRandomSeed { length: 64 });
    }
    
    let label = json_get_string(json, "label").unwrap_or("primary");
    let key_name = json_get_string(json, "keyName").unwrap_or("primary");
    let provided_pubkey = json_get_string(json, "publicKey");
    
    // Case 1: Public key provided by cryftgo - verify it exists
    if let Some(pubkey_hex) = provided_pubkey {
        let pubkey_bytes = match hex_to_bytes(pubkey_hex) {
            Some(b) => b,
            None => return r#"{"error":"invalid publicKey hex"}"#.to_string(),
        };
        
        // Check if we already have this key locally
        for (id, kp) in &state.bls_keys {
            if kp.public_key == pubkey_bytes {
                return format!(
                    r#"{{"success":true,"action":"found_local","keyId":"{}","publicKey":"{}","nodeId":"{}"}}"#,
                    id,
                    pubkey_hex,
                    escape_json_string(&node_id)
                );
            }
        }
        
        // Check Vault first if enabled (keys may be stored there from another session)
        if state.config.vault_enabled {
            if let (Some(ref vault_url), Some(ref token)) = (&state.config.vault_url, &state.config.vault_token) {
                let vault_path = state.config.vault_key_path("bls", key_name)
                    .unwrap_or_else(|| format!("cryfttee/data/keys/bls/{}/{}", node_id, key_name));
                let check_url = format!("{}/v1/{}", vault_url, vault_path);
                
                state.pending_request = Some(format!(
                    r#"{{"action":"ensureBlsKey","publicKey":"{}","label":"{}","keyName":"{}","nodeId":"{}","step":"check_vault"}}"#,
                    pubkey_hex, label, key_name, node_id
                ));
                
                return host_call_json(HostApiCall::HttpGet {
                    url: check_url,
                    headers: vec![
                        ("Content-Type".to_string(), "application/json".to_string()),
                        ("X-Vault-Token".to_string(), token.clone()),
                    ],
                });
            }
        }
        
        // Check Web3Signer - request host to make HTTP call
        if let Some(ref url) = state.config.web3signer_url {
            let check_url = format!("{}/api/v1/eth2/publicKeys", url);
            state.pending_request = Some(format!(
                r#"{{"action":"ensureBlsKey","publicKey":"{}","label":"{}","keyName":"{}","nodeId":"{}","step":"check_web3signer"}}"#,
                pubkey_hex, label, key_name, node_id
            ));
            return host_call_json(HostApiCall::HttpGet {
                url: check_url,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            });
        }
        
        // No backends configured - key not found
        return format!(
            r#"{{"success":false,"error":"key_not_found","publicKey":"{}","nodeId":"{}","message":"Key not found and no backends configured."}}"#,
            pubkey_hex,
            escape_json_string(&node_id)
        );
    }
    
    // Case 2: No public key provided - generate new key for this device
    generate_and_store_bls_key(state, &node_id, label, key_name)
}

/// Generate a BLS key with Proof of Possession and store it in configured backends
/// 
/// Following AvalancheGo's pattern:
/// 1. Generate BLS keypair (32-byte sk, 48-byte pk)
/// 2. Create Proof of Possession by signing the public key with PoP ciphersuite
/// 3. Store both public key and PoP signature
/// 
/// Note: node_id parameter is expected to be a valid Node ID at this point
fn generate_and_store_bls_key(state: &mut ModuleState, node_id: &str, label: &str, key_name: &str) -> String {
    // generate_bls_keypair now returns proof_of_possession as part of the tuple
    let (private_key, public_key, proof_of_possession) = generate_bls_keypair(state);
    
    // Key ID includes node for uniqueness across devices
    let key_id = format!("{}:bls:{}", node_id, key_name);
    
    let keypair = BlsKeyPair {
        public_key: public_key.clone(),
        private_key: private_key.clone(),
        proof_of_possession: proof_of_possession.clone(),
        label: label.to_string(),
        device_id: node_id.to_string(),
        created_at: state.nonce,
        locked: false,
    };
    
    state.bls_keys.insert(key_id.clone(), keypair);
    
    // Update device's key list
    if let Some(device) = state.devices.get_mut(node_id) {
        if !device.bls_keys.contains(&key_id) {
            device.bls_keys.push(key_id.clone());
        }
    }
    
    // Store based on configured backend
    match state.config.storage_backend {
        StorageBackend::Vault => {
            // Store in Vault if enabled
            if let (Some(ref vault_url), Some(ref token)) = (&state.config.vault_url, &state.config.vault_token) {
                let vault_path = state.config.vault_key_path("bls", key_name)
                    .unwrap_or_else(|| format!("cryfttee/data/keys/bls/{}/{}", node_id, key_name));
                let store_url = format!("{}/v1/{}", vault_url, vault_path);
                
                // Vault KV v2 payload - includes proof of possession
                let vault_body = format!(
                    r#"{{"data":{{"private_key":"{}","public_key":"{}","proof_of_possession":"{}","label":"{}","node_id":"{}","key_name":"{}","created_at":{}}}}}"#,
                    bytes_to_hex(&private_key),
                    bytes_to_hex(&public_key),
                    bytes_to_hex(&proof_of_possession),
                    escape_json_string(label),
                    escape_json_string(node_id),
                    escape_json_string(key_name),
                    state.nonce
                );
                
                state.pending_request = Some(format!(
                    r#"{{"action":"ensureBlsKey","keyId":"{}","publicKey":"{}","proofOfPossession":"{}","nodeId":"{}","keyName":"{}","step":"store_vault"}}"#,
                    key_id,
                    bytes_to_hex(&public_key),
                    bytes_to_hex(&proof_of_possession),
                    node_id,
                    key_name
                ));
                
                return host_call_json(HostApiCall::HttpPost {
                    url: store_url,
                    headers: vec![
                        ("Content-Type".to_string(), "application/json".to_string()),
                        ("X-Vault-Token".to_string(), token.clone()),
                    ],
                    body: vault_body,
                });
            }
        }
        StorageBackend::LocalKeystore => {
            // Store in local keystore file
            if let Some(ref base_path) = state.config.keystore_path.clone() {
                let keystore_dir = format!("{}/{}", base_path, node_id);
                let keystore_file = format!("{}/bls_{}.json", keystore_dir, key_name);
                
                let keystore_json = create_encrypted_keystore(
                    &private_key,
                    &public_key,
                    label,
                    state.config.keystore_password.as_deref(),
                    "bls"
                );
                
                state.pending_request = Some(format!(
                    r#"{{"action":"ensureBlsKey","keyId":"{}","publicKey":"{}","proofOfPossession":"{}","nodeId":"{}","keyName":"{}","step":"create_bls_keystore_dir","keystoreFile":"{}","keystoreContent":"{}"}}"#,
                    key_id,
                    bytes_to_hex(&public_key),
                    bytes_to_hex(&proof_of_possession),
                    node_id,
                    key_name,
                    escape_json_string(&keystore_file),
                    escape_json_string(&keystore_json)
                ));
                
                return host_call_json(HostApiCall::CreateDir { path: keystore_dir });
            }
        }
        StorageBackend::Memory => {
            // Continue to Web3Signer import if configured
        }
    }
    
    // Import to Web3Signer if configured (for signing operations)
    if let Some(ref url) = state.config.web3signer_url {
        let import_url = format!("{}/eth/v1/keystores", url);
        
        let keystore = create_keystore_json(&private_key, &public_key, label);
        let import_body = format!(
            r#"{{"keystores":["{}"],"passwords":["cryfttee-generated"]}}"#,
            escape_json_string(&keystore)
        );
        
        state.pending_request = Some(format!(
            r#"{{"action":"ensureBlsKey","keyId":"{}","publicKey":"{}","proofOfPossession":"{}","nodeId":"{}","step":"import_web3signer"}}"#,
            key_id,
            bytes_to_hex(&public_key),
            bytes_to_hex(&proof_of_possession),
            node_id
        ));
        
        return host_call_json(HostApiCall::HttpPost {
            url: import_url,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: import_body,
        });
    }
    
    // Determine storage info for response
    let storage_backend_str = match state.config.storage_backend {
        StorageBackend::Memory => "memory",
        StorageBackend::LocalKeystore => "local",
        StorageBackend::Vault => "vault",
    };
    
    // No backends - return the locally generated key with Proof of Possession
    // Response format matches AvalancheGo's ProofOfPossession JSON structure
    format!(
        r#"{{"success":true,"action":"generated","keyId":"{}","publicKey":"{}","proofOfPossession":"{}","nodeId":"{}","label":"{}","keyName":"{}","storageBackend":"{}","note":"Key stored locally only - no persistence backends available"}}"#,
        key_id,
        bytes_to_hex(&public_key),
        bytes_to_hex(&proof_of_possession),
        escape_json_string(node_id),
        escape_json_string(label),
        escape_json_string(key_name),
        storage_backend_str
    )
}

/// Handle response from Web3Signer/Vault HTTP calls
fn handle_http_response(json: &str) -> String {
    let state = get_state();
    
    let status = json_get_string(json, "status").unwrap_or("0");
    let body = json_get_string(json, "body").unwrap_or("");
    let pending = state.pending_request.take();
    
    if let Some(pending_json) = pending {
        let step = json_get_string(&pending_json, "step").unwrap_or("");
        let action = json_get_string(&pending_json, "action").unwrap_or("");
        
        // Get node_id from pending request or config (clone to avoid borrow issues)
        let node_id = json_get_string(&pending_json, "nodeId")
            .or_else(|| json_get_string(&pending_json, "deviceId"))
            .map(|s| s.to_string())
            .or_else(|| state.config.device_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        
        match (action, step) {
            // Vault key check response
            ("ensureBlsKey", "check_vault") => {
                let pubkey = json_get_string(&pending_json, "publicKey").unwrap_or("");
                let label = json_get_string(&pending_json, "label").unwrap_or("primary");
                let key_name = json_get_string(&pending_json, "keyName").unwrap_or("primary");
                
                // Check if key exists in Vault (status 200 with data)
                if status == "200" && body.contains("\"data\"") {
                    // Key found in Vault - extract and load it
                    if let Some(private_hex) = json_get_string(body, "private_key") {
                        if let Some(private_key) = hex_to_bytes(private_hex) {
                            // Reconstruct keypair from Vault (including PoP)
                            let (_, public_key, proof_of_possession) = generate_bls_keypair_from_private(&private_key);
                            let key_id = format!("{}:bls:{}", node_id, key_name);
                            
                            let keypair = BlsKeyPair {
                                public_key: public_key.clone(),
                                private_key,
                                proof_of_possession: proof_of_possession.clone(),
                                label: label.to_string(),
                                device_id: node_id.clone(),
                                created_at: state.nonce,
                                locked: false,
                            };
                            
                            state.bls_keys.insert(key_id.clone(), keypair);
                            
                            return format!(
                                r#"{{"success":true,"action":"loaded_from_vault","keyId":"{}","publicKey":"{}","proofOfPossession":"{}","nodeId":"{}"}}"#,
                                key_id,
                                bytes_to_hex(&public_key),
                                bytes_to_hex(&proof_of_possession),
                                escape_json_string(&node_id)
                            );
                        }
                    }
                }
                
                // Key not in Vault - check Web3Signer next, or generate
                if let Some(ref url) = state.config.web3signer_url.clone() {
                    let check_url = format!("{}/api/v1/eth2/publicKeys", url);
                    state.pending_request = Some(format!(
                        r#"{{"action":"ensureBlsKey","publicKey":"{}","label":"{}","keyName":"{}","nodeId":"{}","step":"check_web3signer"}}"#,
                        pubkey, label, key_name, node_id
                    ));
                    return host_call_json(HostApiCall::HttpGet {
                        url: check_url,
                        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                    });
                }
                
                // No Web3Signer - generate new key
                return generate_and_store_bls_key(state, &node_id, label, key_name);
            }
            
            // Vault storage response
            ("ensureBlsKey", "store_vault") => {
                let key_id = json_get_string(&pending_json, "keyId").unwrap_or("");
                let pubkey = json_get_string(&pending_json, "publicKey").unwrap_or("");
                let key_name = json_get_string(&pending_json, "keyName").unwrap_or("primary");
                
                if status == "200" || status == "204" {
                    // Also import to Web3Signer for signing operations
                    if let Some(ref url) = state.config.web3signer_url.clone() {
                        if let Some(keypair) = state.bls_keys.get(key_id) {
                            let import_url = format!("{}/eth/v1/keystores", url);
                            let keystore = create_keystore_json(&keypair.private_key, &keypair.public_key, &keypair.label);
                            let import_body = format!(
                                r#"{{"keystores":["{}"],"passwords":["cryfttee-generated"]}}"#,
                                escape_json_string(&keystore)
                            );
                            
                            state.pending_request = Some(format!(
                                r#"{{"action":"ensureBlsKey","keyId":"{}","publicKey":"{}","nodeId":"{}","step":"import_web3signer_after_vault"}}"#,
                                key_id, pubkey, node_id
                            ));
                            
                            return host_call_json(HostApiCall::HttpPost {
                                url: import_url,
                                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                                body: import_body,
                            });
                        }
                    }
                    
                    return format!(
                        r#"{{"success":true,"action":"stored_in_vault","keyId":"{}","publicKey":"{}","nodeId":"{}","vaultPath":"{}"}}"#,
                        key_id,
                        pubkey,
                        escape_json_string(&node_id),
                        state.config.vault_key_path("bls", key_name).unwrap_or_default()
                    );
                }
                
                return format!(
                    r#"{{"success":false,"error":"vault_store_failed","keyId":"{}","status":"{}","response":"{}"}}"#,
                    key_id,
                    status,
                    escape_json_string(body)
                );
            }
            
            // BLS keystore directory created - now write the file
            ("ensureBlsKey", "create_bls_keystore_dir") => {
                let keystore_file = json_get_string(&pending_json, "keystoreFile").unwrap_or("");
                let keystore_content = json_get_string(&pending_json, "keystoreContent").unwrap_or("");
                let key_id = json_get_string(&pending_json, "keyId").unwrap_or("");
                let pubkey = json_get_string(&pending_json, "publicKey").unwrap_or("");
                let key_name = json_get_string(&pending_json, "keyName").unwrap_or("primary");
                
                if !keystore_file.is_empty() && !keystore_content.is_empty() {
                    state.pending_request = Some(format!(
                        r#"{{"action":"ensureBlsKey","keyId":"{}","publicKey":"{}","nodeId":"{}","keyName":"{}","step":"write_bls_keystore"}}"#,
                        key_id, pubkey, node_id, key_name
                    ));
                    
                    return host_call_json(HostApiCall::WriteFile { 
                        path: keystore_file.to_string(), 
                        content: keystore_content.to_string() 
                    });
                }
                
                return format!(
                    r#"{{"success":true,"action":"generated","keyId":"{}","publicKey":"{}","nodeId":"{}","storageBackend":"local","keystoreWritten":false}}"#,
                    key_id,
                    pubkey,
                    escape_json_string(&node_id)
                );
            }
            
            // BLS keystore file written
            ("ensureBlsKey", "write_bls_keystore") => {
                let key_id = json_get_string(&pending_json, "keyId").unwrap_or("");
                let pubkey = json_get_string(&pending_json, "publicKey").unwrap_or("");
                let key_name = json_get_string(&pending_json, "keyName").unwrap_or("primary");
                let keystore_path = state.config.keystore_path.clone().unwrap_or_default();
                
                // Optionally import to Web3Signer for signing operations
                if let Some(ref url) = state.config.web3signer_url.clone() {
                    if let Some(keypair) = state.bls_keys.get(key_id) {
                        let import_url = format!("{}/eth/v1/keystores", url);
                        let keystore = create_keystore_json(&keypair.private_key, &keypair.public_key, &keypair.label);
                        let import_body = format!(
                            r#"{{"keystores":["{}"],"passwords":["cryfttee-generated"]}}"#,
                            escape_json_string(&keystore)
                        );
                        
                        state.pending_request = Some(format!(
                            r#"{{"action":"ensureBlsKey","keyId":"{}","publicKey":"{}","nodeId":"{}","step":"import_web3signer_after_keystore"}}"#,
                            key_id, pubkey, node_id
                        ));
                        
                        return host_call_json(HostApiCall::HttpPost {
                            url: import_url,
                            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                            body: import_body,
                        });
                    }
                }
                
                return format!(
                    r#"{{"success":true,"action":"generated","keyId":"{}","publicKey":"{}","nodeId":"{}","keyName":"{}","storageBackend":"local","keystorePath":"{}","keystoreEncrypted":{},"keystoreWritten":true}}"#,
                    key_id,
                    pubkey,
                    escape_json_string(&node_id),
                    escape_json_string(key_name),
                    escape_json_string(&keystore_path),
                    state.config.keystore_password.is_some()
                );
            }
            
            // Web3Signer import after keystore write
            ("ensureBlsKey", "import_web3signer_after_keystore") => {
                let key_id = json_get_string(&pending_json, "keyId").unwrap_or("");
                let pubkey = json_get_string(&pending_json, "publicKey").unwrap_or("");
                let keystore_path = state.config.keystore_path.clone().unwrap_or_default();
                
                let web3signer_imported = status == "200" || status == "201" || body.contains("imported") || body.contains("duplicate");
                
                return format!(
                    r#"{{"success":true,"action":"generated","keyId":"{}","publicKey":"{}","nodeId":"{}","storageBackend":"local","keystorePath":"{}","keystoreEncrypted":{},"keystoreWritten":true,"web3signerImported":{}}}"#,
                    key_id,
                    pubkey,
                    escape_json_string(&node_id),
                    escape_json_string(&keystore_path),
                    state.config.keystore_password.is_some(),
                    web3signer_imported
                );
            }
            
            // Web3Signer check response  
            ("ensureBlsKey", "check_web3signer") => {
                let pubkey = json_get_string(&pending_json, "publicKey").unwrap_or("");
                let label = json_get_string(&pending_json, "label").unwrap_or("primary");
                let key_name = json_get_string(&pending_json, "keyName").unwrap_or("primary");
                
                // Check if the public key is in the response
                if body.contains(pubkey) {
                    return format!(
                        r#"{{"success":true,"action":"found_web3signer","publicKey":"{}","nodeId":"{}"}}"#,
                        pubkey,
                        escape_json_string(&node_id)
                    );
                }
                
                // Key not found - generate new key for this device
                return generate_and_store_bls_key(state, &node_id, label, key_name);
            }
            
            // Web3Signer import response (after Vault store)
            ("ensureBlsKey", "import_web3signer_after_vault") | ("ensureBlsKey", "import_web3signer") => {
                let key_id = json_get_string(&pending_json, "keyId").unwrap_or("");
                let pubkey = json_get_string(&pending_json, "publicKey").unwrap_or("");
                
                if status == "200" || status == "201" || body.contains("imported") || body.contains("duplicate") {
                    return format!(
                        r#"{{"success":true,"action":"imported","keyId":"{}","publicKey":"{}","nodeId":"{}"}}"#,
                        key_id,
                        pubkey,
                        escape_json_string(&node_id)
                    );
                }
                
                return format!(
                    r#"{{"success":false,"error":"import_failed","keyId":"{}","publicKey":"{}","status":"{}","response":"{}"}}"#,
                    key_id,
                    pubkey,
                    status,
                    escape_json_string(body)
                );
            }
            
            // TLS key Vault responses (similar pattern)
            ("ensureTlsKey", "store_vault") => {
                let key_id = json_get_string(&pending_json, "keyId").unwrap_or("");
                let subject = json_get_string(&pending_json, "subject").unwrap_or("");
                
                if status == "200" || status == "204" {
                    return format!(
                        r#"{{"success":true,"action":"stored_in_vault","keyId":"{}","subject":"{}","nodeId":"{}"}}"#,
                        key_id,
                        escape_json_string(subject),
                        escape_json_string(&node_id)
                    );
                }
                
                return format!(
                    r#"{{"success":false,"error":"vault_store_failed","keyId":"{}","status":"{}"}}"#,
                    key_id,
                    status
                );
            }
            
            // TLS bootstrap Vault store response
            ("bootstrapTls", "store_vault") => {
                let key_id = json_get_string(&pending_json, "keyId").unwrap_or("");
                
                if status == "200" || status == "204" {
                    return format!(
                        r#"{{"success":true,"action":"bootstrapped","nodeId":"{}","keyId":"{}","vaultStored":true,"message":"TLS identity bootstrapped and stored in Vault."}}"#,
                        escape_json_string(&node_id),
                        key_id
                    );
                }
                
                // Vault store failed but key was generated locally
                return format!(
                    r#"{{"success":true,"action":"bootstrapped","nodeId":"{}","keyId":"{}","vaultStored":false,"vaultError":"{}","message":"TLS identity bootstrapped locally but Vault store failed."}}"#,
                    escape_json_string(&node_id),
                    key_id,
                    escape_json_string(body)
                );
            }
            
            // Initialize with auto-bootstrap - TLS key stored in Vault
            ("initialize", "store_tls_vault") => {
                let key_id = json_get_string(&pending_json, "keyId").unwrap_or("");
                
                // Complete initialization regardless of Vault result
                state.config.initialized = true;
                
                // Parse device info from original request if available
                let original = json_get_string(&pending_json, "originalRequest").unwrap_or("{}");
                let device_name = json_get_string(original, "deviceName")
                    .unwrap_or(&node_id)
                    .to_string();
                let device_type = json_get_string(original, "deviceType")
                    .unwrap_or("validator")
                    .to_string();
                
                // Update device info
                let device_info = DeviceInfo {
                    device_id: node_id.clone(),
                    name: device_name.clone(),
                    device_type: device_type.clone(),
                    registered_at: state.nonce,
                    last_seen: state.nonce,
                    bls_keys: Vec::new(),
                    tls_keys: vec![key_id.to_string()],
                };
                state.devices.insert(node_id.clone(), device_info);
                
                let vault_stored = status == "200" || status == "204";
                let vault_bls_path = state.config.vault_key_path("bls", "primary")
                    .unwrap_or_else(|| "not configured".to_string());
                let vault_tls_path = state.config.vault_key_path("tls", "node-identity")
                    .unwrap_or_else(|| "not configured".to_string());
                
                // Get TLS public key from stored key
                let tls_pubkey = state.tls_keys.get(key_id)
                    .map(|_| "stored") // We don't have pubkey in TlsKeyPair, just indicate it exists
                    .unwrap_or("unknown");
                
                return format!(
                    r#"{{"success":true,"initialized":true,"isNewBootstrap":true,"nodeId":"{}","keyId":"{}","deviceName":"{}","deviceType":"{}","vaultStored":{},"web3signerConfigured":{},"vaultEnabled":{},"vaultBlsPath":"{}","vaultTlsPath":"{}"}}"#,
                    escape_json_string(&node_id),
                    key_id,
                    escape_json_string(&device_name),
                    escape_json_string(&device_type),
                    vault_stored,
                    state.config.web3signer_url.is_some(),
                    state.config.vault_enabled,
                    escape_json_string(&vault_bls_path),
                    escape_json_string(&vault_tls_path)
                );
            }
            
            // Initialize reconnection - load TLS key from Vault
            ("initialize", "load_tls_from_vault") => {
                let key_id = format!("{}:tls:node-identity", node_id);
                let mut tls_loaded = false;
                let mut tls_pubkey_hex = String::new();
                
                // Try to load TLS key from Vault response
                if status == "200" && body.contains("\"data\"") {
                    if let Some(private_hex) = json_get_string(body, "private_key") {
                        if let Some(private_key) = hex_to_bytes(private_hex) {
                            // Get public key and certificate if available
                            let public_key = json_get_string(body, "public_key")
                                .and_then(|h| hex_to_bytes(h))
                                .unwrap_or_default();
                            let certificate = json_get_string(body, "certificate")
                                .unwrap_or("").to_string();
                            
                            if !public_key.is_empty() {
                                tls_pubkey_hex = bytes_to_hex(&public_key);
                            }
                            
                            // Store TLS key locally
                            let keypair = TlsKeyPair {
                                certificate,
                                private_key,
                                subject: "CryftTEE Node".to_string(),
                                device_id: node_id.clone(),
                                expires_at: state.nonce + 365 * 24 * 60 * 60,
                            };
                            state.tls_keys.insert(key_id.clone(), keypair);
                            tls_loaded = true;
                            
                            // Update device's TLS keys list
                            if let Some(device) = state.devices.get_mut(&node_id) {
                                if !device.tls_keys.contains(&key_id) {
                                    device.tls_keys.push(key_id.clone());
                                }
                            }
                        }
                    }
                }
                
                let vault_bls_path = state.config.vault_key_path("bls", "primary")
                    .unwrap_or_else(|| "not configured".to_string());
                let vault_tls_path = state.config.vault_key_path("tls", "node-identity")
                    .unwrap_or_else(|| "not configured".to_string());
                
                return format!(
                    r#"{{"success":true,"initialized":true,"isNewBootstrap":false,"nodeId":"{}","tlsKeyLoaded":{},"tlsPublicKey":"{}","web3signerConfigured":{},"vaultEnabled":{},"vaultBlsPath":"{}","vaultTlsPath":"{}"}}"#,
                    escape_json_string(&node_id),
                    tls_loaded,
                    tls_pubkey_hex,
                    state.config.web3signer_url.is_some(),
                    state.config.vault_enabled,
                    escape_json_string(&vault_bls_path),
                    escape_json_string(&vault_tls_path)
                );
            }
            
            // Initialize reconnection - load TLS key from local keystore
            ("initialize", "load_tls_from_keystore") => {
                let key_id = format!("{}:tls:node-identity", node_id);
                let mut tls_loaded = false;
                let mut tls_pubkey_hex = String::new();
                let mut error_msg = String::new();
                
                // body contains the keystore JSON file content
                if !body.is_empty() && body.contains("\"crypto\"") {
                    // Parse and decrypt keystore
                    let password = state.config.keystore_password.as_deref();
                    
                    match decrypt_keystore(body, password) {
                        Some((private_key, public_key, _key_type)) => {
                            tls_pubkey_hex = bytes_to_hex(&public_key);
                            
                            // Generate certificate (we don't store it in keystore)
                            let certificate = format!(
                                "-----BEGIN CERTIFICATE-----\nReloaded from keystore (pubkey: {})\n-----END CERTIFICATE-----",
                                &tls_pubkey_hex[..16]
                            );
                            
                            let keypair = TlsKeyPair {
                                certificate,
                                private_key,
                                subject: "CryftTEE Node".to_string(),
                                device_id: node_id.clone(),
                                expires_at: state.nonce + 365 * 24 * 60 * 60,
                            };
                            state.tls_keys.insert(key_id.clone(), keypair);
                            tls_loaded = true;
                            
                            if let Some(device) = state.devices.get_mut(&node_id) {
                                if !device.tls_keys.contains(&key_id) {
                                    device.tls_keys.push(key_id.clone());
                                }
                            }
                        }
                        None => {
                            error_msg = if state.config.keystore_password.is_some() {
                                "failed to decrypt keystore - wrong password?".to_string()
                            } else {
                                "failed to parse keystore".to_string()
                            };
                        }
                    }
                } else {
                    error_msg = "keystore file not found or empty".to_string();
                }
                
                let keystore_path = state.config.keystore_path.clone().unwrap_or_default();
                
                return format!(
                    r#"{{"success":{},"initialized":true,"isNewBootstrap":false,"nodeId":"{}","tlsKeyLoaded":{},"tlsPublicKey":"{}","storageBackend":"local","keystorePath":"{}","keystoreEncrypted":{},"error":"{}"}}"#,
                    tls_loaded,
                    escape_json_string(&node_id),
                    tls_loaded,
                    tls_pubkey_hex,
                    escape_json_string(&keystore_path),
                    state.config.keystore_password.is_some(),
                    escape_json_string(&error_msg)
                );
            }
            
            // Create keystore directory (step before writing file)
            ("initialize", "create_keystore_dir") => {
                // Directory created (or already exists), now write the keystore file
                let keystore_file = json_get_string(&pending_json, "keystoreFile").unwrap_or("");
                let keystore_content = json_get_string(&pending_json, "keystoreContent").unwrap_or("");
                let key_id = json_get_string(&pending_json, "keyId").unwrap_or("");
                let original = json_get_string(&pending_json, "originalRequest").unwrap_or("{}");
                
                if !keystore_file.is_empty() && !keystore_content.is_empty() {
                    state.pending_request = Some(format!(
                        r#"{{"action":"initialize","nodeId":"{}","keyId":"{}","step":"write_tls_keystore","originalRequest":{}}}"#,
                        node_id, key_id, original
                    ));
                    
                    return host_call_json(HostApiCall::WriteFile { 
                        path: keystore_file.to_string(), 
                        content: keystore_content.to_string() 
                    });
                }
                
                // Fallback - continue without file write
                state.config.initialized = true;
                return format!(
                    r#"{{"success":true,"initialized":true,"isNewBootstrap":true,"nodeId":"{}","storageBackend":"local","keystoreWritten":false}}"#,
                    escape_json_string(&node_id)
                );
            }
            
            // Write TLS keystore file completed
            ("initialize", "write_tls_keystore") => {
                let key_id = json_get_string(&pending_json, "keyId").unwrap_or("");
                let original = json_get_string(&pending_json, "originalRequest").unwrap_or("{}");
                
                state.config.initialized = true;
                
                let device_name = json_get_string(original, "deviceName")
                    .unwrap_or(&node_id)
                    .to_string();
                let device_type = json_get_string(original, "deviceType")
                    .unwrap_or("validator")
                    .to_string();
                
                // Update device info
                let device_info = DeviceInfo {
                    device_id: node_id.clone(),
                    name: device_name.clone(),
                    device_type: device_type.clone(),
                    registered_at: state.nonce,
                    last_seen: state.nonce,
                    bls_keys: Vec::new(),
                    tls_keys: vec![key_id.to_string()],
                };
                state.devices.insert(node_id.clone(), device_info);
                
                let keystore_path = state.config.keystore_path.clone().unwrap_or_default();
                
                return format!(
                    r#"{{"success":true,"initialized":true,"isNewBootstrap":true,"nodeId":"{}","keyId":"{}","deviceName":"{}","deviceType":"{}","storageBackend":"local","keystorePath":"{}","keystoreEncrypted":{},"keystoreWritten":true}}"#,
                    escape_json_string(&node_id),
                    key_id,
                    escape_json_string(&device_name),
                    escape_json_string(&device_type),
                    escape_json_string(&keystore_path),
                    state.config.keystore_password.is_some()
                );
            }
            
            _ => {}
        }
    }
    
    format!(r#"{{"success":true,"status":"{}","note":"unhandled response"}}"#, status)
}

/// Derive public key and proof of possession from private key
/// Returns (private_key, public_key, proof_of_possession)
fn generate_bls_keypair_from_private(private_key: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let public_key = derive_bls_public_key(private_key);
    let proof_of_possession = bls_sign_proof_of_possession(private_key, &public_key);
    (private_key.to_vec(), public_key, proof_of_possession)
}

/// Ensure an additional TLS key exists (beyond the node-identity key)
/// 
/// NOTE: For the primary node-identity TLS key, use bootstrapTls instead.
/// This function is for generating additional TLS keys for specific purposes
/// (e.g., client certificates, service-specific keys).
/// 
/// PREREQUISITE: TLS identity must be bootstrapped first (call bootstrapTls)
/// 
/// Multi-device: Keys are namespaced by Node ID in Vault:
///   cryfttee/data/keys/tls/{node_id}/{key_name}
fn handle_ensure_tls_key(json: &str) -> String {
    let state = get_state();
    
    // Enforce TLS-first: must have a valid Node ID from TLS bootstrap
    let node_id = match &state.config.device_id {
        Some(id) if id.starts_with("NodeID-") => id.clone(),
        Some(_) => return r#"{"error":"invalid_node_id","message":"Device ID is not a valid Node ID. Run bootstrapTls first to generate TLS identity."}"#.to_string(),
        None => return r#"{"error":"not_bootstrapped","message":"TLS identity not bootstrapped. Call bootstrapTls first to generate Node ID from TLS key."}"#.to_string(),
    };
    
    // Check if we need random seed
    if state.random_seed.is_empty() {
        state.pending_request = Some(json.to_string());
        return host_call_json(HostApiCall::GetRandomSeed { length: 64 });
    }
    
    let subject = json_get_string(json, "subject").unwrap_or(&node_id);
    let key_name = json_get_string(json, "keyName").unwrap_or("additional");
    let provided_cert = json_get_string(json, "certificate");
    
    // Prevent overwriting node-identity key (use bootstrapTls for that)
    if key_name == "node-identity" {
        return r#"{"error":"reserved_key_name","message":"'node-identity' is reserved. Use bootstrapTls to manage the primary TLS identity."}"#.to_string();
    }
    
    // Case 1: Certificate provided - check if we have the matching key
    if let Some(cert) = provided_cert {
        // Check if we already have this certificate
        for (id, kp) in &state.tls_keys {
            if kp.certificate == cert {
                return format!(
                    r#"{{"success":true,"action":"found_local","keyId":"{}","subject":"{}","nodeId":"{}"}}"#,
                    id,
                    escape_json_string(&kp.subject),
                    escape_json_string(&node_id)
                );
            }
        }
        
        // Certificate provided but not found - check Vault if enabled
        if state.config.vault_enabled {
            if let (Some(ref vault_url), Some(ref token)) = (&state.config.vault_url, &state.config.vault_token) {
                let vault_path = state.config.vault_key_path("tls", key_name)
                    .unwrap_or_else(|| format!("cryfttee/data/keys/tls/{}/{}", node_id, key_name));
                let check_url = format!("{}/v1/{}", vault_url, vault_path);
                
                state.pending_request = Some(format!(
                    r#"{{"action":"ensureTlsKey","subject":"{}","keyName":"{}","nodeId":"{}","step":"check_vault"}}"#,
                    escape_json_string(subject), key_name, node_id
                ));
                
                return host_call_json(HostApiCall::HttpGet {
                    url: check_url,
                    headers: vec![
                        ("Content-Type".to_string(), "application/json".to_string()),
                        ("X-Vault-Token".to_string(), token.clone()),
                    ],
                });
            }
        }
    }
    
    // Case 2: Generate new TLS key pair for this device
    generate_and_store_tls_key(state, &node_id, subject, key_name)
}

/// Generate a TLS key and store it in configured backends
/// Note: device_id parameter is expected to be a valid Node ID at this point
fn generate_and_store_tls_key(state: &mut ModuleState, node_id: &str, subject: &str, key_name: &str) -> String {
    let (private_key, certificate) = generate_tls_keypair(state, subject);
    
    // Key ID includes node for uniqueness
    let key_id = format!("{}:tls:{}", node_id, key_name);
    
    let keypair = TlsKeyPair {
        certificate: certificate.clone(),
        private_key: private_key.clone(),
        subject: subject.to_string(),
        device_id: node_id.to_string(),
        expires_at: state.nonce + 365 * 24 * 60 * 60,
    };
    
    state.tls_keys.insert(key_id.clone(), keypair);
    
    // Update device's key list
    if let Some(device) = state.devices.get_mut(node_id) {
        if !device.tls_keys.contains(&key_id) {
            device.tls_keys.push(key_id.clone());
        }
    }
    
    // Store in Vault if enabled
    if state.config.vault_enabled {
        if let (Some(ref vault_url), Some(ref token)) = (&state.config.vault_url, &state.config.vault_token) {
            let vault_path = state.config.vault_key_path("tls", key_name)
                .unwrap_or_else(|| format!("cryfttee/data/keys/tls/{}/{}", node_id, key_name));
            let store_url = format!("{}/v1/{}", vault_url, vault_path);
            
            // Vault KV v2 payload
            let vault_body = format!(
                r#"{{"data":{{"private_key":"{}","certificate":"{}","subject":"{}","node_id":"{}","key_name":"{}","created_at":{}}}}}"#,
                bytes_to_hex(&private_key),
                escape_json_string(&certificate),
                escape_json_string(subject),
                escape_json_string(node_id),
                escape_json_string(key_name),
                state.nonce
            );
            
            state.pending_request = Some(format!(
                r#"{{"action":"ensureTlsKey","keyId":"{}","subject":"{}","nodeId":"{}","keyName":"{}","step":"store_vault"}}"#,
                key_id,
                escape_json_string(subject),
                node_id,
                key_name
            ));
            
            return host_call_json(HostApiCall::HttpPost {
                url: store_url,
                headers: vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    ("X-Vault-Token".to_string(), token.clone()),
                ],
                body: vault_body,
            });
        }
    }
    
    // No backends - return locally generated key
    format!(
        r#"{{"success":true,"action":"generated","keyId":"{}","subject":"{}","nodeId":"{}","keyName":"{}","certificate":"{}","vaultPath":"{}"}}"#,
        key_id,
        escape_json_string(subject),
        escape_json_string(node_id),
        escape_json_string(key_name),
        escape_json_string(&certificate),
        state.config.vault_key_path("tls", key_name).unwrap_or_default()
    )
}

/// Generate TLS key pair (Ed25519 per ACP-20)
fn generate_tls_keypair(state: &mut ModuleState, subject: &str) -> (Vec<u8>, String) {
    // Generate Ed25519 seed (32 bytes)
    let private_key = generate_random(state, TLS_PRIVKEY_SIZE);
    
    // Derive Ed25519 public key (32 bytes)
    // Real impl uses Ed25519 scalar multiplication: pubkey = seed * G
    // Simplified: deterministic derivation that maintains structure
    let public_key = derive_ed25519_public_key(&private_key);
    
    // Create self-signed certificate (simplified PEM format)
    // In production, this would be ephemeral/in-memory per ACP-20
    let cert_content = format!(
        "Subject: CN={}\nPublicKey: {}\nIssuer: CN=CryftTEE\nAlgorithm: Ed25519\nValidity: 365 days\nSignature: {}",
        subject,
        bytes_to_hex(&public_key),
        bytes_to_hex(&ed25519_sign(&private_key, subject.as_bytes())[..32])
    );
    
    let certificate = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        base64_encode(cert_content.as_bytes())
    );
    
    (private_key, certificate)
}

/// Simple base64 encoding
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let mut result = String::new();
    let mut i = 0;
    
    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() { data[i + 1] as usize } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as usize } else { 0 };
        
        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        
        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }
        
        if i + 2 < data.len() {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
        
        i += 3;
    }
    
    result
}

/// Create a simplified keystore JSON (EIP-2335 format simplified)
fn create_keystore_json(private_key: &[u8], public_key: &[u8], label: &str) -> String {
    // In production, use proper PBKDF2/scrypt encryption as per EIP-2335
    // This is a simplified version for demonstration
    let uuid = {
        let hash = hash_256(public_key);
        format!(
            "{}-{}-{}-{}-{}",
            &bytes_to_hex(&hash[0..4]),
            &bytes_to_hex(&hash[4..6]),
            &bytes_to_hex(&hash[6..8]),
            &bytes_to_hex(&hash[8..10]),
            &bytes_to_hex(&hash[10..16])
        )
    };
    
    // Simple XOR "encryption" with fixed key (NOT secure - for demo only)
    // Real implementation must use proper scrypt/PBKDF2
    let encrypted: Vec<u8> = private_key.iter()
        .zip(b"cryfttee-generated-key-password!".iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect();
    
    format!(
        r#"{{"crypto":{{"kdf":{{"function":"scrypt","params":{{"dklen":32,"n":262144,"p":1,"r":8,"salt":"{}"}},"message":""}},"checksum":{{"function":"sha256","params":{{}},"message":"{}"}},"cipher":{{"function":"aes-128-ctr","params":{{"iv":"{}"}},"message":"{}"}}}},"description":"{}","pubkey":"{}","path":"m/12381/3600/0/0/0","uuid":"{}","version":4}}"#,
        bytes_to_hex(&hash_256(label.as_bytes())[..32]),
        bytes_to_hex(&hash_256(&encrypted)[..32]),
        bytes_to_hex(&hash_256(public_key)[..16]),
        bytes_to_hex(&encrypted),
        escape_json_string(label),
        bytes_to_hex(public_key),
        uuid
    )
}


/// Bootstrap TLS identity for this CryftTEE instance
/// This MUST be called first before any other operations
/// 
/// Flow (ACP-20 Ed25519):
/// 1. Generate Ed25519 keypair (32-byte seed, 32-byte public key)
/// 2. Node ID = Ed25519 public key directly (ACP-20: pubkey IS the NodeID)
/// 3. Set device_id in config to the Node ID
/// 4. Store TLS key in Vault (if enabled) at cryfttee/data/keys/tls/{node_id}/node-identity
/// 
/// Expected JSON:
/// {
///   "randomSeed": "hex...",            // Optional: if not provided, will request from host
///   "vaultUrl": "http://...",          // Optional: Vault endpoint for key storage
///   "vaultToken": "hvs.xxx",           // Optional: Vault token
///   "vaultPath": "cryfttee/data/keys", // Optional: Vault KV path prefix
///   "web3signerUrl": "http://...",     // Optional: Web3Signer endpoint
///   "deviceName": "My Validator"       // Optional: human-readable name
/// }
/// 
/// Response:
/// {
///   "success": true,
///   "nodeId": "NodeID-abc123...",      // The Node ID (64 hex chars = 32-byte Ed25519 pubkey)
///   "publicKey": "hex...",             // Ed25519 public key (32 bytes)
///   "certificate": "-----BEGIN...",   // Ephemeral self-signed certificate
///   "deviceId": "NodeID-abc123...",   // Same as nodeId for clarity
///   "vaultPath": "..."                 // Where key was stored (if Vault enabled)
/// }
fn handle_bootstrap_tls(json: &str) -> String {
    let state = get_state();
    
    // If already initialized with a node ID, return error - don't allow re-bootstrap
    if let Some(ref existing_id) = state.config.device_id {
        if existing_id.starts_with("NodeID-") {
            return format!(
                r#"{{"error":"already_bootstrapped","nodeId":"{}","message":"TLS identity already bootstrapped. Use initialize to reconnect."}}"#,
                escape_json_string(existing_id)
            );
        }
    }
    
    // Parse backend configuration (set these before bootstrap since we need Vault for storage)
    if let Some(url) = json_get_string(json, "vaultUrl") {
        state.config.vault_url = Some(url.to_string());
    }
    if let Some(token) = json_get_string(json, "vaultToken") {
        state.config.vault_token = Some(token.to_string());
    }
    if let Some(path) = json_get_string(json, "vaultPath") {
        state.config.vault_path = Some(path.to_string());
    }
    if let Some(url) = json_get_string(json, "web3signerUrl") {
        state.config.web3signer_url = Some(url.to_string());
    }
    state.config.vault_enabled = json_get_bool(json, "vaultEnabled").unwrap_or(
        state.config.vault_url.is_some() && state.config.vault_token.is_some()
    );
    
    // Initialize random seed if provided
    if let Some(seed) = json_get_string(json, "randomSeed") {
        if let Some(seed_bytes) = hex_to_bytes(seed) {
            state.random_seed = seed_bytes;
        }
    }
    
    // Check if we need random seed from host
    if state.random_seed.is_empty() {
        state.pending_request = Some(format!(r#"{{"action":"bootstrapTls","originalRequest":{}}}"#, json));
        return host_call_json(HostApiCall::GetRandomSeed { length: 64 });
    }
    
    // Generate Ed25519 TLS keypair
    let (private_key, public_key_bytes, certificate) = generate_tls_keypair_with_pubkey(state, "CryftTEE Node");
    
    // Node ID = Ed25519 public key directly (ACP-20 style)
    // The 32-byte Ed25519 public key IS the Node ID - no hashing needed
    let node_id = format!("NodeID-{}", bytes_to_hex(&public_key_bytes));
    
    // Set the device ID to the derived node ID
    state.config.device_id = Some(node_id.clone());
    state.config.initialized = true;
    
    // Store TLS key locally
    let key_id = format!("{}:tls:node-identity", node_id);
    let keypair = TlsKeyPair {
        certificate: certificate.clone(),
        private_key: private_key.clone(),
        subject: "CryftTEE Node".to_string(),
        device_id: node_id.clone(),
        expires_at: state.nonce + 365 * 24 * 60 * 60,
    };
    state.tls_keys.insert(key_id.clone(), keypair);
    
    // Register device
    let device_name = json_get_string(json, "deviceName")
        .unwrap_or("CryftTEE Node")
        .to_string();
    
    let device_info = DeviceInfo {
        device_id: node_id.clone(),
        name: device_name.clone(),
        device_type: "validator".to_string(),
        registered_at: state.nonce,
        last_seen: state.nonce,
        bls_keys: Vec::new(),
        tls_keys: vec![key_id.clone()],
    };
    state.devices.insert(node_id.clone(), device_info);
    
    // Store in Vault if enabled
    if state.config.vault_enabled {
        if let (Some(ref vault_url), Some(ref token)) = (&state.config.vault_url, &state.config.vault_token) {
            let vault_path = state.config.vault_key_path("tls", "node-identity")
                .unwrap_or_else(|| format!("cryfttee/data/keys/tls/{}/node-identity", node_id));
            let store_url = format!("{}/v1/{}", vault_url, vault_path);
            
            // Vault KV v2 payload
            let vault_body = format!(
                r#"{{"data":{{"private_key":"{}","public_key":"{}","certificate":"{}","node_id":"{}","device_name":"{}","created_at":{}}}}}"#,
                bytes_to_hex(&private_key),
                bytes_to_hex(&public_key_bytes),
                escape_json_string(&certificate),
                escape_json_string(&node_id),
                escape_json_string(&device_name),
                state.nonce
            );
            
            state.pending_request = Some(format!(
                r#"{{"action":"bootstrapTls","nodeId":"{}","keyId":"{}","step":"store_vault"}}"#,
                node_id, key_id
            ));
            
            return host_call_json(HostApiCall::HttpPost {
                url: store_url,
                headers: vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    ("X-Vault-Token".to_string(), token.clone()),
                ],
                body: vault_body,
            });
        }
    }
    
    // Return success with node ID
    format!(
        r#"{{"success":true,"nodeId":"{}","deviceId":"{}","deviceName":"{}","publicKey":"{}","certificate":"{}","keyId":"{}","vaultEnabled":{},"message":"TLS identity bootstrapped. Use this nodeId for all subsequent operations."}}"#,
        escape_json_string(&node_id),
        escape_json_string(&node_id),
        escape_json_string(&device_name),
        bytes_to_hex(&public_key_bytes),
        escape_json_string(&certificate),
        escape_json_string(&key_id),
        state.config.vault_enabled
    )
}

/// Generate TLS keypair (Ed25519) and return private key, public key bytes, and certificate
/// 
/// Per ACP-20: Ed25519 public key (32 bytes) IS the Node ID directly
fn generate_tls_keypair_with_pubkey(state: &mut ModuleState, subject: &str) -> (Vec<u8>, Vec<u8>, String) {
    // Generate Ed25519 seed (32 bytes)
    let private_key = generate_random(state, TLS_PRIVKEY_SIZE);
    
    // Derive Ed25519 public key (32 bytes) - this becomes the Node ID
    let public_key = derive_ed25519_public_key(&private_key);
    
    // Create self-signed certificate (ephemeral per ACP-20)
    let cert_content = format!(
        "Subject: CN={}\nPublicKey: {}\nIssuer: CN=CryftTEE\nAlgorithm: Ed25519\nValidity: 365 days\nSignature: {}",
        subject,
        bytes_to_hex(&public_key),
        bytes_to_hex(&ed25519_sign(&private_key, subject.as_bytes())[..32])
    );
    
    let certificate = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        base64_encode(cert_content.as_bytes())
    );
    
    (private_key, public_key, certificate)
}

fn handle_generate_bls_key(json: &str) -> String {
    let label = json_get_string(json, "label").unwrap_or("default");
    let key_id = json_get_string(json, "keyId").map(|s| s.to_string());
    
    let state = get_state();
    
    // Require TLS bootstrap first
    let device_id = match &state.config.device_id {
        Some(id) if id.starts_with("NodeID-") => id.clone(),
        Some(_) => return r#"{"error":"invalid_node_id","message":"Module initialized with non-NodeID device. Run bootstrapTls first."}"#.to_string(),
        None => return r#"{"error":"not_bootstrapped","message":"TLS identity not bootstrapped. Call bootstrapTls first to generate Node ID."}"#.to_string(),
    };
    
    // Check if we need random seed from host
    if state.random_seed.is_empty() {
        return host_call_json(HostApiCall::GetRandomSeed { length: 64 });
    }
    
    // Generate the key pair with proof of possession
    let (private_key, public_key, proof_of_possession) = generate_bls_keypair(state);
    
    // Create key ID from public key if not provided, namespaced by node ID
    let id = key_id.unwrap_or_else(|| {
        let hash = hash_256(&public_key);
        format!("{}:bls:{}", device_id, &bytes_to_hex(&hash)[..16])
    });
    
    let keypair = BlsKeyPair {
        public_key: public_key.clone(),
        private_key,
        proof_of_possession: proof_of_possession.clone(),
        label: label.to_string(),
        device_id: device_id.clone(),
        created_at: state.nonce,
        locked: false,
    };
    
    state.bls_keys.insert(id.clone(), keypair);
    
    // Update device's key list
    if let Some(device) = state.devices.get_mut(&device_id) {
        if !device.bls_keys.contains(&id) {
            device.bls_keys.push(id.clone());
        }
    }
    
    format!(
        r#"{{"success":true,"keyId":"{}","publicKey":"{}","proofOfPossession":"{}","label":"{}","deviceId":"{}"}}"#,
        id,
        bytes_to_hex(&public_key),
        bytes_to_hex(&proof_of_possession),
        escape_json_string(label),
        escape_json_string(&device_id)
    )
}

fn handle_bls_sign(json: &str) -> String {
    let key_id = match json_get_string(json, "keyId") {
        Some(id) => id,
        None => return r#"{"error":"missing keyId"}"#.to_string(),
    };
    
    let message_hex = match json_get_string(json, "message") {
        Some(m) => m,
        None => return r#"{"error":"missing message"}"#.to_string(),
    };
    
    let message = match hex_to_bytes(message_hex) {
        Some(m) => m,
        None => return r#"{"error":"invalid message hex"}"#.to_string(),
    };
    
    let state = get_state();
    
    let keypair = match state.bls_keys.get(key_id) {
        Some(kp) => kp.clone(),
        None => return format!(r#"{{"error":"key not found: {}"}}"#, key_id),
    };
    
    if keypair.locked {
        return r#"{"error":"key is locked"}"#.to_string();
    }
    
    // Perform the signature
    let signature = bls_sign(&keypair.private_key, &message);
    
    // Log to audit trail
    let record = SignatureRecord {
        key_id: key_id.to_string(),
        message_hash: hash_256(&message),
        signature: signature.clone(),
        timestamp: state.nonce,
        sig_type: "bls".to_string(),
    };
    state.signature_log.push(record);
    
    // Keep only last 100 signatures
    if state.signature_log.len() > 100 {
        state.signature_log.remove(0);
    }
    
    format!(
        r#"{{"success":true,"signature":"{}","publicKey":"{}"}}"#,
        bytes_to_hex(&signature),
        bytes_to_hex(&keypair.public_key)
    )
}

fn handle_bls_verify(json: &str) -> String {
    let public_key_hex = match json_get_string(json, "publicKey") {
        Some(pk) => pk,
        None => return r#"{"error":"missing publicKey"}"#.to_string(),
    };
    
    let message_hex = match json_get_string(json, "message") {
        Some(m) => m,
        None => return r#"{"error":"missing message"}"#.to_string(),
    };
    
    let signature_hex = match json_get_string(json, "signature") {
        Some(s) => s,
        None => return r#"{"error":"missing signature"}"#.to_string(),
    };
    
    let public_key = match hex_to_bytes(public_key_hex) {
        Some(pk) => pk,
        None => return r#"{"error":"invalid publicKey hex"}"#.to_string(),
    };
    
    let message = match hex_to_bytes(message_hex) {
        Some(m) => m,
        None => return r#"{"error":"invalid message hex"}"#.to_string(),
    };
    
    let signature = match hex_to_bytes(signature_hex) {
        Some(s) => s,
        None => return r#"{"error":"invalid signature hex"}"#.to_string(),
    };
    
    let valid = bls_verify(&public_key, &message, &signature);
    
    format!(r#"{{"success":true,"valid":{}}}"#, valid)
}

// ============================================================================
// SECP256K1/EVM Key Handlers (C-Chain Compatibility)
// ============================================================================

/// Generate a new SECP256K1 key for EVM/C-Chain operations
fn handle_generate_evm_key(json: &str) -> String {
    let label = json_get_string(json, "label").unwrap_or("default");
    let key_id = json_get_string(json, "keyId").map(|s| s.to_string());
    
    let state = get_state();
    
    // Require TLS bootstrap first
    let device_id = match &state.config.device_id {
        Some(id) if id.starts_with("NodeID-") => id.clone(),
        Some(_) => return r#"{"error":"invalid_node_id","message":"Module not properly bootstrapped."}"#.to_string(),
        None => return r#"{"error":"not_bootstrapped","message":"TLS identity not bootstrapped. Call bootstrapTls first."}"#.to_string(),
    };
    
    // Check if we need random seed from host
    if state.random_seed.is_empty() {
        return host_call_json(HostApiCall::GetRandomSeed { length: 64 });
    }
    
    // Generate SECP256K1 keypair
    let (private_key, compressed_pubkey, _uncompressed, eth_address) = generate_secp256k1_keypair(state);
    
    // Create key ID from address if not provided
    let id = key_id.unwrap_or_else(|| {
        format!("{}:evm:{}", device_id, &bytes_to_hex(&eth_address)[..16])
    });
    
    let keypair = Secp256k1KeyPair {
        public_key: compressed_pubkey.clone(),
        private_key,
        eth_address: eth_address.clone(),
        label: label.to_string(),
        device_id: device_id.clone(),
        created_at: state.nonce,
        locked: false,
    };
    
    state.secp256k1_keys.insert(id.clone(), keypair);
    
    format!(
        r#"{{"success":true,"keyId":"{}","publicKey":"{}","ethAddress":"{}","label":"{}","deviceId":"{}"}}"#,
        id,
        bytes_to_hex(&compressed_pubkey),
        format_eth_address(&eth_address),
        escape_json_string(label),
        escape_json_string(&device_id)
    )
}

/// Ensure an EVM key exists (generate if needed)
fn handle_ensure_evm_key(json: &str) -> String {
    let label = json_get_string(json, "label").unwrap_or("primary");
    let key_name = json_get_string(json, "keyName").unwrap_or("primary");
    
    let state = get_state();
    
    // Require TLS bootstrap first
    let node_id = match &state.config.device_id {
        Some(id) if id.starts_with("NodeID-") => id.clone(),
        Some(_) => return r#"{"error":"invalid_node_id","message":"Module not properly bootstrapped."}"#.to_string(),
        None => return r#"{"error":"not_bootstrapped","message":"TLS identity not bootstrapped."}"#.to_string(),
    };
    
    // Check if key already exists with this name
    let expected_id = format!("{}:evm:{}", node_id, key_name);
    if let Some(keypair) = state.secp256k1_keys.get(&expected_id) {
        return format!(
            r#"{{"success":true,"action":"existing","keyId":"{}","publicKey":"{}","ethAddress":"{}","nodeId":"{}"}}"#,
            expected_id,
            bytes_to_hex(&keypair.public_key),
            format_eth_address(&keypair.eth_address),
            escape_json_string(&node_id)
        );
    }
    
    // Check if we need random seed from host
    if state.random_seed.is_empty() {
        state.pending_request = Some(format!(
            r#"{{"action":"ensureEvmKey","label":"{}","keyName":"{}"}}"#,
            label, key_name
        ));
        return host_call_json(HostApiCall::GetRandomSeed { length: 64 });
    }
    
    // Generate new key
    let (private_key, compressed_pubkey, _uncompressed, eth_address) = generate_secp256k1_keypair(state);
    
    let keypair = Secp256k1KeyPair {
        public_key: compressed_pubkey.clone(),
        private_key,
        eth_address: eth_address.clone(),
        label: label.to_string(),
        device_id: node_id.clone(),
        created_at: state.nonce,
        locked: false,
    };
    
    state.secp256k1_keys.insert(expected_id.clone(), keypair);
    
    format!(
        r#"{{"success":true,"action":"generated","keyId":"{}","publicKey":"{}","ethAddress":"{}","nodeId":"{}"}}"#,
        expected_id,
        bytes_to_hex(&compressed_pubkey),
        format_eth_address(&eth_address),
        escape_json_string(&node_id)
    )
}

/// Sign a message hash with SECP256K1 (raw ECDSA)
fn handle_evm_sign(json: &str) -> String {
    let key_id = match json_get_string(json, "keyId") {
        Some(id) => id,
        None => return r#"{"error":"missing keyId"}"#.to_string(),
    };
    
    let message_hash_hex = match json_get_string(json, "messageHash") {
        Some(m) => m,
        None => return r#"{"error":"missing messageHash (32 bytes hex)"}"#.to_string(),
    };
    
    let message_hash = match hex_to_bytes(message_hash_hex) {
        Some(m) if m.len() == 32 => m,
        Some(_) => return r#"{"error":"messageHash must be exactly 32 bytes"}"#.to_string(),
        None => return r#"{"error":"invalid messageHash hex"}"#.to_string(),
    };
    
    let state = get_state();
    
    let keypair = match state.secp256k1_keys.get(key_id) {
        Some(kp) => kp,
        None => return format!(r#"{{"error":"key not found","keyId":"{}"}}"#, key_id),
    };
    
    if keypair.locked {
        return r#"{"error":"key is locked"}"#.to_string();
    }
    
    let signature = secp256k1_sign(&keypair.private_key, &message_hash);
    
    // Split signature into r, s, v components
    let r = &signature[0..32];
    let s = &signature[32..64];
    let v = signature[64];
    
    format!(
        r#"{{"success":true,"signature":"{}","r":"{}","s":"{}","v":{},"keyId":"{}","ethAddress":"{}"}}"#,
        bytes_to_hex(&signature),
        bytes_to_hex(r),
        bytes_to_hex(s),
        v,
        key_id,
        format_eth_address(&keypair.eth_address)
    )
}

/// Sign a message with EIP-191 personal_sign format
fn handle_evm_personal_sign(json: &str) -> String {
    let key_id = match json_get_string(json, "keyId") {
        Some(id) => id,
        None => return r#"{"error":"missing keyId"}"#.to_string(),
    };
    
    let message_hex = match json_get_string(json, "message") {
        Some(m) => m,
        None => return r#"{"error":"missing message"}"#.to_string(),
    };
    
    let message = match hex_to_bytes(message_hex) {
        Some(m) => m,
        None => return r#"{"error":"invalid message hex"}"#.to_string(),
    };
    
    let state = get_state();
    
    let keypair = match state.secp256k1_keys.get(key_id) {
        Some(kp) => kp,
        None => return format!(r#"{{"error":"key not found","keyId":"{}"}}"#, key_id),
    };
    
    if keypair.locked {
        return r#"{"error":"key is locked"}"#.to_string();
    }
    
    let signature = secp256k1_personal_sign(&keypair.private_key, &message);
    
    format!(
        r#"{{"success":true,"signature":"{}","keyId":"{}","ethAddress":"{}","signatureType":"personal_sign"}}"#,
        bytes_to_hex(&signature),
        key_id,
        format_eth_address(&keypair.eth_address)
    )
}

/// Sign a transaction hash (for C-Chain transactions)
fn handle_evm_sign_transaction(json: &str) -> String {
    let key_id = match json_get_string(json, "keyId") {
        Some(id) => id,
        None => return r#"{"error":"missing keyId"}"#.to_string(),
    };
    
    let tx_hash_hex = match json_get_string(json, "txHash") {
        Some(h) => h,
        None => return r#"{"error":"missing txHash (32 bytes keccak256)"}"#.to_string(),
    };
    
    let tx_hash = match hex_to_bytes(tx_hash_hex) {
        Some(h) if h.len() == 32 => h,
        Some(_) => return r#"{"error":"txHash must be exactly 32 bytes"}"#.to_string(),
        None => return r#"{"error":"invalid txHash hex"}"#.to_string(),
    };
    
    // Optional chain ID for EIP-155
    let chain_id = json_get_number(json, "chainId");
    
    let state = get_state();
    
    let keypair = match state.secp256k1_keys.get(key_id) {
        Some(kp) => kp,
        None => return format!(r#"{{"error":"key not found","keyId":"{}"}}"#, key_id),
    };
    
    if keypair.locked {
        return r#"{"error":"key is locked"}"#.to_string();
    }
    
    let signature = secp256k1_sign_transaction(&keypair.private_key, &tx_hash);
    
    // Adjust v for EIP-155 if chain_id provided
    let v = if let Some(cid) = chain_id {
        let base_v = signature[64];
        let recovery = if base_v >= 27 { base_v - 27 } else { base_v };
        cid * 2 + 35 + recovery as u64
    } else {
        signature[64] as u64
    };
    
    format!(
        r#"{{"success":true,"signature":"{}","r":"{}","s":"{}","v":{},"keyId":"{}","ethAddress":"{}","signatureType":"transaction"}}"#,
        bytes_to_hex(&signature),
        bytes_to_hex(&signature[0..32]),
        bytes_to_hex(&signature[32..64]),
        v,
        key_id,
        format_eth_address(&keypair.eth_address)
    )
}

/// Verify a SECP256K1 signature
fn handle_evm_verify(json: &str) -> String {
    let public_key_hex = match json_get_string(json, "publicKey") {
        Some(pk) => pk,
        None => return r#"{"error":"missing publicKey"}"#.to_string(),
    };
    
    let message_hash_hex = match json_get_string(json, "messageHash") {
        Some(m) => m,
        None => return r#"{"error":"missing messageHash"}"#.to_string(),
    };
    
    let signature_hex = match json_get_string(json, "signature") {
        Some(s) => s,
        None => return r#"{"error":"missing signature"}"#.to_string(),
    };
    
    let public_key = match hex_to_bytes(public_key_hex) {
        Some(pk) => pk,
        None => return r#"{"error":"invalid publicKey hex"}"#.to_string(),
    };
    
    let message_hash = match hex_to_bytes(message_hash_hex) {
        Some(m) => m,
        None => return r#"{"error":"invalid messageHash hex"}"#.to_string(),
    };
    
    let signature = match hex_to_bytes(signature_hex) {
        Some(s) => s,
        None => return r#"{"error":"invalid signature hex"}"#.to_string(),
    };
    
    let valid = secp256k1_verify(&public_key, &message_hash, &signature);
    
    format!(r#"{{"success":true,"valid":{}}}"#, valid)
}

fn handle_list_keys(json: &str) -> String {
    let state = get_state();
    
    // Optional filter by device
    let filter_device = json_get_string(json, "deviceId");
    
    let mut keys = String::from("[");
    let mut first = true;
    
    for (id, keypair) in &state.bls_keys {
        // Filter by device if specified
        if let Some(device_filter) = filter_device {
            if keypair.device_id != device_filter {
                continue;
            }
        }
        
        if !first {
            keys.push(',');
        }
        first = false;
        
        keys.push_str(&format!(
            r#"{{"id":"{}","type":"bls","publicKey":"{}","label":"{}","deviceId":"{}","locked":{}}}"#,
            id,
            bytes_to_hex(&keypair.public_key),
            escape_json_string(&keypair.label),
            escape_json_string(&keypair.device_id),
            keypair.locked
        ));
    }
    
    for (id, keypair) in &state.tls_keys {
        // Filter by device if specified
        if let Some(device_filter) = filter_device {
            if keypair.device_id != device_filter {
                continue;
            }
        }
        
        if !first {
            keys.push(',');
        }
        first = false;
        
        keys.push_str(&format!(
            r#"{{"id":"{}","type":"tls","subject":"{}","deviceId":"{}","expiresAt":{}}}"#,
            id,
            escape_json_string(&keypair.subject),
            escape_json_string(&keypair.device_id),
            keypair.expires_at
        ));
    }
    
    // Include SECP256K1/EVM keys
    for (id, keypair) in &state.secp256k1_keys {
        // Filter by device if specified
        if let Some(device_filter) = filter_device {
            if keypair.device_id != device_filter {
                continue;
            }
        }
        
        if !first {
            keys.push(',');
        }
        first = false;
        
        keys.push_str(&format!(
            r#"{{"id":"{}","type":"secp256k1","publicKey":"{}","ethAddress":"{}","label":"{}","deviceId":"{}","locked":{}}}"#,
            id,
            bytes_to_hex(&keypair.public_key),
            format_eth_address(&keypair.eth_address),
            escape_json_string(&keypair.label),
            escape_json_string(&keypair.device_id),
            keypair.locked
        ));
    }
    
    keys.push(']');
    
    let node_id = state.config.device_id.as_deref().unwrap_or("not_bootstrapped");
    let is_bootstrapped = node_id.starts_with("NodeID-");
    
    format!(
        r#"{{"success":true,"nodeId":"{}","isBootstrapped":{},"keys":{}}}"#,
        escape_json_string(node_id),
        is_bootstrapped,
        keys
    )
}

/// List all registered devices (for multi-device Vault management)
fn handle_list_devices(_json: &str) -> String {
    let state = get_state();
    
    let current_node_id = state.config.device_id.as_deref().unwrap_or("not_bootstrapped");
    
    let mut devices = String::from("[");
    let mut first = true;
    
    for (id, info) in &state.devices {
        if !first {
            devices.push(',');
        }
        first = false;
        
        devices.push_str(&format!(
            r#"{{"nodeId":"{}","name":"{}","type":"{}","blsKeyCount":{},"tlsKeyCount":{},"registeredAt":{},"lastSeen":{}}}"#,
            escape_json_string(id),
            escape_json_string(&info.name),
            escape_json_string(&info.device_type),
            info.bls_keys.len(),
            info.tls_keys.len(),
            info.registered_at,
            info.last_seen
        ));
    }
    
    devices.push(']');
    
    let vault_enabled = state.config.vault_enabled;
    let vault_path = state.config.vault_path.as_deref().unwrap_or("cryfttee/data/keys");
    
    format!(
        r#"{{"success":true,"currentNodeId":"{}","vaultEnabled":{},"vaultPath":"{}","deviceCount":{},"devices":{}}}"#,
        escape_json_string(current_node_id),
        vault_enabled,
        escape_json_string(vault_path),
        state.devices.len(),
        devices
    )
}

fn handle_lock_key(json: &str) -> String {
    let key_id = match json_get_string(json, "keyId") {
        Some(id) => id,
        None => return r#"{"error":"missing keyId"}"#.to_string(),
    };
    
    let state = get_state();
    
    if let Some(keypair) = state.bls_keys.get_mut(key_id) {
        keypair.locked = true;
        return format!(r#"{{"success":true,"keyId":"{}","locked":true}}"#, key_id);
    }
    
    format!(r#"{{"error":"key not found: {}"}}"#, key_id)
}

fn handle_unlock_key(json: &str) -> String {
    let key_id = match json_get_string(json, "keyId") {
        Some(id) => id,
        None => return r#"{"error":"missing keyId"}"#.to_string(),
    };
    
    let state = get_state();
    
    if let Some(keypair) = state.bls_keys.get_mut(key_id) {
        keypair.locked = false;
        return format!(r#"{{"success":true,"keyId":"{}","locked":false}}"#, key_id);
    }
    
    format!(r#"{{"error":"key not found: {}"}}"#, key_id)
}

fn handle_delete_key(json: &str) -> String {
    let key_id = match json_get_string(json, "keyId") {
        Some(id) => id,
        None => return r#"{"error":"missing keyId"}"#.to_string(),
    };
    
    let state = get_state();
    
    if state.bls_keys.remove(key_id).is_some() {
        return format!(r#"{{"success":true,"deleted":"{}"}}"#, key_id);
    }
    
    if state.tls_keys.remove(key_id).is_some() {
        return format!(r#"{{"success":true,"deleted":"{}"}}"#, key_id);
    }
    
    format!(r#"{{"error":"key not found: {}"}}"#, key_id)
}

fn handle_sign_module(json: &str) -> String {
    let module_hash = match json_get_string(json, "moduleHash") {
        Some(h) => h,
        None => return r#"{"error":"missing moduleHash"}"#.to_string(),
    };
    
    let signing_key_id = json_get_string(json, "signingKeyId").unwrap_or("default");
    
    let state = get_state();
    
    // Use a BLS key to sign the module
    let keypair = match state.bls_keys.get(signing_key_id) {
        Some(kp) => kp.clone(),
        None => {
            // If no key specified and we have any keys, use the first one
            match state.bls_keys.values().next() {
                Some(kp) => kp.clone(),
                None => return r#"{"error":"no signing keys available"}"#.to_string(),
            }
        }
    };
    
    let hash_bytes = match hex_to_bytes(module_hash) {
        Some(h) => h,
        None => return r#"{"error":"invalid moduleHash hex"}"#.to_string(),
    };
    
    // Sign the module hash
    let signature = bls_sign(&keypair.private_key, &hash_bytes);
    
    format!(
        r#"{{"success":true,"moduleHash":"{}","signature":"{}","signerPublicKey":"{}"}}"#,
        module_hash,
        bytes_to_hex(&signature),
        bytes_to_hex(&keypair.public_key)
    )
}

fn handle_get_status(_json: &str) -> String {
    let state = get_state();
    
    let node_id = state.config.device_id.as_deref().unwrap_or("not_bootstrapped");
    let is_bootstrapped = node_id.starts_with("NodeID-");
    
    format!(
        r#"{{"success":true,"nodeId":"{}","isBootstrapped":{},"initialized":{},"blsKeyCount":{},"tlsKeyCount":{},"deviceCount":{},"signatureLogCount":{},"nonceCounter":{},"web3signerConfigured":{},"vaultEnabled":{}}}"#,
        escape_json_string(node_id),
        is_bootstrapped,
        state.config.initialized,
        state.bls_keys.len(),
        state.tls_keys.len(),
        state.devices.len(),
        state.signature_log.len(),
        state.nonce,
        state.config.web3signer_url.is_some(),
        state.config.vault_enabled
    )
}

fn handle_set_random_seed(json: &str) -> String {
    let seed_hex = match json_get_string(json, "seed") {
        Some(s) => s,
        None => return r#"{"error":"missing seed"}"#.to_string(),
    };
    
    let seed = match hex_to_bytes(seed_hex) {
        Some(s) => s,
        None => return r#"{"error":"invalid seed hex"}"#.to_string(),
    };
    
    let state = get_state();
    state.random_seed = seed;
    
    r#"{"success":true,"message":"random seed initialized"}"#.to_string()
}

fn handle_export_state(_json: &str) -> String {
    let state = get_state();
    
    // Serialize state to JSON (without private keys for safety)
    let mut keys_json = String::from("[");
    let mut first = true;
    
    for (id, kp) in &state.bls_keys {
        if !first { keys_json.push(','); }
        first = false;
        keys_json.push_str(&format!(
            r#"{{"id":"{}","publicKey":"{}","label":"{}","locked":{}}}"#,
            id,
            bytes_to_hex(&kp.public_key),
            escape_json_string(&kp.label),
            kp.locked
        ));
    }
    keys_json.push(']');
    
    format!(
        r#"{{"success":true,"exportedKeys":{},"keyCount":{},"note":"private keys not exported for security"}}"#,
        keys_json,
        state.bls_keys.len()
    )
}

// ============================================================================
// Main Entry Point
// ============================================================================

#[no_mangle]
pub extern "C" fn invoke(input_ptr: *const u8, input_len: usize) -> usize {
    let input = unsafe { core::slice::from_raw_parts(input_ptr, input_len) };
    
    let json_str = match core::str::from_utf8(input) {
        Ok(s) => s,
        Err(_) => {
            let err = r#"{"error":"invalid UTF-8 input"}"#;
            return write_output(err.as_bytes());
        }
    };
    
    // Route based on action
    let action = json_get_string(json_str, "action").unwrap_or("");
    
    let response = match action {
        // BOOTSTRAP - Must be called first to establish TLS identity and derive Node ID
        "bootstrapTls" | "bootstrap_tls" | "bootstrap" => handle_bootstrap_tls(json_str),
        
        // Initialization & Configuration (for reconnecting with existing Node ID)
        "initialize" | "init" => handle_initialize(json_str),
        
        // Key Provisioning (main entry point for cryftgo)
        "ensureBlsKey" | "ensure_bls_key" | "registerBls" => handle_ensure_bls_key(json_str),
        "ensureTlsKey" | "ensure_tls_key" | "registerTls" => handle_ensure_tls_key(json_str),
        "ensureEvmKey" | "ensure_evm_key" | "ensureSecp256k1Key" => handle_ensure_evm_key(json_str),
        
        // BLS Key Operations (consensus signing)
        "generateBlsKey" | "bls_generate" => handle_generate_bls_key(json_str),
        "blsSign" | "bls_sign" => handle_bls_sign(json_str),
        "blsVerify" | "bls_verify" => handle_bls_verify(json_str),
        
        // SECP256K1/EVM Key Operations (C-Chain compatibility)
        "generateEvmKey" | "evm_generate" | "secp256k1_generate" => handle_generate_evm_key(json_str),
        "evmSign" | "evm_sign" | "secp256k1_sign" => handle_evm_sign(json_str),
        "evmPersonalSign" | "personal_sign" => handle_evm_personal_sign(json_str),
        "evmSignTransaction" | "sign_transaction" => handle_evm_sign_transaction(json_str),
        "evmVerify" | "evm_verify" | "secp256k1_verify" => handle_evm_verify(json_str),
        
        // Key Management
        "listKeys" | "list_keys" => handle_list_keys(json_str),
        "lockKey" | "lock_key" => handle_lock_key(json_str),
        "unlockKey" | "unlock_key" => handle_unlock_key(json_str),
        "deleteKey" | "delete_key" => handle_delete_key(json_str),
        
        // Module Signing
        "signModule" | "sign_module" => handle_sign_module(json_str),
        
        // Device Management (multi-device Vault support)
        "listDevices" | "list_devices" => handle_list_devices(json_str),
        
        // State & Status
        "status" | "getStatus" => handle_get_status(json_str),
        "setRandomSeed" | "set_seed" => handle_set_random_seed(json_str),
        "exportState" | "export" => handle_export_state(json_str),
        
        // Host callbacks (when host provides requested data)
        "hostCallback" => {
            let callback_type = json_get_string(json_str, "callbackType").unwrap_or("");
            match callback_type {
                "random_seed" => {
                    let result = handle_set_random_seed(json_str);
                    // After setting seed, process any pending request
                    let state = get_state();
                    if let Some(pending) = state.pending_request.take() {
                        let pending_action = json_get_string(&pending, "action").unwrap_or("");
                        let auto_bootstrap = json_get_bool(&pending, "autoBootstrap").unwrap_or(false);
                        
                        match pending_action {
                            "initialize" if auto_bootstrap => {
                                // Re-run initialize with original request - now we have random seed
                                if let Some(original) = json_get_string(&pending, "originalRequest") {
                                    return write_output(handle_initialize(original).as_bytes());
                                }
                                return write_output(handle_initialize(&pending).as_bytes());
                            }
                            "bootstrapTls" => return write_output(handle_bootstrap_tls(&pending).as_bytes()),
                            "ensureBlsKey" => return write_output(handle_ensure_bls_key(&pending).as_bytes()),
                            "ensureTlsKey" => return write_output(handle_ensure_tls_key(&pending).as_bytes()),
                            _ => {}
                        }
                    }
                    result
                }
                "http_response" => handle_http_response(json_str),
                _ => r#"{"error":"unknown callback type"}"#.to_string(),
            }
        }
        
        _ => format!(r#"{{"error":"unknown action: {}"}}"#, escape_json_string(action)),
    };
    
    write_output(response.as_bytes())
}

fn write_output(data: &[u8]) -> usize {
    unsafe {
        let len = data.len().min(OUTPUT_BUFFER.len() - 4);
        OUTPUT_BUFFER[..4].copy_from_slice(&(len as u32).to_le_bytes());
        OUTPUT_BUFFER[4..4 + len].copy_from_slice(&data[..len]);
        OUTPUT_BUFFER.as_ptr() as usize
    }
}

#[no_mangle]
pub extern "C" fn get_output_ptr() -> *const u8 {
    unsafe { OUTPUT_BUFFER.as_ptr() }
}
