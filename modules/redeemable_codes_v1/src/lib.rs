//! Redeemable Codes Module - On-Chain Managed Gift Code System
//!
//! Implementation of US Patent Application 20250139608:
//! "Card System Utilizing On-Chain Managed Redeemable Gift Code"
//!
//! Architecture:
//! - Dual smart contract system (public + private)
//! - Public contract: Status management, transparency, policy enforcement
//! - Private contract: Secure code storage (hash+salt), validation in TEE
//! - CryftTEE acts as the Trusted Execution Environment (TEE)
//!
//! Key Features:
//! - Generate cryptographically secure redeemable codes
//! - Store encrypted representations (hash+salt) in private contract
//! - Public status management (frozen/unfrozen, content assignment)
//! - Blockchain-verified redemption process
//! - Support for validator registrations, NFTs, tokens, and experiences

#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use alloc::collections::BTreeMap;
use core::slice;
use serde::{Deserialize, Serialize};

// ============================================================================
// Global Allocator for no_std WASM
// ============================================================================

use core::alloc::{GlobalAlloc, Layout};

struct WasmAllocator;

unsafe impl GlobalAlloc for WasmAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        let total = size + align;
        let mut buf: Vec<u8> = Vec::with_capacity(total);
        let ptr = buf.as_mut_ptr();
        let aligned = ((ptr as usize + align - 1) & !(align - 1)) as *mut u8;
        core::mem::forget(buf);
        aligned
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Memory freed when module unloads
    }
}

#[global_allocator]
static ALLOCATOR: WasmAllocator = WasmAllocator;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ============================================================================
// WASM Memory Management
// ============================================================================

static mut OUTPUT_BUFFER: Vec<u8> = Vec::new();

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
    buf.resize(size as usize, 0);
    let ptr = buf.as_mut_ptr() as usize;
    core::mem::forget(buf);
    ptr as i32
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: i32, size: i32) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, size as usize, size as usize);
    }
}

#[no_mangle]
pub extern "C" fn get_output_ptr() -> i32 {
    unsafe { OUTPUT_BUFFER.as_ptr() as i32 }
}

#[no_mangle]
pub extern "C" fn get_output_len() -> i32 {
    unsafe { OUTPUT_BUFFER.len() as i32 }
}

fn set_output(data: &[u8]) {
    unsafe {
        OUTPUT_BUFFER = data.to_vec();
    }
}

fn read_input(ptr: i32, len: i32) -> Vec<u8> {
    unsafe {
        slice::from_raw_parts(ptr as *const u8, len as usize).to_vec()
    }
}

// ============================================================================
// Patent-Compliant Type Definitions
// ============================================================================

/// Code status in public smart contract (FIG. 15)
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeStatus {
    /// Code is frozen - cannot be redeemed (default state)
    Frozen,
    /// Code is active - can be redeemed
    Active,
    /// Code has been redeemed
    Redeemed,
    /// Code has been revoked/cancelled
    Revoked,
}

impl Default for CodeStatus {
    fn default() -> Self {
        CodeStatus::Frozen
    }
}

/// Content type that code redeems to (FIG. 16)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedeemableContent {
    /// Access to smart contract wallet (FIG. 9)
    WalletAccess { wallet_address: String },
    /// Private key for externally owned account (FIG. 10)
    PrivateKey { encrypted_key: String },
    /// NFT or token transfer (FIG. 11)
    Token { 
        token_type: String, // "nft", "erc20", "native"
        contract_address: Option<String>,
        token_id: Option<String>,
        amount: Option<String>,
    },
    /// External API trigger for experiences (FIG. 12)
    Experience {
        api_endpoint: String,
        experience_type: String,
        metadata: BTreeMap<String, String>,
    },
    /// Validator registration on Cryft network
    ValidatorRegistration {
        node_id: Option<String>,
        stake_amount: Option<String>,
        delegation_fee: Option<u32>,
    },
    /// Generic content with custom payload
    Custom {
        content_type: String,
        payload: String,
    },
}

/// Unique Identifier structure (FIG. 18)
/// Format: <manager_address>-<index>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UniqueId {
    /// Manager address (wallet/contract) with permission to manage this code
    pub manager_address: String,
    /// Index within manager's codes
    pub index: String,
}

impl UniqueId {
    pub fn to_string(&self) -> String {
        format!("{}-{}", self.manager_address, self.index)
    }
    
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(2, '-').collect();
        if parts.len() == 2 {
            Some(UniqueId {
                manager_address: parts[0].to_string(),
                index: parts[1].to_string(),
            })
        } else {
            None
        }
    }
}

/// Public contract entry - visible on blockchain (FIG. 17c public side)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicCodeEntry {
    /// Unique identifier (manager_address-index)
    pub uid: String,
    /// Current status (frozen, active, redeemed, revoked)
    pub status: CodeStatus,
    /// Assigned redeemable content
    pub content: Option<RedeemableContent>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last status update timestamp
    pub updated_at: u64,
    /// Optional metadata (artwork URL, description, etc.)
    pub metadata: BTreeMap<String, String>,
}

/// Private contract entry - stored securely in TEE (FIG. 17c private side)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateCodeEntry {
    /// Storage index (first portion of gift code - FIG. 17a)
    pub storage_index: String,
    /// Hash of the redeemable portion (FIG. 17b hashed)
    pub code_hash: String,
    /// Salt used in hashing
    pub salt: String,
    /// Associated UID in public contract
    pub uid: String,
    /// Redemption count (usually 0 or 1)
    pub redemption_count: u32,
    /// Max redemptions allowed (usually 1)
    pub max_redemptions: u32,
    /// Redeemer wallet address (set after redemption)
    pub redeemer: Option<String>,
    /// Redemption timestamp
    pub redeemed_at: Option<u64>,
}

/// Full gift code structure (FIG. 17)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GiftCode {
    /// Storage index portion (a) - used to locate hash in private contract
    pub index: String,
    /// Redeemable portion (b) - validated against stored hash
    pub code: String,
    /// Optional dashes for readability (d)
    pub formatted: Option<String>,
}

impl GiftCode {
    /// Format code with dashes for display (XXXX-XXXX-XXXX-XXXX)
    pub fn format_for_display(&self) -> String {
        let full = format!("{}{}", self.index, self.code);
        let chars: Vec<char> = full.chars().collect();
        let mut result = String::new();
        for (i, c) in chars.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                result.push('-');
            }
            result.push(*c);
        }
        result
    }
    
    /// Parse from formatted string
    pub fn from_formatted(formatted: &str) -> Option<Self> {
        let clean: String = formatted.chars().filter(|c| c.is_alphanumeric()).collect();
        if clean.len() < 8 {
            return None;
        }
        // First 4 chars are index, rest is code
        let (index, code) = clean.split_at(4);
        Some(GiftCode {
            index: index.to_string(),
            code: code.to_string(),
            formatted: Some(formatted.to_string()),
        })
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Generate new redeemable code (FIG. 3)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateCodeRequest {
    /// Manager address (who can manage this code)
    pub manager_address: String,
    /// Optional content to assign immediately
    pub content: Option<RedeemableContent>,
    /// Initial status (default: Frozen)
    #[serde(default)]
    pub initial_status: Option<CodeStatus>,
    /// Optional metadata
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Number of codes to generate (batch)
    #[serde(default = "default_one")]
    pub count: u32,
}

fn default_one() -> u32 { 1 }

/// Generated code response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedCode {
    /// The full gift code (index + code)
    pub gift_code: GiftCode,
    /// Unique identifier for management
    pub uid: String,
    /// Formatted for display/printing
    pub formatted_code: String,
    /// QR code data URL (if requested)
    pub qr_code: Option<String>,
}

/// Redeem code request (FIG. 1 step 20-22)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedeemCodeRequest {
    /// The gift code (can be formatted with dashes)
    pub code: String,
    /// Redeemer's wallet address
    pub redeemer_address: String,
    /// Optional: specific content variant to redeem
    pub content_variant: Option<String>,
}

/// Redemption result
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedemptionResult {
    pub success: bool,
    pub uid: String,
    pub content: Option<RedeemableContent>,
    pub message: String,
    /// Transaction hash if blockchain write occurred
    pub tx_hash: Option<String>,
}

/// Update code status (FIG. 15)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatusRequest {
    /// Unique identifier
    pub uid: String,
    /// New status
    pub status: CodeStatus,
    /// Manager signature/proof
    pub manager_signature: Option<String>,
}

/// Update code content (FIG. 16)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateContentRequest {
    /// Unique identifier
    pub uid: String,
    /// New content assignment
    pub content: RedeemableContent,
    /// Manager signature/proof
    pub manager_signature: Option<String>,
}

/// Query code status (FIG. 14)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryStatusRequest {
    /// Unique identifier
    pub uid: String,
}

/// Report lost/stolen card (FIG. 6)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportLostRequest {
    /// Unique identifier of the lost code
    pub uid: String,
    /// Owner's proof of ownership
    pub ownership_proof: String,
    /// Reason for report
    pub reason: Option<String>,
}

/// Batch code operation
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchOperation {
    /// UIDs to operate on
    pub uids: Vec<String>,
    /// Operation type
    pub operation: String, // "freeze", "unfreeze", "revoke"
    /// Manager signature
    pub manager_signature: Option<String>,
}

/// Code listing/search request
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCodesRequest {
    /// Filter by manager address
    pub manager_address: Option<String>,
    /// Filter by status
    pub status: Option<CodeStatus>,
    /// Filter by content type
    pub content_type: Option<String>,
    /// Pagination offset
    #[serde(default)]
    pub offset: u32,
    /// Pagination limit
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 { 50 }

// ============================================================================
// Host Call Types
// ============================================================================

/// Host call for runtime to execute
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HostCall {
    /// Store entry in private contract (TEE-secured)
    StorePrivate {
        entry: PrivateCodeEntry,
    },
    /// Update entry in private contract
    UpdatePrivate {
        storage_index: String,
        updates: BTreeMap<String, String>,
    },
    /// Query private contract
    QueryPrivate {
        storage_index: String,
    },
    /// Store/update entry in public contract (on-chain)
    StorePublic {
        entry: PublicCodeEntry,
    },
    /// Update public contract status
    UpdatePublicStatus {
        uid: String,
        status: CodeStatus,
    },
    /// Query public contract
    QueryPublic {
        uid: String,
    },
    /// List entries from public contract
    ListPublic {
        filter: ListCodesRequest,
    },
    /// Generate random bytes (QRNG)
    GenerateRandom {
        length: u32,
    },
    /// Hash data with salt
    HashWithSalt {
        data: String,
        salt: String,
    },
    /// Blockchain transaction
    SubmitTransaction {
        tx_type: String,
        payload: String,
    },
    /// External API call (for experiences)
    ExternalApi {
        endpoint: String,
        method: String,
        body: Option<String>,
    },
}

// ============================================================================
// Module Info & Entry Points
// ============================================================================

#[derive(Serialize)]
struct ModuleInfo {
    module: &'static str,
    version: &'static str,
    status: &'static str,
    description: &'static str,
    patent: &'static str,
    capabilities: Vec<&'static str>,
}

#[no_mangle]
pub extern "C" fn get_info(_input_ptr: i32, _input_len: i32) -> i32 {
    let info = ModuleInfo {
        module: "redeemable_codes",
        version: "1.0.0",
        status: "operational",
        description: "On-Chain Managed Redeemable Gift Codes - Dual smart contract system per US Patent App 20250139608",
        patent: "US 20250139608 - Card System Utilizing On-Chain Managed Redeemable Gift Code",
        capabilities: vec![
            // Code Generation (FIG. 3)
            "generate_code",
            "generate_batch",
            // Code Redemption (FIG. 1, 7, 8)
            "redeem_code",
            "validate_code",
            // Status Management (FIG. 15)
            "freeze_code",
            "unfreeze_code",
            "revoke_code",
            "get_status",
            // Content Management (FIG. 16)
            "assign_content",
            "update_content",
            // Query Operations (FIG. 14)
            "list_codes",
            "search_codes",
            "get_code_details",
            // Card Management
            "report_lost",
            "transfer_ownership",
            // Batch Operations
            "batch_freeze",
            "batch_unfreeze",
            "batch_assign",
            // Validator Integration
            "redeem_for_validator",
            // Statistics
            "get_stats",
            "get_redemption_history",
        ],
    };
    
    let json = serde_json::to_string(&info).unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string());
    set_output(json.as_bytes());
    0
}

#[derive(Deserialize)]
struct HandleRequest {
    operation: String,
    params: Option<serde_json::Value>,
}

#[no_mangle]
pub extern "C" fn handle_request(input_ptr: i32, input_len: i32) -> i32 {
    let input = read_input(input_ptr, input_len);
    
    let request: HandleRequest = match serde_json::from_slice(&input) {
        Ok(r) => r,
        Err(e) => {
            let error = format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e);
            set_output(error.as_bytes());
            return 1;
        }
    };
    
    let params = request.params.unwrap_or(serde_json::json!({}));
    
    let result = match request.operation.as_str() {
        // === CODE GENERATION ===
        "generate_code" | "generate" => handle_generate_code(&params),
        "generate_batch" | "batch_generate" => handle_generate_batch(&params),
        
        // === CODE REDEMPTION ===
        "redeem_code" | "redeem" => handle_redeem_code(&params),
        "validate_code" | "validate" => handle_validate_code(&params),
        
        // === STATUS MANAGEMENT ===
        "freeze_code" | "freeze" => handle_freeze_code(&params),
        "unfreeze_code" | "unfreeze" | "activate" => handle_unfreeze_code(&params),
        "revoke_code" | "revoke" => handle_revoke_code(&params),
        "get_status" | "status" => handle_get_status(&params),
        "update_status" => handle_update_status(&params),
        
        // === CONTENT MANAGEMENT ===
        "assign_content" | "assign" => handle_assign_content(&params),
        "update_content" => handle_update_content(&params),
        
        // === QUERY OPERATIONS ===
        "list_codes" | "list" => handle_list_codes(&params),
        "search_codes" | "search" => handle_search_codes(&params),
        "get_code_details" | "details" => handle_get_details(&params),
        
        // === CARD MANAGEMENT ===
        "report_lost" | "lost" => handle_report_lost(&params),
        "transfer_ownership" | "transfer" => handle_transfer(&params),
        
        // === BATCH OPERATIONS ===
        "batch_freeze" => handle_batch_operation(&params, CodeStatus::Frozen),
        "batch_unfreeze" => handle_batch_operation(&params, CodeStatus::Active),
        "batch_assign" => handle_batch_assign(&params),
        
        // === VALIDATOR INTEGRATION ===
        "redeem_for_validator" | "validator_redeem" => handle_validator_redeem(&params),
        
        // === STATISTICS ===
        "get_stats" | "stats" => handle_get_stats(&params),
        "get_redemption_history" | "history" => handle_get_history(&params),
        
        _ => format!(r#"{{"success":false,"error":"Unknown operation: {}"}}"#, request.operation),
    };
    
    set_output(result.as_bytes());
    0
}

// ============================================================================
// Handler Implementations
// ============================================================================

/// Generate a new redeemable code (FIG. 3 subprocess)
fn handle_generate_code(params: &serde_json::Value) -> String {
    let req: GenerateCodeRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    if req.manager_address.is_empty() {
        return r#"{"success":false,"error":"Manager address is required"}"#.to_string();
    }
    
    // Request random bytes from QRNG (step 40-42)
    let host_call = HostCall::GenerateRandom { length: 32 };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "next_step": "create_code_entry",
        "params": {
            "manager_address": req.manager_address,
            "content": req.content,
            "initial_status": req.initial_status.unwrap_or(CodeStatus::Frozen),
            "metadata": req.metadata
        },
        "message": "Generating cryptographically secure code..."
    })).unwrap_or_default()
}

/// Generate batch of codes
fn handle_generate_batch(params: &serde_json::Value) -> String {
    let req: GenerateCodeRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    if req.count == 0 || req.count > 1000 {
        return r#"{"success":false,"error":"Count must be between 1 and 1000"}"#.to_string();
    }
    
    let host_call = HostCall::GenerateRandom { length: 32 * req.count };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "batch_size": req.count,
        "message": format!("Generating {} codes...", req.count)
    })).unwrap_or_default()
}

/// Redeem a code (FIG. 1 steps 20-38, FIG. 7/8)
fn handle_redeem_code(params: &serde_json::Value) -> String {
    let req: RedeemCodeRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    // Parse and validate code format
    let gift_code = match GiftCode::from_formatted(&req.code) {
        Some(gc) => gc,
        None => return r#"{"success":false,"error":"Invalid code format"}"#.to_string(),
    };
    
    if req.redeemer_address.is_empty() {
        return r#"{"success":false,"error":"Redeemer address is required"}"#.to_string();
    }
    
    // Step 1: Query private contract to validate code (FIG. 1 step 24)
    let host_call = HostCall::QueryPrivate {
        storage_index: gift_code.index.clone(),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "next_step": "validate_and_check_public",
        "params": {
            "code_portion": gift_code.code,
            "redeemer_address": req.redeemer_address,
            "content_variant": req.content_variant
        },
        "message": "Validating code in secure enclave..."
    })).unwrap_or_default()
}

/// Validate code without redeeming
fn handle_validate_code(params: &serde_json::Value) -> String {
    let code = params.get("code").and_then(|v| v.as_str()).unwrap_or("");
    
    let gift_code = match GiftCode::from_formatted(code) {
        Some(gc) => gc,
        None => return r#"{"success":false,"error":"Invalid code format"}"#.to_string(),
    };
    
    let host_call = HostCall::QueryPrivate {
        storage_index: gift_code.index.clone(),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "validate_only": true,
        "message": "Checking code validity..."
    })).unwrap_or_default()
}

/// Freeze a code (FIG. 15 - set to frozen)
fn handle_freeze_code(params: &serde_json::Value) -> String {
    let uid = params.get("uid").and_then(|v| v.as_str()).unwrap_or("");
    
    if uid.is_empty() {
        return r#"{"success":false,"error":"UID is required"}"#.to_string();
    }
    
    let host_call = HostCall::UpdatePublicStatus {
        uid: uid.to_string(),
        status: CodeStatus::Frozen,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "uid": uid,
        "new_status": "frozen",
        "message": "Freezing code - redemption disabled"
    })).unwrap_or_default()
}

/// Unfreeze/activate a code (FIG. 15 - set to active)
fn handle_unfreeze_code(params: &serde_json::Value) -> String {
    let uid = params.get("uid").and_then(|v| v.as_str()).unwrap_or("");
    
    if uid.is_empty() {
        return r#"{"success":false,"error":"UID is required"}"#.to_string();
    }
    
    let host_call = HostCall::UpdatePublicStatus {
        uid: uid.to_string(),
        status: CodeStatus::Active,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "uid": uid,
        "new_status": "active",
        "message": "Activating code - redemption enabled"
    })).unwrap_or_default()
}

/// Revoke a code permanently
fn handle_revoke_code(params: &serde_json::Value) -> String {
    let uid = params.get("uid").and_then(|v| v.as_str()).unwrap_or("");
    
    if uid.is_empty() {
        return r#"{"success":false,"error":"UID is required"}"#.to_string();
    }
    
    let host_call = HostCall::UpdatePublicStatus {
        uid: uid.to_string(),
        status: CodeStatus::Revoked,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "uid": uid,
        "new_status": "revoked",
        "message": "Code permanently revoked"
    })).unwrap_or_default()
}

/// Get code status (FIG. 14)
fn handle_get_status(params: &serde_json::Value) -> String {
    let uid = params.get("uid").and_then(|v| v.as_str()).unwrap_or("");
    
    if uid.is_empty() {
        return r#"{"success":false,"error":"UID is required"}"#.to_string();
    }
    
    let host_call = HostCall::QueryPublic {
        uid: uid.to_string(),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "message": "Querying public contract status..."
    })).unwrap_or_default()
}

/// Update code status
fn handle_update_status(params: &serde_json::Value) -> String {
    let req: UpdateStatusRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    let host_call = HostCall::UpdatePublicStatus {
        uid: req.uid.clone(),
        status: req.status,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "uid": req.uid,
        "new_status": req.status,
        "message": "Updating code status..."
    })).unwrap_or_default()
}

/// Assign content to code (FIG. 16)
fn handle_assign_content(params: &serde_json::Value) -> String {
    let req: UpdateContentRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    // First query existing entry, then update with content
    let host_call = HostCall::QueryPublic {
        uid: req.uid.clone(),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "next_step": "update_with_content",
        "content": req.content,
        "message": "Assigning redeemable content..."
    })).unwrap_or_default()
}

/// Update existing content assignment
fn handle_update_content(params: &serde_json::Value) -> String {
    handle_assign_content(params)
}

/// List codes with filters
fn handle_list_codes(params: &serde_json::Value) -> String {
    let filter: ListCodesRequest = serde_json::from_value(params.clone()).unwrap_or(ListCodesRequest {
        manager_address: None,
        status: None,
        content_type: None,
        offset: 0,
        limit: 50,
    });
    
    let host_call = HostCall::ListPublic { filter };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "message": "Listing codes..."
    })).unwrap_or_default()
}

/// Search codes
fn handle_search_codes(params: &serde_json::Value) -> String {
    handle_list_codes(params)
}

/// Get detailed code information
fn handle_get_details(params: &serde_json::Value) -> String {
    let uid = params.get("uid").and_then(|v| v.as_str()).unwrap_or("");
    
    if uid.is_empty() {
        return r#"{"success":false,"error":"UID is required"}"#.to_string();
    }
    
    let host_call = HostCall::QueryPublic {
        uid: uid.to_string(),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "include_metadata": true,
        "message": "Fetching code details..."
    })).unwrap_or_default()
}

/// Report lost/stolen card (FIG. 6)
fn handle_report_lost(params: &serde_json::Value) -> String {
    let req: ReportLostRequest = match serde_json::from_value(params.clone()) {
        Ok(r) => r,
        Err(e) => return format!(r#"{{"success":false,"error":"Invalid request: {}"}}"#, e),
    };
    
    // Step 1: Verify ownership (step 86)
    // Step 2: Freeze the code (step 88)
    let host_call = HostCall::UpdatePublicStatus {
        uid: req.uid.clone(),
        status: CodeStatus::Frozen,
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "uid": req.uid,
        "requires_ownership_verification": true,
        "ownership_proof": req.ownership_proof,
        "reason": req.reason,
        "message": "Processing lost card report - code will be frozen"
    })).unwrap_or_default()
}

/// Transfer ownership
fn handle_transfer(params: &serde_json::Value) -> String {
    let uid = params.get("uid").and_then(|v| v.as_str()).unwrap_or("");
    let new_owner = params.get("newOwner").and_then(|v| v.as_str()).unwrap_or("");
    
    if uid.is_empty() || new_owner.is_empty() {
        return r#"{"success":false,"error":"UID and newOwner are required"}"#.to_string();
    }
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "pending": true,
        "uid": uid,
        "new_owner": new_owner,
        "message": "Transferring code ownership..."
    })).unwrap_or_default()
}

/// Batch operation (freeze/unfreeze multiple codes)
fn handle_batch_operation(params: &serde_json::Value, status: CodeStatus) -> String {
    let uids: Vec<String> = params.get("uids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    
    if uids.is_empty() {
        return r#"{"success":false,"error":"UIDs array is required"}"#.to_string();
    }
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "pending": true,
        "batch_operation": true,
        "uids": uids,
        "target_status": status,
        "message": format!("Processing batch {} operation for {} codes...", 
            match status { CodeStatus::Frozen => "freeze", CodeStatus::Active => "unfreeze", _ => "update" },
            uids.len()
        )
    })).unwrap_or_default()
}

/// Batch assign content
fn handle_batch_assign(params: &serde_json::Value) -> String {
    let uids: Vec<String> = params.get("uids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    
    let content: Option<RedeemableContent> = params.get("content")
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    
    if uids.is_empty() {
        return r#"{"success":false,"error":"UIDs array is required"}"#.to_string();
    }
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "pending": true,
        "batch_operation": true,
        "uids": uids,
        "content": content,
        "message": format!("Assigning content to {} codes...", uids.len())
    })).unwrap_or_default()
}

/// Redeem code for validator registration
fn handle_validator_redeem(params: &serde_json::Value) -> String {
    let code = params.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let node_id = params.get("nodeId").and_then(|v| v.as_str());
    let redeemer = params.get("redeemerAddress").and_then(|v| v.as_str()).unwrap_or("");
    
    let gift_code = match GiftCode::from_formatted(code) {
        Some(gc) => gc,
        None => return r#"{"success":false,"error":"Invalid code format"}"#.to_string(),
    };
    
    let host_call = HostCall::QueryPrivate {
        storage_index: gift_code.index.clone(),
    };
    
    serde_json::to_string(&serde_json::json!({
        "host_call": host_call,
        "success": true,
        "pending": true,
        "redemption_type": "validator_registration",
        "next_step": "validate_and_register_validator",
        "params": {
            "code_portion": gift_code.code,
            "node_id": node_id,
            "redeemer_address": redeemer
        },
        "message": "Processing validator registration redemption..."
    })).unwrap_or_default()
}

/// Get statistics
fn handle_get_stats(params: &serde_json::Value) -> String {
    let manager_address = params.get("managerAddress").and_then(|v| v.as_str());
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "pending": true,
        "manager_address": manager_address,
        "message": "Fetching statistics..."
    })).unwrap_or_default()
}

/// Get redemption history
fn handle_get_history(params: &serde_json::Value) -> String {
    let uid = params.get("uid").and_then(|v| v.as_str());
    let manager_address = params.get("managerAddress").and_then(|v| v.as_str());
    
    serde_json::to_string(&serde_json::json!({
        "success": true,
        "pending": true,
        "uid": uid,
        "manager_address": manager_address,
        "message": "Fetching redemption history..."
    })).unwrap_or_default()
}
