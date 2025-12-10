//! LLM Chat Module - Self-Contained Chat Interface with Provider Abstraction
//!
//! This module provides a complete chat interface for LLM interactions.
//! All state management (conversation history, settings, etc.) is handled in-module.
//! 
//! Host calls are used ONLY for:
//! - Network I/O to external LLM APIs (OpenAI, Anthropic, local inference)
//! - Persistence of conversation history
//!
//! The module manages:
//! - Conversation history and context windows
//! - Multiple chat sessions
//! - Provider configuration and switching
//! - Token counting and context management
//! - Response streaming assembly

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

/// Maximum user message length (16 KB)
const MAX_USER_MESSAGE_LEN: usize = 16 * 1024;

/// Maximum assistant response length (64 KB)
const MAX_RESPONSE_LEN: usize = 64 * 1024;

/// Maximum system prompt length (8 KB)
const MAX_SYSTEM_PROMPT_LEN: usize = 8 * 1024;

/// Maximum messages per conversation
const MAX_MESSAGES_PER_CONVERSATION: usize = 500;

/// Maximum concurrent conversations/sessions
const MAX_CONVERSATIONS: usize = 50;

/// Maximum context window tokens (model-specific, but bounded)
const MAX_CONTEXT_TOKENS: usize = 128_000;

/// Maximum model name length
const MAX_MODEL_NAME_LEN: usize = 128;

/// Maximum API key length
const MAX_API_KEY_LEN: usize = 256;

/// Maximum provider URL length
const MAX_PROVIDER_URL_LEN: usize = 2048;

/// Maximum JSON input size
const MAX_JSON_INPUT_SIZE: usize = 128 * 1024;

/// Maximum JSON output size
const MAX_JSON_OUTPUT_SIZE: usize = 128 * 1024;

/// Maximum streaming chunks to buffer
const MAX_STREAM_CHUNKS: usize = 1000;

/// Maximum retry attempts for API calls
const MAX_API_RETRIES: usize = 3;

/// Maximum temperature value (0.0 - 2.0)
const MAX_TEMPERATURE: f32 = 2.0;

/// Maximum top_p value (0.0 - 1.0)
const MAX_TOP_P: f32 = 1.0;

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
        // Simple bump allocator
    }
}

#[global_allocator]
static ALLOCATOR: WasmAllocator = WasmAllocator;

static mut HEAP: [u8; 2 * 1024 * 1024] = [0; 2 * 1024 * 1024]; // 2MB heap for chat history
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

static mut OUTPUT_BUFFER: [u8; 131072] = [0; 131072]; // 128KB for long responses

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    alloc_raw(len)
}

#[no_mangle]
pub extern "C" fn dealloc(_ptr: *mut u8, _len: usize) {}

// ============================================================================
// Data Types
// ============================================================================

#[derive(Clone, PartialEq)]
enum MessageRole {
    System,
    User,
    Assistant,
}

impl MessageRole {
    fn as_str(&self) -> &'static str {
        match self {
            MessageRole::System => "system",
            MessageRole::User => "user",
            MessageRole::Assistant => "assistant",
        }
    }
    
    fn from_str(s: &str) -> Self {
        match s {
            "system" => MessageRole::System,
            "user" => MessageRole::User,
            "assistant" => MessageRole::Assistant,
            _ => MessageRole::User,
        }
    }
}

#[derive(Clone)]
struct ChatMessage {
    role: MessageRole,
    content: String,
    timestamp: u64,
    token_count: usize,
}

#[derive(Clone)]
struct ChatSession {
    id: String,
    title: String,
    messages: Vec<ChatMessage>,
    created_at: u64,
    updated_at: u64,
    system_prompt: Option<String>,
    model: String,
    total_tokens: usize,
}

impl ChatSession {
    fn new(id: String, tick: u64) -> Self {
        Self {
            id,
            title: "New Chat".to_string(),
            messages: Vec::new(),
            created_at: tick,
            updated_at: tick,
            system_prompt: None,
            model: "gpt-4".to_string(),
            total_tokens: 0,
        }
    }
}

#[derive(Clone)]
struct ProviderConfig {
    name: String,
    api_endpoint: String,
    model: String,
    max_tokens: usize,
    temperature: f32,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            name: "openai".to_string(),
            api_endpoint: "https://api.openai.com/v1/chat/completions".to_string(),
            model: "gpt-4".to_string(),
            max_tokens: 4096,
            temperature: 0.7,
        }
    }
}

struct ModuleState {
    sessions: BTreeMap<String, ChatSession>,
    active_session_id: Option<String>,
    provider: ProviderConfig,
    tick: u64,
    pending_response: Option<String>,
    session_counter: u64,
}

impl ModuleState {
    fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
            active_session_id: None,
            provider: ProviderConfig::default(),
            tick: 0,
            pending_response: None,
            session_counter: 0,
        }
    }
    
    fn get_or_create_active_session(&mut self) -> &mut ChatSession {
        if self.active_session_id.is_none() {
            self.session_counter += 1;
            let id = format!("session_{}", self.session_counter);
            let session = ChatSession::new(id.clone(), self.tick);
            self.sessions.insert(id.clone(), session);
            self.active_session_id = Some(id);
        }
        
        let id = self.active_session_id.as_ref().unwrap().clone();
        self.sessions.get_mut(&id).unwrap()
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
        // Handle escaped quotes
        let mut end = 0;
        let chars: Vec<char> = content.chars().collect();
        while end < chars.len() {
            if chars[end] == '"' && (end == 0 || chars[end - 1] != '\\') {
                break;
            }
            end += 1;
        }
        Some(&content[..end])
    } else {
        None
    }
}

fn json_get_int(json: &str, key: &str) -> Option<i64> {
    let search = format!("\"{}\"", key);
    let start = json.find(&search)?;
    let rest = &json[start + search.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    
    let mut num_str = String::new();
    for c in after_colon.chars() {
        if c.is_ascii_digit() || c == '-' {
            num_str.push(c);
        } else if !num_str.is_empty() {
            break;
        }
    }
    
    num_str.parse().ok()
}

fn json_get_float(json: &str, key: &str) -> Option<f32> {
    let search = format!("\"{}\"", key);
    let start = json.find(&search)?;
    let rest = &json[start + search.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    
    let mut num_str = String::new();
    for c in after_colon.chars() {
        if c.is_ascii_digit() || c == '-' || c == '.' {
            num_str.push(c);
        } else if !num_str.is_empty() {
            break;
        }
    }
    
    // Simple float parsing
    let parts: Vec<&str> = num_str.split('.').collect();
    if parts.len() == 2 {
        let whole: i32 = parts[0].parse().ok()?;
        let frac_str = parts[1];
        let frac: i32 = frac_str.parse().ok()?;
        let divisor = 10i32.pow(frac_str.len() as u32);
        Some(whole as f32 + frac as f32 / divisor as f32)
    } else if parts.len() == 1 {
        parts[0].parse::<i32>().ok().map(|n| n as f32)
    } else {
        None
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

fn unescape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                '"' => { result.push('"'); i += 2; }
                '\\' => { result.push('\\'); i += 2; }
                'n' => { result.push('\n'); i += 2; }
                'r' => { result.push('\r'); i += 2; }
                't' => { result.push('\t'); i += 2; }
                _ => { result.push(chars[i]); i += 1; }
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

// ============================================================================
// Token Counting (Simplified)
// ============================================================================

/// Rough token estimation (real impl would use tiktoken)
fn estimate_tokens(text: &str) -> usize {
    // Rough estimate: ~4 characters per token for English
    (text.len() + 3) / 4
}

// ============================================================================
// API Handlers
// ============================================================================

fn handle_send_message(json: &str) -> String {
    let content = match json_get_string(json, "message") {
        Some(m) => unescape_json_string(m),
        None => return r#"{"error":"missing message"}"#.to_string(),
    };
    
    let state = get_state();
    state.tick += 1;
    let tick = state.tick;
    
    // Copy provider info before borrowing session mutably
    let provider_name = state.provider.name.clone();
    let provider_endpoint = state.provider.api_endpoint.clone();
    let provider_max_tokens = state.provider.max_tokens;
    let provider_temperature = state.provider.temperature;
    
    let session = state.get_or_create_active_session();
    
    // Add user message
    let token_count = estimate_tokens(&content);
    let user_msg = ChatMessage {
        role: MessageRole::User,
        content: content.clone(),
        timestamp: tick,
        token_count,
    };
    session.messages.push(user_msg);
    session.total_tokens += token_count;
    session.updated_at = tick;
    
    // Auto-title from first message
    if session.messages.len() == 1 && session.title == "New Chat" {
        session.title = if content.len() > 30 {
            format!("{}...", &content[..30])
        } else {
            content.clone()
        };
    }
    
    // Build the API request for the host to execute
    let messages_json = build_messages_json(session);
    let session_model = session.model.clone();
    let session_id = session.id.clone();
    
    format!(
        r#"{{
            "host_call": "llm_request",
            "provider": "{}",
            "endpoint": "{}",
            "model": "{}",
            "max_tokens": {},
            "temperature": {},
            "messages": {},
            "session_id": "{}"
        }}"#,
        escape_json_string(&provider_name),
        escape_json_string(&provider_endpoint),
        escape_json_string(&session_model),
        provider_max_tokens,
        provider_temperature,
        messages_json,
        escape_json_string(&session_id)
    )
}

fn build_messages_json(session: &ChatSession) -> String {
    let mut json = String::from("[");
    let mut first = true;
    
    // Add system prompt if present
    if let Some(ref system) = session.system_prompt {
        json.push_str(&format!(
            r#"{{"role":"system","content":"{}"}}"#,
            escape_json_string(system)
        ));
        first = false;
    }
    
    // Add conversation history
    for msg in &session.messages {
        if !first {
            json.push(',');
        }
        first = false;
        
        json.push_str(&format!(
            r#"{{"role":"{}","content":"{}"}}"#,
            msg.role.as_str(),
            escape_json_string(&msg.content)
        ));
    }
    
    json.push(']');
    json
}

fn handle_receive_response(json: &str) -> String {
    let content = match json_get_string(json, "content") {
        Some(c) => unescape_json_string(c),
        None => return r#"{"error":"missing content"}"#.to_string(),
    };
    
    let session_id = json_get_string(json, "sessionId");
    
    let state = get_state();
    state.tick += 1;
    
    // Find the session
    let session = if let Some(sid) = session_id {
        state.sessions.get_mut(sid)
    } else {
        state.active_session_id.as_ref()
            .and_then(|id| state.sessions.get_mut(id))
    };
    
    let session = match session {
        Some(s) => s,
        None => return r#"{"error":"session not found"}"#.to_string(),
    };
    
    // Add assistant message
    let token_count = estimate_tokens(&content);
    let assistant_msg = ChatMessage {
        role: MessageRole::Assistant,
        content: content.clone(),
        timestamp: state.tick,
        token_count,
    };
    session.messages.push(assistant_msg);
    session.total_tokens += token_count;
    session.updated_at = state.tick;
    
    format!(
        r#"{{"success":true,"sessionId":"{}","messageCount":{},"totalTokens":{}}}"#,
        escape_json_string(&session.id),
        session.messages.len(),
        session.total_tokens
    )
}

fn handle_get_history(json: &str) -> String {
    let session_id = json_get_string(json, "sessionId");
    let limit = json_get_int(json, "limit").map(|l| l as usize);
    
    let state = get_state();
    
    let session = if let Some(sid) = session_id {
        state.sessions.get(sid)
    } else {
        state.active_session_id.as_ref()
            .and_then(|id| state.sessions.get(id))
    };
    
    let session = match session {
        Some(s) => s,
        None => return r#"{"success":true,"messages":[]}"#.to_string(),
    };
    
    let mut messages_json = String::from("[");
    let messages: Vec<&ChatMessage> = if let Some(l) = limit {
        session.messages.iter().rev().take(l).collect::<Vec<_>>().into_iter().rev().collect()
    } else {
        session.messages.iter().collect()
    };
    
    for (i, msg) in messages.iter().enumerate() {
        if i > 0 {
            messages_json.push(',');
        }
        messages_json.push_str(&format!(
            r#"{{"role":"{}","content":"{}","timestamp":{},"tokens":{}}}"#,
            msg.role.as_str(),
            escape_json_string(&msg.content),
            msg.timestamp,
            msg.token_count
        ));
    }
    messages_json.push(']');
    
    format!(
        r#"{{
            "success": true,
            "sessionId": "{}",
            "title": "{}",
            "messages": {},
            "totalTokens": {},
            "model": "{}"
        }}"#,
        escape_json_string(&session.id),
        escape_json_string(&session.title),
        messages_json,
        session.total_tokens,
        escape_json_string(&session.model)
    )
}

fn handle_new_session(json: &str) -> String {
    let title = json_get_string(json, "title");
    let system_prompt = json_get_string(json, "systemPrompt").map(|s| unescape_json_string(s));
    let model = json_get_string(json, "model");
    
    let state = get_state();
    state.tick += 1;
    state.session_counter += 1;
    
    let id = format!("session_{}", state.session_counter);
    let mut session = ChatSession::new(id.clone(), state.tick);
    
    if let Some(t) = title {
        session.title = t.to_string();
    }
    if let Some(sp) = system_prompt {
        session.system_prompt = Some(sp);
    }
    if let Some(m) = model {
        session.model = m.to_string();
    }
    
    state.sessions.insert(id.clone(), session);
    state.active_session_id = Some(id.clone());
    
    format!(
        r#"{{"success":true,"sessionId":"{}","message":"New session created"}}"#,
        id
    )
}

fn handle_list_sessions(_json: &str) -> String {
    let state = get_state();
    
    let mut sessions_json = String::from("[");
    let mut first = true;
    
    for (id, session) in &state.sessions {
        if !first {
            sessions_json.push(',');
        }
        first = false;
        
        sessions_json.push_str(&format!(
            r#"{{
                "id": "{}",
                "title": "{}",
                "messageCount": {},
                "totalTokens": {},
                "model": "{}",
                "createdAt": {},
                "updatedAt": {}
            }}"#,
            escape_json_string(id),
            escape_json_string(&session.title),
            session.messages.len(),
            session.total_tokens,
            escape_json_string(&session.model),
            session.created_at,
            session.updated_at
        ));
    }
    
    sessions_json.push(']');
    
    let active = state.active_session_id.as_ref()
        .map(|s| format!("\"{}\"", escape_json_string(s)))
        .unwrap_or_else(|| "null".to_string());
    
    format!(
        r#"{{"success":true,"sessions":{},"activeSession":{},"count":{}}}"#,
        sessions_json,
        active,
        state.sessions.len()
    )
}

fn handle_switch_session(json: &str) -> String {
    let session_id = match json_get_string(json, "sessionId") {
        Some(id) => id,
        None => return r#"{"error":"missing sessionId"}"#.to_string(),
    };
    
    let state = get_state();
    
    if state.sessions.contains_key(session_id) {
        state.active_session_id = Some(session_id.to_string());
        format!(
            r#"{{"success":true,"activeSession":"{}"}}"#,
            escape_json_string(session_id)
        )
    } else {
        format!(r#"{{"error":"session not found: {}"}}"#, escape_json_string(session_id))
    }
}

fn handle_delete_session(json: &str) -> String {
    let session_id = match json_get_string(json, "sessionId") {
        Some(id) => id,
        None => return r#"{"error":"missing sessionId"}"#.to_string(),
    };
    
    let state = get_state();
    
    if state.sessions.remove(session_id).is_some() {
        // Clear active if it was the deleted one
        if state.active_session_id.as_ref().map(|s| s.as_str()) == Some(session_id) {
            state.active_session_id = state.sessions.keys().next().cloned();
        }
        format!(
            r#"{{"success":true,"deleted":"{}"}}"#,
            escape_json_string(session_id)
        )
    } else {
        format!(r#"{{"error":"session not found: {}"}}"#, escape_json_string(session_id))
    }
}

fn handle_set_system_prompt(json: &str) -> String {
    let prompt = match json_get_string(json, "prompt") {
        Some(p) => unescape_json_string(p),
        None => return r#"{"error":"missing prompt"}"#.to_string(),
    };
    
    let session_id = json_get_string(json, "sessionId");
    
    let state = get_state();
    
    let session = if let Some(sid) = session_id {
        state.sessions.get_mut(sid)
    } else {
        state.active_session_id.as_ref()
            .and_then(|id| state.sessions.get_mut(id))
    };
    
    match session {
        Some(s) => {
            s.system_prompt = Some(prompt);
            format!(
                r#"{{"success":true,"sessionId":"{}","systemPromptSet":true}}"#,
                escape_json_string(&s.id)
            )
        }
        None => r#"{"error":"no active session"}"#.to_string(),
    }
}

fn handle_configure_provider(json: &str) -> String {
    let state = get_state();
    
    if let Some(name) = json_get_string(json, "provider") {
        state.provider.name = name.to_string();
    }
    if let Some(endpoint) = json_get_string(json, "endpoint") {
        state.provider.api_endpoint = endpoint.to_string();
    }
    if let Some(model) = json_get_string(json, "model") {
        state.provider.model = model.to_string();
    }
    if let Some(max_tokens) = json_get_int(json, "maxTokens") {
        state.provider.max_tokens = max_tokens as usize;
    }
    if let Some(temp) = json_get_float(json, "temperature") {
        state.provider.temperature = temp;
    }
    
    format!(
        r#"{{
            "success": true,
            "provider": "{}",
            "endpoint": "{}",
            "model": "{}",
            "maxTokens": {},
            "temperature": {}
        }}"#,
        escape_json_string(&state.provider.name),
        escape_json_string(&state.provider.api_endpoint),
        escape_json_string(&state.provider.model),
        state.provider.max_tokens,
        state.provider.temperature
    )
}

fn handle_clear_history(json: &str) -> String {
    let session_id = json_get_string(json, "sessionId");
    
    let state = get_state();
    
    let session = if let Some(sid) = session_id {
        state.sessions.get_mut(sid)
    } else {
        state.active_session_id.as_ref()
            .and_then(|id| state.sessions.get_mut(id))
    };
    
    match session {
        Some(s) => {
            let count = s.messages.len();
            s.messages.clear();
            s.total_tokens = 0;
            format!(
                r#"{{"success":true,"sessionId":"{}","cleared":{}}}"#,
                escape_json_string(&s.id),
                count
            )
        }
        None => r#"{"error":"no active session"}"#.to_string(),
    }
}

fn handle_get_status(_json: &str) -> String {
    let state = get_state();
    let heap_used = unsafe { HEAP_POS };
    let heap_total = unsafe { HEAP.len() };
    
    let active_session = state.active_session_id.as_ref()
        .and_then(|id| state.sessions.get(id));
    
    let (msg_count, total_tokens) = active_session
        .map(|s| (s.messages.len(), s.total_tokens))
        .unwrap_or((0, 0));
    
    format!(
        r#"{{
            "success": true,
            "module": "llm_chat_v1",
            "version": "1.0.0",
            "sessionCount": {},
            "activeSessionId": {},
            "activeSessionMessages": {},
            "activeSessionTokens": {},
            "provider": "{}",
            "model": "{}",
            "heapUsed": {},
            "heapTotal": {}
        }}"#,
        state.sessions.len(),
        state.active_session_id.as_ref()
            .map(|s| format!("\"{}\"", escape_json_string(s)))
            .unwrap_or_else(|| "null".to_string()),
        msg_count,
        total_tokens,
        escape_json_string(&state.provider.name),
        escape_json_string(&state.provider.model),
        heap_used,
        heap_total
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
    
    let action = json_get_string(json_str, "action").unwrap_or("");
    
    let response = match action {
        // Chat operations
        "send" | "sendMessage" | "chat" => handle_send_message(json_str),
        "receiveResponse" | "response" => handle_receive_response(json_str),
        "getHistory" | "history" => handle_get_history(json_str),
        "clearHistory" | "clear" => handle_clear_history(json_str),
        
        // Session management
        "newSession" | "new" => handle_new_session(json_str),
        "listSessions" | "sessions" => handle_list_sessions(json_str),
        "switchSession" | "switch" => handle_switch_session(json_str),
        "deleteSession" | "delete" => handle_delete_session(json_str),
        
        // Configuration
        "setSystemPrompt" | "system" => handle_set_system_prompt(json_str),
        "configureProvider" | "provider" => handle_configure_provider(json_str),
        
        // Status
        "status" | "info" => handle_get_status(json_str),
        
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
