//! Debug Module - Self-Contained Diagnostics & Testing
//!
//! This module provides debugging, diagnostics, and testing utilities for the
//! cryfttee runtime. All operations are self-contained within WASM.
//!
//! Features:
//! - Echo requests back with metadata
//! - Runtime information and diagnostics
//! - Memory/allocation testing
//! - Performance benchmarking
//! - Log collection and analysis

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

/// Maximum echo message size
const MAX_ECHO_SIZE: usize = 64 * 1024;

/// Maximum log entries to retain
const MAX_LOG_ENTRIES: usize = 1000;

/// Maximum benchmark iterations
const MAX_BENCHMARK_ITERATIONS: usize = 10000;

/// Maximum memory test allocation size
const MAX_MEMORY_TEST_SIZE: usize = 256 * 1024;

/// Maximum JSON input size
const MAX_JSON_INPUT_SIZE: usize = 64 * 1024;

/// Maximum JSON output size  
const MAX_JSON_OUTPUT_SIZE: usize = 64 * 1024;

/// Maximum key length for diagnostics map
const MAX_DIAG_KEY_LEN: usize = 256;

/// Maximum value length for diagnostics
const MAX_DIAG_VALUE_LEN: usize = 4096;

/// Maximum number of diagnostic entries
const MAX_DIAG_ENTRIES: usize = 100;

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

static mut HEAP: [u8; 512 * 1024] = [0; 512 * 1024]; // 512KB heap
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
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Store panic info in state before looping
    unsafe {
        if let Some(state) = &mut *MODULE_STATE.get() {
            let msg = if let Some(location) = info.location() {
                format!("panic at {}:{}", location.file(), location.line())
            } else {
                "panic occurred".to_string()
            };
            state.last_panic = Some(msg);
        }
    }
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

/// Log entry for diagnostics
#[derive(Clone)]
struct LogEntry {
    level: String,
    message: String,
    timestamp: u64,
}

/// Performance measurement
#[derive(Clone)]
struct PerfMeasurement {
    name: String,
    start_tick: u64,
    end_tick: Option<u64>,
}

/// Module state container
struct ModuleState {
    /// Log entries collected during runtime
    logs: Vec<LogEntry>,
    /// Request counter
    request_count: u64,
    /// Performance measurements
    perf_measurements: BTreeMap<String, PerfMeasurement>,
    /// Last panic message (if any)
    last_panic: Option<String>,
    /// Echo history
    echo_history: Vec<String>,
    /// Tick counter (simulated time)
    tick: u64,
    /// Custom key-value store for testing
    test_store: BTreeMap<String, String>,
}

impl ModuleState {
    fn new() -> Self {
        Self {
            logs: Vec::new(),
            request_count: 0,
            perf_measurements: BTreeMap::new(),
            last_panic: None,
            echo_history: Vec::new(),
            tick: 0,
            test_store: BTreeMap::new(),
        }
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
        let end = content.find('"')?;
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
// API Handlers
// ============================================================================

fn handle_echo(json: &str) -> String {
    let message = json_get_string(json, "message").unwrap_or("");
    
    let state = get_state();
    state.request_count += 1;
    state.tick += 1;
    
    // Store in history
    state.echo_history.push(message.to_string());
    if state.echo_history.len() > 100 {
        state.echo_history.remove(0);
    }
    
    format!(
        r#"{{"success":true,"echo":"{}","requestNumber":{},"timestamp":{}}}"#,
        escape_json_string(message),
        state.request_count,
        state.tick
    )
}

fn handle_info(_json: &str) -> String {
    let state = get_state();
    state.request_count += 1;
    
    let heap_used = unsafe { HEAP_POS };
    let heap_total = unsafe { HEAP.len() };
    
    format!(
        r#"{{
            "success": true,
            "module": "debug_v1",
            "version": "1.0.0",
            "heapUsed": {},
            "heapTotal": {},
            "heapPercent": {:.1},
            "requestCount": {},
            "logCount": {},
            "echoHistoryCount": {},
            "testStoreCount": {},
            "lastPanic": {}
        }}"#,
        heap_used,
        heap_total,
        (heap_used as f64 / heap_total as f64) * 100.0,
        state.request_count,
        state.logs.len(),
        state.echo_history.len(),
        state.test_store.len(),
        state.last_panic.as_ref().map(|p| format!("\"{}\"", escape_json_string(p))).unwrap_or_else(|| "null".to_string())
    )
}

fn handle_log(json: &str) -> String {
    let level = json_get_string(json, "level").unwrap_or("info");
    let message = json_get_string(json, "message").unwrap_or("");
    
    let state = get_state();
    state.tick += 1;
    
    let entry = LogEntry {
        level: level.to_string(),
        message: message.to_string(),
        timestamp: state.tick,
    };
    
    state.logs.push(entry);
    
    // Keep only last 500 logs
    if state.logs.len() > 500 {
        state.logs.remove(0);
    }
    
    format!(
        r#"{{"success":true,"logged":true,"level":"{}","timestamp":{}}}"#,
        level,
        state.tick
    )
}

fn handle_get_logs(json: &str) -> String {
    let limit = json_get_int(json, "limit").unwrap_or(50) as usize;
    let level_filter = json_get_string(json, "level");
    
    let state = get_state();
    
    let mut logs_json = String::from("[");
    let mut count = 0;
    
    for entry in state.logs.iter().rev() {
        if let Some(filter) = level_filter {
            if entry.level != filter {
                continue;
            }
        }
        
        if count >= limit {
            break;
        }
        
        if count > 0 {
            logs_json.push(',');
        }
        
        logs_json.push_str(&format!(
            r#"{{"level":"{}","message":"{}","timestamp":{}}}"#,
            entry.level,
            escape_json_string(&entry.message),
            entry.timestamp
        ));
        
        count += 1;
    }
    
    logs_json.push(']');
    
    format!(r#"{{"success":true,"logs":{},"count":{}}}"#, logs_json, count)
}

fn handle_clear_logs(_json: &str) -> String {
    let state = get_state();
    let count = state.logs.len();
    state.logs.clear();
    
    format!(r#"{{"success":true,"cleared":{}}}"#, count)
}

fn handle_perf_start(json: &str) -> String {
    let name = match json_get_string(json, "name") {
        Some(n) => n,
        None => return r#"{"error":"missing name"}"#.to_string(),
    };
    
    let state = get_state();
    state.tick += 1;
    
    let measurement = PerfMeasurement {
        name: name.to_string(),
        start_tick: state.tick,
        end_tick: None,
    };
    
    state.perf_measurements.insert(name.to_string(), measurement);
    
    format!(
        r#"{{"success":true,"started":"{}","startTick":{}}}"#,
        escape_json_string(name),
        state.tick
    )
}

fn handle_perf_end(json: &str) -> String {
    let name = match json_get_string(json, "name") {
        Some(n) => n,
        None => return r#"{"error":"missing name"}"#.to_string(),
    };
    
    let state = get_state();
    state.tick += 1;
    
    if let Some(measurement) = state.perf_measurements.get_mut(name) {
        measurement.end_tick = Some(state.tick);
        let duration = state.tick - measurement.start_tick;
        
        format!(
            r#"{{"success":true,"name":"{}","startTick":{},"endTick":{},"duration":{}}}"#,
            escape_json_string(name),
            measurement.start_tick,
            state.tick,
            duration
        )
    } else {
        format!(r#"{{"error":"measurement not found: {}"}}"#, escape_json_string(name))
    }
}

fn handle_perf_list(_json: &str) -> String {
    let state = get_state();
    
    let mut measurements_json = String::from("[");
    let mut first = true;
    
    for (name, m) in &state.perf_measurements {
        if !first {
            measurements_json.push(',');
        }
        first = false;
        
        let duration = m.end_tick.map(|e| e - m.start_tick);
        
        measurements_json.push_str(&format!(
            r#"{{"name":"{}","startTick":{},"endTick":{},"duration":{}}}"#,
            escape_json_string(name),
            m.start_tick,
            m.end_tick.map(|e| e.to_string()).unwrap_or_else(|| "null".to_string()),
            duration.map(|d| d.to_string()).unwrap_or_else(|| "null".to_string())
        ));
    }
    
    measurements_json.push(']');
    
    format!(r#"{{"success":true,"measurements":{}}}"#, measurements_json)
}

fn handle_store_set(json: &str) -> String {
    let key = match json_get_string(json, "key") {
        Some(k) => k,
        None => return r#"{"error":"missing key"}"#.to_string(),
    };
    
    let value = json_get_string(json, "value").unwrap_or("");
    
    let state = get_state();
    state.test_store.insert(key.to_string(), value.to_string());
    
    format!(
        r#"{{"success":true,"key":"{}","stored":true}}"#,
        escape_json_string(key)
    )
}

fn handle_store_get(json: &str) -> String {
    let key = match json_get_string(json, "key") {
        Some(k) => k,
        None => return r#"{"error":"missing key"}"#.to_string(),
    };
    
    let state = get_state();
    
    if let Some(value) = state.test_store.get(key) {
        format!(
            r#"{{"success":true,"key":"{}","value":"{}"}}"#,
            escape_json_string(key),
            escape_json_string(value)
        )
    } else {
        format!(r#"{{"success":true,"key":"{}","value":null}}"#, escape_json_string(key))
    }
}

fn handle_store_list(_json: &str) -> String {
    let state = get_state();
    
    let mut keys_json = String::from("[");
    let mut first = true;
    
    for key in state.test_store.keys() {
        if !first {
            keys_json.push(',');
        }
        first = false;
        keys_json.push_str(&format!("\"{}\"", escape_json_string(key)));
    }
    
    keys_json.push(']');
    
    format!(
        r#"{{"success":true,"keys":{},"count":{}}}"#,
        keys_json,
        state.test_store.len()
    )
}

fn handle_store_clear(_json: &str) -> String {
    let state = get_state();
    let count = state.test_store.len();
    state.test_store.clear();
    
    format!(r#"{{"success":true,"cleared":{}}}"#, count)
}

fn handle_memory_test(json: &str) -> String {
    let size_kb = json_get_int(json, "sizeKb").unwrap_or(10) as usize;
    let bytes = size_kb * 1024;
    
    // Try to allocate the requested memory
    let before = unsafe { HEAP_POS };
    let test_vec: Vec<u8> = vec![0xAB; bytes];
    let after = unsafe { HEAP_POS };
    
    // Verify the allocation
    let allocated = after - before;
    let first_byte = test_vec.first().copied().unwrap_or(0);
    let last_byte = test_vec.last().copied().unwrap_or(0);
    
    format!(
        r#"{{
            "success": true,
            "requestedBytes": {},
            "allocatedBytes": {},
            "heapBefore": {},
            "heapAfter": {},
            "firstByte": {},
            "lastByte": {},
            "verified": {}
        }}"#,
        bytes,
        allocated,
        before,
        after,
        first_byte,
        last_byte,
        first_byte == 0xAB && last_byte == 0xAB
    )
}

fn handle_trigger_panic(json: &str) -> String {
    let should_panic = json_get_string(json, "confirm") == Some("yes");
    
    if should_panic {
        panic!("Intentional panic triggered by debug module");
    }
    
    r#"{"success":true,"message":"Panic not triggered. Set confirm=yes to actually panic."}"#.to_string()
}

fn handle_reset(_json: &str) -> String {
    let state = get_state();
    
    let old_request_count = state.request_count;
    
    state.logs.clear();
    state.perf_measurements.clear();
    state.echo_history.clear();
    state.test_store.clear();
    state.last_panic = None;
    state.tick = 0;
    state.request_count = 0;
    
    format!(
        r#"{{"success":true,"message":"State reset","previousRequestCount":{}}}"#,
        old_request_count
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
        // Basic operations
        "echo" => handle_echo(json_str),
        "info" | "status" => handle_info(json_str),
        
        // Logging
        "log" => handle_log(json_str),
        "getLogs" | "logs" => handle_get_logs(json_str),
        "clearLogs" => handle_clear_logs(json_str),
        
        // Performance
        "perfStart" | "perf_start" => handle_perf_start(json_str),
        "perfEnd" | "perf_end" => handle_perf_end(json_str),
        "perfList" | "perf_list" => handle_perf_list(json_str),
        
        // Test store
        "storeSet" | "set" => handle_store_set(json_str),
        "storeGet" | "get" => handle_store_get(json_str),
        "storeList" | "list" => handle_store_list(json_str),
        "storeClear" => handle_store_clear(json_str),
        
        // Memory testing
        "memoryTest" | "memory_test" => handle_memory_test(json_str),
        
        // Danger zone
        "triggerPanic" | "panic" => handle_trigger_panic(json_str),
        "reset" => handle_reset(json_str),
        
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
