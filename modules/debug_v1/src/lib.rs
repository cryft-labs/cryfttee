//! Debug Module for Cryftee Runtime
//!
//! Provides debugging and diagnostics capabilities.

use std::alloc::{alloc, dealloc, Layout};

// Memory allocation exports for WASM host
#[no_mangle]
pub extern "C" fn allocate(size: usize) -> *mut u8 {
    let layout = Layout::from_size_align(size, 1).unwrap();
    unsafe { alloc(layout) }
}

#[no_mangle]
pub extern "C" fn deallocate(ptr: *mut u8, size: usize) {
    let layout = Layout::from_size_align(size, 1).unwrap();
    unsafe { dealloc(ptr, layout) }
}

/// Echo back the input - for connectivity testing
/// Input: JSON string, Output: same JSON string
#[no_mangle]
pub extern "C" fn debug_echo(input_ptr: *const u8, input_len: usize, output_ptr: *mut *mut u8, output_len: *mut usize) -> i32 {
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len) };
    
    // Allocate output and copy input
    let out = allocate(input_len);
    unsafe {
        std::ptr::copy_nonoverlapping(input.as_ptr(), out, input_len);
        *output_ptr = out;
        *output_len = input_len;
    }
    
    0 // Success
}

/// Return debug info about the module
#[no_mangle]
pub extern "C" fn debug_info(_input_ptr: *const u8, _input_len: usize, output_ptr: *mut *mut u8, output_len: *mut usize) -> i32 {
    let info = r#"{"module":"debug_v1","version":"1.0.0","status":"operational","capabilities":["debug_echo","debug_info","debug_panic"]}"#;
    let bytes = info.as_bytes();
    
    let out = allocate(bytes.len());
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        *output_ptr = out;
        *output_len = bytes.len();
    }
    
    0 // Success
}

/// Intentionally panic for testing error handling
#[no_mangle]
pub extern "C" fn debug_panic(_input_ptr: *const u8, _input_len: usize, _output_ptr: *mut *mut u8, _output_len: *mut usize) -> i32 {
    panic!("Intentional panic for debugging purposes");
}
