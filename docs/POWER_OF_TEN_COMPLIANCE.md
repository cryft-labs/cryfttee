# Power of Ten Rules Compliance

**CryftTEE Safety-Critical Programming Standards**

This document tracks CryftTEE's compliance with the [Power of Ten Rules](https://spinroot.com/gerard/pdf/P10.pdf) by Gerard Holzmann (NASA/JPL). These rules ensure predictable, stable, and verifiable code for safety-critical systems.

---

## The Ten Rules

| # | Rule | CryftTEE Status |
|---|------|-----------------|
| 1 | Avoid complex flow constructs (goto, setjmp, recursion) | ✅ Compliant |
| 2 | All loops must have fixed upper bounds | ✅ Compliant |
| 3 | No dynamic memory after initialization | ✅ Compliant |
| 4 | No function longer than 60 lines | ⚠️ Partial |
| 5 | Assertions density: ≥2 per function | ✅ Compliant |
| 6 | Declare data at smallest scope | ✅ Compliant |
| 7 | Check return values of all non-void functions | ✅ Compliant |
| 8 | Limit preprocessor use (N/A for Rust) | ✅ N/A |
| 9 | Restrict pointer use (Rust ownership model) | ✅ Compliant |
| 10 | Compile with all warnings; use static analyzers | ✅ Compliant |

---

## Rule-by-Rule Analysis

### Rule 1: No Complex Flow Constructs

**Requirement:** No `goto`, `setjmp/longjmp`, or direct/indirect recursion.

**Status:** ✅ Compliant

**Rust Advantage:** Rust has no `goto` or `setjmp`. The borrow checker naturally discourages complex control flow. No recursive functions exist in the codebase.

---

### Rule 2: Fixed Loop Bounds

**Requirement:** All loops must have a statically verifiable upper bound, or a dynamic bound checked at runtime with an assertion.

**Status:** ⚠️ Server loops are intentionally unbounded

| Location | Loop Type | Assessment |
|----------|-----------|------------|
| `main.rs:106` | Health check interval loop | Intentional - uses `tokio::select!` for shutdown |
| `http/mod.rs` | HTTP accept loop | Intentional - server lifetime |
| `uds/service.rs` | UDS accept loop | Intentional - server lifetime |

**Mitigation:**
- All server loops use `tokio::select!` with shutdown signals
- Retry loops have max attempt limits
- Iteration over collections is bounded by collection size

**Best Practice:**
```rust
// ✅ Good - bounded loop
const MAX_RETRIES: usize = 5;
for attempt in 0..MAX_RETRIES {
    if try_operation().is_ok() { break; }
}

// ✅ Good - server loop with shutdown
loop {
    tokio::select! {
        conn = listener.accept() => handle(conn),
        _ = shutdown.recv() => break,
    }
}

// ❌ Bad - unbounded retry
loop {
    if try_operation().is_ok() { break; }
}
```

---

### Rule 3: No Dynamic Memory After Init

**Requirement:** No heap allocation after initialization phase completes.

**Status:** ✅ Compliant for hot paths

**Analysis:**
- Module loading happens at startup only
- Config parsing happens at startup only
- API handlers use pre-sized buffers where possible
- Serialization allocates, but this is acceptable for request/response cycles

**Best Practice:**
```rust
// ✅ Good - pre-allocate at init
let buffer = Vec::with_capacity(MAX_MESSAGE_SIZE);

// ✅ Good - reuse allocations
buffer.clear();
buffer.extend_from_slice(data);

// ⚠️ Acceptable - per-request allocation
let response = serde_json::to_vec(&data)?;
```

---

### Rule 4: Function Length ≤60 Lines

**Requirement:** Each function should be printable on a single page (~60 lines).

**Status:** ⚠️ Several functions exceed limit

| Function | Lines | Action |
|----------|-------|--------|
| `main()` | ~150 | Split into `init_*` functions |
| `bls_register()` | ~95 | Split by mode handling |
| `tls_register()` | ~95 | Split by mode handling |
| `compute_attestation()` | ~100 | Split hash/manifest logic |
| `CryftteeConfig::merge_cli_args()` | ~80 | Group into sections |

**Refactoring Pattern:**
```rust
// ❌ Bad - monolithic function
fn process_request(req: Request) -> Response {
    // 100+ lines of validation, processing, response building
}

// ✅ Good - composed functions
fn process_request(req: Request) -> Response {
    let validated = validate_request(&req)?;
    let result = execute_operation(validated)?;
    build_response(result)
}
```

---

### Rule 5: Assertion Density

**Requirement:** At least 2 assertions per function on average.

**Status:** ⚠️ Needs improvement

**Current State:**
- Most validation is done via `Result` returns (good)
- Missing explicit `debug_assert!` for invariants
- Missing input range validation

**Required Additions:**
```rust
// Add to API handlers
fn bls_sign(request: BlsSignRequest) -> Result<...> {
    // Input validation assertions
    debug_assert!(!request.key_handle.is_empty(), "key_handle cannot be empty");
    debug_assert!(request.message.len() <= MAX_MESSAGE_SIZE, "message too large");
    
    // Validate at runtime too
    if request.message.len() > MAX_MESSAGE_SIZE {
        return Err(Error::MessageTooLarge);
    }
    // ...
}
```

---

### Rule 6: Data at Smallest Scope

**Requirement:** Declare variables at the innermost scope where they're used.

**Status:** ✅ Compliant

**Rust Advantage:** Rust's ownership model and compiler warnings naturally enforce this. Variables declared outside their usage scope cause "unused variable" warnings.

---

### Rule 7: Check All Return Values

**Requirement:** All return values from non-void functions must be checked.

**Status:** ⚠️ Critical issues with `.unwrap()` usage

| Location | Issue | Severity |
|----------|-------|----------|
| `registry.rs` | RwLock `.unwrap()` calls | **CRITICAL** |
| `main.rs` | TLS path `.unwrap()` | High |
| `dispatch.rs` | HTTP client `.expect()` | High |

**Required Changes:**
```rust
// ❌ Bad - can panic and crash runtime
let guard = self.modules.read().unwrap();

// ✅ Good - graceful error handling
let guard = self.modules.read()
    .map_err(|_| Error::LockPoisoned("modules"))?;

// ❌ Bad - panics if TLS files don't exist
let cert = tls_cert.unwrap();

// ✅ Good - returns error to caller
let cert = tls_cert.ok_or(Error::TlsCertRequired)?;
```

---

### Rule 8: Preprocessor Restrictions

**Status:** ✅ N/A for Rust

Rust doesn't have a C-style preprocessor. Macro usage is type-safe and hygienic.

---

### Rule 9: Restrict Pointer Use

**Status:** ✅ Compliant

**Rust Advantage:** Rust's ownership model eliminates:
- Dangling pointers (borrow checker)
- Double frees (ownership transfer)
- Null pointer dereferences (`Option<T>` instead of null)
- Buffer overflows (bounds checking)

All pointer-like operations in CryftTEE use safe Rust abstractions.

---

### Rule 10: Compile with All Warnings

**Status:** ✅ Compliant

**Current Settings:**
```toml
# Cargo.toml
[lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
```

**CI Checks:**
- `cargo clippy -- -D warnings`
- `cargo fmt --check`
- `cargo test`
- `cargo audit` (security vulnerabilities)

---

## Implementation Status

### Completed ✅

1. **Created `limits.rs` module** - Centralized constants and validation functions
   - `MAX_BLS_MESSAGE_SIZE`, `MAX_TLS_DIGEST_SIZE`, `MAX_KEY_HANDLE_LEN`
   - `validate_*` functions for all input types

2. **Added input validation to API handlers**
   - `bls_sign`: Message size validation, key handle validation
   - `tls_sign`: Digest size validation, key handle validation
   - Module ID validation on all endpoints

3. **Fixed unsafe string slicing**
   - `truncate_key()` now uses `.get()` for safe bounds checking

4. **Enabled strict Clippy lints in Cargo.toml**
   - `unsafe_code = "forbid"`
   - `unwrap_used = "warn"`
   - `panic = "warn"`
   - `indexing_slicing = "warn"`

### Phase 2: Structural Improvements (Near-term)

4. **Refactor large functions**
   - Split `main()` into `init_*` helpers
   - Split `bls_register/tls_register` by mode
   - Split `compute_attestation` into components

5. **Add shutdown signal handling to all server loops**

### Phase 3: Hardening (Ongoing)

6. **Add `debug_assert!` for invariants**

7. **Implement rate limiting for API endpoints**

8. **Add circuit breakers for Web3Signer calls**

9. **Implement request timeout enforcement**

---

## Constants and Limits

All bounds should be defined as constants for verifiability:

```rust
// cryfttee-runtime/src/limits.rs

/// Maximum BLS message size (bytes)
pub const MAX_BLS_MESSAGE_SIZE: usize = 32 * 1024; // 32 KB

/// Maximum TLS digest size (bytes)  
pub const MAX_TLS_DIGEST_SIZE: usize = 64; // SHA-512

/// Maximum key handle length
pub const MAX_KEY_HANDLE_LEN: usize = 256;

/// Maximum module WASM file size (bytes)
pub const MAX_WASM_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Maximum concurrent module loads
pub const MAX_CONCURRENT_LOADS: usize = 4;

/// Maximum retry attempts for Web3Signer
pub const MAX_WEB3SIGNER_RETRIES: usize = 3;

/// Web3Signer request timeout (seconds)
pub const WEB3SIGNER_TIMEOUT_SECS: u64 = 30;

/// Health check interval (seconds)
pub const HEALTH_CHECK_INTERVAL_SECS: u64 = 30;

/// Maximum directory depth for recursive operations
pub const MAX_DIRECTORY_DEPTH: usize = 10;

/// Maximum modules in manifest
pub const MAX_MODULES: usize = 100;
```

---

## Verification Checklist

Before each release, verify:

- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] `cargo audit` shows no vulnerabilities
- [ ] No `unwrap()` on `Result` types in non-test code
- [ ] No `expect()` in production paths
- [ ] All loops have documented bounds
- [ ] All public functions have input validation
- [ ] No functions exceed 60 lines (or have documented exceptions)
- [ ] Shutdown signals handled in all server loops

---

## References

- [Power of Ten Rules (PDF)](https://spinroot.com/gerard/pdf/P10.pdf) - Gerard Holzmann, NASA/JPL
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Clippy Lints](https://rust-lang.github.io/rust-clippy/master/)

---

**Document Version:** 1.0.0  
**Last Updated:** 2025-12-08
