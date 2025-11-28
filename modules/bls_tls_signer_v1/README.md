# BLS/TLS Signing Module v1

This is a placeholder for the compiled WASM module.

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

- `0` = Persistent (stored in Web3Signer)
- `1` = Ephemeral (in-memory only)
- `2` = Import (import existing key material)

## Return Codes

- `0` = Success
- `-1` = Invalid parameter
- `-2` = Key not found
- `-3` = Signing error
- `-4` = Web3Signer communication error

## Optional GUI

Modules can optionally provide a web GUI that will be rendered as a tab in the Cryftee kiosk UI. To enable this:

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

