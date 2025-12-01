# IPFS Module v2.0.0

Self-contained IPFS module for CryftTEE with embedded Iroh node (default) or optional kubo support.

## Architecture

```
ipfs_v1/
├── src/
│   └── lib.rs              # WASM module (request validation, host calls)
├── native/
│   ├── Cargo.toml          # Native binary dependencies (iroh, tokio, axum)
│   └── src/
│       └── main.rs         # Iroh daemon with kubo-compatible HTTP API
├── gui/
│   ├── index.html          # Main UI shell with sidebar navigation
│   ├── styles.css          # CryftTEE-themed styles
│   └── js/
│       ├── app.js          # Main application logic
│       ├── api.js          # IPFS API client
│       ├── config.js       # Configuration
│       ├── utils.js        # Utility functions
│       └── pages/          # UI pages
│           ├── status.js   # Node status & control
│           ├── files.js    # File browser
│           ├── explore.js  # CID explorer
│           ├── peers.js    # Peer management
│           ├── pins.js     # Pin management
│           ├── ipns.js     # IPNS keys & publishing
│           └── settings.js # Node settings
├── module.json             # Module manifest
└── README.md               # This file
```

## How It Works

1. **WASM Module** (`src/lib.rs`)
   - Validates requests and generates `HostCall` instructions
   - Runs inside CryftTEE runtime sandbox
   - Pure request generation - no networking

2. **Native Binary** (`native/ipfs-node`)
   - Embedded Iroh node providing kubo-compatible API
   - Runs as subprocess managed by the runtime
   - Handles actual IPFS networking, storage, DHT

3. **Communication Flow**
   ```
   GUI → WASM Module → HostCall → Runtime → Native Binary → IPFS Network
                                     ↓
                              HTTP API (localhost:5001)
   ```

## Backend Options

### Iroh (Default)
- **No external dependencies** - Iroh node ships with the module
- Modern Rust implementation, fast QUIC transport
- Automatic startup/shutdown with the module
- Data stored in `~/.cryfttee/ipfs`

### Kubo (Optional)
- Use your existing kubo (go-ipfs) daemon
- Full IPNS support, mature DHT implementation
- Set `backend: "kubo"` in config

### Auto-Detect
- Default behavior: checks if kubo is running on port 5001
- Uses kubo if available, otherwise starts embedded Iroh

## Configuration

```json
{
  "backend": "auto",          // "iroh", "kubo", or "auto"
  "api_url": "http://127.0.0.1:5001",
  "gateway_url": "http://127.0.0.1:8080",
  "public_gateway": "https://gateway.cryft.network",
  "data_dir": "~/.cryfttee/ipfs",
  "timeout_secs": 60
}
```

## Building

### WASM Module
```bash
cd modules/ipfs_v1
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/ipfs_v1.wasm ./module.wasm
```

### Native Binary
```bash
cd modules/ipfs_v1/native
cargo build --release
# Binary at: native/target/release/ipfs-node
```

## API Endpoints

The native binary exposes a kubo-compatible API:

| Endpoint | Description |
|----------|-------------|
| `POST /api/v0/id` | Node identity |
| `POST /api/v0/add` | Add content |
| `POST /api/v0/cat` | Get content |
| `POST /api/v0/pin/add` | Pin content |
| `POST /api/v0/pin/rm` | Unpin content |
| `POST /api/v0/pin/ls` | List pins |
| `POST /api/v0/name/publish` | Publish to IPNS |
| `POST /api/v0/key/list` | List IPNS keys |
| `POST /api/v0/swarm/peers` | List peers |
| `POST /api/v0/repo/stat` | Repository stats |
| `GET /ipfs/:cid` | Gateway fetch |

## GUI Features

The module includes a web GUI with:

- **Status Page**: Node control, peer count, storage stats
- **Files Page**: Upload, browse, download files
- **Explore Page**: CID lookup with gateway preview
- **Peers Page**: Connected peers, bootstrap management
- **Pins Page**: Pin management with search
- **IPNS Page**: Key management, publishing
- **Settings Page**: Backend selection, configuration

## Limitations

### Iroh Backend
- IPNS resolution not yet supported (publish is local-only)
- CID format is blake3-based, different from IPFS CIDv0/v1
- No MFS (mutable filesystem) support

### Both Backends
- Large file streaming requires chunked handling
- No IPLD/DAG advanced operations yet

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IPFS_DATA_DIR` | Data directory | `~/.cryfttee/ipfs` |
| `IPFS_API_PORT` | API port | `5001` |
| `IPFS_GATEWAY_PORT` | Gateway port | `8080` |
| `IPFS_API_ADDR` | Bind address | `127.0.0.1` |
| `IPFS_PUBLIC_GATEWAY` | Public gateway URL | `https://gateway.cryft.network` |

## License

MIT License - Cryft Labs 2025
