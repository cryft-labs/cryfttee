# IPFS Embedded Node Module (ipfs_v1) v2.0.0

Standalone IPFS module with **embedded node** - No external daemon required. Supports Full Node (default) or Light Node modes.

## Features

- **Embedded IPFS Node**: Runs a complete IPFS node within CryftTEE - no kubo required
- **Full Node Mode** (default): Complete DHT participation, content routing, block serving
- **Light Node Mode**: Minimal DHT, request-only, low resource usage
- **Local Pinning**: All pins stored on your embedded node
- **Content Management**: Add, pin, unpin, search, and list content
- **IPNS Support**: Publish and resolve IPNS names via DHT
- **Peer Management**: Connect/disconnect peers, DHT operations
- **Key Management**: Create and manage IPNS keys

## Node Modes

### Full Node (Default)

Complete IPFS node with:
- Full DHT server participation
- Content routing and providing
- Block serving to other peers
- Relay and NAT traversal support
- Higher bandwidth and storage usage

**Best for**: Servers, always-on machines, content providers

### Light Node

Lightweight IPFS client with:
- DHT client mode only (queries but doesn't serve DHT)
- Requests content but doesn't serve blocks
- Minimal peer connections
- Lower bandwidth and storage usage
- Delegates to gateways when needed

**Best for**: Laptops, mobile devices, limited bandwidth

## Capabilities

| Capability | Description |
|------------|-------------|
| `node_init` | Initialize embedded node |
| `node_start` | Start the embedded IPFS node |
| `node_stop` | Stop the embedded node |
| `node_status` | Get node status (running, peers, storage) |
| `node_config` | Get/set node configuration |
| `ipfs_add` | Add new content to IPFS |
| `ipfs_cat` / `ipfs_get` | Fetch content from IPFS |
| `ipfs_pin` | Pin content by CID |
| `ipfs_unpin` | Unpin content |
| `ipfs_ls` | List all local pins |
| `ipfs_stat` | Get object statistics |
| `ipns_publish` | Publish CID to IPNS name |
| `ipns_resolve` | Resolve IPNS name to CID |
| `ipns_keys` | List/generate IPNS keys |
| `peer_connect` | Connect to a peer |
| `peer_disconnect` | Disconnect from a peer |
| `peer_list` | List connected peers |
| `dht_find_peer` | Find peer addresses via DHT |
| `dht_find_providers` | Find content providers |
| `dht_provide` | Announce content to DHT |
| `block_get` / `block_put` / `block_stat` | Raw block operations |

## Configuration

| Setting | Default Value | Description |
|---------|---------------|-------------|
| Node Mode | `full` | `full` or `light` |
| Data Directory | `~/.cryfttee/ipfs` | Node storage location |
| Swarm Ports | TCP/UDP 4001 | libp2p swarm listeners |
| API Listen | `127.0.0.1:5001` | Local API endpoint |
| Gateway Listen | `127.0.0.1:8080` | Local gateway |
| Public Gateway | `https://gateway.cryft.network` | For shareable URLs |
| Max Storage | 50 GB | Storage limit |
| Max Connections | 900 | Peer connection limit |

## API Examples

### Start Node (Full Mode)

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "node_start",
    "data": {
      "config": {"node_type": "full"}
    }
  }'
```

### Start Node (Light Mode)

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "node_start",
    "data": {
      "config": {"node_type": "light"}
    }
  }'
```

### Get Node Status

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{"operation": "node_status", "data": {}}'
```

### Add Content

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "ipfs_add",
    "data": {
      "content": "Hello IPFS!",
      "filename": "hello.txt",
      "pin": true,
      "cid_version": 1
    }
  }'
```

### Pin Content

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "ipfs_pin",
    "data": {
      "cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
      "name": "my-content",
      "recursive": true
    }
  }'
```

### Connect to Peer

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "swarm_connect",
    "data": {
      "peer_addr": "/ip4/1.2.3.4/tcp/4001/p2p/QmPeerID..."
    }
  }'
```

### Find Content Providers

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "dht_findprovs",
    "data": {
      "cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
      "num_providers": 20
    }
  }'
```

### Publish to IPNS

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "ipns_publish",
    "data": {
      "cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
      "key": "self",
      "ttl_secs": 3600,
      "lifetime_secs": 86400
    }
  }'
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    CryftTEE Runtime                       │
├──────────────────────────────────────────────────────────┤
│  IPFS Module (WASM)                                      │
│  ┌─────────────────┐  ┌─────────────────┐               │
│  │ Request Parser  │  │ Response Builder│               │
│  └────────┬────────┘  └────────▲────────┘               │
│           │                    │                         │
│  ┌────────▼────────────────────┴────────┐               │
│  │       HostApiCall Generator           │               │
│  └────────┬─────────────────────────────┘               │
│           │                                              │
├───────────▼──────────────────────────────────────────────┤
│  IPFS Embedded Node (Runtime)                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  libp2p      │  │  Bitswap     │  │  DHT/Kad     │   │
│  │  Networking  │  │  Exchange    │  │  Routing     │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  Block Store │  │  Pin Manager │  │  IPNS Pub    │   │
│  │  (Local)     │  │              │  │  /Resolve    │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
└──────────────────────────────────────────────────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │   IPFS Network         │
              │   - DHT Peers          │
              │   - Bootstrap Nodes    │
              │   - Content Providers  │
              └────────────────────────┘
```

## Embedded vs External Daemon

| Feature | Embedded (v2.0) | External kubo (v1.x) |
|---------|-----------------|----------------------|
| Setup | Zero config | Install + init + start kubo |
| Dependencies | None | kubo daemon |
| Resource sharing | Integrated | Separate process |
| Node modes | Full/Light | Single mode |
| Portability | Complete | Requires kubo |
| Control | Full | Limited to API |

## GUI

The module includes a sidebar-style web GUI (similar to IPFS Desktop) at `/modules/ipfs_v1/gui/`:

### Structure

```
gui/
├── index.html          # Main shell with sidebar layout
├── styles.css          # CryftTEE-themed styles (~600 lines)
└── js/
    ├── config.js       # Configuration constants
    ├── utils.js        # Utility functions
    ├── api.js          # IPFS API wrapper
    ├── app.js          # Main application entry
    └── pages/
        ├── status.js   # Node status & control
        ├── files.js    # File browser & upload
        ├── explore.js  # CID explorer
        ├── peers.js    # Peer management
        ├── pins.js     # Pin management
        ├── ipns.js     # IPNS keys & publish
        └── settings.js # Configuration
```

### Pages

| Page | Description |
|------|-------------|
| **Status** | Node status, mode selection (Full/Light), stats, bandwidth |
| **Files** | File browser, drag & drop upload, folder management |
| **Explore** | Browse IPFS by CID, preview content, pin discoveries |
| **Peers** | Connected peers, bootstrap management, connect/disconnect |
| **Pins** | Pinned content list, search, filter by type, unpin |
| **IPNS** | Key management, publish to IPNS, resolve names |
| **Settings** | Network, storage, gateway, connection manager config |

### Features

- **Sidebar Navigation**: Click menu items to switch between pages
- **Live Status**: Sidebar shows node online/offline status
- **Storage Indicator**: Visual progress bar for storage usage
- **Responsive**: Works on mobile with collapsible sidebar
- **Theme**: Matches CryftTEE dashboard styling (light/dark mode)

## Building

```bash
cd modules/ipfs_v1
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/ipfs_v1.wasm module.wasm
```

## Migration from v1.x

If upgrading from v1.x (kubo-based):

1. Export your pins: `ipfs pin ls > pins.txt`
2. Stop kubo daemon
3. Update to v2.0 module
4. Start embedded node
5. Re-pin content (or import pins)

Note: Your kubo repository (`~/.ipfs`) is separate from the embedded node (`~/.cryfttee/ipfs`).

## License

MIT License - Cryft Labs
