# IPFS Local Node Module (ipfs_v1)

Self-contained IPFS module with **LOCAL pinning only** - connects to a local kubo daemon, no external pinning services.

## Features

- **Local Pinning**: All pins stored on your local IPFS node
- **Content Management**: Add, pin, unpin, search, and list content
- **IPNS Support**: Publish and resolve IPNS names
- **Gateway URLs**: Generate shareable URLs via `gateway.cryft.network`
- **Key Management**: Create and manage IPNS keys
- **Node Status**: Monitor local IPFS daemon health

## Prerequisites

### Local IPFS Node (kubo)

This module requires a running IPFS daemon. Install kubo (formerly go-ipfs):

**Linux/macOS:**
```bash
# Install kubo
wget https://dist.ipfs.tech/kubo/v0.27.0/kubo_v0.27.0_linux-amd64.tar.gz
tar xzf kubo_v0.27.0_linux-amd64.tar.gz
sudo mv kubo/ipfs /usr/local/bin/

# Initialize and start
ipfs init
ipfs daemon
```

**Docker:**
```bash
docker run -d --name ipfs \
  -p 5001:5001 \
  -p 8080:8080 \
  -v ipfs_data:/data/ipfs \
  ipfs/kubo:latest
```

**Windows:**
```powershell
# Download from https://dist.ipfs.tech/kubo/
# Extract and add to PATH, then:
ipfs init
ipfs daemon
```

## Capabilities

| Capability | Description |
|------------|-------------|
| `ipfs_pin` | Pin content by CID to local node |
| `ipfs_unpin` | Unpin content from local node |
| `ipfs_add` | Add new content to IPFS |
| `ipfs_get` / `ipfs_cat` | Fetch content from IPFS |
| `ipfs_ls` | List all local pins |
| `ipfs_search` | Search pins by name, CID, or tags |
| `ipfs_stat` | Get object statistics |
| `ipns_publish` | Publish CID to IPNS name |
| `ipns_resolve` | Resolve IPNS name to CID |
| `ipns_keys` | List or generate IPNS keys |
| `node_status` | Check if local node is online |
| `node_id` | Get node peer ID and info |

## Configuration

Default settings (configurable via GUI or API):

| Setting | Default Value | Description |
|---------|---------------|-------------|
| API URL | `http://127.0.0.1:5001` | Local kubo API endpoint |
| Local Gateway | `http://127.0.0.1:8080` | Local gateway for content retrieval |
| Public Gateway | `https://gateway.cryft.network` | Public gateway for shareable URLs |
| Timeout | 60 seconds | Request timeout |
| Max Add Size | 100 MB | Maximum file size for add operations |

## API Examples

### Pin Content

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "ipfs_pin",
    "data": {
      "cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
      "name": "my-content",
      "recursive": true,
      "tags": {"type": "module", "version": "1.0.0"}
    }
  }'
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
      "cidVersion": 1
    }
  }'
```

### List Pins

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "ipfs_ls",
    "data": {"pinType": "recursive"}
  }'
```

### Publish to IPNS

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "ipns_publish",
    "data": {
      "cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
      "key": "self",
      "ttl": 3600,
      "lifetime": 86400
    }
  }'
```

### Resolve IPNS

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "ipns_resolve",
    "data": {"name": "k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8"}
  }'
```

### Check Node Status

```bash
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{"operation": "node_status", "data": {}}'
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
│  │         RuntimeAction Generator       │               │
│  └────────┬─────────────────────────────┘               │
│           │ IpfsApiCall                                  │
├───────────▼──────────────────────────────────────────────┤
│  IPFS Backend (Runtime)                                  │
│  ┌─────────────────┐  ┌─────────────────┐               │
│  │ Local Metadata  │  │ HTTP Client     │               │
│  │ Database (JSON) │  │ (reqwest)       │               │
│  └─────────────────┘  └────────┬────────┘               │
└─────────────────────────────────┼────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   Local kubo Daemon     │
                    │   http://127.0.0.1:5001 │
                    └─────────────────────────┘
```

## Local-Only Design

This module intentionally does **NOT** use:
- External pinning services (Pinata, Infura, etc.)
- Remote pin APIs
- Third-party storage backends

**Why local-only?**

1. **Privacy**: Content stays on your infrastructure
2. **Control**: No dependence on external services
3. **Cost**: No pinning service fees
4. **Security**: Keys and content under your control

**Trade-offs:**
- Content only available when your node is online
- No automatic geographic distribution
- You manage storage and availability

## Gateway URLs

Content pinned locally can be shared via public gateways:

- **Local**: `http://127.0.0.1:8080/ipfs/<CID>`
- **Public**: `https://gateway.cryft.network/ipfs/<CID>`

Note: For content to be accessible via public gateways, your local node must be:
1. Online and reachable
2. Connected to the IPFS DHT
3. Serving the content to requesting peers

## GUI

The module includes a web GUI accessible at `/modules/ipfs_v1/gui/` with:

- **Local Pins**: Browse and manage pinned content
- **Add Content**: Upload files or pin existing CIDs
- **IPNS**: Publish and resolve IPNS names, manage keys
- **Node Info**: View local node status and addresses
- **Settings**: Configure API endpoints and gateways

## Building

```bash
cd modules/ipfs_v1
cargo build --target wasm32-unknown-unknown --release
```

The compiled WASM will be at:
`target/wasm32-unknown-unknown/release/ipfs_v1.wasm`

## Module Distribution via IPFS

This module enables CryftTEE to distribute WASM modules via IPFS:

1. **Publisher**: Builds and pins module to local IPFS, publishes to IPNS
2. **Registry**: Manifest references modules by CID
3. **Nodes**: Fetch modules from any IPFS gateway
4. **Verification**: CID is a content hash - inherent integrity check

### Publishing a Module

```bash
# Build the WASM module
cargo build --target wasm32-unknown-unknown --release

# Add and pin to local IPFS
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "ipfs_add",
    "data": {
      "content": "<base64-encoded-wasm>",
      "base64": true,
      "filename": "module.wasm",
      "pin": true,
      "name": "my_module_v1.0.0"
    }
  }'

# Publish to IPNS for mutable reference
curl -X POST http://localhost:3232/v1/modules/ipfs_v1/call \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "ipns_publish",
    "data": {"cid": "Qm...", "key": "my-module-key"}
  }'
```

## License

MIT License - Cryft Labs
