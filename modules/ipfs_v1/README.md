# CryftIPFS Module

**Unified IPFS Storage with Validator Pin Rewards**

A decentralized storage network where validators earn CRYFT tokens for pinning content that is registered on the Cryft blockchain.

## Overview

CryftIPFS combines standard IPFS functionality with blockchain-based storage incentives:

1. **Content Creators** can incentivize their content by depositing CRYFT tokens
2. **Validators** pin incentivized content and respond to storage challenges
3. **Proofs** are verified and rewards are distributed automatically

```
┌─────────────────────────────────────────────────────────────────┐
│                      CryftIPFS Architecture                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │   Content    │───▶│  Blockchain  │───▶│    Validators    │  │
│  │   Creator    │    │   Registry   │    │   (IPFS Nodes)   │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│        │                    │                     │             │
│        │ Deposit            │ Track               │ Pin         │
│        │ CRYFT              │ Incentives          │ Content     │
│        ▼                    ▼                     ▼             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ Incentivized │    │   Storage    │    │     Rewards      │  │
│  │     Pin      │───▶│  Challenges  │───▶│    (nCRYFT)      │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Features

### Standard IPFS Operations
- `add` - Add content to IPFS
- `cat`/`get` - Retrieve content by CID
- `pin`/`unpin` - Manage local pins
- `pin_ls` - List pins (optionally filter incentivized only)
- `swarm_peers` - View connected peers
- `repo_stat` - Storage statistics

### Validator Reward Operations
- `validator_stats` - View validator statistics (pins, rewards, challenges)
- `incentivized_list` - List all network-wide incentivized pins
- `incentivize_pin` - Register new incentivized content (requires deposit)
- `storage_challenge` - Respond to proof-of-storage challenges
- `claim_rewards` - Claim earned rewards

## Reward Tiers

| Tier | Multiplier | Use Case |
|------|------------|----------|
| Basic | 1x | General content storage |
| Standard | 2x | Important data |
| Priority | 5x | High-availability content |
| Critical | 10x | Infrastructure-critical data |

## Usage Examples

### Start Node as Validator
```javascript
// Start node with validator ID for reward tracking
await module.call("node_start", {
  validatorId: "NodeID-ABC123...",
  maxStorageGb: 500,
  rpcUrl: "http://localhost:9650"
});
```

### Add & Pin Incentivized Content
```javascript
// Add content with incentive flag
const result = await module.call("add", {
  content: "Important data...",
  pin: true,
  incentivize: true,
  tier: "priority"
});
// Returns: { hash: "bafybeig...", size: "1234" }
```

### Register Network-Wide Incentive
```javascript
// Sponsor content for network-wide pinning
await module.call("incentivize", {
  cid: "bafybeig...",
  minReplicas: 10,
  rewardPerEpoch: 1000000, // nCRYFT per hour
  tier: "standard",
  rewardPool: 100000000,   // Total budget
  expiresAt: 0             // Never expires
});
```

### Check Validator Stats
```javascript
const stats = await module.call("validator_stats");
// Returns:
// {
//   totalPins: 150,
//   incentivizedPins: 45,
//   storageUsed: 52428800000,  // 50GB
//   challengesPassed: 1234,
//   totalRewardsEarned: 5000000000, // 5 CRYFT
//   pendingRewards: 50000000
// }
```

### Claim Rewards
```javascript
const claim = await module.call("claim_rewards");
// Returns:
// {
//   validatorId: "NodeID-ABC123",
//   epoch: 12345,
//   challengesPassed: 50,
//   rewardAmount: 50000000,  // nCRYFT
//   message: "Reward claim submitted"
// }
```

## Storage Challenges

Validators must respond to periodic **proof-of-storage** challenges to earn rewards:

1. A random byte range is requested from pinned content
2. Validator computes hash of that range
3. Proof is submitted and verified
4. Rewards accumulate for valid proofs

```javascript
// Respond to challenge (usually automatic)
const proof = await module.call("challenge", {
  cid: "bafybeig...",
  offset: 1024,
  length: 256
});
// Returns:
// {
//   challengeId: "bafybeig-1024-1234567890",
//   chunkHash: "abc123...",
//   provenAt: 1234567890
// }
```

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `api_url` | `http://127.0.0.1:5001` | IPFS API endpoint |
| `gateway_url` | `http://127.0.0.1:8080` | IPFS Gateway endpoint |
| `validator_id` | - | Validator node ID (required for rewards) |
| `rpc_url` | `http://127.0.0.1:9650` | Blockchain RPC for reward claims |
| `max_storage_gb` | 100 | Maximum storage allocation |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CryftTEE Runtime                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────────┐       ┌─────────────────────────┐ │
│  │   WASM Module   │       │    Native Binary        │ │
│  │  (lib.rs)       │──────▶│    (cryft-ipfs)         │ │
│  │                 │       │                         │ │
│  │ • Request       │       │ • Iroh IPFS Engine      │ │
│  │   validation    │       │ • Pin Registry          │ │
│  │ • HostCall      │       │ • Challenge Handler     │ │
│  │   generation    │       │ • Reward Tracker        │ │
│  └─────────────────┘       └─────────────────────────┘ │
│           │                          │                  │
│           ▼                          ▼                  │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Cryft Blockchain                    │   │
│  │  • Incentivized Pin Registry                    │   │
│  │  • Reward Distribution                          │   │
│  │  • Challenge Verification                       │   │
│  └─────────────────────────────────────────────────┘   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Building

```bash
# Build WASM module
cargo build --release --target wasm32-unknown-unknown

# Build native binary
cd native
cargo build --release
```

## API Endpoints (Native Binary)

The native binary exposes both kubo-compatible and Cryft extension endpoints:

### Standard IPFS API (`/api/v0/...`)
- `POST /api/v0/add` - Add content
- `POST /api/v0/cat` - Get content
- `POST /api/v0/pin/add` - Pin content
- `POST /api/v0/pin/rm` - Unpin content
- `POST /api/v0/pin/ls` - List pins
- `GET /api/v0/id` - Node identity
- `GET /api/v0/repo/stat` - Repo stats

### Cryft Reward Extensions (`/api/v0/cryft/...`)
- `GET /api/v0/cryft/stats` - Validator statistics
- `GET /api/v0/cryft/incentivized` - List incentivized pins
- `POST /api/v0/cryft/incentivize` - Register incentive
- `POST /api/v0/cryft/challenge` - Respond to challenge
- `POST /api/v0/cryft/prove` - Submit proof
- `POST /api/v0/cryft/claim` - Claim rewards
- `GET /api/v0/cryft/proofs` - List pending proofs

### Gateway
- `GET /ipfs/{cid}` - Retrieve content via gateway

## License

MIT License - Cryft Labs 2024
