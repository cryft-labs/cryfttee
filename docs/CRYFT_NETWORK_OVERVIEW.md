# Cryft Network Overview

## What is Cryft?

Cryft is a next-generation blockchain network designed for high-throughput, low-latency transactions with full Ethereum compatibility. Built on a streamlined two-chain architecture, Cryft aims to deliver Alpenglow-class speeds while maintaining the flexibility to support diverse subnet ecosystems.

---

## Core Architecture

### Two Primary Chains

Unlike networks with three or more chains, Cryft simplifies its architecture to two purpose-built chains:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CRYFT NETWORK                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────┐      ┌─────────────────────────────────────┐  │
│   │       P-Chain           │      │           X-EVM Chain               │  │
│   │   (Platform Chain)      │      │    (Execution/Exchange Chain)       │  │
│   ├─────────────────────────┤      ├─────────────────────────────────────┤  │
│   │ • Validator management  │      │ • Smart contracts (Solidity)        │  │
│   │ • Staking & delegation  │      │ • Full EVM compatibility            │  │
│   │ • Subnet creation       │      │ • Parallel transaction execution    │  │
│   │ • Network governance    │      │ • DeFi, NFTs, dApps                 │  │
│   │ • Cross-chain routing   │      │ • Ethereum JSON-RPC interface       │  │
│   └─────────────────────────┘      └─────────────────────────────────────┘  │
│                                                                             │
│                    ┌─────────────────────────────────┐                      │
│                    │         Subnets                 │                      │
│                    │  Custom chains with dedicated   │                      │
│                    │  validators, rules, and tokens  │                      │
│                    └─────────────────────────────────┘                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### P-Chain (Platform Chain)
- **Purpose**: Network coordination, staking, and subnet management
- **Consensus**: Snowman consensus for linear chain ordering
- **Functions**:
  - Validator registration and staking
  - Delegation management
  - Subnet creation and configuration
  - Cross-subnet messaging coordination

#### X-EVM Chain (Execution/Exchange Chain)
- **Purpose**: Smart contract execution with Ethereum compatibility
- **Interface**: Full Ethereum JSON-RPC support
- **Features**:
  - Solidity smart contracts
  - Parallel transaction processing
  - Sub-second finality (targeting Alpenglow speeds)
  - Native integration with existing Ethereum tooling (MetaMask, Hardhat, etc.)

---

## Core Components

### CryftGo

CryftGo is the primary node implementation for the Cryft network, written in Go. It handles:

- **Consensus participation** - Validates and proposes blocks
- **P2P networking** - Gossip protocol for transaction and block propagation
- **Chain state management** - Maintains blockchain state for both chains
- **API endpoints** - JSON-RPC, REST, and WebSocket interfaces
- **Subnet orchestration** - Manages subnet validator sets and cross-chain operations

### CryftTEE

CryftTEE is a secure sidecar runtime that provides trusted execution capabilities:

- **Key Management** - BLS and TLS key operations for staking
- **Module System** - WASM-based plugins for extensibility
- **Attestation** - Cryptographic proofs of runtime integrity
- **IPFS Integration** - Decentralized content pinning and distribution

CryftGo spawns and controls CryftTEE, passing configuration via environment variables.

```
┌──────────────┐     spawns      ┌──────────────┐
│   CryftGo    │ ──────────────▶ │  CryftTEE    │
│  (Go node)   │                 │ (Rust sidecar)│
│              │ ◀────────────── │              │
│              │   UDS/HTTPS     │  ┌─────────┐ │
│              │   API calls     │  │ Modules │ │
└──────────────┘                 │  └─────────┘ │
                                 └──────────────┘
```

---

## Staking & Rewards

### Validator Requirements

To become a validator on the Cryft network:

1. **Stake CRYFT tokens** on the P-Chain
2. **Register BLS keys** for consensus participation
3. **Run CryftGo + CryftTEE** with the staking module enabled
4. **Maintain uptime** to earn rewards

### Delegation

Token holders who don't want to run validators can delegate their stake:

- Delegate to any active validator
- Earn proportional rewards minus validator commission
- No minimum delegation amount (subject to change)
- Unbonding period for security

### Reward Distribution

Rewards are distributed based on:

- **Uptime** - Validators must maintain high availability
- **Stake weight** - Proportional to staked + delegated tokens
- **Chain integrity contributions** - Additional rewards for pinning and verification (see below)

---

## Chain Integrity & IPFS Pinning

### The Problem

Blockchain networks need to ensure:
- Historical data remains available
- State can be reconstructed and verified
- Fraud proofs can reference past data

### Cryft's Solution: Incentivized Pinning

Validators and node operators earn additional rewards for **pinning critical chain data** to IPFS:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     CHAIN INTEGRITY REWARDS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                   │
│   │  Block Data │ ──▶ │  IPFS Pin   │ ──▶ │  Prove Pin  │ ──▶ Earn Rewards │
│   │  (headers,  │     │  (via IPFS  │     │  (pinning   │                   │
│   │   receipts, │     │   module)   │     │   receipt)  │                   │
│   │   state)    │     │             │     │             │                   │
│   └─────────────┘     └─────────────┘     └─────────────┘                   │
│                                                                             │
│   What can be pinned:                                                       │
│   • Block headers and transaction receipts                                  │
│   • State snapshots at epoch boundaries                                     │
│   • Smart contract code and metadata                                        │
│   • Subnet genesis configurations                                           │
│   • Fraud proof evidence                                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **CryftTEE's IPFS Module** runs an embedded IPFS node
2. **Genesis pins** define required content that validators must pin
3. **Pinning receipts** are submitted to prove data availability
4. **Reward calculation** factors in pin duration, redundancy, and data criticality
5. **Verification** via random sampling ensures honest pinning

### Benefits

- **Data permanence** - Critical chain data persists even if some nodes go offline
- **Decentralized storage** - No single point of failure
- **Economic incentives** - Validators are rewarded for storage contributions
- **Fraud proof support** - Historical data available for dispute resolution

---

## Performance Targets

### Alpenglow-Class Speeds

Cryft aims to achieve performance comparable to the Avalanche Alpenglow upgrade:

| Metric | Target |
|--------|--------|
| Time to Finality | < 500ms |
| Transactions per Second | 10,000+ (X-EVM) |
| Block Time | ~250ms |
| Cross-Subnet Latency | < 2 seconds |

### Parallel Execution

The X-EVM chain supports parallel transaction execution:

- Transactions touching different state are executed concurrently
- Conflict detection ensures correctness
- Significant throughput improvements for DeFi and gaming workloads

---

## Ethereum Compatibility

### Full EVM Support

The X-EVM chain is fully compatible with Ethereum:

- **Solidity** - Deploy existing contracts unchanged
- **JSON-RPC** - Standard Ethereum API (eth_*, net_*, web3_*)
- **Tooling** - Works with MetaMask, Hardhat, Foundry, Truffle
- **Tokens** - ERC-20, ERC-721, ERC-1155 standards supported

### Migration Path

Moving from Ethereum to Cryft:

```bash
# Same deployment process, different RPC endpoint
npx hardhat run scripts/deploy.js --network cryft

# In hardhat.config.js
networks: {
  cryft: {
    url: "https://api.cryft.network/ext/bc/X/rpc",
    chainId: 43114,  // Cryft chain ID
    accounts: [PRIVATE_KEY]
  }
}
```

---

## Subnets

### What Are Subnets?

Subnets are independent blockchain networks that:

- Share Cryft's security through validator overlap
- Define custom rules, tokens, and consensus parameters
- Can be public or permissioned
- Interoperate via cross-subnet messaging

### Use Cases

| Subnet Type | Description |
|-------------|-------------|
| **Gaming** | High-TPS chains optimized for game logic |
| **Enterprise** | Permissioned chains for business consortiums |
| **DeFi** | Specialized chains for financial applications |
| **Compliance** | KYC-gated chains for regulated assets |

### Creating a Subnet

1. Define subnet parameters (validators, gas token, consensus)
2. Submit creation transaction on P-Chain
3. Validators opt-in to validate the subnet
4. Deploy contracts and launch

---

## Security Model

### BLS Signatures

Validators use BLS12-381 keys for:

- Block signing
- Consensus voting
- Aggregate signatures for efficiency

### TLS Authentication

Node-to-node communication uses TLS with:

- Certificate-based identity
- Mutual authentication
- Perfect forward secrecy

### Attestation

CryftTEE provides runtime attestation:

- Binary hash verification by CryftGo
- Module integrity checks
- Signed attestation receipts

---

## FAQs

### General

**Q: How is Cryft different from Avalanche?**
A: Cryft uses a simplified two-chain architecture (P-Chain + X-EVM) instead of three chains. We focus on Ethereum compatibility with parallel execution, targeting Alpenglow-class performance while incentivizing chain data availability through IPFS pinning rewards.

**Q: What consensus mechanism does Cryft use?**
A: Cryft uses Snowman consensus (similar to Avalanche) for the P-Chain and an optimized variant for X-EVM that supports parallel transaction execution.

**Q: Is Cryft EVM compatible?**
A: Yes, the X-EVM chain is fully compatible with Ethereum. You can deploy Solidity contracts and use standard Ethereum tools like MetaMask and Hardhat.

### Staking

**Q: How much do I need to stake to become a validator?**
A: Minimum stake requirements are still being finalized. Check the official documentation for current values.

**Q: What are the hardware requirements for validators?**
A: Validators need to run CryftGo and CryftTEE. Recommended specs include 8+ CPU cores, 32GB RAM, and 1TB SSD storage.

**Q: How do pinning rewards work?**
A: Validators earn additional rewards for pinning and serving chain data via IPFS. The IPFS module in CryftTEE handles pinning automatically, and rewards are distributed based on proven data availability.

### Development

**Q: Can I deploy my Ethereum dApp to Cryft?**
A: Yes, Ethereum smart contracts work on Cryft without modification. Just point your deployment tools to the Cryft RPC endpoint.

**Q: How do I create a subnet?**
A: Subnet creation involves staking tokens on the P-Chain and defining your subnet's parameters. Detailed guides are available in the developer documentation.

**Q: What programming languages can I use?**
A: Smart contracts use Solidity. CryftGo is written in Go, and CryftTEE modules can be written in Rust (compiled to WASM).

---

## Roadmap

### Phase 1: Foundation (Current)
- Core CryftGo and CryftTEE development
- P-Chain and X-EVM implementation
- Basic staking and delegation

### Phase 2: Pinning & Integrity
- IPFS module deployment
- Genesis pin configuration
- Pinning reward distribution

### Phase 3: Subnets & Scale
- Public subnet creation
- Cross-subnet messaging
- Parallel execution optimization

### Phase 4: Ecosystem Growth
- Developer tooling and SDKs
- Bridge integrations
- Enterprise partnerships

---

*This document provides a high-level overview. Technical specifications are subject to change as development progresses.*
