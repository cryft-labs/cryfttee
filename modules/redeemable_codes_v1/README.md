# Redeemable Codes Module

**On-Chain Managed Gift Code System**

Implementation of US Patent Application 20250139608: "Card System Utilizing On-Chain Managed Redeemable Gift Code"

## Overview

This module implements a dual smart contract system that separates gift code management into two distinct layers:

1. **Public Smart Contract** - Manages non-sensitive information (status, content assignments)
2. **Private Smart Contract** - Securely stores encrypted codes (hash+salt) in TEE

```
┌─────────────────────────────────────────────────────────────────┐
│                    Redeemable Code Architecture                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │    User      │───▶│   Public     │◀──▶│    Private       │  │
│  │  Interface   │    │   Contract   │    │    Contract      │  │
│  └──────────────┘    └──────────────┘    │    (in TEE)      │  │
│        │                    │             └──────────────────┘  │
│        │                    │                     │             │
│        │ Enter Code         │ Status/Content      │ Hash/Salt   │
│        │                    │ Management          │ Validation  │
│        ▼                    ▼                     ▼             │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                     CryftTEE Runtime                      │  │
│  │              (Trusted Execution Environment)              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Key Features

### Security
- Sensitive codes stored as hash+salt in private contract
- Private contract executed in Trusted Execution Environment (TEE)
- Public status management without exposing codes
- Cryptographic proof of ownership for management operations

### Transparency
- Anyone can verify code status via public contract
- Blockchain-recorded redemption transactions
- Immutable audit trail of status changes

### Flexibility
- Dynamic content assignment (tokens, NFTs, experiences, validator registration)
- Freeze/unfreeze for lost/stolen cards
- Batch operations for enterprise use
- Multiple redemption content types

## Code Structure (FIG. 17)

```
Gift Code: XXXX-YYYY-YYYY-YYYY
           ├──┘ └──────────────┘
           │          │
           │          └── Redeemable Portion (b)
           │              Validated against stored hash
           │
           └── Storage Index (a)
               Locates hash in private contract

Public Contract State:
┌────────────────────────────────────────┐
│ UID: 0x1234...abcd-0001                │
│ Status: active                          │
│ Content: { type: "token", ... }        │
│ Created: 1701388800                    │
└────────────────────────────────────────┘

Private Contract State (in TEE):
┌────────────────────────────────────────┐
│ Index: XXXX                            │
│ Hash: sha256(YYYY...YYYY + salt)       │
│ Salt: [random bytes]                   │
│ UID: 0x1234...abcd-0001               │
└────────────────────────────────────────┘
```

## Usage Examples

### Generate a Redeemable Code

```javascript
// Generate single code
const result = await module.call("generate_code", {
  managerAddress: "0x1234...abcd",
  content: {
    type: "token",
    tokenType: "nft",
    contractAddress: "0xNFT...",
    tokenId: "42"
  },
  metadata: {
    artwork: "ipfs://Qm...",
    description: "Limited Edition NFT"
  }
});

// Returns:
// {
//   giftCode: { index: "A1B2", code: "C3D4E5F6G7H8" },
//   uid: "0x1234...abcd-0001",
//   formattedCode: "A1B2-C3D4-E5F6-G7H8"
// }
```

### Activate a Code for Redemption

```javascript
// Code starts frozen by default
// Retailer activates when sold
await module.call("unfreeze_code", {
  uid: "0x1234...abcd-0001"
});
```

### Redeem a Code

```javascript
const redemption = await module.call("redeem_code", {
  code: "A1B2-C3D4-E5F6-G7H8",
  redeemerAddress: "0xRedeemer..."
});

// Returns:
// {
//   success: true,
//   uid: "0x1234...abcd-0001",
//   content: { type: "token", ... },
//   txHash: "0x..."
// }
```

### Check Code Status (Public Verification)

```javascript
const status = await module.call("get_status", {
  uid: "0x1234...abcd-0001"
});

// Returns:
// {
//   uid: "0x1234...abcd-0001",
//   status: "active",
//   content: { ... },
//   metadata: { ... }
// }
```

### Report Lost/Stolen Card

```javascript
await module.call("report_lost", {
  uid: "0x1234...abcd-0001",
  ownershipProof: "signature...",
  reason: "Card stolen from wallet"
});
// Code is immediately frozen
```

### Validator Registration Redemption

```javascript
// Special redemption type for Cryft validators
const result = await module.call("redeem_for_validator", {
  code: "A1B2-C3D4-E5F6-G7H8",
  nodeId: "NodeID-ABC123...",
  redeemerAddress: "0xValidator..."
});
```

## Content Types

| Type | Description | Use Case |
|------|-------------|----------|
| `wallet_access` | Access to smart contract wallet | Multi-sig wallet access |
| `private_key` | Encrypted private key | Direct wallet ownership |
| `token` | NFT or ERC20 transfer | Digital collectibles, rewards |
| `experience` | External API trigger | Event tickets, game items |
| `validator_registration` | Cryft validator setup | Network participation |
| `custom` | Generic payload | Any custom integration |

## Status Flow (FIG. 15)

```
                    ┌──────────┐
                    │  FROZEN  │◀─── Default State
                    │(default) │
                    └────┬─────┘
                         │
              unfreeze() │
                         ▼
                    ┌──────────┐
         ┌─────────│  ACTIVE  │─────────┐
         │         └────┬─────┘         │
         │              │               │
  freeze()│       redeem()│        revoke()│
         │              │               │
         ▼              ▼               ▼
    ┌──────────┐  ┌──────────┐   ┌──────────┐
    │  FROZEN  │  │ REDEEMED │   │ REVOKED  │
    └──────────┘  └──────────┘   └──────────┘
```

## Batch Operations

For enterprise/retailer use:

```javascript
// Batch generate 100 codes
const codes = await module.call("generate_batch", {
  managerAddress: "0x...",
  count: 100,
  content: { type: "token", ... }
});

// Batch activate when stock received
await module.call("batch_unfreeze", {
  uids: ["uid1", "uid2", "uid3", ...]
});
```

## Integration with Cryft Network

This module integrates with the broader Cryft ecosystem:

- **Validator Registration**: Redeem codes for instant validator setup
- **Staking Rewards**: Codes can unlock staking positions
- **NFT Collections**: Issue collectibles via redeemable codes
- **Event Access**: Ticket-based redemption for network events

## Patent Reference

This implementation is based on:

**US Patent Application 20250139608**
- Title: Card System Utilizing On-Chain Managed Redeemable Gift Code
- Filed: October 29, 2024
- Publication: May 01, 2025
- Inventor: Scully, Chad G.
- Applicant: Wood Brothers Steel Stamping Company

Key innovations:
- Dual smart contract architecture (public + private)
- TEE-based private contract execution
- Dynamic content assignment
- Blockchain-verified status management

## Building

```bash
# Build WASM module
cargo build --release --target wasm32-unknown-unknown

# Output: target/wasm32-unknown-unknown/release/redeemable_codes_v1.wasm
```

## License

MIT License - Cryft Labs 2024

Patent rights reserved per US Application 20250139608.
