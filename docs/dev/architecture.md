# System Architecture

This document describes the architecture of witnessd, including component relationships, data flow, and design decisions.

## Table of Contents

- [Overview](#overview)
- [Architecture Diagram](#architecture-diagram)
- [Core Components](#core-components)
- [Data Flow](#data-flow)
- [Key Hierarchy](#key-hierarchy)
- [Storage Architecture](#storage-architecture)
- [Platform-Specific Components](#platform-specific-components)
- [Design Decisions](#design-decisions)

## Overview

Witnessd is a cryptographic authorship witnessing system composed of:

1. **CLI Application** (`rust/witnessd-cli`): Primary interface for checkpointing and verification
2. **Core Library** (`rust/witnessd-core`): Core logic for evidence creation and verification
3. **Platform Wrappers** (`platforms/`): Native GUI/daemon integrations (e.g. macOS App)

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              USER INTERFACES                                     │
├─────────────────────────────────┬───────────────────────────────────────────────┤
│         CLI (witnessd)          │           macOS App (WitnessdApp)             │
│  ┌─────────────────────────┐    │    ┌─────────────────────────────────────┐   │
│  │ rust/witnessd-cli/src   │    │    │ WitnessdApp.swift                   │   │
│  │ - init, commit, log     │    │    │ - Menu bar UI                       │   │
│  │ - export, verify        │    │    │ - Quick actions                     │   │
│  │ - track, calibrate      │    │    ├─────────────────────────────────────┤   │
│  │ - smart_defaults.rs     │    │    │ WitnessdBridge.swift                │   │
│  └─────────────────────────┘    │    │ - CLI subprocess wrapper            │   │
└──────────────┬──────────────────┴────┴─────────────────────────────────────────┘
               │                           │
               │ (Library Calls)           │ (JSON IPC / CLI)
               ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              CORE LIBRARY (witnessd-core)                        │
├───────────────────┬───────────────────┬───────────────────┬─────────────────────┤
│ src/config.rs     │ src/evidence.rs   │ src/store.rs      │ src/keyhierarchy    │
│ - Config loading  │ - Evidence packet │ - SecureStore     │ - Master identity   │
│ - Validation      │ - Declaration     │ - Integrity       │ - Session certs     │
│ - Defaults        │ - Export/import   │ - SQLite backend  │ - Ratchet keys      │
├───────────────────┼───────────────────┼───────────────────┼─────────────────────┤
│ src/vdf/          │ src/mmr/          │ src/wal.rs        │ src/checkpoint.rs   │
│ - VDF compute     │ - Merkle Mountain │ - Write-ahead log │ - Checkpoint chain  │
│ - VDF verify      │   Range           │ - Crash recovery  │ - Hash linking      │
│ - Calibration     │ - Inclusion proof │                   │ - Signatures        │
├───────────────────┼───────────────────┼───────────────────┼─────────────────────┤
│ src/jitter/       │ src/analysis/     │ src/sentinel/     │ src/presence/       │
│ - Keystroke logic │ - Forensics       │ - Background      │ - Presence verify   │
│ - Event capture   │ - Statistics      │   monitoring      │ - Challenges        │
│                   │ - Fingerprinting  │                   │ - Responses         │
├───────────────────┼───────────────────┼───────────────────┼─────────────────────┤
│ src/tpm/          │ src/anchors/      │ src/api.rs        │                     │
│ - Attestation     │ - RFC3161         │ - FFI/Bridge      │                     │
│ - Secure enclave  │ - Bitcoin         │ - High-level API  │                     │
│ - Hardware bind   │                   │                   │                     │
└───────────────────┴───────────────────┴───────────────────┴─────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              STORAGE LAYER                                       │
├─────────────────────────────────┬───────────────────────────────────────────────┤
│ ~/.witnessd/                    │ ~/Library/Application Support/Witnessd/       │
│ (CLI)                           │ (macOS App)                                   │
│ ├── events.db     (SQLite)      │ ├── events.db                                 │
│ ├── signing_key   (Ed25519)     │ ├── signing_key                               │
│ ├── identity.json               │ ├── identity.json                             │
│ ├── puf_seed                    │ ├── puf_seed                                  │
│ ├── config.json                 │ ├── config.json                               │
│ ├── chains/                     │ ├── chains/                                   │
│ ├── sessions/                   │ ├── sessions/                                 │
│ └── evidence/                   │ └── evidence/                                 │
└─────────────────────────────────┴───────────────────────────────────────────────┘
```

## Core Components

### CLI Application (`rust/witnessd-cli`)

The main entry point handling:
- Command-line argument parsing (`clap`)
- Subcommand dispatch
- User interaction and output

Key files:
- `main.rs`: Entry point and command dispatch
- `smart_defaults.rs`: Logic for inferring user intent

### Core Library (`rust/witnessd-core`)

Contains the business logic and cryptographic implementation.

### Evidence System (`src/evidence.rs`)

Creates and manages evidence packets:

```rust
pub struct Packet {
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub document: DocumentInfo,
    pub checkpoints: Vec<Checkpoint>,
    pub declaration: Option<Declaration>,
    // ...
}
```

### VDF Engine (`src/vdf/`)

Implements Verifiable Delay Functions (Pietrzak/Wesolowski):

```rust
pub struct Proof {
    pub input: [u8; 32],
    pub output: [u8; 32],
    pub iterations: u64,
}

pub fn compute(input: [u8; 32], duration: Duration, params: Parameters) -> Result<Proof>;
pub fn verify(proof: &Proof, params: Parameters) -> Result<bool>;
```

### MMR (Merkle Mountain Range) (`src/mmr/`)

Append-only authenticated data structure:

```rust
pub struct MMR {
    store: Box<dyn Store>,
    // ...
}

impl MMR {
    pub fn append(&mut self, data: &[u8]) -> Result<u64>;
    pub fn get_root(&self) -> Result<[u8; 32]>;
    pub fn generate_proof(&self, leaf_index: u64) -> Result<InclusionProof>;
}
```

### Key Hierarchy (`src/keyhierarchy/`)

Three-tier key management:

```rust
// Tier 0: Master Identity
pub struct MasterIdentity {
    pub public_key: [u8; 32], // Ed25519
    pub fingerprint: String,
    pub device_id: String,
}

// Tier 1: Session
pub struct SessionCertificate {
    pub session_id: [u8; 32],
    pub session_pubkey: [u8; 32],
    pub master_pubkey: [u8; 32],
    pub signature: [u8; 64],
}
```

### Storage (`src/store.rs`)

Secure SQLite storage with integrity protection:

```rust
pub struct SecureStore {
    conn: Connection,
    hmac_key: [u8; 32],
}

pub struct SecureEvent {
    pub device_id: [u8; 16],
    pub timestamp_ns: i64,
    pub content_hash: [u8; 32],
    // ...
}
```

### Forensic Analysis (`src/analysis/`)

Modules for analyzing behavioral patterns:
- `behavioral_fingerprint.rs`: Statistical analysis of typing cadence.

### Hardware Security (`src/tpm/`)

Abstracts over:
- `secure_enclave.rs`: macOS Secure Enclave
- `linux.rs`: Linux TPM 2.0
- `windows.rs`: Windows TPM 2.0
- `software.rs`: Fallback for development

## Data Flow

### Checkpoint Creation

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│   User      │    │   Compute    │    │   Sign      │    │   Store      │
│   Commits   │───▶│   Hashes     │───▶│   Checkpoint│───▶│   to DB      │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
       │                  │                   │                  │
       │                  ▼                   ▼                  ▼
       │           ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
       │           │ Content hash │    │ VDF proof   │    │ SQLite +     │
       │           │ VDF input    │    │ Ratchet sig │    │ HMAC         │
       │           └──────────────┘    └─────────────┘    └──────────────┘
```

### Verification Flow

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│   Parse     │    │   Verify     │    │   Verify    │    │   Verify     │
│   Packet    │───▶│   Chain      │───▶│   VDFs      │───▶│   Keys       │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
                          │                   │                  │
                          ▼                   ▼                  ▼
                   ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
                   │ Hash links   │    │ Timing      │    │ Session cert │
                   │ Signatures   │    │ proofs      │    │ Ratchet sigs │
                   └──────────────┘    └─────────────┘    └──────────────┘
```

## Key Hierarchy

Same as legacy, but implemented in Rust:

1. **Tier 0 (Identity):** Derived from PUF/Mnemonic.
2. **Tier 1 (Session):** Ephemeral per-session keys.
3. **Tier 2 (Ratchet):** Rolling keys for each checkpoint to ensure forward secrecy.

## Storage Architecture

### SQLite Schema

Schema is maintained in `src/store.rs` via `rusqlite`.

```sql
CREATE TABLE IF NOT EXISTS secure_events (
    id INTEGER PRIMARY KEY,
    device_id BLOB NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    content_hash BLOB NOT NULL,
    -- ...
    hmac BLOB NOT NULL
);
```

## Design Decisions

### Why Rust?

- **Memory Safety:** Critical for cryptographic software.
- **Performance:** VDF computation requires raw CPU speed.
- **Cross-Platform:** Excellent support for macOS, Linux, and Windows.
- **FFI:** Easy integration with Swift (macOS) and other languages.

### Why VDF Instead of Trusted Timestamps?

VDFs provide:
- No trusted third party required
- Works offline
- Cannot be backdated even by the author
- Cryptographically verifiable

### Why SQLite Instead of Flat Files?

SQLite provides:
- ACID transactions
- Efficient querying
- Single file backup
- Built-in corruption detection

---

See also:
- [Building](../../README.md#development--building) - Build instructions
- [Protocol Specifications](../spec/evidence-packet-v1.schema.json) - Data formats
