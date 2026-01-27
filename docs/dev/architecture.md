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

1. **CLI Application** (`cmd/witnessd`): Primary interface for checkpointing and verification
2. **Internal Libraries** (`internal/`): Core logic for evidence creation and verification
3. **Package Libraries** (`pkg/`): Reusable components (anchoring, verification)
4. **macOS Application** (`platforms/macos/`): Native GUI for macOS

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              USER INTERFACES                                     │
├─────────────────────────────────┬───────────────────────────────────────────────┤
│         CLI (witnessd)          │           macOS App (WitnessdApp)             │
│  ┌─────────────────────────┐    │    ┌─────────────────────────────────────┐   │
│  │ cmd/witnessd/main.go    │    │    │ StatusBarController.swift           │   │
│  │ - init, commit, log     │    │    │ - Menu bar UI                       │   │
│  │ - export, verify        │    │    │ - Quick actions                     │   │
│  │ - track, sentinel       │    │    ├─────────────────────────────────────┤   │
│  │ - presence, calibrate   │    │    │ WitnessdBridge.swift                │   │
│  │ - Interactive menu      │    │    │ - CLI subprocess wrapper            │   │
│  └─────────────────────────┘    │    │ - JSON IPC                          │   │
└─────────────────────────────────┴────┴─────────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              CORE LIBRARIES                                      │
├───────────────────┬───────────────────┬───────────────────┬─────────────────────┤
│ internal/config   │ internal/evidence │ internal/store    │ internal/keyhierarchy│
│ - Config loading  │ - Evidence packet │ - SecureStore     │ - Master identity   │
│ - Validation      │ - Declaration     │ - HMAC integrity  │ - Session certs     │
│ - Defaults        │ - Export/import   │ - SQLite backend  │ - Ratchet keys      │
├───────────────────┼───────────────────┼───────────────────┼─────────────────────┤
│ internal/vdf      │ internal/mmr      │ internal/wal      │ internal/checkpoint │
│ - VDF compute     │ - Merkle Mountain │ - Write-ahead log │ - Checkpoint chain  │
│ - VDF verify      │   Range           │ - Crash recovery  │ - Hash linking      │
│ - Calibration     │ - Inclusion proof │ - Append-only     │ - Signatures        │
├───────────────────┼───────────────────┼───────────────────┼─────────────────────┤
│ internal/tracking │ internal/jitter   │ internal/sentinel │ internal/presence   │
│ - Keystroke count │ - Timing jitter   │ - Background      │ - Presence verify   │
│ - Event capture   │ - Statistics      │   monitoring      │ - Challenges        │
│ - WAL integration │ - Evidence export │ - Auto checkpoint │ - Responses         │
├───────────────────┼───────────────────┼───────────────────┼─────────────────────┤
│ internal/tpm      │ internal/          │ internal/         │                     │
│ - TPM attestation │   declaration     │   forensics       │                     │
│ - Secure enclave  │ - Signed decl     │ - Correlator      │                     │
│ - Hardware bind   │ - Process record  │ - Analysis        │                     │
└───────────────────┴───────────────────┴───────────────────┴─────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              PACKAGE LIBRARIES                                   │
├─────────────────────────────────┬───────────────────────────────────────────────┤
│ pkg/anchors                     │ pkg/verify                                    │
│ - AnchorRegistry                │ - Verification engine                         │
│ - Bitcoin anchor                │ - Evidence validation                         │
│ - Keybase proofs                │ - Report generation                           │
│ - Drand beacon                  │                                               │
└─────────────────────────────────┴───────────────────────────────────────────────┘
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
│ └── tracking/*.wal              │ └── tracking/*.wal                            │
└─────────────────────────────────┴───────────────────────────────────────────────┘
```

## Core Components

### Command Layer (`cmd/witnessd`)

The main entry point handling:
- Command-line argument parsing
- Interactive menu mode
- Subcommand dispatch
- Error handling and user feedback

Key files:
- `main.go`: Entry point and command dispatch
- `menu.go`: Interactive menu system

### Configuration (`internal/config`)

Manages application configuration:
- TOML and JSON config file parsing
- Default value handling
- Environment variable overrides
- Directory path resolution

### Evidence System (`internal/evidence`)

Creates and manages evidence packets:

```go
type EvidencePacket struct {
    Version      string
    Created      time.Time
    Document     DocumentInfo
    Checkpoints  []Checkpoint
    KeyHierarchy KeyHierarchyInfo
    Declaration  SignedDeclaration
    Anchors      []AnchorProof
}
```

### VDF Engine (`internal/vdf`)

Implements Verifiable Delay Functions:

```go
type Proof struct {
    Input      [32]byte
    Output     [32]byte
    Iterations uint64
    Duration   time.Duration
}

func Compute(input [32]byte, duration time.Duration, params *Params) (*Proof, error)
func Verify(proof *Proof) bool
```

Uses sequential squaring in RSA group for non-parallelizable delay.

### MMR (Merkle Mountain Range) (`internal/mmr`)

Append-only authenticated data structure:

```go
type MMR struct {
    store Store
    size  uint64
    peaks []uint64
}

func (m *MMR) Append(data []byte) (uint64, error)
func (m *MMR) GetRoot() ([32]byte, error)
func (m *MMR) GenerateProof(leafIndex uint64) (*InclusionProof, error)
```

Properties:
- O(log n) append
- O(log n) proof generation
- O(log n) verification
- Supports efficient range proofs

### Key Hierarchy (`internal/keyhierarchy`)

Three-tier key management:

```go
// Tier 0: Master Identity
type MasterIdentity struct {
    PublicKey   ed25519.PublicKey
    Fingerprint string
    DeviceID    string
}

// Tier 1: Session
type SessionCertificate struct {
    SessionID     [32]byte
    SessionPubKey ed25519.PublicKey
    MasterPubKey  ed25519.PublicKey
    Signature     [64]byte
}

// Tier 2: Ratchet
type RatchetState struct {
    current   [32]byte
    ordinal   uint64
    sessionID [32]byte
}
```

### Storage (`internal/store`)

Secure SQLite storage with integrity protection:

```go
type SecureStore struct {
    db      *sql.DB
    hmacKey []byte
}

type SecureEvent struct {
    DeviceID      [16]byte
    TimestampNs   int64
    FilePath      string
    ContentHash   [32]byte
    FileSize      int64
    VDFInput      [32]byte
    VDFOutput     [32]byte
    VDFIterations uint64
    HMAC          []byte
}
```

### WAL (Write-Ahead Log) (`internal/wal`)

Crash-safe event logging:

```go
type WAL struct {
    file     *os.File
    position uint64
}

func (w *WAL) Append(entry Entry) error
func (w *WAL) Recover() ([]Entry, error)
```

### Tracking (`internal/tracking`)

Keystroke event capture (count only, not content):

```go
type Tracker struct {
    documentPath string
    keystrokeCount uint64
    jitterSamples  []JitterSample
    wal            *wal.WAL
}
```

### Sentinel (`internal/sentinel`)

Background monitoring daemon:

```go
type Sentinel struct {
    config    *Config
    documents map[string]*TrackedDocument
    ticker    *time.Ticker
}

func (s *Sentinel) Start() error
func (s *Sentinel) TrackDocument(path string)
func (s *Sentinel) AutoCheckpoint()
```

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
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        If Tracking Active                            │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐       │
│  │ Keystroke     │    │ Jitter        │    │ Include in    │       │
│  │ count         │───▶│ statistics    │───▶│ checkpoint    │       │
│  └───────────────┘    └───────────────┘    └───────────────┘       │
└─────────────────────────────────────────────────────────────────────┘
```

### Evidence Export

```
┌──────────────────────────────────────────────────────────────────────┐
│                       Evidence Packet Creation                        │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────┐    │
│  │ Load        │         │ Include     │         │ Add         │    │
│  │ Checkpoints │────────▶│ VDF Proofs  │────────▶│ Key         │    │
│  │ from DB     │         │             │         │ Hierarchy   │    │
│  └─────────────┘         └─────────────┘         └─────────────┘    │
│         │                       │                       │            │
│         ▼                       ▼                       ▼            │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────┐    │
│  │ Generate    │         │ Create      │         │ Serialize   │    │
│  │ Declaration │────────▶│ Anchors     │────────▶│ to JSON/    │    │
│  │             │         │ (optional)  │         │ CBOR        │    │
│  └─────────────┘         └─────────────┘         └─────────────┘    │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
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
                                              │
                                              ▼
                   ┌──────────────────────────────────────────────────────┐
                   │                  Verification Report                  │
                   │  - Pass/Fail status for each check                   │
                   │  - Evidence tier classification                       │
                   │  - Timing analysis                                    │
                   └──────────────────────────────────────────────────────┘
```

## Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TIER 0: IDENTITY ROOT                               │
│                                                                             │
│  PUF Response ──▶ HKDF-SHA256 ──▶ master_key ──▶ Ed25519 Public Key        │
│                                                                             │
│  Properties:                                                                │
│  - Device-bound via PUF                                                     │
│  - Never used directly for checkpoints                                      │
│  - Signs session certificates only                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HKDF derivation
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TIER 1: SESSION KEY                                 │
│                                                                             │
│  master_key + session_id + timestamp ──▶ HKDF ──▶ session_key              │
│                                                                             │
│  Session Certificate:                                                       │
│  { session_id, session_pubkey, document_hash, master_pubkey, signature }   │
│                                                                             │
│  Properties:                                                                │
│  - Generated per writing session                                            │
│  - Certified by master key                                                  │
│  - Initializes the ratchet                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Ratchet derivation
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TIER 2: RATCHETING CHECKPOINT KEY                        │
│                                                                             │
│  For each checkpoint n:                                                     │
│    ratchet_n ──▶ HKDF ──▶ signing_key_n                                    │
│    Sign(signing_key_n, checkpoint_hash_n)                                   │
│    ratchet_n + checkpoint_hash_n ──▶ HKDF ──▶ ratchet_{n+1}               │
│    SecureWipe(ratchet_n)                                                    │
│                                                                             │
│  Properties:                                                                │
│  - Each checkpoint has unique key                                           │
│  - Forward secrecy (can't derive past keys)                                 │
│  - Backward secrecy (can't derive future keys)                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Storage Architecture

### SQLite Schema

```sql
-- Secure events with HMAC protection
CREATE TABLE secure_events (
    id INTEGER PRIMARY KEY,
    device_id BLOB NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    content_hash BLOB NOT NULL,
    file_size INTEGER NOT NULL,
    size_delta INTEGER,
    context_type TEXT,
    vdf_input BLOB,
    vdf_output BLOB,
    vdf_iterations INTEGER,
    event_hash BLOB NOT NULL,
    hmac BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_events_file ON secure_events(file_path);
CREATE INDEX idx_events_timestamp ON secure_events(timestamp_ns);
```

### WAL Format

Binary format for crash recovery:

```
┌─────────────────────────────────────────────────────────────────┐
│ WAL Header (64 bytes)                                           │
├─────────────────────────────────────────────────────────────────┤
│ Magic: "WWAL" (4 bytes)                                         │
│ Version: uint32 (4 bytes)                                       │
│ Flags: uint32 (4 bytes)                                         │
│ SessionID: [32]byte                                             │
│ Created: int64 (8 bytes)                                        │
│ Reserved: 12 bytes                                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Entry (variable length)                                         │
├─────────────────────────────────────────────────────────────────┤
│ Length: uint32 (4 bytes)                                        │
│ Type: uint8 (1 byte)                                            │
│ Timestamp: int64 (8 bytes)                                      │
│ Payload: [Length - 13]byte                                      │
│ CRC32: uint32 (4 bytes)                                         │
└─────────────────────────────────────────────────────────────────┘
```

## Platform-Specific Components

### macOS App Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SwiftUI Layer                             │
├─────────────────────────────────────────────────────────────────┤
│ StatusBarController     │ SettingsView    │ OnboardingView      │
│ PopoverViews            │ HistoryView     │ NotificationManager │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Bridge Layer                                 │
├─────────────────────────────────────────────────────────────────┤
│ WitnessdBridge.swift                                            │
│ - Spawns witnessd CLI subprocess                                │
│ - JSON-based IPC                                                │
│ - Async/await interface                                         │
│ - Status polling                                                │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     CLI Subprocess                               │
├─────────────────────────────────────────────────────────────────┤
│ Bundled witnessd binary                                         │
│ - Runs in Application Support container                         │
│ - WITNESSD_DATA_DIR environment variable                        │
│ - JSON output mode for machine parsing                          │
└─────────────────────────────────────────────────────────────────┘
```

## Design Decisions

### Why VDF Instead of Trusted Timestamps?

VDFs provide:
- No trusted third party required
- Works offline
- Cannot be backdated even by the author
- Cryptographically verifiable

Trade-off: Requires CPU time for each checkpoint.

### Why SQLite Instead of Flat Files?

SQLite provides:
- ACID transactions
- Efficient querying
- Single file backup
- Built-in corruption detection

With HMAC layer for tamper evidence.

### Why Three-Tier Key Hierarchy?

Balances security properties:
- Tier 0: Long-term identity (rarely used)
- Tier 1: Session isolation (limits blast radius)
- Tier 2: Forward secrecy (protects past)

### Why MMR Instead of Standard Merkle Tree?

MMR advantages:
- Append-only (no rebalancing)
- Efficient range proofs
- Constant-time append
- Naturally fits document evolution

---

See also:
- [Building](building.md) - Build instructions
- [Protocol Specifications](../protocol/evidence-format.md) - Data formats
- [Key Management](../security/key-management.md) - Key details
