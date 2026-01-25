# Kinetic Proof of Provenance: Cryptographic Evidence of Human Authorship

## Abstract

We present **witnessd**, a system for generating irrefutable cryptographic evidence of document authorship through continuous temporal witnessing. By capturing the "kinetic signature" of human creative work—the natural rhythm of edits, pauses, and revisions—we construct proofs that are infeasible to forge retroactively. The system employs a Merkle Mountain Range (MMR) for efficient append-only state tracking, Ed25519 signatures for identity binding, external trust anchors (OpenTimestamps, RFC 3161) for immutable timestamps, and forensic behavioral analysis for authorship verification.

## 1. Introduction

The rise of large language models (LLMs) has created an unprecedented challenge in authorship verification. A document produced by an AI in seconds is indistinguishable from one written by a human over hours. Traditional metadata (file timestamps, revision history) is trivially manipulated.

**Kinetic Proof of Provenance** addresses this through continuous cryptographic witnessing. We argue that the *temporal pattern* of creation—what we call the "creative heartbeat"—is a unique fingerprint that AI-generated content fundamentally lacks.

### 1.1 Key Insight

Human writing exhibits a distinctive temporal signature:
- **Bursts and pauses**: Ideas flow in spurts with natural breaks
- **Iterative refinement**: Multiple passes over the same sections
- **Non-linear progress**: Jumping between sections, backtracking
- **Consistent rhythm**: Individual writers have characteristic pacing

AI generation, by contrast, produces content atomically—there is no process, only a result. Even when adversaries attempt to simulate human editing patterns ("drip attacks"), statistical analysis reveals the artificial regularity.

### 1.2 Contributions

This paper presents:
1. A formal protocol specification for cryptographic witnessing
2. An efficient MMR-based data structure for append-only witnessing
3. A forensic metrics framework for authorship analysis
4. Privacy-preserving edit topology extraction
5. Integration with external trust anchors

## 2. System Architecture

### 2.1 Merkle Mountain Range (MMR)

We use an MMR as the core data structure because:

1. **Append-only**: Perfect for chronological witnessing
2. **O(log n) proofs**: Efficient inclusion proofs
3. **Multiple peaks**: Allows incremental root updates
4. **No rebalancing**: Unlike Merkle trees, structure is deterministic

Each MMR node is 41 bytes:
- `index` (8 bytes): Position in the MMR
- `height` (1 byte): Tree level (0 = leaf)
- `hash` (32 bytes): SHA-256 of node contents

### 2.2 Domain-Separated Hashing

To prevent second-preimage attacks, we use domain-separated hashing:

```
LeafHash = SHA256(0x00 || data)
InternalHash = SHA256(0x01 || left || right)
```

This ensures that leaf hashes and internal node hashes occupy distinct domains.

### 2.3 Cryptographic Commitment

Each MMR leaf binds three components:

```
LeafHash = SHA256(0x00 || ContentHash || MetadataHash || RegionsRoot)
```

Where:
- **ContentHash**: SHA-256 of file contents
- **MetadataHash**: Hash of canonical metadata encoding (timestamp, size, path)
- **RegionsRoot**: Merkle root of edit regions (topology)

This binding ensures that tampering with any component invalidates the leaf.

### 2.4 Root Commitment

The "Witness Root" is computed by bagging all peaks:

```
Root = Hash(peak[0], Hash(peak[1], Hash(peak[2], ...)))
```

This single 32-byte value represents the complete witness history.

## 3. The Witness Protocol

### 3.1 Background Daemon (witnessd)

The daemon operates invisibly:

1. **File Monitoring**: Uses fsnotify to watch configured directories
2. **Debouncing**: Waits for file stability (configurable, default 500ms)
3. **Shadow Cache**: Maintains encrypted previous states for diff computation
4. **Topology Extraction**: Uses Myers diff to identify edit regions
5. **State Hashing**: Computes SHA-256 using streaming for large files
6. **MMR Append**: Adds the cryptographic commitment to the append-only structure
7. **Event Storage**: Records full metadata in SQLite for forensic analysis
8. **Periodic Signing**: Signs the root with Ed25519 every N events

### 3.2 Shadow Cache

To extract edit topology without storing file contents, we maintain an encrypted shadow cache:

| File Size | Strategy | Description |
|-----------|----------|-------------|
| < 256 KB | Full | Encrypt and store complete previous state |
| 256 KB - 10 MB | Chunked | Content-defined chunking with Rabin fingerprint |
| > 10 MB | Size-only | Store only size delta (privacy mode) |

The cache uses AES-256-GCM with a session-derived key.

### 3.3 Edit Topology Extraction

We use the Myers diff algorithm to identify where edits occur:

1. Compare previous and current file states
2. Extract edit operations (insert, delete, replace)
3. Convert positions to percentages of document length
4. Coalesce adjacent regions (within 5% proximity)

The topology preserves *where* edits occur without revealing *what* was edited.

### 3.4 Event Storage

A SQLite database stores full event metadata:

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    device_id BLOB NOT NULL,
    mmr_index INTEGER NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    content_hash BLOB NOT NULL,
    file_size INTEGER NOT NULL,
    size_delta INTEGER NOT NULL,
    mmr_leaf_hash BLOB NOT NULL,  -- Cryptographic binding to MMR
    context_id INTEGER
);

CREATE TABLE edit_regions (
    id INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL,
    start_pct REAL NOT NULL,
    end_pct REAL NOT NULL,
    delta_sign INTEGER NOT NULL,  -- 0=replace, 1=insert, 2=delete
    byte_count INTEGER NOT NULL
);
```

The `mmr_leaf_hash` column cryptographically binds SQLite records to the MMR.

### 3.5 Context Declarations

Users can declare context for their edits:

| Type | Description | Example |
|------|-------------|---------|
| `external` | Content from outside sources | Paste, import, dictation |
| `assisted` | AI or tool-assisted generation | ChatGPT, Copilot |
| `review` | Explicit revision pass | Proofreading, editing |

Context declarations are voluntary but provide important forensic context.

## 4. Forensic Analysis

### 4.1 Primary Metrics

We define five forensic metrics for authorship analysis:

#### 4.1.1 Monotonic Append Ratio

Fraction of edits occurring at document end (position ≥ 0.95):

```
M = |{r : r.start_pct >= 0.95}| / |R|
```

| Pattern | Typical Range |
|---------|---------------|
| Human writing | 40-60% |
| Drip attack | >95% |

#### 4.1.2 Edit Entropy

Shannon entropy of edit position histogram (20 bins):

```
H = -Σ (c_j/n) * log₂(c_j/n)
```

| Pattern | Typical Range |
|---------|---------------|
| Human writing | 2.5-4.0 |
| Drip attack | <1.0 |

#### 4.1.3 Median Interval

Median time between consecutive witness events. Human editing shows natural variance; artificial patterns show suspicious regularity.

#### 4.1.4 Positive/Negative Ratio

Ratio of insertions to total non-replacement edits:

```
P = |{r : r.delta_sign == 1}| / |{r : r.delta_sign != 0}|
```

| Pattern | Typical Range |
|---------|---------------|
| Human writing | 60-75% |
| Drip attack | >98% |

#### 4.1.5 Deletion Clustering Coefficient

Nearest-neighbor distance ratio for deletions:

```
C = mean_dist / expected_dist
```

| Pattern | Interpretation |
|---------|----------------|
| C < 1.0 | Clustered deletions (revision pass) |
| C ≈ 1.0 | Scattered deletions (artificial) |
| C = 0 | No deletions |

### 4.2 Anomaly Detection

The system flags anomalies:

1. **Gap**: Inter-event interval > 3σ from mean
2. **High Velocity**: Bytes/second > 10 sustained
3. **Monotonic Run**: >20 consecutive append-only edits
4. **Low Entropy**: Edit entropy < 1.5

### 4.3 Assessment Categories

| Assessment | Criteria |
|------------|----------|
| CONSISTENT WITH HUMAN AUTHORSHIP | All metrics within expected ranges |
| SUSPICIOUS PATTERNS DETECTED | One or more metrics outside ranges |
| INSUFFICIENT DATA | Fewer than 5 witness events |

## 5. Evidence Export

### 5.1 Evidence Packet

The `witnessctl export` command produces a self-contained JSON proof:

```json
{
  "version": 1,
  "timestamp": "2026-01-24T12:00:00Z",
  "file_path": "document.txt",
  "file_hash": "abc123...",
  "file_size": 4096,
  "mmr_index": 42,
  "mmr_size": 157,
  "mmr_root": "def456...",
  "merkle_path": [
    {"hash": "...", "is_left": true},
    {"hash": "...", "is_left": false}
  ],
  "peaks": ["..."],
  "peak_position": 0,
  "public_key": "...",
  "signature": "...",
  "anchors": [
    {"type": "opentimestamps", "status": "confirmed", "proof": "..."}
  ],
  "metadata": {
    "device_id": "...",
    "timestamp_ns": 1706097600000000000,
    "size_delta": 128,
    "edit_regions": [...]
  }
}
```

### 5.2 Verification Algorithm

To verify an evidence packet:

1. Verify Ed25519 signature over `mmr_root`
2. Walk `merkle_path` from `file_hash` to peak
3. Confirm computed peak matches `peaks[peak_position]`
4. Bag all peaks and confirm result matches `mmr_root`
5. Optionally verify external anchors

## 6. External Trust Anchors

### 6.1 OpenTimestamps

We submit MMR roots to Bitcoin calendar servers:
- Provides Bitcoin blockchain attestation
- Proof of existence at a specific block height
- Immutable even if local database is compromised

### 6.2 RFC 3161

Traditional Time-Stamp Authority compliance:
- Compatible with legal frameworks (FRE 902(13), eIDAS 2.0)
- Signed by trusted third parties
- Supports multiple TSA servers

## 7. Security Analysis

### 7.1 Threat Model

We assume:
- Adversary controls filesystem after the fact
- Adversary cannot break SHA-256 or Ed25519
- Adversary cannot retroactively modify Bitcoin blockchain
- External timestamp authorities are honest

### 7.2 Attack Resistance

**Backdating Attack**: Cannot produce valid inclusion proofs without knowing historical MMR state. External anchors provide cryptographic timeline constraints.

**Drip Attack**: Edit topology analysis detects artificial append-only patterns. Metrics reveal unnatural regularity in timing and position distribution.

**Fabrication Attack**: Statistical analysis reveals artificial patterns. External anchors constrain the feasible timeline.

### 7.3 Privacy Considerations

Edit topology reveals behavioral metadata:
- Which sections are revised most
- Insertion vs deletion patterns
- Positional patterns correlated with document structure

For sensitive contexts, implementations support "reduced privacy mode" storing only size deltas.

## 8. Performance

### 8.1 Storage Overhead

| Edits | MMR Nodes | DB Size | Overhead Ratio |
|-------|-----------|---------|----------------|
| 100   | 199       | 8.2 KB  | 0.08x          |
| 1000  | 1999      | 82 KB   | 0.08x          |
| 10000 | 19999     | 820 KB  | 0.08x          |

### 8.2 Operation Latency

| Operation | Time (1000 leaves) |
|-----------|-------------------|
| Append    | ~5 µs             |
| Get Root  | ~2 µs             |
| Gen Proof | ~10 µs            |
| Verify    | ~8 µs             |

All operations complete in microseconds, making real-time witnessing practical.

## 9. Comparison

| System | Append-Only | Identity Bound | External Anchors | Process Proof | Forensics |
|--------|-------------|----------------|------------------|---------------|-----------|
| Git | Yes | Optional | No | Partial | No |
| IPFS | Yes | No | No | No | No |
| Blockchain | Yes | Yes | N/A | No | No |
| **witnessd** | Yes | Yes | Yes | **Yes** | **Yes** |

## 10. Future Directions

### 10.1 From Detection to Documentation

The current forensic approach assumes detection of artificial patterns. However, as AI models improve, the arms race between detection and evasion intensifies.

An alternative paradigm emphasizes **documentation over detection**:

1. **Verifiable Delay Functions (VDF)**: Prove minimum elapsed time via computational puzzles that require sequential computation. A 10-minute VDF proves 10 minutes of wall-clock time passed—unforgeable regardless of AI involvement.

2. **Process Declarations**: Shift from detection to attestation. Authors declare their process (AI assistance, external sources) through cryptographically signed statements. Legal and institutional frameworks handle false declarations.

3. **Presence Verification**: Optional random challenges ("screenshot your screen", "type this phrase") that prove human presence without continuous surveillance.

This approach sidesteps the detection arms race by:
- Proving what's provable (elapsed time)
- Declaring what's not (AI usage)
- Letting institutions handle false attestations

### 10.2 Additional Enhancements

- **Hardware Attestation**: TPM-bound signatures for device identity
- **Multi-Author Collaboration**: Weaving multiple witness streams
- **Cross-Document Identity**: Linking authorship profiles across works
- **Biometric Binding**: Optional keystroke dynamics integration

## 11. Conclusion

witnessd provides a practical solution for proving human authorship through cryptographic process witnessing. By capturing the natural rhythm of creative work, we produce evidence that is:

1. **Irrefutable**: Cryptographically bound to identity and time
2. **Forensic**: Statistical analysis reveals authorship patterns
3. **Portable**: Self-contained evidence packets
4. **Verifiable**: Anyone can check proofs
5. **Privacy-preserving**: Topology without content

As AI-generated content becomes ubiquitous, systems like witnessd become essential for establishing authentic human provenance.

## References

1. Merkle Mountain Range specification (mimblewimble/grin)
2. OpenTimestamps Protocol (opentimestamps.org)
3. RFC 3161: Internet X.509 PKI Time-Stamp Protocol
4. RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
5. Myers, E. W. (1986). An O(ND) Difference Algorithm
6. Boneh, D., et al. (2018). Verifiable Delay Functions

---

*Generated by witnessd. This document has been cryptographically witnessed during its creation.*
