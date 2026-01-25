# Witness Protocol Specification v1.0.0

**Status:** Draft
**Version:** 1.0.0
**Date:** 2026-01-24
**Authors:** witnessd contributors

---

## Abstract

This document specifies the Witness Protocol, a cryptographic system for generating tamper-evident proof of document authorship through continuous temporal witnessing. The protocol captures the "kinetic signature" of human creative work—the natural rhythm of edits, pauses, and revisions—producing evidence that is computationally infeasible to forge retroactively.

## 1. Introduction

### 1.1 Purpose

The Witness Protocol provides:

1. **Temporal Proof**: Cryptographic evidence that a document existed in a specific state at a specific time
2. **Process Proof**: Evidence of the *manner* of creation, not just the result
3. **Identity Binding**: Cryptographic link between document history and author identity
4. **External Anchoring**: Integration with trusted third-party timestamp authorities

### 1.2 Scope

This specification defines:

- The Merkle Mountain Range (MMR) data structure and operations
- The cryptographic commitment scheme binding content, metadata, and topology
- The evidence packet format for portable proofs
- The forensic metrics for authorship analysis

This specification does NOT define:

- Implementation details of any specific client
- User interface requirements
- Network protocols for daemon communication

### 1.3 Terminology

| Term | Definition |
|------|------------|
| **Witness Event** | A cryptographic snapshot of a document state at a point in time |
| **Edit Region** | A contiguous portion of a document affected by a single edit operation |
| **Edit Topology** | The spatial distribution of edits within a document over time |
| **Leaf** | A witness event commitment stored in the MMR |
| **Peak** | The root of a complete binary subtree within the MMR |
| **Witness Root** | The single hash representing the entire witness history |

## 2. Data Structures

### 2.1 Merkle Mountain Range (MMR)

The MMR is an append-only authenticated data structure consisting of multiple perfect binary trees ("mountains") of decreasing size.

#### 2.1.1 Properties

- **Append-only**: New leaves can only be added; existing nodes are immutable
- **O(log n) proofs**: Inclusion proofs grow logarithmically with tree size
- **Multiple peaks**: Structure contains 1 to log₂(n) peaks at any time
- **Deterministic**: Given the same sequence of appends, the structure is identical

#### 2.1.2 Node Structure

Each node in the MMR contains:

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `index` | uint64 | 8 bytes | Position in the MMR (0-indexed) |
| `height` | uint8 | 1 byte | Height in the tree (0 = leaf) |
| `hash` | bytes | 32 bytes | SHA-256 hash of node contents |

**Total node size: 41 bytes**

#### 2.1.3 Domain-Separated Hashing

To prevent second-preimage attacks, leaf and internal node hashes use distinct prefixes:

```
LeafHash = SHA256(0x00 || data)
InternalHash = SHA256(0x01 || left_hash || right_hash)
```

Where:
- `0x00` is the leaf domain separator
- `0x01` is the internal node domain separator
- `||` denotes concatenation

#### 2.1.4 Peak Bagging

The Witness Root is computed by "bagging" all peaks from right to left:

```
Root = Hash(peak[0], Hash(peak[1], Hash(peak[2], ...)))
```

For a single peak, `Root = peak[0]`.

### 2.2 Witness Event

A witness event captures a document state with full metadata.

| Field | Type | Description |
|-------|------|-------------|
| `device_id` | bytes[16] | UUID of the witnessing device |
| `mmr_index` | uint64 | Position in the MMR |
| `timestamp_ns` | int64 | Unix timestamp in nanoseconds |
| `file_path` | string | Path to the witnessed file |
| `content_hash` | bytes[32] | SHA-256 of file contents |
| `file_size` | int64 | Size in bytes |
| `size_delta` | int32 | Change from previous state |
| `context_id` | int64? | Optional reference to active context |

### 2.3 Edit Region

An edit region describes where an edit occurred within a document.

| Field | Type | Description |
|-------|------|-------------|
| `start_pct` | float32 | Start position as fraction [0.0, 1.0] |
| `end_pct` | float32 | End position as fraction [0.0, 1.0] |
| `delta_sign` | int8 | Change type: 0=replace, 1=insert, 2=delete |
| `byte_count` | int32 | Number of bytes affected |

**Position normalization**: All positions are expressed as fractions of the ORIGINAL document length, preserving privacy while capturing topology.

### 2.4 Context Declaration

A context declaration annotates a period of editing activity.

| Field | Type | Description |
|-------|------|-------------|
| `id` | int64 | Unique identifier |
| `type` | string | One of: "external", "assisted", "review" |
| `note` | string | Freeform explanation |
| `start_ns` | int64 | Start timestamp in nanoseconds |
| `end_ns` | int64? | End timestamp (null if active) |

**Context types**:
- `external`: Content from outside sources (paste, import, dictation)
- `assisted`: AI or tool-assisted generation
- `review`: Explicit revision pass

## 3. Cryptographic Commitment

### 3.1 Commitment Structure

Each MMR leaf is a cryptographic commitment binding three components:

```
LeafHash = SHA256(0x00 || ContentHash || MetadataHash || RegionsRoot)
```

Where:
- `ContentHash`: SHA-256 of the file contents
- `MetadataHash`: Hash of canonical metadata encoding
- `RegionsRoot`: Merkle root of edit regions

### 3.2 Metadata Hash

The metadata hash is computed from a canonical encoding:

```
MetadataHash = SHA256(
    BigEndian(timestamp_ns) ||    // 8 bytes
    BigEndian(file_size) ||       // 8 bytes
    BigEndian(size_delta) ||      // 4 bytes
    UTF8(file_path)               // variable
)
```

Field order and encoding MUST be exactly as specified for deterministic hashing.

### 3.3 Regions Root

The regions root is a Merkle tree of edit regions:

1. Each region is hashed as:
   ```
   RegionHash = SHA256(
       Float32Bits(start_pct) ||  // 4 bytes
       Float32Bits(end_pct) ||    // 4 bytes
       delta_sign ||              // 1 byte
       BigEndian(byte_count)      // 4 bytes
   )
   ```

2. The tree is built bottom-up, padding odd levels with zero hash
3. If no regions exist, `RegionsRoot = 0x00...00` (32 zero bytes)

### 3.4 Verification

To verify event integrity:

1. Recompute `MetadataHash` from stored metadata
2. Recompute `RegionsRoot` from stored edit regions
3. Recompute `LeafHash = SHA256(0x00 || ContentHash || MetadataHash || RegionsRoot)`
4. Compare with stored `mmr_leaf_hash`

If any component has been tampered with, the leaf hash will not match.

## 4. Evidence Packet

### 4.1 Structure

An evidence packet is a self-contained proof that a file was witnessed.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | integer | Yes | Schema version (currently 1) |
| `timestamp` | string | Yes | ISO 8601 timestamp of export |
| `file_path` | string | Yes | Original file path |
| `file_hash` | string | Yes | Hex-encoded SHA-256 of file |
| `file_size` | integer | Yes | Size in bytes |
| `mmr_index` | integer | Yes | Position in MMR |
| `mmr_size` | integer | Yes | Total MMR size at proof time |
| `mmr_root` | string | Yes | Hex-encoded witness root |
| `merkle_path` | array | Yes | Inclusion proof elements |
| `peaks` | array | Yes | All peak hashes for bagging |
| `peak_position` | integer | Yes | Which peak this leaf belongs to |
| `public_key` | string | Yes | Hex-encoded Ed25519 public key |
| `signature` | string | Yes | Hex-encoded Ed25519 signature |
| `anchors` | array | No | External timestamp proofs |

### 4.2 Merkle Path Element

Each element in `merkle_path`:

| Field | Type | Description |
|-------|------|-------------|
| `hash` | string | Hex-encoded sibling hash |
| `is_left` | boolean | True if sibling is on the left |

### 4.3 Anchor Proof

Each element in `anchors`:

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | "opentimestamps" or "rfc3161" |
| `status` | string | "pending", "confirmed", or "failed" |
| `proof` | string | Base64-encoded proof data |
| `anchor_time` | string | ISO 8601 timestamp (if confirmed) |

### 4.4 Verification Algorithm

To verify an evidence packet:

1. **Verify signature**: Check Ed25519 signature over `mmr_root` using `public_key`
2. **Verify inclusion**: Walk `merkle_path` from `file_hash` to peak
3. **Verify peak**: Confirm computed peak matches `peaks[peak_position]`
4. **Verify root**: Bag all peaks and confirm result matches `mmr_root`

## 5. Forensic Metrics

### 5.1 Primary Metrics

The protocol defines five primary metrics for authorship analysis:

#### 5.1.1 Monotonic Append Ratio

**Definition**: Fraction of edits occurring at document end (position ≥ 0.95).

```
M = |{r : r.start_pct >= 0.95}| / |R|
```

**Interpretation**:
- Human writing: 40-60%
- Drip attack: >95%

#### 5.1.2 Edit Entropy

**Definition**: Shannon entropy of edit position histogram.

Given regions R partitioned into B bins:

```
H = -Σ (c_j/n) * log₂(c_j/n)
```

Where `c_j` is the count in bin j, `n` is total regions.

**Parameters**: B = 20 bins (default)

**Interpretation**:
- Human writing: 2.5-4.0
- Drip attack: <1.0

#### 5.1.3 Median Interval

**Definition**: Median time between consecutive witness events.

```
intervals = [(t_i - t_{i-1}) for i in 2..n]
median_interval = median(intervals)
```

**Interpretation**: Varies by author; unusually regular intervals are suspicious.

#### 5.1.4 Positive/Negative Ratio

**Definition**: Ratio of insertions to total non-replacement edits.

```
P = |{r : r.delta_sign == 1}| / |{r : r.delta_sign != 0}|
```

**Interpretation**:
- Human writing: 60-75%
- Drip attack: >98%

#### 5.1.5 Deletion Clustering Coefficient

**Definition**: Nearest-neighbor distance ratio for deletions.

```
deletions = sorted([r for r in R if r.delta_sign == 2], by=start_pct)
mean_dist = Σ(deletions[i+1].start_pct - deletions[i].start_pct) / (n-1)
expected_dist = 1 / (n+1)
C = mean_dist / expected_dist
```

**Interpretation**:
- Clustered deletions (revision pass): C < 1.0
- Scattered deletions (fake): C ≈ 1.0
- No deletions: C = 0

### 5.2 Anomaly Detection

An anomaly is flagged when:

1. **Gap**: Inter-event interval > 3σ from mean
2. **High Velocity**: Bytes/second exceeds human typing threshold (>10 bytes/sec sustained)
3. **Monotonic Run**: >20 consecutive append-only edits
4. **Low Entropy**: Edit entropy < 1.5

### 5.3 Assessment

Overall assessment categories:

- **CONSISTENT WITH HUMAN AUTHORSHIP**: All metrics within expected ranges, no unexplained anomalies
- **SUSPICIOUS PATTERNS DETECTED**: One or more metrics outside expected ranges
- **INSUFFICIENT DATA**: Fewer than 5 witness events

## 6. External Anchors

### 6.1 OpenTimestamps

Integration with Bitcoin blockchain via OpenTimestamps protocol:

1. Submit witness root to calendar servers
2. Receive pending attestation
3. Upgrade to Bitcoin attestation when block is mined

**Calendar servers**:
- `https://a.pool.opentimestamps.org`
- `https://b.pool.opentimestamps.org`
- `https://a.pool.eternitywall.com`

### 6.2 RFC 3161

Integration with Time-Stamp Authorities per RFC 3161:

1. Create TimeStampReq with witness root as message imprint
2. Submit to TSA server
3. Receive signed TimeStampResp

**TSA servers**:
- `https://freetsa.org/tsr`
- `https://zeitstempel.dfn.de`

## 7. Security Considerations

### 7.1 Threat Model

**Assumptions**:
- Adversary controls filesystem after the fact
- Adversary cannot break SHA-256 or Ed25519
- Adversary cannot retroactively modify Bitcoin blockchain
- External timestamp authorities are honest

### 7.2 Attack Resistance

**Backdating**: Cannot produce valid inclusion proofs without knowing historical MMR state.

**Drip Attack**: Edit topology analysis detects artificial append-only patterns.

**Fabrication**: External anchors constrain timeline; statistical analysis reveals artificial patterns.

### 7.3 Privacy Considerations

Edit topology reveals behavioral metadata:
- Which sections are revised most (uncertainty)
- Insertion vs deletion patterns (confidence)
- Positional patterns correlated with document structure

For sensitive contexts, implementations SHOULD support a "reduced privacy mode" storing only size deltas.

## 8. Conformance

### 8.1 Implementation Requirements

A conforming implementation MUST:

1. Use SHA-256 for all hash operations
2. Use Ed25519 for all signatures
3. Apply domain separators exactly as specified
4. Encode metadata in the exact canonical format
5. Compute regions root as specified

### 8.2 Interoperability

Evidence packets produced by any conforming implementation MUST be verifiable by any other conforming implementation.

## Appendix A: Reference Values

### A.1 Domain Separators

| Purpose | Value |
|---------|-------|
| Leaf prefix | `0x00` |
| Internal node prefix | `0x01` |

### A.2 Hash Algorithms

| Purpose | Algorithm |
|---------|-----------|
| Content hash | SHA-256 |
| Node hash | SHA-256 |
| Metadata hash | SHA-256 |
| Regions hash | SHA-256 |

### A.3 Signature Algorithm

| Purpose | Algorithm |
|---------|-----------|
| Root signing | Ed25519 |

## Appendix B: Changelog

### v1.0.0 (2026-01-24)

- Initial specification release
