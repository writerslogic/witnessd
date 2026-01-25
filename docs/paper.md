# Kinetic Proof of Provenance: Cryptographic Evidence of Human Authorship

## Abstract

We present **witnessd**, a system for generating irrefutable cryptographic evidence of document authorship through continuous temporal witnessing. By capturing the "kinetic signature" of human creative work—the natural rhythm of edits, pauses, and revisions—we construct proofs that are infeasible to forge retroactively. The system employs a Merkle Mountain Range (MMR) for efficient append-only state tracking, Ed25519 signatures for identity binding, and external trust anchors (OpenTimestamps, RFC 3161) for immutable timestamps.

## 1. Introduction

The rise of large language models (LLMs) has created an unprecedented challenge in authorship verification. A document produced by an AI in seconds is indistinguishable from one written by a human over hours. Traditional metadata (file timestamps, revision history) is trivially manipulated.

**Kinetic Proof of Provenance** addresses this through continuous cryptographic witnessing. We argue that the *temporal pattern* of creation—what we call the "creative heartbeat"—is a unique fingerprint that AI-generated content fundamentally lacks.

### 1.1 Key Insight

Human writing exhibits a distinctive temporal signature:
- **Bursts and pauses**: Ideas flow in spurts with natural breaks
- **Iterative refinement**: Multiple passes over the same sections
- **Non-linear progress**: Jumping between sections, backtracking
- **Consistent rhythm**: Individual writers have characteristic pacing

AI generation, by contrast, produces content atomically—there is no process, only a result.

## 2. System Architecture

### 2.1 Merkle Mountain Range (MMR)

We use an MMR as the core data structure because:

1. **Append-only**: Perfect for chronological witnessing
2. **O(log n) proofs**: Efficient inclusion proofs
3. **Multiple peaks**: Allows incremental root updates
4. **No rebalancing**: Unlike Merkle trees, structure is deterministic

The MMR stores hashes of witnessed document states. Each state captures:
- SHA-256 hash of file contents
- Implicit ordering through MMR position

### 2.2 Domain Separation

To prevent second-preimage attacks, we use domain-separated hashing:

```
LeafHash = SHA256(0x00 || data)
InternalHash = SHA256(0x01 || left || right)
```

This ensures that leaf hashes and internal node hashes occupy distinct domains.

### 2.3 Root Commitment

The "Witness Root" is computed by bagging all peaks:

```
Root = Hash(peak[0], Hash(peak[1], Hash(peak[2], ...)))
```

This single 32-byte value represents the complete witness history.

## 3. The Witness Protocol

### 3.1 Background Daemon (witnessd)

The daemon operates invisibly:

1. **File Monitoring**: Uses fsnotify to watch configured directories
2. **Debouncing**: Waits for file stability (configurable, default 5 seconds)
3. **State Hashing**: Computes SHA-256 using streaming for large files
4. **MMR Append**: Adds the hash to the append-only structure
5. **Periodic Signing**: Signs the root with Ed25519 every N events

### 3.2 Evidence Export

The `witnessctl export` command produces a JSON "Evidence Packet":

```json
{
  "version": 1,
  "file_path": "document.txt",
  "file_hash": "abc123...",
  "mmr_index": 42,
  "mmr_size": 157,
  "mmr_root": "def456...",
  "merkle_path": [...],
  "peaks": [...],
  "signature": "789..."
}
```

This packet is self-contained and can be verified by anyone with the public key.

## 4. External Trust Anchors

### 4.1 OpenTimestamps

We submit MMR roots to Bitcoin calendar servers:
- Provides Bitcoin blockchain attestation
- Proof of existence at a specific block height
- Immutable even if local database is compromised

### 4.2 RFC 3161

Traditional Time-Stamp Authority compliance:
- Compatible with legal frameworks
- Signed by trusted third parties
- Supports multiple TSA servers

## 5. Security Analysis

### 5.1 Threat Model

We assume:
- Adversary controls file system after the fact
- Adversary cannot break SHA-256 or Ed25519
- Adversary cannot retroactively modify blockchain
- External anchors are trusted

### 5.2 Attack Resistance

**Backdating Attack**: Even if an adversary creates documents with old timestamps, they cannot produce valid MMR inclusion proofs without knowing the MMR state at that time. The root hash and external anchors provide a cryptographic commitment.

**Fabrication Attack**: An adversary could generate many fake "edit" hashes, but:
1. The temporal density would be suspicious (too regular)
2. External anchors pin the timeline
3. Statistical analysis reveals artificial patterns

### 5.3 Creative Heartbeat Analysis

Future work includes statistical analysis of witness patterns:
- Edit frequency distribution
- Time-of-day patterns
- Inter-edit interval variance
- Section-jumping behavior

These metrics form a "creativity fingerprint" unique to human authors.

## 6. Performance

### 6.1 Storage Overhead

| Edits | MMR Nodes | DB Size | Overhead Ratio |
|-------|-----------|---------|----------------|
| 100   | 199       | 8.2 KB  | 0.08x          |
| 1000  | 1999      | 82 KB   | 0.08x          |
| 10000 | 19999     | 820 KB  | 0.08x          |

The 41-byte node format (8 index + 1 height + 32 hash) is highly efficient.

### 6.2 Operation Latency

| Operation | Time (1000 leaves) |
|-----------|-------------------|
| Append    | ~5 µs             |
| Get Root  | ~2 µs             |
| Gen Proof | ~10 µs            |
| Verify    | ~8 µs             |

All operations complete in microseconds, making real-time witnessing practical.

## 7. Comparison with Alternatives

| System | Append-Only | Identity Bound | External Anchors | Process Proof |
|--------|-------------|----------------|------------------|---------------|
| Git    | Yes         | Optional       | No               | Partial       |
| IPFS   | Yes         | No             | No               | No            |
| Blockchain | Yes     | Yes            | N/A              | No            |
| **witnessd** | Yes   | Yes            | Yes              | **Yes**       |

Only witnessd captures the *process* of creation, not just the result.

## 8. Conclusion

witnessd provides a practical solution for proving human authorship through cryptographic process witnessing. By capturing the natural rhythm of creative work, we produce evidence that is:

1. **Irrefutable**: Cryptographically bound to identity and time
2. **Portable**: Self-contained evidence packets
3. **Verifiable**: Anyone can check proofs
4. **Efficient**: Minimal overhead during creation

As AI-generated content becomes ubiquitous, systems like witnessd become essential for establishing authentic human provenance.

## References

1. Merkle Mountain Range specification (mimblewimble/grin)
2. OpenTimestamps Protocol (opentimestamps.org)
3. RFC 3161: Internet X.509 PKI Time-Stamp Protocol
4. EdDSA and Ed25519 (RFC 8032)

---

*Generated by witnessd. This document has been cryptographically witnessed during its creation.*
