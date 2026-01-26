# Protocol Specification Update Recommendations

This document outlines required changes to `witness-protocol-v1.md` to align with the current checkpoint chain implementation.

## Summary

The current specification describes an MMR (Merkle Mountain Range) based system, but the implementation uses a **checkpoint chain with VDF time proofs**. This document details the sections that need modification.

---

## Sections to Remove or Replace

### Section 2.1: Merkle Mountain Range (MMR)
**Action:** Replace entirely

The entire MMR section (2.1.1 through 2.1.4) describes data structures not used in evidence packet export. Replace with:

**New Section 2.1: Checkpoint Chain**
```
The checkpoint chain is a sequential, hash-linked series of document commits.
Each checkpoint cryptographically commits to:
- The document content at that point in time
- The previous checkpoint hash (forming a chain)
- A VDF proof establishing minimum elapsed time

Properties:
- Sequential: Checkpoints are strictly ordered by ordinal
- Hash-linked: Each checkpoint includes the hash of its predecessor
- Time-proven: VDF proofs establish minimum elapsed time between commits
- Deterministic: Given the same inputs, checkpoint hashes are identical
```

### Section 2.1.2: Node Structure
**Action:** Replace with Checkpoint Structure

| Field | Type | Description |
|-------|------|-------------|
| `ordinal` | uint64 | Sequence number (0-indexed) |
| `content_hash` | bytes[32] | SHA-256 of document content |
| `content_size` | int64 | Document size in bytes |
| `timestamp` | datetime | Wall-clock time of commit |
| `previous_hash` | bytes[32] | Hash of previous checkpoint |
| `hash` | bytes[32] | SHA-256 of this checkpoint |
| `vdf_input` | bytes[32] | VDF input (previous checkpoint hash) |
| `vdf_output` | bytes[32] | VDF output after iterations |
| `vdf_iterations` | uint64 | Number of VDF iterations |

### Section 2.1.3: Domain-Separated Hashing
**Action:** Remove or simplify

MMR domain separators (0x00 for leaf, 0x01 for internal) are not applicable. The checkpoint chain uses standard SHA-256 of the checkpoint structure.

### Section 2.1.4: Peak Bagging
**Action:** Remove

Peak bagging is an MMR-specific operation. Replace with description of chain hash (hash of the final checkpoint).

---

## Sections to Update

### Section 2.2: Witness Event → Checkpoint
**Action:** Rename and update

Change "Witness Event" terminology to "Checkpoint" throughout. Update the field table to match `CheckpointProof` struct.

### Section 3: Cryptographic Commitment
**Action:** Rewrite for checkpoint chain

The commitment structure changes from:
```
LeafHash = SHA256(0x00 || ContentHash || MetadataHash || RegionsRoot)
```

To:
```
CheckpointHash = SHA256(
    Ordinal ||
    ContentHash ||
    ContentSize ||
    Timestamp ||
    PreviousHash ||
    VDFOutput
)
```

### Section 4: Evidence Packet
**Action:** Complete rewrite

The evidence packet format differs significantly. Update to match `evidence.Packet` structure:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | integer | Yes | Schema version (1) |
| `exported_at` | datetime | Yes | Export timestamp |
| `strength` | integer | Yes | Evidence tier (1-4) |
| `document` | object | Yes | Document metadata |
| `checkpoints` | array | Yes | Checkpoint chain |
| `vdf_params` | object | Yes | VDF parameters |
| `chain_hash` | string | Yes | Final checkpoint hash |
| `declaration` | object | Yes | Signed process declaration |
| `presence` | object | No | Presence verification |
| `hardware` | object | No | TPM attestations |
| `keystroke` | object | No | Keystroke evidence |
| `behavioral` | object | No | Edit topology/metrics |
| `contexts` | array | No | Context periods |
| `external` | object | No | External anchors |
| `claims` | array | Yes | What evidence proves |
| `limitations` | array | Yes | What evidence cannot prove |

### Section 4.4: Verification Algorithm
**Action:** Rewrite

Current algorithm describes MMR inclusion proof verification. Replace with:

1. **Verify chain integrity**: Walk checkpoint chain, verify each `previous_hash` matches
2. **Verify VDF proofs**: For each checkpoint with VDF, verify output matches claimed iterations
3. **Verify document hash**: Confirm `document.final_hash` matches last checkpoint's `content_hash`
4. **Verify declaration**: Check Ed25519 signature, verify hash bindings
5. **Verify keystroke chain** (if present): Walk jitter samples, verify chain hashes
6. **Verify TPM bindings** (if present): Verify quote signatures
7. **Verify external anchors** (if present): Validate anchor proofs

---

## New Sections Needed

### Section 2.X: Verifiable Delay Function (VDF)
Add new section explaining:
- VDF purpose (time-lock puzzles)
- Parameters (modulus, iterations_per_sec, security_param)
- How elapsed time is derived from iterations
- Verification process

### Section 2.X: Process Declaration
Add new section for the required declaration:
- Structure (input modalities, AI tools, collaborators)
- Signing process (Ed25519)
- Hash bindings (document_hash, chain_hash)

### Section 2.X: Keystroke Evidence
Add new section for jitter-based keystroke verification:
- Sample structure (ordinal, timestamp, doc_hash, jitter)
- Chain integrity (sample hash linking)
- Statistical properties (plausibility checks)

### Section 2.X: Evidence Strength Tiers
Add explanation of the four-tier system:
- **Basic (1)**: Checkpoints + Declaration
- **Standard (2)**: + Presence verification
- **Enhanced (3)**: + Hardware attestation
- **Maximum (4)**: + Behavioral + External anchors

---

## Terminology Changes

| Old Term | New Term |
|----------|----------|
| Witness Event | Checkpoint |
| MMR | Checkpoint Chain |
| Leaf | Checkpoint |
| Peak | (remove) |
| Witness Root | Chain Hash |
| MMR Index | Ordinal |
| MMR Size | Checkpoint Count |
| Inclusion Proof | (remove, use chain verification) |

---

## Schema References

Update Appendix or add new appendix:

| Schema | Purpose |
|--------|---------|
| `evidence-packet-v1.schema.json` | Evidence packet validation |
| `verification-result-v1.schema.json` | Verification output validation |
| `forensic-profile-v1.schema.json` | Forensic analysis output |
| `attestation-v1.schema.json` | TPM attestation template |

---

## Backward Compatibility Note

The MMR-based system (`internal/mmr/`) still exists in the codebase and is used by the storage layer (`internal/store/`). However, the **evidence export format** uses the checkpoint chain model. Future versions may reconcile these systems or provide conversion utilities.

---

## Priority

1. **High**: Section 4 (Evidence Packet) - directly affects interoperability
2. **High**: Section 2.1 (Data Structures) - foundational definitions
3. **Medium**: Section 3 (Cryptographic Commitment) - verification logic
4. **Medium**: New sections (VDF, Declaration, Keystroke)
5. **Low**: Terminology updates throughout
