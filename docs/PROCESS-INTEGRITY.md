# Process Integrity Statement

## Purpose

This document specifies the exact operations performed by the witnessd software,
operations it does not perform, known failure modes, update procedures, and
verification methods. This document is intended as technical reference material
for forensic examiners, expert witnesses, and legal professionals evaluating
evidence produced by this system.

## 1. System Operations

### 1.1 Operations Performed

The software performs the following operations:

| Operation | Input | Output | Algorithm |
|-----------|-------|--------|-----------|
| File change detection | File system events | Event record | fsnotify library, polling fallback |
| Content hashing | File byte stream | 32-byte hash | SHA-256 (FIPS 180-4) |
| Metadata capture | Operating system calls | Structured record | See 1.2 |
| Hash chaining | Current hash, previous hash | Combined hash | SHA-256 with 0x01 prefix |
| Record storage | Hash chain node | Persisted node | Merkle Mountain Range append |
| Root signing | MMR root hash | 64-byte signature | Ed25519 (RFC 8032) |
| External submission | Root hash | Third-party proof | OpenTimestamps, RFC 3161 |

### 1.2 Data Captured Per File Event

Each file change event results in the following data being recorded:

**Mandatory fields:**
- `timestamp_ns`: Nanoseconds since Unix epoch (int64), from system clock
- `file_path`: Absolute file path (string), from operating system
- `content_hash`: SHA-256 of file bytes (32 bytes), computed by this software
- `file_size`: Byte count (int64), from operating system stat call
- `size_delta`: Byte difference from previous recorded state (int32)
- `mmr_index`: Position in Merkle Mountain Range (uint64)
- `mmr_leaf_hash`: Hash binding this record to MMR (32 bytes)

**Optional fields (when enabled):**
- `edit_regions`: Normalized positions (0.0-1.0) of detected changes
- `keystroke_intervals`: Milliseconds between key events (no characters)

### 1.3 Algorithms and Libraries

| Component | Algorithm | Reference | Implementation |
|-----------|-----------|-----------|----------------|
| Content hash | SHA-256 | FIPS 180-4 | Rust `sha2` crate |
| Internal node hash | SHA-256 | FIPS 180-4 | Rust `sha2` crate, 0x01 prefix |
| Leaf node hash | SHA-256 | FIPS 180-4 | Rust `sha2` crate, 0x00 prefix |
| Signature | Ed25519 | RFC 8032 | Rust `ed25519-dalek` crate |
| Encryption (optional) | AES-256-GCM | FIPS 197, SP 800-38D | Rust `aes-gcm` crate |

### 1.4 Storage Format

**MMR file (mmr.bin):**
```
Per node: [8-byte index][1-byte height][32-byte hash] = 41 bytes
Nodes stored sequentially. No compression.
```

**SQLite database (events.db):**
```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    device_id BLOB NOT NULL,
    mmr_index INTEGER NOT NULL,
    mmr_leaf_hash BLOB NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    content_hash BLOB NOT NULL,
    file_size INTEGER NOT NULL,
    size_delta INTEGER,
    context_id INTEGER
);
```

## 2. Operations NOT Performed

### 2.1 The software does NOT:

**Content analysis:**
- Read, parse, or interpret file contents beyond computing hash
- Perform text analysis, natural language processing, or AI detection
- Compare content to external sources or databases
- Store file contents (only stores SHA-256 hash)

**Identity verification:**
- Verify identity of the person operating the computer
- Perform biometric identification
- Connect to identity services or directories
- Prove which human typed the content

**Access control:**
- Prevent file modification
- Enforce file permissions
- Block or monitor other users
- Detect privilege escalation or administrative access

**Network monitoring:**
- Monitor network connections
- Detect remote access or screen sharing
- Verify network isolation

**Tamper prevention:**
- Prevent modification of its own database
- Prevent deletion of MMR file
- Prevent administrative users from altering records

### 2.2 Limitations of timestamp data:

- Timestamps are derived from the system clock
- System clocks can be manipulated by users with administrative access
- Without external anchoring, timestamps are assertions, not proofs
- The software does not detect or prevent clock manipulation

### 2.3 Limitations of access control data:

- File permissions are captured at observation time only
- Cannot determine historical permission changes
- Cannot enumerate all users with potential access
- Administrative users always have implicit access
- Network file shares may grant additional access not visible locally

## 3. Attack Surfaces

### 3.1 Capture Environment Integrity

**Attack**: Compromised operating system or kernel-level tooling injects
false events or manipulates observations.

| Attack Vector | Detection Capability | Mitigation |
|---------------|---------------------|------------|
| Kernel rootkit | None | TPM attestation of boot state |
| Hypervisor compromise | None | Hardware attestation, bare metal |
| Malicious kernel module | None | Secure Boot, kernel lockdown |
| LD_PRELOAD injection | Partial (hash mismatch) | Static binary, integrity checks |
| ptrace/debugging | None | Disable ptrace in production |

**Assessment**: This software cannot detect or prevent kernel-level compromise.
If the operating system kernel is compromised, all observations are suspect.

**Mitigation**: TPM attestation (when enabled) records platform state at
signing time. Secure Boot with measured launch provides evidence of boot
chain integrity. Neither proves runtime integrity.

### 3.2 Clock Manipulation

**Attack**: System clock set backwards or forwards to falsify timestamps.

| Attack Vector | Detection Capability | Mitigation |
|---------------|---------------------|------------|
| NTP manipulation | None locally | External anchors |
| Manual clock change | None locally | External anchors |
| VM snapshot restore | None locally | External anchors, TPM monotonic counter |
| Hardware clock tampering | None | TPM clock attestation |

**Assessment**: Local timestamps are assertions from the system clock. Without
external anchors, timestamps are not independently verifiable.

**Mitigation**: External anchors (OpenTimestamps, RFC 3161) establish
independently-verifiable time bounds. The gap between local timestamp and
anchor time represents the manipulation window.

**Quantification**: If record shows local timestamp T and Bitcoin anchor
confirms at block time T+Δ, the record existed no later than T+Δ. The
claimed timestamp T cannot be verified without additional evidence.

### 3.3 Event Injection

**Attack**: False file events or keystroke data injected into the record.

| Attack Vector | Detection Capability | Mitigation |
|---------------|---------------------|------------|
| Fake fsnotify events | None | Hash verification of actual file |
| Synthetic keystrokes | Behavioral analysis | Jitter entropy, device fingerprinting |
| Scripted typing | Statistical anomaly | Forensic metrics, timing analysis |
| Replay of recorded keystrokes | Partial | Document hash binding |

**Assessment**: File content hashes are verified against actual files. Keystroke
timing can be synthesized but requires matching behavioral patterns.

**Mitigation**: Keystroke evidence binds to document state hashes. Forensic
metrics detect statistically anomalous patterns. Device fingerprinting
detects virtual keyboards.

### 3.4 Summary: Trust Boundaries

| Trust Assumption | Consequence if Violated |
|------------------|------------------------|
| Kernel integrity | All observations suspect |
| Hardware clock | Local timestamps unreliable |
| Signing key security | Valid signatures on false data |
| File system integrity | Hash verification fails |
| Network path to anchors | Anchoring may be delayed/blocked |

**Critical**: This software operates within the trust boundary of the
operating system. It cannot provide guarantees stronger than the platform
it runs on. For high-assurance scenarios, TPM attestation and external
anchors are essential.

### 3.5 Available Mitigations

The following mitigations are implemented to constrain the attack surface:

**TPM/Secure Enclave Attestation:**
- Platform state recorded at boot (PCR values)
- Monotonic counter prevents rollback attacks
- TPM quotes provide cryptographic proof of platform state
- Secure Enclave (macOS) ensures signing keys never leave hardware

**Remote Verification Protocol:**
- Device enrollment with TPM endorsement key + PUF fingerprint
- Challenge-response with fresh nonces (replay protection)
- PCR comparison against enrolled baseline
- Counter verification ensures forward progress

**Platform Security State Capture:**
- Secure Boot status recorded
- SIP/Gatekeeper status (macOS)
- Kernel lockdown mode (Linux)
- Virtualization detection (VM/hypervisor)
- Debugger attachment detection
- Executable hash for binary integrity

**External Anchoring:**
- Bitcoin blockchain provides independent timestamp
- RFC 3161 TSA provides third-party attestation
- Limits clock manipulation window to anchor interval

**Behavioral Analysis:**
- Keystroke timing bound to document hashes
- Jitter entropy analysis detects synthetic input
- Device fingerprinting detects virtual keyboards
- Statistical anomaly detection flags suspicious patterns

### 3.6 Residual Risk

Even with all mitigations enabled, the following risks remain:

| Attack | Mitigated By | Residual Risk |
|--------|--------------|---------------|
| OS compromise before boot | Secure Boot | Pre-UEFI attacks |
| VM snapshot restore | TPM counter, timestamps | Snapshot before anchoring |
| Clock manipulation | External anchors | Gap between local time and anchor |
| Sophisticated rootkit | PCR measurement | Rootkit that doesn't change PCRs |
| Hardware implant | None | Physical access attack |

**Conclusion**: For contested evidence, enable TPM attestation, external
anchoring, and require remote verification. Document the security state
at capture time. The combination significantly raises the bar for
undetected manipulation.

## 4. Failure Modes

### 4.1 Detectable Failures

| Failure | Detection | Result |
|---------|-----------|--------|
| MMR hash mismatch | Recomputation during verify | Error reported |
| SQLite corruption | PRAGMA integrity_check | Error reported |
| Index gap in MMR | Sequential index validation | Error reported |
| Invalid signature | Ed25519 verification | Verification failure |
| Missing MMR node | Index lookup failure | Error reported |

### 3.2 Failures That May Not Be Detected

| Failure | Reason Undetected |
|---------|-------------------|
| File edits while daemon stopped | No observation occurred |
| System clock manipulation | No independent time source locally |
| Signing key compromise | Valid signatures still produced |
| Administrative database modification | No runtime integrity monitoring |
| Memory corruption | Process isolation limits detection |

### 3.3 Implications

- Gaps in the record may indicate daemon was not running, or may indicate tampering
- Local timestamps without external anchors are not independently verifiable
- Records from a compromised signing key are indistinguishable from legitimate records
- An administrator with disk access can modify the database

## 4. Software Updates

### 4.1 Version Format

```
MAJOR.MINOR.PATCH

MAJOR: Changes to evidence format or cryptographic algorithms
MINOR: New functionality, backwards compatible
PATCH: Bug fixes
```

### 4.2 Compatibility

| Data Type | Compatibility Rule |
|-----------|-------------------|
| Evidence packets | Read by same or later major version |
| MMR structure | Unchanged within major version |
| SQLite schema | Migrations provided |
| Configuration | Additive changes only within major version |

### 4.3 Update Procedure

1. Verify release signature
2. Backup witnessd data directory
3. Stop running daemon
4. Install new version
5. Run verification on existing data
6. Start daemon

## 5. Verification Procedures

### 5.1 MMR Verification

To verify MMR integrity:
1. Read each node from mmr.bin
2. For leaf nodes (height=0): verify hash matches stored value
3. For internal nodes: compute SHA-256(0x01 || left_child || right_child)
4. Verify computed hash matches stored hash
5. Verify indices are sequential without gaps

### 5.2 Database-MMR Binding Verification

For each event in SQLite:
1. Read mmr_leaf_hash from events table
2. Locate corresponding node in MMR by mmr_index
3. Verify hashes match

### 5.3 Signature Verification

1. Compute MMR root by bagging peaks (see specification)
2. Load Ed25519 public key
3. Verify signature over root hash per RFC 8032

### 5.4 External Anchor Verification

**OpenTimestamps:**
1. Parse .ots file
2. Follow attestation path to Bitcoin block
3. Verify Merkle path to block header
4. Verify block exists in Bitcoin blockchain

**RFC 3161:**
1. Parse TimeStampResp (ASN.1 DER)
2. Extract MessageImprint
3. Verify matches submitted hash
4. Verify TSA signature
5. Verify TSA certificate chain

### 5.5 Independent Verification Code

Evidence can be verified without this software. Example (Python):

```python
import hashlib
import json

def verify_content_hash(file_path, expected_hash):
    """Verify file content matches expected SHA-256 hash."""
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest() == expected_hash

def verify_merkle_path(leaf_hash, path, expected_peak):
    """Verify Merkle path from leaf to peak."""
    current = bytes.fromhex(leaf_hash)
    for step in path:
        sibling = bytes.fromhex(step['hash'])
        h = hashlib.sha256()
        h.update(b'\x01')  # Internal node prefix
        if step['is_left']:
            h.update(current)
            h.update(sibling)
        else:
            h.update(sibling)
            h.update(current)
        current = h.digest()
    return current.hex() == expected_peak

def bag_peaks(peaks):
    """Combine MMR peaks into root hash."""
    if len(peaks) == 1:
        return peaks[0]
    result = bytes.fromhex(peaks[-1])
    for peak in reversed(peaks[:-1]):
        h = hashlib.sha256()
        h.update(bytes.fromhex(peak))
        h.update(result)
        result = h.digest()
    return result.hex()
```

## 6. Audit Log

### 6.1 Events Logged

| Event | Data Recorded |
|-------|---------------|
| Daemon start | Version, configuration path, device identifier |
| Daemon stop | Shutdown reason |
| File witnessed | File path, hash (truncated), MMR index |
| Root signed | Root hash (truncated), signature (truncated) |
| Anchor submitted | Anchor type, submitted hash |
| Verification performed | File path, result |
| Error | Error message, stack trace |

### 6.2 Log Format

```json
{
  "timestamp": "2026-01-26T12:00:00.123456789Z",
  "level": "INFO",
  "event": "file_witnessed",
  "device_id": "...",
  "data": {
    "file_path": "/path/to/file",
    "content_hash": "abc123...",
    "mmr_index": 42
  }
}
```

## 7. Standards Referenced

| Standard | Use in This Software |
|----------|---------------------|
| FIPS 180-4 | SHA-256 hash algorithm |
| RFC 8032 | Ed25519 signature scheme |
| RFC 3161 | Timestamp protocol client |
| ETSI EN 319 612 | EU Trusted List parsing |

This software implements parsing and validation of EU Trusted Lists according
to ETSI EN 319 612. This implementation does not confer any legal status on
timestamps; legal determinations require evaluation by qualified counsel.

---

*Document Version: 1.1*
*Revision Date: 2026-01-26*
*Software Version: 0.x*
