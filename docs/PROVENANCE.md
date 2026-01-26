# Record Provenance and Chain of Custody

This document specifies how witnessd establishes, maintains, and verifies the
provenance of witnessed records. It addresses: who initiated records, where
they were generated, access control, and chain of custody requirements.

## 1. Record Initiation

### 1.1 Initiator Identification

Every witnessed record cryptographically binds the following initiator data:

| Field | Description | Source |
|-------|-------------|--------|
| `device_id` | 16-byte unique device identifier | Generated at first run, stored in config |
| `signing_pubkey` | Ed25519 public key (32 bytes) | User's signing key |
| `hostname` | System hostname at record time | `os.Hostname()` |
| `user_id` | Operating system user ID | Process UID |

**Generation Process:**

```
device_id = SHA-256(machine_id || signing_pubkey || creation_timestamp)[:16]
```

Where `machine_id` is:
- **macOS**: `IOPlatformUUID` from IOKit
- **Linux**: `/etc/machine-id` or `/var/lib/dbus/machine-id`
- **Windows**: `MachineGuid` from registry

### 1.2 Record Creation Flow

1. File system event detected (fsnotify)
2. Debounce period elapsed (default: 500ms)
3. Content hash computed (SHA-256, streaming)
4. Metadata captured:
   - Timestamp (nanoseconds since Unix epoch)
   - File path (absolute, canonical)
   - File size
   - Size delta from previous state
5. Edit topology extracted (if shadow cache enabled)
6. MMR leaf computed:
   ```
   leaf = SHA-256(0x00 || content_hash || metadata_hash || regions_root)
   ```
7. Leaf appended to MMR
8. Event stored in SQLite with `mmr_leaf_hash` binding
9. Periodic root signing with Ed25519

### 1.3 What Is NOT Captured

The system explicitly does NOT capture:
- File contents (only SHA-256 hashes)
- Keystroke characters (only timing intervals)
- Screen content or clipboard text
- Network traffic or remote access logs
- Other users' file activity

## 2. Device and System Identification

### 2.1 Hardware Identification

When keystroke tracking is enabled, the system records input device information:

| Field | Description |
|-------|-------------|
| `vendor_id` | USB Vendor ID (16-bit) |
| `product_id` | USB Product ID (16-bit) |
| `serial_number` | Device serial (if available) |
| `device_path` | OS-specific device path |
| `connection_type` | USB, Bluetooth, PS/2, Internal, Virtual |
| `fingerprint` | SHA-256 of device identifiers |

**Device Fingerprint Computation:**

```
fingerprint = SHA-256("witnessd-device-v1" || vendor_id || product_id ||
                       version_num || product_name || serial_number)
```

### 2.2 System Environment Capture

Each session records:

```json
{
  "session_id": "hex-encoded-32-bytes",
  "started_at": "2026-01-26T12:00:00Z",
  "system": {
    "hostname": "workstation-01",
    "os": "darwin",
    "os_version": "14.2.1",
    "arch": "arm64",
    "device_id": "hex-encoded-16-bytes"
  },
  "signing_key": {
    "algorithm": "Ed25519",
    "public_key": "hex-encoded-32-bytes",
    "key_source": "file|tpm|secure_enclave"
  },
  "input_devices": [
    {
      "vendor_id": 1452,
      "product_id": 835,
      "product_name": "Apple Internal Keyboard",
      "connection_type": "Internal",
      "fingerprint": "hex-encoded-32-bytes"
    }
  ]
}
```

### 2.3 TPM/Secure Enclave Binding

When hardware security is available, records include:

| Platform | Hardware | Binding |
|----------|----------|---------|
| macOS | Secure Enclave | Key never leaves hardware; attestation included |
| Linux | TPM 2.0 | PCR-sealed keys; Quote attestation |
| Windows | TPM 2.0 | Key bound to platform state |

The TPM binding provides:
- **Monotonic counter**: Proves temporal ordering
- **Clock info**: Hardware-backed timestamp
- **Attestation**: Signed by TPM's Endorsement Key
- **Platform state**: PCR values at signing time

## 3. Access Control Documentation

### 3.1 Write Access Tracking

For each witnessed file, the system can document who had write access:

**What We Track:**

| Data Point | Method | Reliability |
|------------|--------|-------------|
| File owner | `os.Stat()` | High - from filesystem |
| File permissions | `os.Stat().Mode()` | High - from filesystem |
| Process UID | `os.Getuid()` | High - process identity |
| Signing key holder | Signature verification | Cryptographic - cannot forge |

**What We Cannot Track:**

| Data Point | Reason |
|------------|--------|
| All users with read access | Would require enumerating ACLs, groups |
| Root/admin access | Privileged users always have access |
| Network share access | External to local filesystem |
| Historical access grants | File permissions are point-in-time |

### 3.2 Access Control in Evidence Packets

Evidence packets include access information when available:

```json
{
  "access_control": {
    "captured_at": "2026-01-26T12:00:00Z",
    "file_owner": {
      "uid": 501,
      "username": "author"
    },
    "file_permissions": "0644",
    "file_group": {
      "gid": 20,
      "groupname": "staff"
    },
    "process_identity": {
      "uid": 501,
      "euid": 501,
      "username": "author"
    },
    "limitations": [
      "Root users always have implicit write access",
      "ACL entries not enumerated",
      "Network share permissions not visible"
    ]
  }
}
```

### 3.3 Explicit Non-Access Declaration

To document who did NOT have access, authors can create process declarations:

```json
{
  "access_declaration": {
    "declared_at": "2026-01-26T12:00:00Z",
    "author_statement": "During the creation of this document, only I (author@example.com) had write access to the file. The system was not connected to any network shares, and no other users were logged in.",
    "system_state": {
      "network_shares_mounted": false,
      "other_users_logged_in": false,
      "remote_access_enabled": false
    },
    "signature": "Ed25519 signature of above"
  }
}
```

**Important:** These declarations are attestations, not proofs. The system
cannot cryptographically prove who did NOT have access.

## 4. Chain of Custody

### 4.1 Cryptographic Chain

The MMR provides an immutable chain of custody:

```
Event 0: leaf_0 = H(content_0 || metadata_0 || regions_0)
Event 1: leaf_1 = H(content_1 || metadata_1 || regions_1)
         peak_1 = H(0x01 || leaf_0 || leaf_1)
Event 2: leaf_2 = H(content_2 || metadata_2 || regions_2)
         ...
Root:    H(peak_bag) signed by Ed25519 key
```

Any modification to any event is detectable because it would change
all subsequent hashes up to and including the root.

### 4.2 External Anchoring

To extend chain of custody beyond the local system:

| Anchor Type | What It Proves | Trust Model |
|-------------|----------------|-------------|
| OpenTimestamps | MMR root existed before Bitcoin block | Decentralized (Bitcoin) |
| RFC 3161 TSA | Root existed at TSA timestamp | Trusted third party |
| EU Trust List | TSA certificate validated | EU member state authority |

### 4.3 Custody Transfer Events

When evidence leaves the witnessd system:

1. **Export**: `witnessctl export` creates self-contained proof
2. **Verification**: Any party can verify using `witnessctl verify`
3. **Archival**: External systems should preserve:
   - The evidence packet (JSON)
   - Any .ots files (OpenTimestamps proofs)
   - Any TSA responses (RFC 3161)

### 4.4 Custody Gaps

The system documents potential custody gaps:

| Gap Type | Detection | Documentation |
|----------|-----------|---------------|
| Time gaps | Inter-event interval > threshold | Flagged as `anomaly.gap` |
| Device changes | Different device fingerprint | Flagged in device report |
| Key rotation | Different signing key | Requires explicit transition record |
| System restart | Session ID change | New session record created |

### 4.5 Multi-Device Synchronization

For documents edited across multiple devices:

```json
{
  "weave": {
    "timestamp": "2026-01-26T12:00:00Z",
    "device_roots": {
      "device_a_id": "mmr_root_a",
      "device_b_id": "mmr_root_b"
    },
    "weave_hash": "H(sorted_device_roots)",
    "signatures": {
      "device_a_id": "sig_a",
      "device_b_id": "sig_b"
    }
  }
}
```

## 5. Evidence Packet Contents

A complete evidence packet contains:

```json
{
  "version": 1,
  "generated_at": "2026-01-26T12:00:00Z",

  "record_provenance": {
    "device_id": "...",
    "hostname": "...",
    "signing_key": "...",
    "session_id": "..."
  },

  "file_evidence": {
    "path": "/path/to/file",
    "content_hash": "...",
    "size": 12345,
    "mmr_index": 42
  },

  "chain_of_custody": {
    "mmr_root": "...",
    "merkle_path": [...],
    "peaks": [...],
    "signature": "..."
  },

  "external_anchors": [...],

  "access_control": {
    "file_owner": "...",
    "file_permissions": "...",
    "process_identity": "..."
  },

  "device_info": {
    "primary_device": {...},
    "device_changes": [...],
    "consistency_score": 0.95
  },

  "limitations": [
    "Local timestamps may be manipulated without external anchors",
    "Access control reflects point-in-time state only",
    "Cannot prove who did NOT have access"
  ]
}
```

## 6. Verification Checklist

To verify chain of custody:

1. [ ] Verify Ed25519 signature over MMR root
2. [ ] Walk Merkle path from content hash to peak
3. [ ] Verify peak matches in peaks array
4. [ ] Bag peaks and confirm matches signed root
5. [ ] If external anchors present, verify each
6. [ ] Check device consistency report
7. [ ] Review any custody gap flags
8. [ ] Confirm evidence packet schema validates

## 7. Limitations and Explicit Non-Guarantees

This system:
- **DOES NOT** prove who physically typed content
- **DOES NOT** prove network isolation during creation
- **DOES NOT** prove absence of screen sharing/recording
- **DOES NOT** guarantee timestamps without external anchors
- **DOES NOT** prevent authorized users from modifying files
- **DOES NOT** detect kernel-level compromise

These limitations are fundamental to any software-based system and should be
communicated to any party relying on witnessd evidence.
