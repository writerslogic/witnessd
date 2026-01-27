# witnessd

**Kinetic Proof of Provenance** — A cryptographic file witnessing daemon that
creates tamper-evident records of file authorship and modification history.

## Overview

witnessd continuously monitors files and creates cryptographic proofs of their
state over time. Unlike traditional version control, witnessd focuses on
**proving when and how content was created**, enabling:

- **Legal Evidence:** Admissible, burden-shifting evidence under FRE 902(13) and equivalent rules
- **Authorship Verification:** Detect AI-generated vs human-authored content
- **Tamper Detection:** Cryptographically verify historical file states
- **Compliance:** Implements EU Trusted List parsing and validation according to ETSI EN 319 612

## Key Features

### Cryptographic Witnessing
- **Append-only MMR:** Merkle Mountain Range for efficient inclusion proofs
- **Ed25519 Signatures:** Sign commitments with hardware or software keys
- **TPM Integration:** Optional hardware-bound attestations
- **External Anchoring:** OpenTimestamps and RFC 3161 TSA support

### Forensic Analysis
- **Kinetic Integrity:** Behavioral biometrics from editing patterns
- **Topology Extraction:** Privacy-preserving edit region detection
- **Authorship Profiling:** Statistical analysis of writing behavior
- **Anomaly Detection:** Flag suspicious editing patterns

### Privacy by Design
- **Local-first:** All processing occurs on your device
- **Hash-only Storage:** File contents are never stored (optional shadow cache)
- **Timing-only Biometrics:** Measure when, not what, is typed

## Quick Start

### Installation

```bash
# From source
git clone https://github.com/writerslogic/witnessd.git
cd witnessd
make build
sudo make install

# Generate signing key
ssh-keygen -t ed25519 -f ~/.ssh/witnessd_signing_key -N ""
```

### Configuration

Create `~/.witnessd/config.toml`:

```toml
# Directories to monitor
watch_paths = ["~/Documents", "~/Projects"]

# File patterns to include
include_patterns = ["*.md", "*.txt", "*.go", "*.py"]

# Signing key location
signing_key_path = "~/.ssh/witnessd_signing_key"

# Debounce interval (milliseconds)
debounce_ms = 500
```

### Running

```bash
# Start the daemon
witnessd

# Check status
witnessctl status

# Verify a file
witnessctl verify ~/Documents/important.md

# Export evidence packet
witnessctl export ~/Documents/important.md > evidence.json

# Analyze authorship patterns
witnessctl forensics ~/Documents/important.md
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        witnessd                              │
├─────────────────────────────────────────────────────────────┤
│  Watcher          │  Hasher           │  Store              │
│  ├─ fsnotify      │  ├─ SHA-256       │  ├─ SQLite events   │
│  ├─ debounce      │  ├─ streaming     │  ├─ MMR (binary)    │
│  └─ patterns      │  └─ topology      │  └─ shadow cache    │
├─────────────────────────────────────────────────────────────┤
│  Signer           │  Anchors          │  Forensics          │
│  ├─ Ed25519       │  ├─ OpenTimestamps│  ├─ metrics         │
│  ├─ TPM (opt)     │  ├─ RFC 3161      │  ├─ profiling       │
│  └─ passphrase    │  └─ blockchain    │  └─ anomaly detect  │
└─────────────────────────────────────────────────────────────┘
```

## Documentation

### Protocol Specification

The formal Witness Protocol specification is maintained separately from the implementation:

- [spec/witness-protocol-v1.md](spec/witness-protocol-v1.md) — Formal protocol specification
- [spec/CHANGELOG.md](spec/CHANGELOG.md) — Specification version history

### JSON Schemas

Schemas for validating witnessd output:

- [schema/witness-proof-v1.schema.json](schema/witness-proof-v1.schema.json) — Evidence packet validation
- [schema/forensic-profile-v1.schema.json](schema/forensic-profile-v1.schema.json) — Forensic analysis validation
- [schema/attestation-v1.schema.json](schema/attestation-v1.schema.json) — TPM attestation template validation

### Spec Fixtures

Minimal, schema-valid examples used for compatibility testing:

- [spec/fixtures/witness-proof-v1.json](spec/fixtures/witness-proof-v1.json)
- [spec/fixtures/forensic-profile-v1.json](spec/fixtures/forensic-profile-v1.json)

### General

- [SECURITY.md](../SECURITY.md) — Security model and vulnerability reporting
- [PRIVACY.md](../PRIVACY.md) — Privacy policy and data handling
- [CONTRIBUTING.md](../CONTRIBUTING.md) — Contribution guidelines

### Provenance and Process Integrity

- [PROVENANCE.md](PROVENANCE.md) — Record provenance, device identification, access control, chain of custody
- [PROCESS-INTEGRITY.md](PROCESS-INTEGRITY.md) — What the system does/doesn't do, failure modes, update policy, verification steps

### Independent Verification

- [INDEPENDENT-VERIFICATION.md](INDEPENDENT-VERIFICATION.md) — Third-party verification without witnessd software

### Evidence Architecture

- [EVIDENCE-ARCHITECTURE.md](EVIDENCE-ARCHITECTURE.md) — Forensic evidence specification forcing binary forks

### Versioning

The specification and implementation are versioned independently:

| Component | Tag Format | Example |
|-----------|------------|---------|
| Protocol Spec | `spec/vX.Y.Z` | `spec/v1.0.0` |
| Daemon | `witnessd/vX.Y.Z` | `witnessd/v1.0.0` |

This separation ensures:
- Protocol stability independent of implementation changes
- Clear compatibility tracking for third-party implementations
- Judicial auditability of evidence format without parsing source code

## Use Cases

### Legal Discovery
Generate self-authenticating evidence packets (FRE 902(13)):
```bash
witnessctl export --format=legal document.pdf > evidence.json
```

### Academic Integrity
Verify original authorship of research papers and code:
```bash
witnessctl forensics thesis.md
```

### IP Protection
Establish priority dates for inventions and creative works:
```bash
witnessctl export --anchor=ots invention.md
```

### Compliance
Meet regulatory requirements for document authenticity:
```bash
witnessctl verify --anchor=rfc3161 contract.pdf
```

## Comparison

| Feature | witnessd | Git | Blockchain |
|---------|----------|-----|------------|
| Local-first | ✅ | ✅ | ❌ |
| Append-only proof | ✅ | ❌ | ✅ |
| Behavioral biometrics | ✅ | ❌ | ❌ |
| Hardware binding | ✅ | ❌ | ❌ |
| Real-time monitoring | ✅ | ❌ | ❌ |
| Selective disclosure | ✅ | ❌ | ❌ |

## License

Dual License: Non-commercial use free; commercial license required for business use.
Patent Pending: USPTO Application No. 19/460,364.
See [LICENSE](../LICENSE) for complete terms.

## Acknowledgments

Built with inspiration from:
- [OpenTimestamps](https://opentimestamps.org/)
- [Merkle Mountain Ranges](https://github.com/opentimestamps/python-opentimestamps)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/)
