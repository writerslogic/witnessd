# Witness Protocol Specification Changelog

All notable changes to the Witness Protocol specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `evidence-packet-v1.schema.json` - New schema for checkpoint chain evidence format
- `verification-result-v1.schema.json` - Schema for arbiter verification output
- `evidence-packet-v1.example.json` - Realistic example evidence packet
- `PROTOCOL-UPDATE-RECOMMENDATIONS.md` - Migration guide from MMR to checkpoint chain

### Deprecated

- `witness-proof-v1.schema.json` - MMR-based format not used in current evidence exports

### Changed

- Evidence packet format now uses checkpoint chain with VDF proofs instead of MMR
- Added support for keystroke evidence layer
- Added support for process declaration layer
- Added evidence strength tiers (basic, standard, enhanced, maximum)

## [1.0.0] - 2026-01-24

### Added

- Initial specification release
- Merkle Mountain Range (MMR) data structure definition
- Domain-separated hashing scheme (leaf prefix 0x00, internal prefix 0x01)
- Cryptographic commitment binding content, metadata, and edit topology
- Evidence packet format for portable proofs
- Five primary forensic metrics:
  - Monotonic Append Ratio
  - Edit Entropy
  - Median Interval
  - Positive/Negative Ratio
  - Deletion Clustering Coefficient
- Context declaration system (external, assisted, review)
- External anchor integration (OpenTimestamps, RFC 3161)
- Security considerations and threat model

### JSON Schemas

- `witness-proof-v1.schema.json` - Evidence packet validation
- `forensic-profile-v1.schema.json` - Forensic analysis output validation

---

## Version Numbering

The specification follows semantic versioning:

- **MAJOR**: Breaking changes to evidence format or verification algorithm
- **MINOR**: Backward-compatible additions (new optional fields, new anchor types)
- **PATCH**: Clarifications, typo fixes, documentation improvements

Evidence packets include a `version` field indicating which specification version they conform to.
