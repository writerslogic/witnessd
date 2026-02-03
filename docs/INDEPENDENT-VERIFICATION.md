# Independent Verification Guide

## Purpose

This document enables any third party to verify evidence produced by witnessd
without using witnessd software and without trusting its authors. All
verification uses standard algorithms implemented in widely-available
cryptographic libraries.

**This document is intended for:** Forensic examiners, expert witnesses, opposing
counsel, and courts evaluating evidence.

---

## 1. Overview

Evidence from this system can be independently verified because:

1. **Standard Algorithms**: SHA-256 (FIPS 180-4) and Ed25519 (RFC 8032) only
2. **Deterministic Computation**: Same inputs always produce same outputs
3. **External Anchors**: Bitcoin blockchain and RFC 3161 TSAs provide independent timestamps
4. **Self-Contained Proofs**: Evidence packets contain all data needed for verification

**No witnessd software is required for verification.**

---

## 2. What to Verify

An evidence packet contains claims that can be independently verified:

| Claim | Verification Method | Trust Model |
|-------|---------------------|-------------|
| File had this content | Recompute SHA-256 hash | Mathematical (hash collision infeasible) |
| Record exists in chain | Walk Merkle path to root | Mathematical (hash collision infeasible) |
| Chain was signed by key | Ed25519 signature verification | Cryptographic (forgery infeasible) |
| Record existed before time T | Verify external anchors | Third-party (Bitcoin, TSA) |

---

## 3. Step-by-Step Verification

### 3.1 Verify File Content

**Claim**: The file at `file_path` had content producing hash `file_hash`.

**Verification**:
```
computed_hash = SHA-256(file_contents)
PASS if computed_hash == file_hash
```

**Tools** (any will work):
```bash
# OpenSSL
openssl dgst -sha256 -hex document.txt

# Python
python3 -c "import hashlib; print(hashlib.sha256(open('document.txt','rb').read()).hexdigest())"

# Rust
# (requires cargo-script or similar, or full file)
# echo 'fn main() { println!("{}", hex::encode(sha2::Sha256::digest(std::fs::read("document.txt").unwrap()))); }' > verify.rs
# cargo run

# Go
go run -e 'package main; import ("crypto/sha256"; "encoding/hex"; "os"; "fmt"); func main() { d,_:=os.ReadFile("document.txt"); fmt.Println(hex.EncodeToString(sha256.New().Sum(d))) }'
```

### 3.2 Verify Merkle Path

**Claim**: The file hash is included in the chain with root `mmr_root`.

**Algorithm**:
```
1. Start with current = file_hash (as bytes)
2. For each step in merkle_path:
     sibling = step.hash (as bytes)
     if step.is_left:
         current = SHA-256(0x01 || current || sibling)
     else:
         current = SHA-256(0x01 || sibling || current)
3. Result is the "peak" this record belongs to
4. PASS if current == peaks[peak_position]
```

**Reference implementation** (Python):
```python
import hashlib

def verify_merkle_path(file_hash_hex, merkle_path, peaks, peak_position):
    """
    Verify a file hash is included in the MMR.

    Args:
        file_hash_hex: Hex-encoded SHA-256 of file contents
        merkle_path: List of {"hash": hex_string, "is_left": bool}
        peaks: List of hex-encoded peak hashes
        peak_position: Index into peaks array

    Returns:
        True if path is valid, False otherwise
    """
    current = bytes.fromhex(file_hash_hex)

    for step in merkle_path:
        sibling = bytes.fromhex(step["hash"])
        h = hashlib.sha256()
        h.update(b'\x01')  # Internal node domain separator

        if step["is_left"]:
            h.update(current)
            h.update(sibling)
        else:
            h.update(sibling)
            h.update(current)

        current = h.digest()

    expected_peak = bytes.fromhex(peaks[peak_position])
    return current == expected_peak
```

### 3.3 Verify MMR Root

**Claim**: The peaks combine to form `mmr_root`.

**Algorithm** (peak bagging):
```
1. Start with result = last peak (as bytes)
2. For each peak from second-to-last to first:
     result = SHA-256(peak || result)
3. PASS if result == mmr_root
```

**Reference implementation** (Python):
```python
def verify_mmr_root(peaks, expected_root_hex):
    """
    Verify peaks bag to the expected MMR root.

    Args:
        peaks: List of hex-encoded peak hashes (leftmost first)
        expected_root_hex: Hex-encoded expected root

    Returns:
        True if peaks bag to expected root, False otherwise
    """
    if len(peaks) == 0:
        return False

    if len(peaks) == 1:
        return peaks[0] == expected_root_hex

    result = bytes.fromhex(peaks[-1])

    for peak_hex in reversed(peaks[:-1]):
        peak = bytes.fromhex(peak_hex)
        h = hashlib.sha256()
        h.update(peak)
        h.update(result)
        result = h.digest()

    return result.hex() == expected_root_hex
```

### 3.4 Verify Signature

**Claim**: `mmr_root` was signed by the holder of `public_key`.

**Algorithm**:
```
Ed25519.Verify(public_key, mmr_root, signature)
```

**Reference implementation** (Python with PyNaCl):
```python
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignature

def verify_signature(mmr_root_hex, signature_hex, public_key_hex):
    """
    Verify Ed25519 signature over MMR root.

    Args:
        mmr_root_hex: Hex-encoded 32-byte MMR root
        signature_hex: Hex-encoded 64-byte Ed25519 signature
        public_key_hex: Hex-encoded 32-byte Ed25519 public key

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        verify_key = VerifyKey(bytes.fromhex(public_key_hex))
        verify_key.verify(
            bytes.fromhex(mmr_root_hex),
            bytes.fromhex(signature_hex)
        )
        return True
    except BadSignature:
        return False
```

**Alternative implementations**:
```bash
# Using OpenSSL (requires public key in PEM format)
openssl pkeyutl -verify -pubin -inkey pubkey.pem -sigfile sig.bin -in root.bin

# Using Go standard library
# (see Go crypto/ed25519 package)
```

### 3.5 Verify External Anchors

External anchors provide independent proof of timestamp from third parties.

#### 3.5.1 OpenTimestamps (Bitcoin)

**Claim**: `mmr_root` was included in Bitcoin block at height N.

**Verification**:
1. Parse the .ots file (OpenTimestamps format)
2. Follow attestation path from `mmr_root` to Bitcoin block
3. Verify block exists in Bitcoin blockchain at claimed height
4. Verify Merkle path to block header

**Tools**:
```bash
# Official OpenTimestamps client
ots verify evidence.ots

# Or verify manually against any Bitcoin node
bitcoin-cli getblock <block_hash>
```

**Independent verification**: Query any Bitcoin block explorer:
- https://blockstream.info/
- https://blockchain.info/
- https://mempool.space/

#### 3.5.2 RFC 3161 Timestamp

**Claim**: `mmr_root` was timestamped by TSA at time T.

**Verification**:
1. Parse TimeStampResp (ASN.1 DER encoded)
2. Extract MessageImprint from TSTInfo
3. Verify MessageImprint matches `mmr_root`
4. Verify TSA signature
5. Verify TSA certificate chain to trusted root

**Tools**:
```bash
# Using OpenSSL
openssl ts -verify -in response.tsr -data root.bin -CAfile ca-bundle.crt

# Parse timestamp structure
openssl ts -reply -in response.tsr -text
```

---

## 4. Complete Verification Script

```python
#!/usr/bin/env python3
"""
Independent verification of witnessd evidence packets.

This script verifies evidence WITHOUT using witnessd software.
Dependencies: hashlib (stdlib), nacl (pip install pynacl)
"""

import hashlib
import json
import sys

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignature
except ImportError:
    print("Install PyNaCl: pip install pynacl")
    sys.exit(1)


def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash."""
    return hashlib.sha256(data).digest()


def verify_content_hash(file_path: str, expected_hash: str) -> bool:
    """Verify file content matches expected SHA-256 hash."""
    try:
        with open(file_path, 'rb') as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        return actual == expected_hash
    except FileNotFoundError:
        return False


def verify_merkle_path(leaf_hash: str, path: list, peaks: list, peak_pos: int) -> bool:
    """Verify Merkle inclusion proof."""
    current = bytes.fromhex(leaf_hash)

    for step in path:
        sibling = bytes.fromhex(step["hash"])
        h = hashlib.sha256()
        h.update(b'\x01')  # Internal node prefix
        if step["is_left"]:
            h.update(current)
            h.update(sibling)
        else:
            h.update(sibling)
            h.update(current)
        current = h.digest()

    return current == bytes.fromhex(peaks[peak_pos])


def verify_mmr_root(peaks: list, expected_root: str) -> bool:
    """Verify peaks bag to MMR root."""
    if len(peaks) == 1:
        return peaks[0] == expected_root

    result = bytes.fromhex(peaks[-1])
    for peak in reversed(peaks[:-1]):
        h = hashlib.sha256()
        h.update(bytes.fromhex(peak))
        h.update(result)
        result = h.digest()

    return result.hex() == expected_root


def verify_signature(root: str, signature: str, public_key: str) -> bool:
    """Verify Ed25519 signature over MMR root."""
    try:
        vk = VerifyKey(bytes.fromhex(public_key))
        vk.verify(bytes.fromhex(root), bytes.fromhex(signature))
        return True
    except BadSignature:
        return False


def verify_evidence(evidence_path: str, file_path: str = None) -> dict:
    """
    Verify an evidence packet.

    Args:
        evidence_path: Path to evidence.json file
        file_path: Optional path to original file (for content verification)

    Returns:
        Dictionary with verification results
    """
    with open(evidence_path) as f:
        evidence = json.load(f)

    results = {
        "content_hash": None,
        "merkle_path": None,
        "mmr_root": None,
        "signature": None,
        "overall": None
    }

    # 1. Verify content hash (if file provided)
    if file_path:
        results["content_hash"] = verify_content_hash(
            file_path,
            evidence["file_hash"]
        )
    else:
        results["content_hash"] = "SKIPPED (no file provided)"

    # 2. Verify Merkle path
    results["merkle_path"] = verify_merkle_path(
        evidence["file_hash"],
        evidence["merkle_path"],
        evidence["peaks"],
        evidence["peak_position"]
    )

    # 3. Verify MMR root
    results["mmr_root"] = verify_mmr_root(
        evidence["peaks"],
        evidence["mmr_root"]
    )

    # 4. Verify signature
    results["signature"] = verify_signature(
        evidence["mmr_root"],
        evidence["signature"],
        evidence["public_key"]
    )

    # Overall result
    checks = [results["merkle_path"], results["mmr_root"], results["signature"]]
    if file_path:
        checks.append(results["content_hash"])
    results["overall"] = all(checks)

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify.py evidence.json [original_file]")
        sys.exit(1)

    evidence_path = sys.argv[1]
    file_path = sys.argv[2] if len(sys.argv) > 2 else None

    results = verify_evidence(evidence_path, file_path)

    print("Verification Results")
    print("=" * 40)
    print(f"Content Hash:  {results['content_hash']}")
    print(f"Merkle Path:   {results['merkle_path']}")
    print(f"MMR Root:      {results['mmr_root']}")
    print(f"Signature:     {results['signature']}")
    print("=" * 40)
    print(f"OVERALL:       {'PASS' if results['overall'] else 'FAIL'}")
```

---

## 5. What Verification Proves

### 5.1 If All Checks Pass

| Verification | Conclusion |
|--------------|------------|
| Content hash matches | File has not been modified since witnessing |
| Merkle path valid | Record is included in the claimed chain |
| MMR root valid | Chain structure is internally consistent |
| Signature valid | Holder of private key signed this chain state |
| OpenTimestamps valid | Chain state existed before Bitcoin block time |
| RFC 3161 valid | Chain state existed at TSA-attested time |

### 5.2 If Content Hash Fails

The file has been modified since it was witnessed. The original content
had the hash recorded in the evidence packet.

### 5.3 If Merkle Path Fails

Either:
- The evidence packet has been tampered with
- The file was not actually witnessed (fabricated evidence)

### 5.4 If Signature Fails

Either:
- The evidence packet has been tampered with
- The signature was not produced by the claimed key

### 5.5 If External Anchor Fails

Either:
- The anchor proof has been tampered with
- The claimed timestamp is false

---

## 6. External Anchor Trust Model

### 6.1 OpenTimestamps / Bitcoin

**Trust assumption**: Bitcoin blockchain is not reorganized beyond the anchor block.

**Verification path**:
```
mmr_root -> OTS attestation path -> Bitcoin block header -> Bitcoin consensus
```

**Independent verification**: Query any Bitcoin full node or block explorer.

### 6.2 RFC 3161 Timestamp Authorities

**Trust assumption**: TSA correctly reports time and does not backdate.

**Verification path**:
```
mmr_root -> TSA response -> TSA certificate -> Certificate Authority
```

**Independent verification**: Verify TSA certificate chain against public CA bundle.

---

## 7. Algorithms Reference

### 7.1 SHA-256

- Standard: FIPS 180-4
- Output: 32 bytes (256 bits)
- Implementation: Any FIPS-compliant library

### 7.2 Ed25519

- Standard: RFC 8032
- Public key: 32 bytes
- Signature: 64 bytes
- Implementation: Any RFC 8032-compliant library

### 7.3 Domain Separation

| Context | Prefix |
|---------|--------|
| Leaf node | 0x00 |
| Internal node | 0x01 |

### 7.4 Peak Bagging

```
bag([p1]) = p1
bag([p1, p2]) = SHA-256(p1 || bag([p2]))
bag([p1, p2, ..., pn]) = SHA-256(p1 || bag([p2, ..., pn]))
```

---

## 8. Tool Requirements

Verification requires only:

| Purpose | Any implementation of |
|---------|----------------------|
| Hash computation | SHA-256 (FIPS 180-4) |
| Signature verification | Ed25519 (RFC 8032) |
| Bitcoin anchor | Bitcoin block parsing |
| TSA anchor | ASN.1 DER parsing, X.509 |

Widely available in: OpenSSL, Python, Go, Java, Rust, JavaScript, etc.

---

## 9. Legal Standing

Evidence that passes independent verification has significant legal weight:

### 9.1 Self-Authentication (FRE 902(13))

Under U.S. Federal Rules of Evidence 902(13), electronic records are
self-authenticating when accompanied by a certification from a qualified
person that the record:
- Was generated by an electronic process or system
- Produces an accurate result

Evidence packets with verified external anchors meet this standard. The
opponent bears the burden of proving tampering rather than the proponent
proving authenticity.

### 9.2 Burden-Shifting

When evidence passes verification:
1. **Hash verification** proves content integrity (mathematical certainty)
2. **Signature verification** proves chain was signed by key holder
3. **External anchors** prove existence at attested time (third-party attestation)

This combination shifts the evidentiary burden. Challenging parties must
demonstrate how tampering occurred despite:
- SHA-256 collision (computationally infeasible)
- Ed25519 forgery (computationally infeasible)
- Bitcoin blockchain modification (requires >50% hashrate)
- TSA certificate compromise (audited infrastructure)

### 9.3 Multi-Jurisdiction Recognition

The underlying standards have broad recognition:
- **SHA-256**: FIPS 180-4 (U.S.), recognized internationally
- **Ed25519**: RFC 8032, IETF standard
- **RFC 3161**: ISO/IEC 18014-2, ETSI TS 101 861
- **Bitcoin**: Recognized as timestamp evidence in multiple jurisdictions

### 9.4 What This Does NOT Constitute

- eIDAS Qualified Electronic Timestamp (requires QTSP)
- Notarization (requires licensed notary)
- Legal certification (requires authorized body)

The evidence is admissible and persuasive; specific legal conclusions
require evaluation under applicable law.

---

## 10. Limitations of Verification

Verification proves:
- The file content matches the recorded hash
- The record is included in a signed chain
- External anchors attest to time

Verification does NOT prove:
- Who typed the content
- That no other copies exist
- That the signing key was not compromised
- That the computer was not under remote control

These limitations apply to all digital evidence systems.

---

*Document Version: 1.0*
*Date: 2026-01-26*
