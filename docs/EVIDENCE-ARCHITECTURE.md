# Evidence Architecture Specification

## Purpose

This document specifies the evidence architecture for witnessd. The goal is
not to prove the system was secure. The goal is to force any challenger to
choose between:

1. Conceding integrity, **or**
2. Making a concrete, testable allegation of fraud

Vague doubt is architectural failure. Specificity is victory.

---

## 1. Capture Environment Declaration (CED)

### 1.1 Framing

The CED is not a log. It is **environment testimony**:

> "These were the observable properties of the system at time T.
> If they are false, then either:
> (a) our capture mechanism was falsified, or
> (b) the environment behaved inconsistently with itself."

### 1.2 Mandatory Contents

Every CED must contain:

| Field | Type | Source | Absence Handling |
|-------|------|--------|------------------|
| `os_name` | string | runtime.GOOS | Never absent |
| `os_version` | string | OS API | "unknown" if unavailable |
| `kernel_version` | string | uname/equivalent | "unknown" if unavailable |
| `secure_boot` | bool/null | Firmware query | `null` = "unavailable" |
| `tpm_present` | bool | TPM probe | Explicit false |
| `tpm_version` | string/null | TPM query | `null` if absent |
| `virtualization_detected` | bool | Multiple heuristics | Explicit result |
| `hypervisor_type` | string | Detection | "none" or identified |
| `monotonic_clock_ns` | int64 | Monotonic source | Required |
| `wall_clock_ns` | int64 | System clock | Required |
| `ntp_offset_ms` | int64/null | NTP query | `null` if unavailable |
| `process_uid` | int | OS | Required |
| `process_euid` | int | OS | Required |
| `executable_hash` | bytes | SHA-256 of binary | Required |
| `sip_enabled` | bool/null | macOS only | `null` on other platforms |
| `kernel_lockdown` | string/null | Linux only | `null` on other platforms |

### 1.3 Explicit Negatives

The CED must explicitly state what is **not** present:

```json
{
  "explicit_negatives": [
    "TPM not available",
    "Secure Boot status unknown",
    "NTP synchronization not verified"
  ]
}
```

This prevents the claim: "They didn't check for X."

### 1.4 CED Lifecycle

1. Generated at session start
2. Hashed: `ced_hash = SHA-256(canonical_json(CED))`
3. Bound to every subsequent operation
4. Signed with session key
5. Included in final seal
6. Externally anchored

---

## 2. Invariant Enforcement

### 2.1 Hard Invariants

These invariants are enforced automatically. Violation triggers automatic
evidence downgrade.

| Invariant | Violation Meaning | Downgrade Action |
|-----------|-------------------|------------------|
| Monotonic time never decreases | Clock manipulation | Class D (unreliable) |
| Hash chain never forks | Data tampering | Class D (unreliable) |
| External anchor ≥ last local time | Future-dating attempt | Class C (suspicious) |
| CED fingerprint constant | Environment changed | Class C (suspicious) |
| Key use within lifecycle bounds | Key misuse | Class D (unreliable) |

### 2.2 Violation Recording

Every violation is:

1. Detected automatically
2. Recorded with timestamp and details
3. Hashed into the chain
4. Signed
5. Cannot be suppressed

The violation record itself becomes evidence.

### 2.3 The Fork

After invariant enforcement, a challenger must argue:

> "The system was compromised **and** failed to detect its own inconsistency."

This is an allegation of **systematic falsification**, not generic doubt.

---

## 3. Environment Fingerprint Binding

### 3.1 Binding Rule

The CED hash is included in:

- Every Merkle leaf
- Every signed root
- Every evidence packet
- Every verification transcript

### 3.2 The Trap

> If the environment changed, the fingerprint changed.
> If the fingerprint didn't change, the environment didn't.

There is no middle story.

### 3.3 Binding Structure

```
leaf_hash = SHA-256(
    0x00 ||
    content_hash ||
    metadata_hash ||
    ced_hash ||          // Environment binding
    regions_hash
)
```

---

## 4. Semantic Minimalism

### 4.1 What We Assert

We assert **only irreversible process facts**:

- "Hash H was computed at time T"
- "Signature S was applied to root R"
- "Anchor A attests to hash H"

### 4.2 What We Never Assert

We **never** assert:

- Intent
- Authorship identity
- Cognitive origin
- Creative process
- Legal meaning

This is deliberate. Overclaiming kills evidence.

### 4.3 Semantic Restraint as Strength

A system that refuses to testify for itself is trusted more than one
that claims too much.

---

## 5. Causality Locks

### 5.1 Event Dependencies

Every event explicitly states:

| Field | Meaning |
|-------|---------|
| `depends_on` | Events that must exist for this event to be valid |
| `forbids` | Events that become impossible after this event |
| `requires_next` | Events that must follow (or explicit termination) |

### 5.2 Example: Commit Event

```json
{
  "type": "commit",
  "depends_on": ["all_prior_edits"],
  "forbids": ["edit_to_this_revision"],
  "requires_next": ["new_revision", "session_end"]
}
```

### 5.3 Irreversibility

Courts care about irreversibility. Causality locks create it.

Once a commit exists:
- Prior edits cannot be removed
- The committed state cannot be altered
- Any attempt is recorded as a violation

---

## 6. Negative Semantic Evidence

### 6.1 Recording Absence

We record not just what happened, but what **should have happened but didn't**.

| Assertion | Meaning |
|-----------|---------|
| "No input events during pause" | The pause was real |
| "No edits after commit" | The commit was final |
| "No reordering observed" | Timeline is authentic |

### 6.2 Absence as Fact

These absences are:

1. Computed (not assumed)
2. Hashed
3. Signed
4. Anchored

### 6.3 The Fork

A challenger must now claim:

> "The system both failed to record events **and** failed to notice that failure."

This is **systemic dishonesty**, not accident.

---

## 7. Evidence-Scoped Keys

### 7.1 Key Derivation

Keys are:

- Per-session or per-artifact
- Derived: `session_key = HKDF(master_key, session_id || timestamp)`
- Destroyed immediately after sealing

### 7.2 No Global Signing Keys

Global signing keys allow:

> "The key could have been stolen anytime."

Session keys force:

> "The key for **this exact artifact** was compromised **before sealing**."

That is fact-specific, not vibe.

### 7.3 Key Material Handling

```
1. session_id = random(32)
2. session_key = HKDF-SHA256(master_key, session_id || start_time)
3. ... signing operations ...
4. final_seal = Sign(session_key, root || ced_hash)
5. SecureZero(session_key)
6. session_key = nil
```

---

## 8. Key Lifecycle Attestation

### 8.1 Lifecycle Declaration

Every artifact declares:

| Field | Meaning |
|-------|---------|
| `key_generated_at` | When the session key was derived |
| `key_first_use` | First signing operation |
| `key_last_use` | Final seal operation |
| `key_destroyed_at` | When key material was zeroed |

### 8.2 Bounded Exposure

We do not claim perfect secrecy. We claim **bounded exposure**:

> "This key existed for 47 minutes and was used for 12 operations."

Courts understand bounds. They distrust absolutes.

### 8.3 Lifecycle Metadata

This metadata is:

1. Hashed into the final seal
2. Signed
3. Externally anchored

---

## 9. Verifier-Enforced Lifecycle Sanity

### 9.1 Mandatory Rejections

A verifier **must refuse acceptance** if:

| Condition | Rejection Reason |
|-----------|------------------|
| Key use outside declared bounds | "Key use at T outside [T1, T2]" |
| Lifecycle ordering inconsistent | "Destruction before last use" |
| First use before generation | "Use before derivation" |
| Missing lifecycle declaration | "Lifecycle undeclared" |

### 9.2 The Fork

Key compromise becomes:

> "Stolen **when**, exactly?"

If they can't answer, the argument dies.

---

## 10. Evidence Class System

### 10.1 Classes

| Class | Meaning | Suitable For |
|-------|---------|--------------|
| A | Full integrity, all invariants satisfied | Forensic reliance |
| B | Minor warnings, no invariant violations | General use |
| C | Suspicious patterns detected | Review required |
| D | Invariant violated | Not suitable for reliance |
| X | Verification failed | Rejected |

### 10.2 Automatic Downgrade

Violations trigger automatic downgrade:

| Violation | Downgrade To |
|-----------|--------------|
| Clock regression | D |
| Chain fork | D |
| Anchor time < local time | C |
| CED fingerprint change | C |
| Key lifecycle violation | D |
| Missing negative evidence | B |

### 10.3 Self-Limiting Evidence

The system explicitly states:

> "This evidence is Class [X]. [Reason]."

A system that refuses to testify for itself is trusted.

---

## 11. Verification Transcript

### 11.1 Contents

Every verification produces a transcript containing:

1. All checks performed
2. All results (pass/fail/warning)
3. Evidence class determination
4. Explicit limitations
5. Verifier identity and timestamp

### 11.2 Transcript Integrity

The transcript is:

1. Hashed
2. Signed by verifier
3. Bound to the evidence packet

### 11.3 Reproducibility

Any party can re-run verification and must get identical results
(modulo timestamp).

---

## 12. Hostile Expert Failure Analysis

### 12.1 Attack: "The OS was compromised"

**Response**: The CED declares observable state. Either:
- CED is false → allegation of falsified capture
- CED is true → environment was as declared

No middle ground.

### 12.2 Attack: "The timestamps are fake"

**Response**: External anchors constrain time. Either:
- Bitcoin block is fake → allegation of blockchain manipulation
- TSA is compromised → allegation of third-party fraud
- Timestamps are bounded by external proof

No middle ground.

### 12.3 Attack: "The key was stolen"

**Response**: Key lifecycle is declared. Either:
- Key was stolen within [T1, T2] → specific, testable allegation
- Key was used outside bounds → verifier would have rejected
- Lifecycle is false → allegation of systematic falsification

No middle ground.

### 12.4 Attack: "The chain was modified"

**Response**: Hash chain is immutable. Either:
- Hash collision found → cryptographic breakthrough claim
- Chain fork detected → automatic Class D downgrade
- External anchor mismatch → detected automatically

No middle ground.

---

## 13. Legal Posture

### 13.1 What We Provide

- Tamper-evident records
- Independent verifiability
- Bounded temporal claims
- Self-limiting evidence class
- Reproducible verification

### 13.2 What We Do Not Provide

- Proof of intent
- Proof of identity
- Proof of cognition
- Legal conclusions
- Absolute guarantees

### 13.3 The Result

A challenger must allege **all of**:

1. Environment declaration is false **and** self-inconsistency went undetected
2. Process structure is misleading **despite** explicit irreversibility
3. Scoped key was compromised **within** a provable window
4. Hash chain was modified **without** triggering detection
5. External anchors were manipulated **by** Bitcoin miners or TSAs

This is not reasonable doubt.
This is coordinated fabrication.

Courts do not accept that lightly.

---

*Document Version: 1.0*
*Date: 2026-01-26*
