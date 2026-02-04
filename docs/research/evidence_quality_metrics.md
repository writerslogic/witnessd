# Evidence Quality Metrics Framework

## Purpose

This framework establishes quantitative criteria for comparing evidence quality between local file witnessing and universal (system-wide) witnessing approaches. The goal is to ensure any universal witnessing solution maintains evidence integrity within acceptable degradation limits.

---

## 1. Evidence Packet Structure Analysis

### 1.1 Complete JSON Structure (evidence-packet-v1.example.json - 205 lines)

```
evidence-packet-v1.example.json
├── version: 1                              # Schema version
├── exported_at: ISO 8601 timestamp         # When evidence was exported
├── strength: 2                             # Proof strength level
├── document                                # Document identification
│   ├── title: string
│   ├── path: string
│   ├── final_hash: SHA-256 (64 hex chars)
│   └── final_size: integer (bytes)
├── checkpoints[]                           # Array of 5 temporal checkpoints
│   ├── ordinal: integer (0-indexed)
│   ├── content_hash: SHA-256
│   ├── content_size: integer
│   ├── timestamp: ISO 8601
│   ├── message: string
│   ├── vdf_input: SHA-256                  # VDF proof (checkpoints 1-4)
│   ├── vdf_output: SHA-256
│   ├── vdf_iterations: integer (e.g., 270000000)
│   ├── elapsed_time: nanoseconds
│   ├── previous_hash: SHA-256
│   └── hash: SHA-256
├── vdf_params                              # VDF configuration
│   ├── modulus: 2048-bit RSA modulus
│   ├── iterations_per_sec: 100000
│   └── security_param: 128
├── chain_hash: SHA-256                     # Final chain hash
├── declaration                             # Author attestation
│   ├── document_hash: SHA-256
│   ├── chain_hash: SHA-256
│   ├── title: string
│   ├── input_modalities[]                  # Array of input types
│   │   ├── type: "keyboard"|"paste"|etc.
│   │   ├── percentage: 0-100
│   │   └── note: string
│   ├── ai_tools: []
│   ├── statement: string
│   ├── created_at: ISO 8601
│   ├── version: 1
│   ├── author_public_key: Base64 Ed25519
│   └── signature: Base64 Ed25519 signature
├── keystroke                               # Behavioral biometrics
│   ├── session_id: string
│   ├── started_at: ISO 8601
│   ├── ended_at: ISO 8601
│   ├── duration: nanoseconds
│   ├── total_keystrokes: integer (e.g., 18542)
│   ├── total_samples: integer (e.g., 1854)
│   ├── keystrokes_per_minute: float (e.g., 57.9)
│   ├── unique_document_states: integer
│   ├── chain_valid: boolean
│   ├── plausible_human_rate: boolean
│   └── samples[]                           # Timing samples
│       ├── n: sample number
│       ├── t: ISO 8601 timestamp
│       ├── h: SHA-256 state hash
│       ├── z: zone transition string
│       ├── b: burst count
│       ├── j: jitter value (microseconds)
│       └── s: sample hash
├── contexts[]                              # Contextual annotations
│   ├── type: "external"|"review"
│   ├── note: string
│   ├── start_time: ISO 8601
│   └── end_time: ISO 8601
├── external                                # External anchors
│   └── opentimestamps[]
│       ├── chain_hash: SHA-256
│       ├── proof: Base64
│       └── status: "pending"|"confirmed"
├── claims[]                                # Evidence assertions
│   ├── type: string
│   ├── description: string
│   └── confidence: "cryptographic"|"attestation"
└── limitations[]                           # Explicit limitations
```

### 1.2 Forensic Profile Keys (from forensics.rs:1-2307)

**Primary Metrics (forensics.rs:45-75):**
| Key | Purpose | Range | Threshold |
|-----|---------|-------|-----------|
| `monotonic_append_ratio` | Forward-only writing pattern detection | 0.0-1.0 | >0.85 = suspicious (line 52) |
| `edit_entropy` | Randomness of edit positions | 0.0-∞ | <1.5 = suspicious (line 338) |
| `median_interval_ms` | Typical time between events | >0 ms | Varies by author |
| `positive_negative_ratio` | Insertions vs deletions | 0.0-∞ | >0.98 = suspicious |
| `deletion_clustering` | Burst deletion detection | 0.0-1.0 | C < 1.0 = revision pass |

**Cadence Metrics (forensics.rs:77-120):**
| Key | Purpose | Range | Threshold |
|-----|---------|-------|-----------|
| `coefficient_of_variation` | Typing rhythm consistency | 0.0-∞ | <0.15 = robotic (line 89) |
| `is_robotic` | Automated input detection | boolean | CV < ROBOTIC_CV_THRESHOLD |
| `burst_count` | Rapid typing sequences | integer | N/A |
| `pause_count` | Significant gaps | integer | N/A |
| `mean_burst_length` | Average burst duration | float | N/A |
| `mean_pause_duration_ms` | Average pause length | float | N/A |

**Assessment Metrics (forensics.rs:122-160):**
| Key | Purpose | Range |
|-----|---------|-------|
| `overall_score` | Aggregate authenticity | 0.0-100.0 |
| `human_likelihood` | Probability of human authorship | 0.0-1.0 |
| `consistency_score` | Pattern stability | 0.0-1.0 |
| `assessment` | Categorical verdict | "CONSISTENT"|"SUSPICIOUS"|"INSUFFICIENT" |

### 1.3 Temporal Proof Structure

**VDF Proof Length (from evidence-packet-v1.example.json):**
- `vdf_params.modulus`: 2048-bit RSA modulus (617 hex characters)
- `vdf_iterations`: Variable (270M - 630M iterations in example)
- `elapsed_time`: Nanoseconds (2.7T - 6.3T ns = 45-105 minutes)

**Checkpoint Chain (5 checkpoints in example):**
- Checkpoint 0: Initial (no VDF)
- Checkpoints 1-4: Full VDF proofs with `vdf_input`, `vdf_output`, `vdf_iterations`

### 1.4 Behavioral Metrics Structure

**No explicit `behavioral_metrics` object** in evidence-packet-v1.example.json.
Behavioral data is captured within `keystroke.samples[]`:
- `z`: Zone transition state (e.g., "idle->active", "active")
- `b`: Burst count
- `j`: Jitter value in microseconds

---

## 2. Rust Source Files Containing Forensic/Evidence/Quality Code

Files found via `grep -l 'forensic|evidence|quality'`:

1. **rust/witnessd-core/src/forensics.rs** (2307 lines) - Primary forensic analysis
2. **rust/witnessd-core/src/evidence.rs** - Evidence packet generation
3. **rust/witnessd-core/src/jitter.rs** - Keystroke jitter analysis
4. **rust/witnessd-core/src/presence.rs** - Presence detection
5. **rust/witnessd-core/src/engine.rs** - Core witnessing engine
6. **rust/witnessd-core/src/store.rs** - Evidence storage
7. **rust/witnessd-core/src/keyhierarchy.rs** - Key management
8. **rust/witnessd-core/src/physjitter_bridge.rs** - Physical jitter bridge
9. **rust/witnessd-core/src/research.rs** - Research utilities
10. **rust/witnessd-core/src/api.rs** - Public API
11. **rust/witnessd-core/src/bridge.rs** - Platform bridge
12. **rust/witnessd-core/src/vdf/timekeeper.rs** - VDF timekeeper
13. **rust/witnessd-core/src/lib.rs** - Library root
14. **rust/witnessd-core/src/frb_generated.rs** - Flutter bridge (generated)

---

## 3. Witness Protocol References (witness-protocol-v1.md)

**Keystroke/Timing/Cadence References:**

| Line | Content |
|------|---------|
| 296 | `intervals = [(t_i - t_{i-1}) for i in 2..n]` - Interval calculation |
| 297 | `median_interval = median(intervals)` - Median interval metric |
| 300 | Interpretation: "unusually regular intervals are suspicious" |
| 334 | Gap detection: "Inter-event interval > 3σ from mean" |
| 335 | High velocity: ">10 bytes/sec sustained" |

**Forensic Metrics Specification (lines 255-346):**
- Section 5.1: Primary Metrics (monotonic append, edit entropy, median interval, P/N ratio, deletion clustering)
- Section 5.2: Anomaly Detection (gap, high velocity, monotonic run, low entropy)
- Section 5.3: Assessment categories (CONSISTENT, SUSPICIOUS, INSUFFICIENT)

---

## 4. Quantitative Scoring Rubric (0-100 Scale)

### 4.1 Category Weights

| Category | Weight | Max Points | Rationale |
|----------|--------|------------|-----------|
| **Keystroke Timing Precision** | 30% | 30 | Core biometric signal for human verification |
| **Edit Topology Completeness** | 20% | 20 | Document evolution tracking |
| **Temporal Proof Strength** | 20% | 20 | Cryptographic anchoring (VDF + external) |
| **Forensic Profile Richness** | 15% | 15 | Statistical analysis depth |
| **Behavioral Metrics Coverage** | 15% | 15 | Human authenticity signals |

**Total: 100% = 100 points**

### 4.2 Keystroke Timing Precision (30 points max)

| Score | Criteria |
|-------|----------|
| 30 | Microsecond precision (±1μs), all keystrokes captured, no gaps |
| 25 | Millisecond precision (±1ms), >99% keystroke capture rate |
| 20 | Millisecond precision (±5ms), >95% keystroke capture rate |
| 15 | Millisecond precision (±10ms), >90% keystroke capture rate |
| 10 | Millisecond precision (±50ms), >80% keystroke capture rate |
| 5 | Sub-second precision, >50% keystroke capture rate |
| 0 | No timing data or >50% loss |

**Measurement Method:**
- Precision = standard deviation of timestamp accuracy vs ground truth
- Capture rate = (captured keystrokes) / (actual keystrokes)
- Verify via controlled input test with known timestamps

### 4.3 Edit Topology Completeness (20 points max)

| Score | Criteria |
|-------|----------|
| 20 | Full edit graph: every insertion, deletion, cursor position, regions |
| 16 | Complete insertions/deletions with edit regions, approximate positions |
| 12 | All text changes with size deltas, no cursor tracking |
| 8 | Most text changes (>90%), no edit region data |
| 4 | Partial text changes (50-90%) |
| 0 | <50% text changes or snapshot-only |

**Measurement Method:**
- Reconstruct document from edit log
- Compare reconstruction accuracy against final document
- Calculate edit_entropy and monotonic_append_ratio

### 4.4 Temporal Proof Strength (20 points max)

| Score | Criteria |
|-------|----------|
| 20 | VDF proofs + blockchain anchor (confirmed) + TSA |
| 16 | VDF proofs + one external anchor (confirmed) |
| 12 | VDF proofs only, no external anchor |
| 8 | Hash chain with timestamps, no VDF |
| 4 | Timestamps only, no cryptographic chain |
| 0 | No temporal proof |

**Measurement Method:**
- Verify VDF proof validity (`vdf_output = VDF(vdf_input, iterations)`)
- Check external anchor availability and status ("confirmed" vs "pending")
- Validate hash chain integrity (each `previous_hash` matches prior `hash`)

### 4.5 Forensic Profile Richness (15 points max)

| Score | Criteria |
|-------|----------|
| 15 | All metrics computed (primary + cadence + assessment), statistical significance (n≥500) |
| 12 | Primary + cadence metrics, adequate sample size (n≥100) |
| 9 | Primary metrics only, adequate sample size (n≥50) |
| 6 | Partial metrics, marginal sample size (n=20-50) |
| 3 | Minimal metrics, insufficient samples (n<20) |
| 0 | No forensic profile |

**Measurement Method:**
- Count available metrics vs expected metrics
- Verify sample size (minimum 50 for primary, 100 for cadence, 500 for significance)
- Check for null/undefined values in metric output

### 4.6 Behavioral Metrics Coverage (15 points max)

| Score | Criteria |
|-------|----------|
| 15 | Zone mapping (`z`), digraph timing, pause/burst patterns (`b`), jitter (`j`) |
| 12 | Zone transitions + timing patterns (pause/burst) |
| 9 | Timing patterns only (intervals, bursts) |
| 6 | Basic interval statistics (median, variance) |
| 3 | Keystroke counts only |
| 0 | No behavioral data |

**Measurement Method:**
- Check for zone data (`z` field) in keystroke samples
- Verify digraph statistics exist in forensic profile
- Confirm cadence metrics computed (coefficient_of_variation, is_robotic)

---

## 5. Baseline Quality Thresholds

### 5.1 Local File Witnessing Baseline

Expected scores for local file witnessing (CLI with witnessd):

| Category | Expected Score | Minimum Acceptable |
|----------|---------------|-------------------|
| Keystroke Timing Precision | 28-30 | 25 |
| Edit Topology Completeness | 18-20 | 16 |
| Temporal Proof Strength | 16-20 | 12 |
| Forensic Profile Richness | 13-15 | 12 |
| Behavioral Metrics Coverage | 13-15 | 12 |
| **Total** | **88-100** | **77** |

### 5.2 Universal Witnessing Minimum Thresholds

For universal witnessing to be acceptable:

| Category | Minimum Score | Rationale |
|----------|--------------|-----------|
| Keystroke Timing Precision | 20 | ±5ms precision acceptable for cadence analysis |
| Edit Topology Completeness | 12 | Text changes required, cursor tracking optional |
| Temporal Proof Strength | 12 | VDF proofs mandatory for temporal claims |
| Forensic Profile Richness | 9 | Primary metrics required (n≥50 samples) |
| Behavioral Metrics Coverage | 9 | Timing patterns required for human verification |
| **Total** | **62** | Floor for forensic utility |

### 5.3 Evidence Class Correlation

| Total Score | Evidence Class | Suitable For |
|-------------|---------------|--------------|
| 85-100 | A | Forensic reliance |
| 70-84 | B | General use |
| 55-69 | C | Review required |
| 40-54 | D | Not suitable for reliance |
| <40 | X | Rejected |

---

## 6. Comparison Methodology

### 6.1 Test Protocol

**Test 1: Controlled Input Test**
1. Create 500-word document with scripted content
2. Type identical text using:
   - Local: witnessd CLI watching file
   - Universal: System-wide capture (CGEventTap/rdev)
3. Use hardware timer for ground truth timestamps
4. Compare captured vs actual:
   - Timestamp precision (ms)
   - Keystroke capture rate (%)
   - Zone accuracy (if applicable)

**Test 2: Natural Writing Test**
1. 30-minute free writing session
2. Same writer, same document type, both modes
3. Compare forensic profiles:
   - monotonic_append_ratio
   - edit_entropy
   - coefficient_of_variation
   - human_likelihood score

**Test 3: Edit Pattern Test**
1. Create document with known edit history
2. Perform scripted edits (insert, delete, navigate)
3. Verify edit topology reconstruction:
   - Region accuracy (start_pct, end_pct)
   - Delta sign correctness
   - Byte count accuracy

### 6.2 Scoring Formula

```
Total_Score = Σ (Category_Score × Category_Weight)

Where weights are:
  Keystroke_Timing × 0.30
  Edit_Topology × 0.20
  Temporal_Proof × 0.20
  Forensic_Profile × 0.15
  Behavioral_Metrics × 0.15

Quality_Ratio = Universal_Score / Local_Score

Degradation = 1 - Quality_Ratio

Acceptable = (Degradation < 0.20) AND (All_Hard_Limits_Met)
```

### 6.3 Per-Metric Comparison Table

| Metric | Local Method | Universal Method | Comparison |
|--------|-------------|------------------|------------|
| Timestamp source | File modification events | CGEventTap/rdev events | Verify both capture NSEvent.timestamp |
| Keystroke capture | File system watching | System-wide event tap | Compare capture rate (%) |
| Edit topology | Diff between states | Inferred from keystrokes | Compare edit_entropy |
| Zone mapping | File position tracking | Key code → zone mapping | Compare zone accuracy |
| VDF proof | Computed per checkpoint | Computed per checkpoint | Should be identical |

---

## 7. Technical Capability vs Forensic Value Trade-offs

### 7.1 Trade-off Matrix

| Approach | Technical Capability | Forensic Value | Trade-off |
|----------|---------------------|----------------|-----------|
| **Local CLI** | File-specific, editor-agnostic | Full topology, high precision | Limited to local files only |
| **CGEventTap** | System-wide, all apps | Keystroke timing only | Loses edit topology |
| **IME (active)** | All apps including browser | Full keystroke data | Requires user action |
| **Clipboard monitor** | Copy/paste events only | No keystroke timing | Supplements, not replaces |
| **rdev (cross-platform)** | System-wide, multi-OS | Keystroke timing | Platform-specific gaps |

### 7.2 Forensic Value Preservation

**What MUST be preserved (Hard Requirements):**
1. Keystroke timing (>80% capture rate)
2. Hash chain integrity (100%)
3. VDF proof capability (100%)
4. Monotonic timestamps (100%)
5. Human verification metrics (coefficient_of_variation, is_robotic)

**What CAN be degraded (Soft Requirements):**
1. Edit topology precision (cursor position optional)
2. Zone mapping (key code available, position may be estimated)
3. Digraph analysis (reduced precision acceptable)

### 7.3 Decision Framework

```
IF keystroke_capture_rate >= 80% AND
   timing_precision < 100ms AND
   hash_chain_valid AND
   vdf_proof_valid AND
   human_metrics_computable
THEN
   Universal approach is forensically viable
ELSE
   Universal approach fails minimum requirements
```

---

## 8. Acceptance Criteria: <20% Degradation Rule

### 8.1 Definition

**Universal witnessing is acceptable if:**

```
Degradation = (Local_Score - Universal_Score) / Local_Score

ACCEPTABLE: Degradation < 0.20
```

**Example Calculation:**
- Local baseline score: 90 points
- Maximum acceptable degradation: 90 × 0.20 = 18 points
- Minimum universal score: 90 - 18 = 72 points

### 8.2 Per-Category Degradation Limits

| Category | Max Degradation | Example: Local=100 |
|----------|----------------|---------------------|
| Keystroke Timing Precision | 25% | 30 → 22.5 minimum |
| Edit Topology Completeness | 30% | 20 → 14 minimum |
| Temporal Proof Strength | 10% | 20 → 18 minimum |
| Forensic Profile Richness | 20% | 15 → 12 minimum |
| Behavioral Metrics Coverage | 25% | 15 → 11.25 minimum |

### 8.3 Hard Limits (Non-Negotiable)

These MUST be met regardless of overall score:

| Requirement | Threshold | Failure Consequence |
|-------------|-----------|---------------------|
| Keystroke capture rate | >80% | Gaps invalidate timing analysis |
| Timing precision | <100ms | Cadence metrics become meaningless |
| Hash chain integrity | 100% | Any break = Evidence Class X |
| VDF proof validity | 100% | Required for temporal claims |
| Monotonic timestamps | 100% | Regression = automatic Class D downgrade |
| Minimum samples | ≥50 | INSUFFICIENT DATA assessment |

### 8.4 Sample Size Requirements

| Analysis Type | Minimum Samples | Ideal Samples | Source |
|---------------|-----------------|---------------|--------|
| Primary metrics | 50 keystrokes | 500+ | witness-protocol-v1.md:345 |
| Cadence analysis | 100 keystrokes | 1000+ | forensics.rs:89 |
| Zone mapping | 200 keystrokes | 2000+ | Empirical |
| Digraph analysis | 500 keystrokes | 5000+ | Statistical significance |

---

## 9. Reporting Format

### 9.1 Comparison Report Structure

```json
{
  "comparison_id": "uuid-v4",
  "test_date": "2026-02-03T12:00:00Z",
  "test_type": "controlled|natural|edit_pattern",

  "local_evidence": {
    "total_score": 92,
    "category_scores": {
      "keystroke_timing_precision": 28,
      "edit_topology_completeness": 18,
      "temporal_proof_strength": 18,
      "forensic_profile_richness": 14,
      "behavioral_metrics_coverage": 14
    },
    "evidence_class": "A",
    "sample_count": 1854,
    "capture_rate": 0.995
  },

  "universal_evidence": {
    "total_score": 78,
    "category_scores": {
      "keystroke_timing_precision": 22,
      "edit_topology_completeness": 14,
      "temporal_proof_strength": 18,
      "forensic_profile_richness": 12,
      "behavioral_metrics_coverage": 12
    },
    "evidence_class": "B",
    "sample_count": 1760,
    "capture_rate": 0.949
  },

  "comparison": {
    "degradation": 0.152,
    "per_category_degradation": {
      "keystroke_timing_precision": 0.214,
      "edit_topology_completeness": 0.222,
      "temporal_proof_strength": 0.0,
      "forensic_profile_richness": 0.143,
      "behavioral_metrics_coverage": 0.143
    },
    "hard_limits_met": true,
    "acceptable": true
  },

  "notes": [
    "Keystroke precision reduced from ±1ms to ±5ms",
    "Edit topology lost cursor position tracking",
    "VDF proofs identical between methods"
  ]
}
```

---

## 10. Key Thresholds Summary

| Metric | Local Baseline | Universal Minimum | Hard Limit |
|--------|---------------|-------------------|------------|
| Overall Score | 88+ | 70+ | 62 |
| Evidence Class | A | B | C |
| Timing Precision | ±1ms | ±5ms | ±100ms |
| Capture Rate | >99% | >90% | >80% |
| Edit Completeness | 100% | >85% | >70% |
| Overall Degradation | 0% | <20% | <35% |
| Sample Count | n≥500 | n≥100 | n≥50 |

---

*Document Version: 1.0*
*Created: 2026-02-03*
*For witnessd universal witnessing evaluation*
