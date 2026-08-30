# Decision register

Every decision that constrains future work lives here as an ADR. Nothing in this repository is
frozen; a decision is changed by superseding its ADR, never by editing the outcome in place.

| ID | Decision | Status | Supersedes / notes |
|---|---|---|---|
| [D-001](0001-d001-shared-trunk-and-l1-budget.md) | Shared detector/age-head trunk + measured `adapter_cap` | **Resolved** | Option B alone was insufficient (−80 MB against a −240 MB gap) |
| [D-002](0002-d002-baseline-model-format.md) | Baseline model format and size ceiling | **Resolved** | ONNX + signed coefficient JSON, ≤150 MB |
| [D-003](0003-d003-egress-policy-independent-release.md) | Egress policy bundle releases independently of the OS | **Resolved** | "D-105" in FEATURES v1.0 F12 R5 was a phantom reference; deleted |
| [D-004](0004-d004-l1-disk-theft-posture.md) | L1 disk-theft posture | **Resolved** | Accept readable disk; disclose; mandate read-only device accounts on L1 |
| [D-005](0005-d005-local-session-duration.md) | Local session mode duration during a T2 outage | **Resolved** | 72 h full, then read-only |
| [D-006](0006-sealed-pipeline-redaction-boundary.md) | Where the age head runs relative to redaction | **Resolved** | Introduces the sealed pipeline process; amends frozen principle 5 |
| [D-007](0007-rtl-l2-som.md) | RTL-L2 is a System-on-Module, not a USB4 accelerator enclosure | **Resolved** | Renames `accelerator_attested` → `module_attested` |
| [D-008](0008-review-resolutions.md) | Seven smaller SPEC/FEATURES corrections | **Resolved** | C3-on-L1, suppression metric class, k floors, cap composition, clock skew, F10 track, new F21/F22 |

## Open

None. Any new decision is filed here before the work it blocks enters IMPLEMENT.
