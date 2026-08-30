# D-006 — The sealed pipeline: where the age head runs relative to redaction

**Status:** Resolved
**Owner:** T1 Agent with Security Agent (two-person, control feature)
**Blocks:** F07, F08, F09, D-001's shared trunk, frozen principle 5

## Problem

SPEC v3.0 §11 mandates irreversible face and text redaction **before** S1 detection, while F09
requires age estimation **before** tracking and after S1. Read literally, the age head is asked to
estimate age from frames whose faces have already been irreversibly obscured. Either:

- the age head consumes unredacted frames (contradicting §11's stated order), or
- age estimation is body/posture-based, with materially worse boundary error exactly where DPDP
  makes false negatives a prohibited-processing event.

F08 R2 already hints at the intended reading — "only transient in-memory frames may be unredacted,
and only within the pipeline process" — but the pipeline diagram contradicts it, and D-001's shared
detector/age trunk forces the question: a single trunk producing both detections and age bands
necessarily runs once, on one version of the frame.

## Decision

Define the **sealed pipeline process** as an explicit architectural object, and place the redaction
boundary inside it rather than at its entrance.

```
╔═ SEALED PIPELINE PROCESS ════════════════════════════════════════╗
║  CAPTURE (decode)                                                ║
║    ↓ prohibited-zone check        refuse instantiation           ║
║    ↓ S0 motion                                                   ║
║    ↓ S1 SHARED TRUNK              detections + age bands, one    ║
║    ↓                              pass, unredacted pixels        ║
║    ↓ AGE GATE                     under-22 → detection dropped   ║
║    ↓                              before it becomes a track      ║
║    ↓ REDACT                       faces + text, irreversible     ║
╚════════╪═════════════════════════════════════════════════════════╝
         ↓  ← the redaction boundary. Nothing crosses unredacted.
      S2 tracking (adults only) → C3 → S3 VLM on redacted crops
      → enum mapping → k ≥ 3 → egress filter → bridge
```

### Properties the sealed process must hold — enforced, not asserted

1. **No egress of any kind.** The process has no network namespace access, no bridge socket, and no
   write access to any persistent path. Enforced by container policy (`nftables` default-deny plus
   a read-only rootfs with tmpfs-only scratch), verified at boot by the privacy-set check.
2. **No IPC carrying pixels.** The only outputs crossing the boundary are (a) redacted frames and
   crops and (b) structured detections stripped of any age value — a boolean `age_gate_passed`, never
   an estimated age or band. Enforced by the output schema: the downstream type has no age field to
   populate.
3. **Unredacted frames are tmpfs/anonymous memory only**, pre-allocated, pinned, and zeroed on
   release. Swap is already prohibited on L1; the sealed process additionally sets `MADV_DONTDUMP`
   and disables core dumps.
4. **Redaction failure drops the frame** (F08 R3, unchanged) and the drop is counted.
5. **Crash of the sealed process is fail-closed**: no frames cross the boundary, tracking halts,
   `redactor_down` / `age_gate_down` raise within 30 s.

### Frozen principle 5 is amended

| | Text |
|---|---|
| v3.0 | "Redaction precedes storage and all downstream analysis." |
| v3.1 | "Redaction precedes storage, every process boundary, and all downstream analysis. Unredacted pixels exist only inside the sealed pipeline process, which can neither store nor transmit." |

Principle 6 ("the age gate precedes tracking") is unchanged and is now literally true: suppression
happens on detections, before any of them become tracks.

## Why this is the stronger control, not a weakening

The v3.0 order was unimplementable, and unimplementable controls get quietly reinterpreted during
implementation — which is precisely the failure mode the lifecycle's "mechanism, not convention"
review question exists to catch. Stating the boundary explicitly makes it testable: the adversarial
suite can assert that the sealed process has no socket, no writable mount, and that its output type
cannot express an age. A convention that "we redact early" cannot be tested at all.

## Test obligations

| Test | Suite | Asserts |
|---|---|---|
| `sealed_no_egress` | `capability-probe` | Process has no route to the bridge; attempted connect fails |
| `sealed_no_persist` | `egress-fuzz` | Every writable path in the sealed namespace is tmpfs |
| `age_never_crosses` | `age-probe` | Boundary output schema rejects any age-valued field |
| `age-probe` boundary set | `age-probe` | Fixtures 16–24 suppress on the correct side |
| `redactor_crash` | bench | Frames drop, nothing unredacted downstream, alert < 30 s |
