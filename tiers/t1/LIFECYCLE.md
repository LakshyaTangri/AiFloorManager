# T1 — Development Lifecycle

**Document:** `/tiers/t1/LIFECYCLE.md`
**Version:** 1.1
**Parent:** `/tiers/t1/SPEC.md` v3.1, `/tiers/t1/FEATURES.md` v1.1
**Applies to:** every T1 feature F01–F22

---

## The loop

```
DESIGN → IMPLEMENT → TEST → REVIEW → REFACTOR → DOCUMENT
   ▲                                                 │
   └────────── next feature, or re-entry on ─────────┘
              contract change / control gap
```

One feature moves through all six before the next begins in the same module. Parallelism happens **across** modules, never across stages within a feature.

## Why T1 needs its own version of this

Three properties make T1 different from the other tiers, and each bends a stage:

| Property | Consequence |
|---|---|
| **Hardware in the loop** | TEST cannot complete in CI. Every feature has a bench gate on real hardware |
| **Yocto builds take hours** | IMPLEMENT must be testable without a full image rebuild; containers and host-side simulation carry most iterations |
| **Controls are the product** | REVIEW is a Security Agent gate for control features, not a code-quality read |
| **Memory is a hard ceiling** | REFACTOR is not optional on L1 paths. A feature that fits functionally but not in budget is not done |

---

# Stage 1 — DESIGN

**Agent:** T1 Agent (architecture), with Contract Agent for any interface touch.
**Model:** Opus.

## Inputs

```
/canon/03-controls.md
/canon/02-data-classes.md
/contracts/t1-t2/*            (read-only; changes go through Contract Agent)
/tiers/t1/SPEC.md             the relevant section
/tiers/t1/FEATURES.md         the feature's requirements + ACs
```

## Outputs

A module brief at `/tiers/t1/modules/{feature-id}.md` containing:

| Section | Content |
|---|---|
| Interfaces | Exact function/service boundaries; which contract slice applies |
| Data flow | What enters, what leaves, what is stored, what is dropped |
| **Failure design** | What happens when the dependency is down, the input is malformed, the budget is exceeded |
| **Resource budget** | RAM ceiling, CPU share, disk, startup time — per profile (L1/L2/L3) |
| Control mapping | Which of C1–C14 this feature enforces, and by what mechanism |
| Test plan outline | Which ACs are CI-testable, which need bench, which need field |
| Open questions | Anything requiring an ADR before implementation |

## Gate to advance

- [ ] Every AC in FEATURES.md maps to a design element
- [ ] Resource budget stated per profile and summed against §7 of SPEC
- [ ] Failure design covers: cloud down, dependency container down, malformed input, budget exceeded
- [ ] No contract change required, **or** a contract change request is filed and resolved
- [ ] Control mechanism named — "enforced by X", not "should not Y"

**Stop condition:** if design reveals that a control can only be satisfied by convention rather than mechanism, escalate to Supervisor. Do not implement.

---

# Stage 2 — IMPLEMENT

**Agent:** T1 sub-agent, scoped to one module.
**Model:** Sonnet (Opus for cascade, privacy pipeline, boot chain).

## Rules

1. **Write the refusal path first.** For any feature with a control, the rejection case is implemented and passing before the accept case exists. This inverts the usual order deliberately — it is how C3, C4, C6 and C12 stop being aspirational.
2. **No image rebuild in the inner loop.** Containers run against a host-side simulator (`t1-sim`) providing fake streams, fake shadow deltas and a fake bridge. Yocto rebuild is a nightly job, not a per-commit one.
3. **Budget instrumentation from the first commit.** Every container reports RSS at startup and steady state. A container without a cgroup ceiling does not merge.
4. **Signed artifacts are fixtures.** Implementation uses test keys from a dev CA; production keys never enter a development environment.

## Scaffolding provided before any feature work

| Tool | Purpose |
|---|---|
| `t1-sim` | Synthetic RTSP streams, MQTT points, POS webhooks, shadow deltas, bridge sink |
| `t1-bench` | Runner for hardware-in-the-loop tests against a real box |
| `budget-report` | Per-container RSS against declared ceiling; fails CI on breach |
| `chain-verify` | Audit chain verification, used in tests and shipped in the local UI |
| `egress-fuzz` | Generates malformed and hostile payloads for the filter |
| `sealed-probe` | Asserts the sealed pipeline process has no network route, no writable persistent path, and that no age-typed field is reachable from any boundary-crossing schema (D-006) |

All five, plus `sealed-probe`, run on the developer's own machine. `t1-bench` is the only one that
needs hardware, and it degrades to a clear "no rig attached" rather than a failure, so the inner
loop never depends on the lab.

## Gate to advance

- [ ] All CI-testable ACs pass
- [ ] Refusal paths implemented and asserted
- [ ] `budget-report` green against the declared ceiling
- [ ] No `TODO`, no commented-out control check, no bypass flag
- [ ] Runs under `t1-sim` end to end

---

# Stage 3 — TEST

**Agent:** QA sub-agent. Independent of the implementing agent.
**Model:** Sonnet; Haiku for mechanical fixture generation.

## Four test layers, in order

### 3.1 Unit and container (CI, every commit)

Logic, schema conformance, state machines, policy evaluation. Fast, hermetic.

### 3.2 Simulated integration (CI, every merge)

Full pipeline under `t1-sim`: synthetic camera → cascade → privacy pipeline → egress → fake bridge. Asserts on both what emerges and what does not.

### 3.3 Bench — hardware in the loop (nightly + pre-merge for hardware features)

Run on the reference rig: three real PC configurations for L1, one **SoM carrier** for L2 (D-007), one appliance for L3.

| Test | Verifies |
|---|---|
| Boot matrix | Real UEFI variants, Secure Boot on/off, USB boot order |
| Thermal soak | 8 h sustained load, throttle detection |
| Decode capacity | Actual streams sustained per profile |
| Memory ceiling | Real steady-state RSS against §7 budget |
| Rollback | Forced update failure → automatic slot rollback |
| Disk pull | Hot disconnect behaviour, chain integrity on reconnect |
| **Crypto-erase** | Decommission erases the data partition irrecoverably, preserves and exports the audit partition, and emits a receipt whose hash matches T2's record. Verified by forensic read-back of the raw device after erase, not by the tool's own exit code (F16 R3) |
| **Clock skew** | Boot with the RTC days behind true time, run offline, reconnect: backfill carries `clock_offset_ms` and `time_uncertain`, nothing is silently misdated (F14 R6) |

### 3.4 Adversarial (pre-merge for control features)

The tests that matter most for T1's compliance claims.

| Suite | Attempts |
|---|---|
| `egress-fuzz` | Free text in typed fields, oversized payloads, base64 media, missing basis, absent `retention_until`, forged policy version |
| `k-probe` | Windows engineered at k=1, 2, 3 to confirm suppression boundary |
| `age-probe` | Boundary-age fixtures (16–24) confirming suppression side of the threshold |
| `capability-probe` | Desired states exceeding every capability vector field |
| `session-probe` | Expired certs, wrong purpose, wrong device, L1 P2P attempt |
| `chain-tamper` | Single-record modification, confirms verification fails and localises |
| `signing-domain` | OS bundle signed with model key, and every other wrong-key permutation |
| `sealed-probe` | Egress attempt from inside the sealed process; write attempt to a persistent path; age field smuggled into a boundary-crossing type; sealed-process kill (must stop the stream, never fall back) |
| `policy-floor` | Bundle with a floor below canon (`floor_below_canon`); bundle older than the recorded floor (`policy_downgrade`); rootfs rollback carrying an older bundle |
| `class-trust` | Every C3/C4/C5 schema submitted on a `software_bound` device with otherwise-valid basis and entitlement (`trust_level_forbids_class`) |

**Every adversarial suite must fail closed. A pass is a refusal, correctly logged.**

## Field test — required for eight features

F01, F02, F06, F09, F17, F18, F19, F20 and **F21** cannot be certified without a real site — F21 because a commissioning gate that has never been run against real signage, real cameras and a real FE is untested. These enter the design-partner rotation and carry a `field_verified` flag in the feature register.

## Gate to advance

- [ ] Layers 3.1–3.2 green
- [ ] Bench green for hardware-touching features
- [ ] Adversarial suites green for control features
- [ ] Coverage of ACs traced: every AC in FEATURES.md has a named test
- [ ] Field test scheduled (not necessarily complete) for the eight above

---

# Stage 4 — REVIEW

Two reviews run in parallel. Both must pass.

## 4.1 Code review

**Agent:** Review Agent. **Model:** Sonnet.

| Check | |
|---|---|
| Contract conformance | Matches generated types exactly; no hand-written interface code |
| Structure | Module boundaries respected; no cross-module imports outside declared interfaces |
| Error handling | Every failure path from the design brief exists |
| Resource discipline | Allocation in loops, unbounded buffers, missing back-pressure |
| Observability | Health metrics, OTel spans, log levels appropriate |
| No dead controls | No feature flag, env var or config key can disable a control |

## 4.2 Control review

**Agent:** Security Agent. **Required for:** F03, F04, F05, F07, F08, F09, F10, F11, F12, F13, F16, F17, F18, F21, F22.

F07 joins the list because the sealed process is now a control boundary, not just orchestration; F21
because it is the mechanism that makes activation refusable; F22 because a control surface that
misreports state is a compliance defect.
**Model:** Opus. **Two-person** for F12 (egress filter) and F09 (age gate).

| Question | |
|---|---|
| Mechanism, not convention | Is the control structural, or does it rely on the caller behaving? |
| Fail-closed | On every failure mode, does it deny? |
| Bypass | Is there any path — config, flag, debug, race — that skips it? |
| Evidence | Does it produce an audit record sufficient for a DPDP auditor? |
| Version binding | Does the enforcing artifact's version appear in the envelope and attestation? |

**Security Agent has veto.** A vetoed feature returns to DESIGN, not to IMPLEMENT — a control that cannot be made structural is a design problem.

## Gate to advance

- [ ] Code review passed
- [ ] Control review passed where required
- [ ] Contract Agent sign-off if any interface was touched
- [ ] No open review comment of severity ≥ major

---

# Stage 5 — REFACTOR

**Agent:** T1 sub-agent (original implementer).
**Model:** Sonnet.

Not optional on T1. The memory ceiling makes it structural.

## Triggers — any one mandates a refactor pass

| Trigger | Threshold |
|---|---|
| Memory over budget | Any container above its declared ceiling |
| L1 total approaching limit | Sum > 3.28 GB — the v3.1 ceiling (D-001), leaving ~120 MB against 3.40 GB usable |
| Startup time | Any container > 10 s to ready |
| Duplication | Same logic in two containers → extract to shared library |
| Decode inefficiency | Achieved streams below profile target |
| Test brittleness | Any test requiring a sleep or retry to pass |

## Rules

1. **Refactor changes no behaviour.** All tests from Stage 3 must pass unchanged. If a test needs modifying, this is not a refactor.
2. **Budget must improve or hold.** `budget-report` diff attached to the commit.
3. **Controls are never simplified away.** A refactor that removes a check is rejected regardless of its performance benefit.

## The D-001 case

D-001 is resolved: shared trunk, keyframe-only decode with pinned pre-allocated buffers, and a
bounded spool cache, totalling 3.28 GB. The precedent stands — a structural memory decision is a
**design-stage** decision. If the measured bench figure comes in above the ceiling, the correct
action is to escalate and return to DESIGN, or to let pre-flight drop `adapter_cap` to 2 on that
host class; it is never to shave memory out of an adjacent container to make room.

## Gate to advance

- [ ] All Stage 3 tests pass unchanged
- [ ] `budget-report` improved or held
- [ ] No control check removed or weakened
- [ ] Complexity reduced, evidenced by a stated metric

---

# Stage 6 — DOCUMENT

**Agent:** Docs sub-agent. **Model:** Haiku for mechanical, Sonnet for narrative.

## Six artifacts, all mandatory

| Artifact | Location | Content |
|---|---|---|
| **Module doc update** | `/tiers/t1/modules/{id}.md` | Design brief updated to as-built; deviations recorded with reasons |
| **Feature register** | `/tiers/t1/FEATURES.md` | Status, test refs per AC, `field_verified` flag |
| **ADR** | `/canon/05-decisions/` | Any decision made during the cycle that constrains future work |
| **Runbook entry** | `/ops/runbooks/` | How this fails in the field, what the symptom looks like, what the FE or OPS does |
| **API/contract doc** | Generated | If interfaces changed, regenerated by Contract Agent |
| **Field note** | `/ops/field/` | Anything the Field Engineer must know: BIOS settings, camera positioning, common failure |

## The runbook entry is the one that gets skipped

It is also the one that determines support cost. Required content:

```
Symptom          What the customer or FE observes
Likely cause     Ranked
Diagnosis        Exact commands or UI path
Remedy           Step by step
Escalation       When to stop and who to call
Prevention       What commissioning step avoids this
```

## Gate to close the feature

- [ ] All six artifacts present
- [ ] Feature register updated with test references
- [ ] Runbook entry reviewed by whoever will answer the support call
- [ ] Field note added for anything install-affecting
- [ ] Handoff report filed to Supervisor

---

# Feature classes and their lifecycle weight

Not every feature needs equal ceremony. Three classes:

| Class | Features | Design | Review | Adversarial | Field |
|---|---|---|---|---|---|
| **Control** | F03, F04, F05, F07, F08, F09, F10, F11, F12, F13, F16, F17, F18, F21, F22 | Full brief + ADR | **Code + Security, 2-person on F09/F12** | Required | F09, F17, F18, F21 |
| **Infrastructure** | F06, F14, F15, F20 | Full brief | Code review | Capability + session probes | F06, F20 |
| **Application** | F01, F02, F19 | Brief | Code review | — | All three |

F07 moved from Infrastructure to Control in v1.1: once the sealed process is the redaction boundary,
the cascade orchestrator is enforcing C1 and C5, not merely scheduling stages.

A control feature that skips its Security review is not merged. An application feature that skips field test is not certified.

---

# Cycle time expectations

Per feature, single sub-agent, excluding field verification:

| Class | Design | Implement | Test | Review | Refactor | Document | Total |
|---|---|---|---|---|---|---|---|
| Control | 2–3 d | 4–8 d | 3–5 d | 2–3 d | 1–3 d | 1 d | **13–23 d** |
| Infrastructure | 1–2 d | 3–6 d | 2–4 d | 1 d | 1–2 d | 1 d | **9–16 d** |
| Application | 1 d | 2–4 d | 1–2 d | 1 d | 0–1 d | 1 d | **6–10 d** |

Bench and field time are wall-clock and parallelisable across features; they do not serialise the agent's work.

---

# Parallelisation map

What can run simultaneously without collision:

```
Track A (control)      F03 → F04 → F05 → F12 → F13
Track B (pipeline)     F10 → F07 → F08 → F09 → F11
Track C (integration)  F06 → F14 → F15
Track D (surface)      F01 → F02 → F17 → F20 → F22 → F21
Track E (L2/L3 only)   F16 → F18 → F19
```

F10 moved from Track E to the head of Track B in v1.1. It was mis-placed: the prohibited-zone check
is the **first stage of the pipeline on every profile**, and only its recognition-consent half is
L2/L3-only. An L1 with no zone service is an L1 that can be pointed at a changing room.

**Cross-track dependencies to respect:**
- F12 (egress filter) must reach REVIEW before F11 (k-anonymity) leaves DESIGN — the floor policy loads through the filter's bundle.
- F09 (age gate) blocks F19 (Manager loop) — no briefing without minor suppression proven.
- F05 (capability gate) blocks F15 (convergence) — the gate is upstream of apply.
- F10's zone service blocks F07 — the cascade cannot instantiate a stream it cannot check.
- F21 (commissioning gate) closes last on its track: it asserts on every other feature's refusal path, so it cannot be certified before them.

---

# Re-entry conditions

A closed feature returns to the loop when:

| Trigger | Re-enters at |
|---|---|
| Contract change affecting its interface | DESIGN |
| A canon control is added or tightened | DESIGN |
| Security Agent finds a bypass post-merge | DESIGN |
| Budget regression from an adjacent feature | REFACTOR |
| Field failure with no runbook entry | DOCUMENT |
| Recurring support ticket | DESIGN (the fix is usually structural) |

**Re-entry at IMPLEMENT is not permitted for control features.** If a control needs changing, the design that produced it was wrong.

---

# Definition of done — T1 feature

A feature is done when all six are true:

1. Every AC in FEATURES.md has a passing named test
2. Adversarial suites pass where the feature class requires them
3. Security Agent has signed off where required
4. Resource budget is within ceiling on every applicable profile
5. Runbook and field note exist and have been read by the person who will use them
6. `field_verified` is set, or an explicit waiver with expiry is recorded

Anything less is in progress, regardless of whether the code works.

---

# Working on a host that is not the target

Development happens on ordinary Linux machines, which are not L1 hosts and must never be mistaken
for one. The rule is that **the host-side loop proves logic; only the bench proves hardware.**

| Provable on any dev host | Bench only |
|---|---|
| Every control refusal path | Real steady-state RSS on a 4 GB host |
| Egress filter, k floors, class/trust rules | Achieved decode throughput per profile |
| Audit chain construction and tamper detection | Boot matrix, Secure Boot, USB boot order |
| Sealed-process namespace and schema assertions | Thermal soak and throttle behaviour |
| Age-gate ordering and boundary fixtures | Crypto-erase forensic read-back |
| Spool priority, backfill ordering, clock skew | RTC-less clock behaviour on real silicon |

`budget-report` running on a dev host reports **declared ceilings and simulated allocation**, not
measured L1 truth. It is a regression guard, not evidence. No datasheet number — including the
3.28 GB in D-001 — is published until `t1-bench` produces it on the reference rig.
