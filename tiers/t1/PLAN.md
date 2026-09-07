# T1 — implementation gap analysis and dependency plan

**Document:** `/tiers/t1/PLAN.md`
**Version:** 1.0
**Parent:** `/tiers/t1/ARCHITECTURE.md` v1.0, `/tiers/t1/TRACEABILITY.md` v1.0
**Status:** live. Phases are closed by evidence, not by opinion.

## 1. Where the repository actually is

The repository is a **host-side control and privacy core with a simulation harness**. It is not an
appliance. Nothing in it boots, nothing in it talks to a camera, and nothing in it has run on the
target hardware.

| Category | Content |
|---|---|
| EXISTING | Canon constants; sealed-boundary contracts and structural guard; sealed pipeline skeleton with age gate and redaction ordering; capability vector and gate; signed policy bundle with monotonic floor; egress filter; k-anonymity; zones/consent; retention enforcer; SQLite spool with ordered backfill and aggregation collapse; audit chain; commissioning gate; reconnect backoff; lifecycle CLIs; CI running the control gates as named steps; **M01 pre-flight qualification (this change)** |
| INCOMPLETE | M04 (environment assertions only, no supervisor); M06 (backoff only); M08 (trunk and redactor are injected callables; the bundle gate verifies artifacts it does not execute); M09 Edge Manager (no baseline learner, no explainer, no outcome step); M10 (domain, retention and erase policy with no LUKS2 operation and no supervised sweep); M11 sessions; M12 bridge (no MQTT 5 / TLS 1.3 transport); M16 (budgets only, no health) |
| MISSING | All of S01 below M01 — boot chain, OS image, runtime; M05 listeners and vault; M07 decoder; M08 model execution; M13 desired/reported state; M14 OTA; M17 GUI; factory provisioning; runbooks and field procedures |
| CONFLICTING | See §2 |
| UNSPECIFIED | See §3 |
| BROKEN | None. `ruff`, `mypy --strict` and the full suite are green on this branch |

## 2. Conflicts between the repository and D8/D9

1. **Feature baseline drift.** D8/D9 enumerate F01–F20. The repository baseline is F01–F22, adding
   F21 commissioning gate and F22 local control surfaces, both of which are implemented or planned.
   The repository is ahead, not wrong; D8/D9's feature list needs the two additions and a module
   owner for each (ADR-REQ-001).
2. **M08 is one module but two processes.** D9 gives M08 responsibility for detection, age
   estimation and redaction. D-006 requires those to run inside a sealed process that the rest of
   M08 may not enter. The code already splits them; the architecture text should state the split
   rather than leaving it to implementers. D-010 settles it: the sealed pipeline is one of four
   separately signed units (ADR-REQ-007).
3. **Egress filter placement.** D9 locates the egress filter in M15 as part of security. D-003
   requires the filter to be separately signed and released so tightening can ship independently of
   the runtime. That is a packaging constraint D9 does not express; D-010 makes the egress
   filter/policy bundle its own unit with its own release lifecycle (ADR-REQ-007).
4. **Language and runtime.** The repository is pure Python with no dependencies. The target stack
   named in the tier's own material is Yocto Linux, ONNX Runtime, MQTT 5, TLS 1.3, RAUC, SQLite,
   Rust/C++ and Python. Whether the Python control set was the production implementation or the
   executable reference for a native one was the single largest open question; D-009 answers it —
   Python is production for control-plane logic, native code enters only where a requirement is
   measured, and process-boundary contracts outlive any component that is later rewritten.

## 3. Architecture decisions required

Each item is a question, not a proposal to act on. Blocking items stop a phase; non-blocking items
have a recorded working assumption that can be reversed cheaply.

Three entries in the first version of this register were not open questions at all: SPEC §3.1 gives
the storage layout and the media part, §4 gives the L1 anti-clone enrolment, and §5 gives the boot
chain and disk-unlock model. They are recorded below as answered by SPEC, with only the residue
still open. Reading SPEC.md before writing the register would have caught this.

| ID | Question | Working assumption | Impact | Blocks |
|---|---|---|---|---|
| ADR-REQ-001 | Which modules own F21 and F22, and is D8/D9's feature list updated to F01–F22? | F21 → M13, F22 → M17 | Ownership and review routing | Non-blocking |
| ADR-REQ-002 | ~~Is the Python control set the production implementation?~~ **Answered by [D-009](../../canon/05-decisions/0009-d009-control-plane-implementation-language.md)**: yes for control-plane logic; native Rust/C++ only for measured performance, hardware access or security-sensitive performance paths; process-boundary contracts survive any later rewrite | Decided | Every module from M03 onward; team shape; CI | Closed |
| ADR-REQ-003 | ~~What is the on-device storage layout?~~ **Answered by SPEC §3.1 and §5**: rootfs-A / rootfs-B / LUKS2 data / 8 GB append-only audit / spool; audit survives rootfs rollback; zram 512 MB and no swap on the boot SSD. Open residue: partition sizes. What is crypto-erasable per data class is now stated in `src/t1/storage/domains.py` — C3/C4/C5 live only on the LUKS2 domains, the audit domain is preserved — and needs confirming rather than deciding | Implement the SPEC layout as given | M02, M03, M10, F16 | Non-blocking; sizes needed before phase 4 closes |
| ADR-REQ-004 | ~~How is L1 identity rooted with no TPM?~~ **Answered by SPEC §4**: identity derives from SSD controller serial + host DMI fingerprint, one certificate, T2 refuses a second enrolment for the disk, fingerprint change → `RE_ENROLMENT_PENDING` with human approval. Open residue: custody of the pre-flight/profile signing key, and how the enrolment key wrapping the LUKS key is protected on a stolen disk (SPEC concedes it is attackable) | Implement SPEC §4 as given | F04, F05 trust level, entitlement | Non-blocking; key custody needed before phase 5 closes |
| ADR-REQ-005 | Is a virtualised host a refusal or an advisory at pre-flight? | Advisory, reported | F01 outcome on VMs | Non-blocking |
| ADR-REQ-006 | By what method may pre-flight obtain the internal disk's last-boot evidence without violating AD-01? A read-only mount is still a mount. | Unmeasured is a refusal (`host_dedication_unverified`) | F01 R5 certification | **Blocks F01 bench sign-off** |
| ADR-REQ-007 | ~~What is the container decomposition, and which units are separately signed and released?~~ **Answered by [D-010](../../canon/05-decisions/0010-d010-unit-decomposition-and-release.md)**: four supervised units — sealed pipeline, control plane, egress filter/policy bundle, bridge — each with an explicit process boundary, least-privilege credentials, health supervision, versioned contracts and signature verification before activation | Decided | M04, M08, M12, M14 | Closed |
| ADR-REQ-008 | Is the D8 GUI navigation the same set as the F22 local control surfaces, or a subset? | Subset of F22 | M17 scope | Non-blocking until phase 10 |
| ADR-REQ-009 | ~~Is 128 GB the minimum media capacity?~~ **Answered by SPEC §3.1**: Tangri supplies a 256 GB SATA SSD in a USB 3.0 UASP enclosure, so `MIN_T1_MEDIA_MB` is that part's usable capacity. Open residue: the endurance and thermal class that qualifies the part | 256 GB part; class unqualified | M01 bench matrix, BOM | **Blocks M01 media qualification** |
| ADR-REQ-010 | What is the published `counting_score` threshold, and who may change it? F02 R2 requires a published number; SPEC publishes none, and the number decides which streams carry an accuracy commitment | Working value 0.60, in code rather than in signed policy so it cannot be lowered per site after the contract is written | F02 commissioning outcome, T5 no-refund defensibility | Non-blocking; needed before the first accuracy commitment is signed |

## 4. Phase plan

Order follows the approved dependency order. Each phase is closed only when its definition of done
is met; a phase may start while a later phase's design work proceeds, but no phase closes on the
strength of host-side evidence where the feature touches hardware.

| Phase | Modules | Principal tasks | Depends on | Definition of done |
|---|---|---|---|---|
| 0 | — | Architecture carried in-repo; traceability; this plan; ADR-REQ register | — | **Done in this change** for the analysis; ADR-REQs answered is a separate close |
| 1a | M01 | Pre-flight host and site qualification, signed profile, named remedies, CLI | Phase 0 | **Host-side done in this change.** Media endurance/thermal/power-loss matrix and the dedication probe remain (ADR-REQ-006, 009) |
| 1b | M02, M03 | Portable-media image, UEFI/Secure Boot chain, A/B slots, read-only rootfs, storage domains per SPEC §3.1/§5 | Phase 1a; unblocked by D-009 | **Host-side done in this change** (F03 R3–R5: slot state, boot-counter rollback, stage ordering, privacy-set gate, layout invariants). Remaining: the shim/GRUB2/signed-kernel chain (R1–R2), the Yocto image, and bench proof that the device boots on two qualified hosts with the internal disk untouched and rollback exercised |
| 1c | M04 | Container runtime, sealed-process supervision enforcing `SealedEnvironment`, capability enforcement at launch | 1b; unblocked by D-010 | **Supervision policy done in this change** (four units, start order, per-unit signature and scope refusal, health). Remaining: the runtime that enforces it — namespaces, capabilities, seccomp — and `sealed-probe` run against the real supervisor rather than the type system |
| 2 | M06, M05 | Reachability, adapters, discovery, read-only credentials, camera assessment (F02, F06) | 1c | **Host-side done in this change** (reachability posture and firewall sheet, TLS-interception and inbound-rule refusal, camera scoring and accuracy commitment, discovery policy, adapter cap, vault credential rules). Remaining: the probe that opens sockets and pins the Tangri Service CA, mDNS/SSDP/ARP listeners, signed adapter plug-ins, the sealed vault, and real cameras enumerated and scored on bench |
| 3 | M07, M08, M09 | Decode and cascade, model bundle behind the sealed trunk, tracking, aggregation, Edge Manager | 2 | **Host-side done in this change** (stream admission and stage gating, overload drops with reported coverage, model-bundle and model-card release gate, tracking and dwell outside the sealed process, aggregation windows on canon k floors, Edge Manager loop with a signed action library and composed caps). Remaining: the decoder and a measured frame budget, ONNX/NPU execution with real weights and measured age-gate accuracy, a baseline learner and explainer, the F19 outcome step, and end-to-end counts on real streams |
| 4 | M10 | Storage domains, retention enforcement on durable storage, crypto-erase | 1b, ADR-REQ-003 residue | **Host-side done in this change** (domain placement with erasable/preserved separation, durable retention index the enforcer opens by path, two-phase deletion receipts, signed decommission order, chain export before erase, bound receipt and `partial` outcome). Remaining: `cryptsetup luksErase` against a real LUKS2 header, forensic proof that the data partition is unrecoverable, the index on the encrypted volume under power loss, and a supervised unit that runs the sweep |
| 5 | M15 | Identity and enrolment per SPEC §4, anti-clone, kill switch; existing filter/policy/audit integrated into the runtime | 4, ADR-REQ-004 residue | **Host-side done in this change** (profile-rooted identity, one-time enrolment, clone refusal with alert, `RE_ENROLMENT_PENDING` on an L1 host change with signed T2 approval to leave it, egress halted while pending, scoped and durable kill switch with TA-authorised release and an L3 hardware override, evidence-backed commissioning items). Remaining: real Fleet Provisioning against T2, SEC-1/TPM key generation and attestation, the L3 DI line, the measured ingest-stop budget, and kill state on the LUKS2 volume |
| 6 | M11 | P2P sessions with no store access | 5 | Session refusals proven adversarially |
| 7 | M12, M13 | MQTT 5 / TLS 1.3 transport behind the existing bridge, spool drain, desired/reported state, commissioning gate wired to activation | 5 | 72 h offline then ordered backfill against a real broker; activation impossible with an open gate |
| 8 | M14 | OTA bundles, signature verification, slot switch, rollback | 1b, 7 | Failed update rolls back automatically; policy floor survives rollback |
| 9 | M16 | Health, degraded-mode reporting, budgets from live counters | 7 | Every failure class surfaces with its outcome |
| 10 | M17 | On-premise GUI and the F22 surfaces behind session/purpose/authorisation/capability/policy/audit | 7, 9, ADR-REQ-008 | Every surface refuses without an authorised session and is audited |

## 5. Standing rules for every phase

- Refusal path first, then the success path.
- Every acceptance criterion gets a named test; a criterion with no test is not met.
- Host-side green is never evidence of hardware behaviour. Bench and field gates are separate and
  are recorded per `/tiers/t1/LIFECYCLE.md`.
- Unspecified detail becomes an ADR-REQ row here; it does not become an implementer's guess.
