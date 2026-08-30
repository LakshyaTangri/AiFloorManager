# T1 — Features, Requirements, User Stories, Acceptance Criteria

**Document:** `/tiers/t1/FEATURES.md`
**Version:** 1.1
**Parent:** `/tiers/t1/SPEC.md` v3.1
**Status:** Build baseline. F01–F22

**Personas**
- **FE** — Field Engineer (installs, commissions, signs off)
- **SM** — Store Manager (consumes briefings, uses local UI)
- **TA** — Tenant Admin (owns config, privacy posture)
- **OPS** — Tangri fleet operator (IaaS agent / human)
- **DPO** — Customer's privacy officer / DPDP auditor
- **SEC** — Tangri security owner

**Controls** referenced as C1–C14 per `/canon/03-controls.md`.

**Changed in v1.1** (see `/canon/05-decisions/`): F01 measured adapter cap · F04 L2 identity is
SEC-1-rooted and the L1 key claim is corrected · F06 read-only credentials mandatory on L1 ·
F07/F08/F09 restated around the sealed pipeline process · F09 gains a model-card release gate · F11
floors come from canon · F12 gains the monotonic policy floor and loses the phantom D-105 reference ·
F14 gains clock-skew buffering · F18 gains the 72-hour offline session rule · **F21 and F22 are new**.

---

## T1-F01 — Pre-flight host qualification

Boots from USB on an unknown customer PC and decides whether the product can run there, before anything is sold as working.

**Requirements**
- R1. The checker shall probe CPU arch, AVX2, core count, RAM, NIC, USB 3.0, GPU/NPU presence, storage, boot mode, virtualization, and sleep/hibernate state without writing to the host's internal disk.
- R2. The checker shall emit a signed `host_profile` JSON including `usable_ram_mb`, a **derived** `adapter_cap`, `stream_cap`, and derived `trust_level`. `adapter_cap` shall be computed from measured usable RAM per D-001 (≥3.40 GB → 3; ≥3.26 GB → 2; below → refuse), never assumed.
- R3. Every failure shall carry a named remedy string (e.g. `sleep_enabled → disable in BIOS > Power`), never a bare fail.
- R4. The checker shall complete in under 5 minutes on minimum-spec hardware.
- R5. The checker shall refuse a non-dedicated host: if it detects an installed OS with recent boot activity it shall flag `host_not_dedicated` as a hard fail for the 4 GB profile.
- R6. Host qualification shall apply to **L1 only**. For L2/L3 the checker shall run a *site* qualification instead — power, network reachability, camera reachability, mounting — and shall not probe or gate on the attached PC (D-007).

**User stories**
- As **FE**, I want a pass/fail with named remedies on the customer's PC within minutes, so I can fix the BIOS on the spot or tell the customer honestly that this machine won't work.
- As **OPS**, I want every pre-flight result uploaded to TG_CMS with the job, so failed hosts never become support tickets later.

**Acceptance criteria**
- Given a PC with 4 GB RAM and sleep enabled, when pre-flight runs, then result is FAIL with remedy `sleep_enabled` and no partition on the internal disk has been touched.
- Given a PC meeting all requirements with 3.45 GB usable, when pre-flight runs, then a signed `host_profile` is produced with `stream_cap: 2`, `adapter_cap: 3`, `trust_level: software_bound` and the run completes in <5 min.
- Given a PC with 3.30 GB usable, when pre-flight runs, then `adapter_cap: 2` is emitted with remedy `add_ram_for_third_adapter`, and commissioning offers 2 adapters rather than failing the install.
- Given an L2 site qualification, when pre-flight runs, then no property of the attached PC appears in the result and `host_not_dedicated` cannot be raised.
- Given a host whose internal disk shows an OS booted within 7 days, when pre-flight runs for the L1 profile, then `host_not_dedicated` is a hard fail.

**Controls:** C13. **Depends:** none. **Blocks:** T1-F02, T5 onboarding step 7.

---

## T1-F02 — Camera assessment

Scores each candidate stream for counting suitability. The score is the contractual accuracy basis.

**Requirements**
- R1. Per stream, the assessor shall score angle, resolution, lighting, occlusion and achieved frame rate into a single `counting_score` (0–1) plus an `issues[]` enum list.
- R2. Streams scoring below the published threshold shall be flagged `not_suitable_for_counting`; commissioning shall require the FE to either exclude them from the accuracy commitment or reposition and re-score.
- R3. Assessment results shall be embedded in the commissioning record and uploaded to TG_CMS with the FE's sign-off.
- R4. Issue enums shall be closed-set (`angle_too_shallow`, `backlit`, `occluded`, `low_resolution`, `fps_below_min`, `lens_dirty`, `ir_glare`) — no free text.

**User stories**
- As **FE**, I want per-camera scores with named issues, so I can reposition a camera during the visit instead of discovering bad accuracy at T+30.
- As **OPS**, I want the signed assessment stored against the contract, so an accuracy dispute is resolved by evidence, not argument.

**Acceptance criteria**
- Given a camera mounted at a shallow angle, when assessed, then `counting_score < threshold` and `issues` contains `angle_too_shallow`.
- Given an FE accepts a below-threshold stream, when commissioning completes, then that stream is marked excluded-from-accuracy-commitment in the job record.
- Given assessment completes, when the record is uploaded, then TG_CMS shows scores per stream attached to the install job.

**Controls:** —. **Depends:** T1-F01. **Blocks:** T5 no-refund defensibility.

---

## T1-F03 — Boot chain and A/B update slots

**Requirements**
- R1. L1/L2 shall boot via MS-signed shim → GRUB2 → signed kernel → signed initramfs from the Tangri SSD, leaving the client internal disk untouched.
- R2. L3 shall boot via Tangri-owned UEFI keys with the MS key removed.
- R3. Root filesystems shall be A/B with a boot counter; 3 consecutive failed health checks shall trigger automatic rollback to the previous slot.
- R4. The privacy control set signature shall be verified before any application container starts; on failure the device shall enter ingest-only mode with the bridge disabled.
- R5. The audit partition shall be mounted append-only before any service starts and shall survive rootfs rollback.

**User stories**
- As **OPS**, I want failed updates to roll back without a site visit, so a bad release costs minutes, not truck rolls.
- As **SEC**, I want the box refusing to talk to the cloud if its privacy set doesn't verify, so a tampered filter can never leak quietly.

**Acceptance criteria**
- Given slot B fails health check 3 times after an update, when the box reboots, then it boots slot A and reports `rollback` with the failing version.
- Given a corrupted privacy-set signature, when the box boots, then app containers do not start, the bridge is disabled, local ingest continues, and a local alert is raised.
- Given a rollback, when the audit log is inspected, then entries from before and after the rollback are contiguous and the chain verifies.

**Controls:** C3, C7. **Depends:** none.

---

## T1-F04 — Device identity, enrolment, anti-clone

**Requirements**
- R1. **L1** identity shall be derived from SSD controller serial + host DMI fingerprint. **L2** identity shall be derived from SoM serial + SEC-1 device identity, and shall not incorporate any property of an attached PC. **L3** identity shall come from factory-provisioned SEC-1/TPM (D-007).
- R2. First boot shall perform one-time enrolment via AWS IoT Fleet Provisioning; T2 shall refuse a second enrolment for the same device identity.
- R3. A host fingerprint change **on L1** shall move the device to `RE_ENROLMENT_PENDING`, halting egress until human approval. Attaching, swapping or removing a PC on L2 shall have no effect on identity or operation.
- R4. Private keys shall be non-exportable on L2 (SEC-1) and L3 (TPM). On L1 keys are **enrolment-bound**, which prevents reuse of a copied identity but does **not** protect key material from an attacker holding the disk; this limitation shall be disclosed in the local UI (D-004).

**User stories**
- As **SEC**, I want a cloned disk to be rejected at enrolment and alerted, so one stolen image can't become a fleet.
- As **FE**, I want a disk moved to a replacement PC to pause and ask, so a legitimate hardware swap is an approval, not a mystery outage.

**Acceptance criteria**
- Given a disk image copied to a second machine, when it attempts enrolment, then enrolment is refused, the event is classified `clone_attempt`, and SEC is alerted.
- Given an L1 customer replaces the PC, when the box next boots, then state is `RE_ENROLMENT_PENDING`, no data egresses, and the local UI explains why.
- Given an L2 customer replaces the attached PC, when the SoM continues running, then no state change occurs, no alert raises, and ingest is uninterrupted.
- Given approval is granted in T2, when the box reconnects, then it re-enrols with a new fingerprint binding and resumes.

**Controls:** C12. **Depends:** T2 P1.

---

## T1-F05 — Capability gate

**Requirements**
- R1. The device shall hold a signed local copy of its capability vector and reject any desired state exceeding it, with a named reason per rejected key.
- R2. Rejection shall be reported in reported-state and logged locally; it shall never be silent.
- R3. The gate shall run before the policy gate and before any artifact download triggered by the desired state.
- R4. The gate shall be independent of T2's plan-time validation (defence in depth).

**User stories**
- As **OPS**, I want a misconfigured plan to bounce with a reason, so I fix the plan instead of debugging a wedged box.
- As **SEC**, I want a compromised control plane to be physically unable to over-drive a device, so blast radius stays bounded.

**Acceptance criteria**
- Given desired state names a 4th adapter for an L1, when the delta arrives, then it is rejected with `adapter_cap_exceeded`, reported-state carries the rejection, and no artifact download begins.
- Given desired state sets `recognition: true` on `software_bound`, when evaluated, then rejection is `trust_level_insufficient`.

**Controls:** C8, C12. **Depends:** T1-F04.

---

## T1-F06 — Adapter framework and discovery

**Requirements**
- R1. Adapters shall be signed plug-ins, hot-loadable, delivered via desired state; no adapter logic in the core runtime.
- R2. Passive discovery (mDNS, SSDP/WS-Discovery, ARP/DHCP observation, BACnet Who-Is, MQTT topic scan) shall run by default; active probing shall be opt-in, rate-limited, with a do-not-probe list.
- R3. Discovered devices shall be fingerprinted and matched to a proposed driver with a confidence score for FE confirmation.
- R4. Unmatched fingerprints and manual mappings shall be reported to T2 as metadata (point-map library growth).
- R5. L1 shall enforce `any 3` adapters at commissioning; a 4th selection shall be refused with the upgrade path named.
- R6. Device credentials shall be entered locally, stored in the sealed vault, never synced to T2, and every use logged.
- R7. On `software_bound` (L1) the vault shall accept **read-only** device accounts only; a credential presenting write capability shall be refused with `rw_credential_forbidden_l1`, because the L1 disk is readable if stolen (D-004).

**User stories**
- As **FE**, I want cameras and meters found and pre-matched, so mapping a site takes minutes.
- As **TA**, I want our device passwords to stay on our premises, so Tangri never holds our credentials.

**Acceptance criteria**
- Given an ONVIF camera on the subnet, when discovery runs, then it appears with proposed driver `onvif` and confidence ≥0.8 within 60 s.
- Given three adapters active on L1, when the FE selects a fourth, then the UI refuses with `adapter_cap` and shows the L2 upgrade path.
- Given a credential is used to open an RTSP session, when the audit log is inspected, then a `credential_use` entry exists; when T2's stores are inspected, then no credential material exists anywhere.
- Given an L1 install, when the FE enters a camera account with PTZ/config write rights, then storage is refused with `rw_credential_forbidden_l1` and the UI names the read-only account remedy.

**Controls:** C1, C8. **Depends:** T1-F05.

---

## T1-F07 — Decode and cascade orchestration

**Requirements**
- R1. The cascade shall gate stages: S0 motion → S1 shared trunk (detection + age band) only on change → age gate → redaction → S2 tracking only on class-of-interest → S3 only on unresolved/low-confidence S2. S0–S1, the gate and redaction shall execute **inside the sealed pipeline process**; S2 and later shall execute outside it (D-006).
- R1a. The sealed process shall run with no network namespace access, no bridge socket, no writable persistent mount, and core dumps disabled. Its crash shall stop the affected stream, never fall back to an unsealed path.
- R2. Stream decode shall be capped at the profile's `stream_cap`; keyframe-only sampling on L1.
- R3. Every inference output shall carry `model_bundle` hash, `confidence`, and stage provenance.
- R4. Cascade overload shall degrade by dropping frames, never by skipping the privacy pipeline stages.

**User stories**
- As **OPS**, I want a busy Saturday to drop frames rather than melt the box, so counts degrade gracefully with a data-quality flag.

**Acceptance criteria**
- Given no motion for 60 s, when frames arrive, then S1 does not run (verified by stage counters).
- Given sustained overload, when load exceeds capacity, then frame-drop increments, `data_quality.coverage` falls, and redaction/age-gate stages still execute on every processed frame.

**Acceptance criteria (sealed process)**
- Given the sealed process is running, when its namespace is inspected, then it has no route to any network and no writable mount outside anonymous memory; an attempted `connect()` from within it fails.
- Given the sealed process is killed, when frames continue arriving, then the stream stops within 5 s, `sealed_pipeline_down` raises, and no frame is processed by an unsealed path.

**Controls:** C5, C14. **Depends:** T1-F06.

---

## T1-F08 — Redaction

**Requirements**
- R1. Faces and legible text shall be irreversibly redacted before storage, before **any process boundary**, and before all downstream analysis (C5 media, C3 crops).
- R2. Unredacted pixels shall exist only inside the sealed pipeline process (F07 R1a). The only pixel data crossing the boundary shall be redacted frames and redacted crops; the only structured data crossing it shall be detections carrying `age_gate_passed: true` — **never an age value, band or score** (D-006).
- R3. Redaction failure on a frame shall drop the frame, never pass it through.
- R4. Unredacted frame buffers shall be pre-allocated, pinned, excluded from swap and core dumps, and zeroed on release.

**User stories**
- As **DPO**, I want stored clips and snapshots to be structurally incapable of identifying a shopper, so a seized disk yields nothing personal.

**Acceptance criteria**
- Given an `event_clip` is stored, when inspected, then all faces and text regions are irreversibly obscured; original pixels are not recoverable from the stored artifact.
- Given the redactor crashes, when frames continue arriving, then frames are dropped and a `redactor_down` alert raises within 30 s; no unredacted frame reaches storage.
- Given any type crossing the redaction boundary, when the contract schemas are checked in CI, then no field of age type is reachable from any of them; a schema change introducing one fails the build.

**Controls:** C5. **Depends:** T1-F07.

---

## T1-F09 — Age gate (minor suppression)

**Requirements**
- R1. Every retail pipeline shall run age estimation before tracking; a detection estimated under 22 shall be **dropped inside the sealed process**, before it can become a track, and shall therefore be absent from S2, C3 and C4 by construction.
- R2. Suppressed persons shall be counted only as `minor_suppressed_n` within C1 aggregates. The derived `minor_suppression_rate` is a site-level **C0** health ratio with no per-person content (D-008 §2).
- R3. The age-gate model version shall appear in attestation and in every egress envelope.
- R6. The model card shall state the measured boundary error rate for the 16–24 band on the validation set. Artifact verification shall refuse a bundle whose card omits it with `model_card_incomplete` (D-008 §5).
- R4. Suppression rate per site shall be computed and reported as a health metric; a >2σ shift shall raise an alert locally and fleet-side.
- R5. Commissioning shall include a functional verification of the gate; activation is blocked without it.

**User stories**
- As **DPO**, I want children never tracked, with the conservative threshold documented, so DPDP's prohibition is met by architecture rather than policy.
- As **OPS**, I want a suppression-rate anomaly to page, so a bad model release is caught as a compliance event, not a metric.

**Acceptance criteria**
- Given a person estimated age 19, when they cross zones, then no `visit_trace` includes them and C1 `minor_suppressed_n` increments.
- Given the age-gate container is down, when frames arrive, then tracking halts (fail closed) and an alert raises; counting may continue as C1-only with `age_gate_down` flagged.
- Given a new age-gate model drops site suppression from 8% to 2%, when the ring evaluates, then the rollout halts automatically.
- Given commissioning, when the gate verification step has not passed, then the ACTIVATE transition is refused.
- Given a model bundle whose card has no 16–24 boundary error rate, when the device verifies the artifact, then installation is refused with `model_card_incomplete` and the previous bundle stays active.

**Controls:** C4. **Depends:** T1-F07. **Blocks:** activation.

---

## T1-F10 — Consent/zone service and prohibited zones

**Requirements**
- R1. Zones shall carry a legal-basis tag; streams mapped to prohibited zones (changing rooms, toilets, prayer rooms, declared staff-only) shall be refused instantiation and the refusal logged.
- R2. Zone geometry and basis shall be editable only through commissioning or TA-approved config change; every change is audited.
- R3. Recognition capability shall check, per enrolled person, a live consent or legitimate-use record before matching; absence disables matching for that person.
- R4. Withdrawal shall delete the local template and derived C4 records within 24 h and emit a signed deletion receipt.

**User stories**
- As **TA**, I want a camera accidentally covering the trial room to be impossible to activate, so a mapping mistake can't become an incident.
- As an employee (**via DPO**), I want my withdrawal to provably delete my template within a day, so consent is real.

**Acceptance criteria**
- Given a stream is mapped to a zone tagged `prohibited`, when commissioning attempts to activate it, then activation is refused with `prohibited_zone` and the attempt is audited.
- Given a withdrawal arrives via T2, when 24 h elapse, then the template is gone, C4 records for that person are purged, and a signed `deletion_receipt` exists in the audit chain and at T2.

**Controls:** C4, C5, C9. **Depends:** T2 consent registry.

---

## T1-F11 — k-anonymity and per-metric floors

**Requirements**
- R1. Every count-class emission shall enforce its per-metric floor before egress; suppressed windows shall emit `k_suppressed` markers, not zeros.
- R2. Aggregation floors shall be per-metric, loaded from the signed policy bundle, not hard-coded.
- R3. The canonical default floors are those in `/canon/02-data-classes.md` (footfall/passerby/zone flow/entry wait k≥3, corporate occupancy k≥10, dwell and duration k≥20, group composition/repeat rate k≥3). A policy bundle may **raise** a floor; a bundle setting any floor below its canonical default shall be refused with `floor_below_canon` and the previous bundle retained (D-008 §3).

**Acceptance criteria**
- Given a 15-min window with 2 people, when footfall egresses, then the window is suppressed and marked `k_suppressed: true`; downstream sums remain consistent.
- Given a policy bundle raises dwell's floor, when the next window closes, then the new floor applies without a code deploy.
- Given a policy bundle setting footfall's floor to 2, when it is loaded, then it is refused with `floor_below_canon`, the prior bundle stays in force, and the attempt is audited.

**Controls:** C6. **Depends:** T1-F12.

---

## T1-F12 — Egress filter

**Requirements**
- R1. The filter shall validate: schema existence, class assignment, field allowlist, free-text rejection by type, per-metric floor, k threshold, `lawful_basis` presence/validity, `retention_until` presence, trust-level permission, entitlement, payload size cap (no media, no base64).
- R2. The filter shall fail closed: an unparseable policy bundle disables the bridge and leaves local ingest running.
- R3. Every rejection shall be counted and reported as a health metric by class and reason.
- R4. Every accepted message shall be appended to the hash-chained audit log before spool.
- R5. The filter shall be a separate container, separately signed and separately released from the OS, under its own two-person approval (D-003).
- R6. The device shall record the highest policy-bundle version ever enforced in the audit partition and refuse any bundle below it with `policy_downgrade`, so that a rootfs rollback cannot reinstate a looser filter (D-003).
- R7. The filter shall refuse any class the device's `trust_level` does not permit — on `software_bound`, classes C3, C4 and C5 — with `trust_level_forbids_class`, independent of what the schema or entitlement allows (D-008 §1).

**User stories**
- As **SEC**, I want the filter to be the one gate every byte passes, versioned in every envelope, so "what could have left this site" is always answerable.

**Acceptance criteria**
- Given a payload containing a free-text string field in a C2 event, when it reaches the filter, then it is rejected with `free_text_forbidden` and counted.
- Given the policy bundle fails signature check on boot, when the box comes up, then bridge is disabled, ingest continues, and `policy_invalid` raises.
- Given any accepted egress, when the envelope is inspected at T2, then `policy_version`, `age_gate_ver` and `class` are present and the audit chain contains the matching entry.
- Given a C3 `visit_trace` submitted on an L1, when it reaches the filter, then it is rejected with `trust_level_forbids_class` even if a valid schema, basis and entitlement are present.
- Given the rootfs is rolled back to an image carrying an older policy bundle, when the filter boots, then the older bundle is refused with `policy_downgrade`, the bridge stays disabled, and ingest continues.

**Controls:** C3, C6, C7. **Depends:** policy bundles from T2.

---

## T1-F13 — Audit chain

**Requirements**
- R1. The audit log shall be append-only, hash-chained, on its own partition, with 1-year minimum retention.
- R2. Recorded events: egress accept/reject, config changes, credential use, model runs (bundle hash), consent actions, kill-switch actions, P2P sessions, enrolment events.
- R3. Chain verification shall be runnable locally from the UI and exportable for audit.

**Acceptance criteria**
- Given any 30-day span, when verification runs, then the chain verifies end-to-end; given one tampered record, verification fails and names the break point.
- Given a DPO export request, when generated, then the export covers the requested range and verifies independently.

**Controls:** C7. **Depends:** T1-F03 (partition).

---

## T1-F14 — Spool and offline operation

**Requirements**
- R1. Spool depth: 7 d (L1), 30 d (L2), 90 d (L3), with overflow priority: safety/security events → refrigeration excursions → operational events → aggregates → health. Aggregates coarsen before dropping; health drops first.
- R2. Reconnect shall use exponential backoff (1 s → 15 min) with per-device jitter derived from device_id hash.
- R3. Backfill shall use the separate ingest endpoint, marked `backfill: true`, original timestamps preserved, rate-limited.
- R4. No raw video backlog shall ever accumulate due to a T2 outage.
- R5. Local function (counting, alerts, briefing on L2/L3, local UI) shall be unaffected by any cloud outage.
- R6. Spooled records shall carry `device_time` plus a monotonic `seq` and `boot_id`. On reconnect the device shall obtain trusted time, compute `clock_offset_ms`, and stamp every backfilled record with it rather than rewriting `device_time`. An offset beyond ±300 s shall mark the affected windows `time_uncertain` and raise `clock_skew` (D-008 §6).

**User stories**
- As **SM**, I want the store to run identically during an internet outage, so my alerts and briefing don't depend on my ISP.

**Acceptance criteria**
- Given 7 days offline on L1, when reconnected, then all aggregate windows arrive via backfill in order with original timestamps and no live-path delay.
- Given spool at 95% on L1, when a refrigeration excursion and a health packet compete, then health is dropped first and the excursion is retained.
- Given a fleet-wide AWS blip, when 1,000 simulated devices reconnect, then connection attempts are spread by jitter (no >5% in any single second).
- Given an L1 with no RTC battery that boots 6 days behind true time and runs offline for 24 h, when it reconnects, then backfilled records carry the measured `clock_offset_ms`, the affected windows are marked `time_uncertain`, and no record is silently misdated.

**Controls:** C13. **Depends:** T1-F12.

---

## T1-F15 — Desired-state convergence and OTA

**Requirements**
- R1. Shadow deltas shall pass capability gate → policy gate → apply, with reported-state closing the loop; rejections carry named reasons.
- R2. OTA shall be IoT Jobs orchestrated, RAUC executed, A/B with health-gated commit and automatic rollback; all bundles signed; delta updates supported.
- R3. Artifact downloads shall verify signature per artifact class key before staging.
- R4. Convergence status shall be reported: converging / converged / rejected / failed.

**Acceptance criteria**
- Given a valid desired state naming a new detector, when applied, then the bundle downloads, verifies against the model key, stages, and reported-state shows the new hash after health check.
- Given an OS bundle signed with the model key, when verified, then it is refused (`wrong_signing_domain`).

**Controls:** C3, C8. **Depends:** T1-F03, T1-F05, T2 P2.

---

## T1-F16 — Retention enforcer and crypto-erase

**Requirements**
- R1. Retention shall be enforced by an independent service (not application code): C3 by profile (7/30/90 d), C5 by clip policy, C4 by basis expiry.
- R2. Expiry shall produce deletion receipts in the audit chain.
- R3. Decommission/RMA shall crypto-erase the data partition and emit a final receipt bound to the device identity. On L1 the audit partition shall be preserved and exported before erase, so the chain survives the device.

**Acceptance criteria**
- Given a C3 trace at retention+1 day with the application stopped, when the enforcer runs, then the trace is deleted and a receipt exists.
- Given an RMA crypto-erase, when the disk is forensically examined, then the data partition is unrecoverable and the receipt hash matches T2's record.

**Controls:** C9, C10. **Depends:** T1-F13.

---

## T1-F17 — Kill switch

**Requirements**
- R1. Kill shall be available per camera, per zone, per capability, from the local UI and (L3) hardware DI input; L1's software-only nature shall be disclosed in the UI.
- R2. Kill state shall survive reboot, propagate to reported-state, and be audited with actor and reason.
- R3. Un-kill shall require TA-level authorisation.

**Acceptance criteria**
- Given SM kills camera 2, when the box reboots, then camera 2 remains killed, reported-state shows it, and the audit records actor and time.
- Given L3 hardware kill asserted, when any software attempts stream start, then it fails while the input is asserted.

**Controls:** C14. **Depends:** T1-F06.

---

## T1-F18 — P2P local API and session enforcement (L2/L3)

**Requirements**
- R1. The local API shall serve the same OpenAPI paths as cloud T3 over mTLS on the LAN, validating session certs against the Session CA and enforcing the cert's bound purpose.
- R2. `software_bound` devices shall not run the P2P service at all.
- R3. Every session shall be logged (user, purpose, duration) to the audit chain.
- R4. Live responses shall be marked `mode: live_onsite` and never persisted by the box beyond their retention class.
- R5. Local sessions shall behave normally for the first 72 h of a T2 outage. Beyond 72 h the device shall enter **read-only local mode**: existing sessions expire on their own TTL, new sessions are issued read-only, and write/actuation calls are refused with `local_session_readonly`. Full function shall return on successful attestation and entitlement refresh, not on mere connectivity (D-005).

**Acceptance criteria**
- Given a valid 15-min session cert bound to purpose `operations`, when a request arrives with purpose `marketing`, then it is refused `purpose_violation`.
- Given an expired cert, when a request arrives, then refusal with `session_expired`; renewal path succeeds at 75% TTL.
- Given an L1, when scanned, then no P2P port is open.
- Given T2 has been unreachable for 73 h, when a new local session is requested, then it is issued read-only and a write call on it is refused with `local_session_readonly`.
- Given the link returns after 80 h, when TCP reachability is restored but attestation has not yet completed, then the device remains read-only until attestation and entitlement refresh both succeed.

**Controls:** C2, C11, C12. **Depends:** T2 session broker.

---

## T1-F19 — Edge Manager loop (L2/L3)

**Requirements**
- R1. Baseline, deviation, explanation, recommendation, outcome and briefing shall run locally on L2/L3 using the same calc/contract versions pinned by desired state.
- R2. Explanation output shall conform to the no-free-text schema; recommendations shall come only from the signed action library; ≤3 recommendations/site/day.
- R3. Briefing shall generate and deliver locally even with T2 unreachable; sync as derived C2 on reconnect.

**Acceptance criteria**
- Given a queue-breach pattern matching an action trigger, when the loop runs, then a recommendation is issued citing evidence refs, confidence and expected impact, and the daily cap is respected.
- Given T2 offline overnight, when morning comes, then the briefing renders locally on time; on reconnect it appears in T2's event store marked with original timestamps.
- Given the explanation model attempts a string outside `cause_enum`, when validated, then the output is rejected and the fallback enum `unknown` is used with reduced confidence.

**Controls:** C8 (library), C14. **Depends:** T3 Phase 6 artifacts, T1-F15.

---

## T1-F20 — Health, host monitoring, camera degradation

**Requirements**
- R1. Device health (CPU, mem, temp, disk, stream FPS, spool backlog) shall publish per C0 at 5-min cadence.
- R2. The **L1** host monitor shall detect thermal throttling, memory pressure, disk removal and competing workloads, raising local + fleet alerts. It shall not run on L2/L3, whose hardware is Tangri-owned and monitored directly (D-007).
- R2a. Health shall include `clock_offset_ms`, `sealed_pipeline_up`, `minor_suppression_rate` and `egress_reject_rate{class,reason}`, all class C0.
- R3. Camera degradation (occlusion, misalignment, focus, lighting) shall be detected continuously and emitted as `camera_degraded` with `counting_impact_pct`.

**Acceptance criteria**
- Given a camera becomes 40% occluded, when detection runs, then `camera_degraded` emits within 15 min with cause `occluded` and a non-zero counting impact, and the SM sees it in the app.
- Given the customer starts a heavy workload on a supposedly dedicated L1 host, when detected, then `host_contention` raises and data-quality flags apply to affected windows.

**Controls:** C14. **Depends:** T1-F07.

---

## T1-F21 — Commissioning gate

SPEC §18 defined the gate but no feature owned it, so it had no acceptance criteria and no Security
review. It is a control feature: it is the step that makes activation refusable (D-008 §7).

**Requirements**
- R1. ACTIVATE shall be refused unless **every** gate item passes: pre-flight PASS, camera assessment complete with each stream either above threshold or explicitly excluded from the accuracy commitment, zone map with a legal basis on every zone, notice/signage photographed and attached, age-gate functional verification passed, kill switch exercised, credentials stored read-only where the profile requires it, and FE sign-off.
- R2. Each refusal shall name the failing item and its remedy; a partial gate shall never yield a partially active device.
- R3. The commissioning record shall be signed, appended to the audit chain, and uploaded to TG_CMS before ACTIVATE completes.
- R4. No gate item shall be waivable in the field. A waiver shall exist only as a T2-issued, expiring, two-person-approved exception recorded in the chain.
- R5. The gate shall run offline end to end, queuing the upload.

**User stories**
- As **DPO**, I want activation to be impossible without signage and a working age gate, so "no signage, no activation" is a mechanism rather than a promise.
- As **FE**, I want the remaining blockers listed on one screen, so I know exactly what is left before I leave site.

**Acceptance criteria**
- Given every item passes except the signage photo, when ACTIVATE is attempted, then it is refused with `notice_missing`, the device stays in COMMISSIONING, and no stream is processing.
- Given the age-gate verification has not been run, when ACTIVATE is attempted, then refusal is `age_gate_unverified`.
- Given the site is offline, when the full gate passes, then ACTIVATE completes locally and the signed record uploads on reconnect with its original timestamps.
- Given an FE attempts to bypass an item locally, when the attempt is made, then there is no code path that accepts it and the attempt is audited.

**Controls:** C2, C7, C9, C14. **Depends:** T1-F01, T1-F02, T1-F09, T1-F10, T1-F13, T1-F17. **Blocks:** activation.

---

## T1-F22 — Local control surfaces

SPEC §17 lists eleven surfaces that are compliance mechanisms, not chrome — a mode indicator that
lies is a defect. They are specified here so they carry ACs and Security review (D-008 §7).

**Requirements**
- R1. The local UI shall render, from live device state and never from cached or optimistic values: mode indicator, confidence badge with the action threshold, k-suppressed notice, data-quality banner, camera health chip, consent-zone map, kill switch, audit viewer, notice status, minor-suppression statistic, trust-level chip.
- R2. The trust-level chip shall expand on `software_bound` to the D-004 disclosure: software-only kill switch, no secure element, disk readable if stolen.
- R3. Any surface whose backing state is stale beyond 60 s shall render as `unknown`, never as its last good value.
- R4. The UI shall be reachable on the LAN without T2 and shall function fully offline.
- R5. On L2, the UI shall be served to the attached PC without that PC holding state or credentials.

**User stories**
- As **SM**, I want the screen to tell me when it does not know, so I never act on a number that stopped updating an hour ago.
- As **TA**, I want the trust level and its limits stated on the device itself, so nobody in my building believes L1 is tamper-proof.

**Acceptance criteria**
- Given the age gate is down, when the dashboard is opened, then the mode indicator shows degraded, the affected metrics carry the data-quality banner, and no trace-derived metric renders.
- Given the state feed stalls for 90 s, when the dashboard is viewed, then affected chips read `unknown` rather than their last value.
- Given an L1, when the trust-level chip is expanded, then the software-only kill switch and readable-disk disclosures are both shown.
- Given T2 is unreachable, when the UI is loaded from the LAN, then every surface still renders from local state.

**Controls:** C7, C13, C14. **Depends:** T1-F13, T1-F17, T1-F20.

---

## Traceability

| Control | Features |
|---|---|
| C1 raw stays on site | F06, F07, F08, F12, F14, F18 |
| C2 purpose required | F18, F21 |
| C3 dual egress enforcement | F03, F12, F15 |
| C4 age gate | F09, F10 |
| C5 redaction first | F07, F08, F10 |
| C6 per-metric k floors | F11, F12 |
| C7 audit/fail-closed | F03, F12, F13, F21, F22 |
| C8 entitlement ∧ capability | F05, F06, F15, F19 |
| C9 basis per record | F10, F12, F16, F21 |
| C10 retention | F16 |
| C11 no store access for P2P path | F18 |
| C12 capability vectors | F04, F05, F18 |
| C13 offline-first | F01, F14, F22 |
| C14 mode/confidence surfaced | F07, F17, F19, F20, F21, F22 |

**Open decisions blocking features:** none. D-001, D-003, D-004, D-005 are resolved; D-006
(sealed pipeline) constrains F07/F08/F09, D-007 (SoM) constrains F01/F04/F20, and D-008 records the
review corrections carried into this revision.
