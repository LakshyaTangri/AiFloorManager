# T1 — implementation traceability

**Document:** `/tiers/t1/TRACEABILITY.md`
**Version:** 1.0
**Parent:** `/tiers/t1/ARCHITECTURE.md` v1.0, `/tiers/t1/FEATURES.md` v1.1

```text
D8/D9 → subsystem → module → component → source files → tests
```

Status vocabulary: **EXISTING** (implemented and tested at this tier), **INCOMPLETE** (a real
component exists but the module's scope is not met), **MISSING** (nothing in the repository),
**CONFLICTING** (repository and D8/D9 disagree — see PLAN.md), **UNSPECIFIED** (architecture does
not yet say enough to implement).

Every row is host-side unless marked. Nothing in this table is evidence of hardware behaviour:
per `/tiers/t1/LIFECYCLE.md`, bench and field gates are separate and none of them have been run.

| Sub | Module | Component | Source | Tests | Status |
|---|---|---|---|---|---|
| S01 | M01 | Pre-flight host qualification (F01) | `src/t1/platform/probe.py`, `src/t1/platform/qualification.py`, `src/t1/tools/preflight.py` | `tests/test_preflight.py` | EXISTING (bench-unproven) |
| S01 | M01 | Portable media qualification: endurance, thermal, TRIM, power-loss | — | — | MISSING |
| S01 | M02 | A/B slot state, boot-counter rollback, pre-service ordering, privacy-set gate (F03 R3–R5) | `src/t1/platform/boot.py` | `tests/test_boot.py` | EXISTING (host-side logic; unproven on hardware) |
| S01 | M02 | Measured boot and Secure Boot chain: shim, GRUB2, signed kernel and initramfs (F03 R1–R2) | — | — | MISSING |
| S01 | M03 | Storage layout and its invariants: AD-01, read-only roots, LUKS2, append-only audit, no disk swap | `src/t1/platform/layout.py` | `tests/test_boot.py` | EXISTING (model only; no imaging) |
| S01 | M03 | T1 OS image build (Yocto), image signing and release | — | — | MISSING |
| S01 | M04 | Unit supervision: four D-010 units, start order, per-unit artifact signature, scope allow-list, health | `src/t1/platform/supervisor.py`, `src/t1/sealed/guard.py` | `tests/test_supervisor.py`, `tests/test_sealed_probe.py` | EXISTING (policy only; no runtime enforcement) |
| S01 | M04 | Container runtime itself: namespaces, capabilities, seccomp, cgroups | — | — | MISSING |
| S02 | M05 | Camera assessment scoring, closed issue set, accuracy commitment (F02) | `src/t1/devices/assessment.py` | `tests/test_camera_assessment.py` | EXISTING (scores measurements; no decode path to produce them) |
| S02 | M05 | Discovery policy, fingerprint→driver match, adapter cap, credential vault rules (F06) | `src/t1/devices/discovery.py` | `tests/test_discovery.py` | EXISTING (policy only) |
| S02 | M05 | Discovery listeners (mDNS, SSDP, ARP/DHCP, BACnet Who-Is) and signed hot-loadable adapter plug-ins (F06 R1–R2) | — | — | MISSING |
| S02 | M05 | Sealed credential vault backed by TPM/SEC-1 | — | — | MISSING |
| S02 | M06 | Outbound reachability assessment, TLS-interception and inbound-rule refusal, offline posture, firewall sheet | `src/t1/platform/reachability.py`, `src/t1/bridge/backoff.py` (reconnect only) | `tests/test_reachability.py`, `tests/test_bridge_probe.py` | EXISTING (scores observations; no socket, resolver or TLS client) |
| S02 | M06 | The probe itself: DNS, TCP 443, TLS with Tangri Service CA pinning, ALPN, proxy client | — | — | MISSING |
| S03 | M07 | Stream admission, stage gating, overload drops, coverage (F07) | `src/t1/pipeline/cascade.py` | `tests/test_cascade.py` | EXISTING (orchestration only; no decoder) |
| S03 | M07 | The decoder itself: demuxer, keyframe parsing, hardware decode sessions, measured frame budget | — | — | MISSING |
| S03 | M08 | Sealed half: trunk, age gate, redaction (F08, F09) | `src/t1/sealed/pipeline.py`, `src/t1/contracts.py`, `src/t1/sealed/guard.py` | `tests/test_sealed_probe.py`, `tests/test_age_probe.py`, `tests/test_contracts.py` | INCOMPLETE (trunk and redactor are injected) |
| S03 | M08 | Model bundle verification, model-card gate, downgrade floor, suppression-shift halt (F09 R3, R4, R6) | `src/t1/sealed/bundle.py` | `tests/test_model_bundle.py` | EXISTING (gates artifacts it does not execute) |
| S03 | M08 | Model execution: ONNX Runtime / NPU session, weights, measured accuracy | — | — | MISSING |
| S03 | M08 | Unsealed half: tracking, dwell, C3-at-rest refusal | `src/t1/analytics/tracking.py` | `tests/test_tracking.py` | EXISTING (IoU association, not ByteTrack) |
| S03 | M09 | k-anonymity suppression (F11) | `src/t1/control/kanon.py` | `tests/test_k_probe.py` | EXISTING |
| S03 | M09 | Aggregation windows, coverage and time_uncertain carriage (F11, F14 R6) | `src/t1/analytics/aggregation.py` | `tests/test_aggregation.py` | EXISTING (caller-driven; no window scheduler) |
| S03 | M09 | Edge Manager loop: deviation, closed-vocabulary explanation, signed action library, caps, briefing (F19) | `src/t1/analytics/edge_manager.py` | `tests/test_edge_manager.py` | INCOMPLETE (no baseline learner, no explainer, no outcome step) |
| S04 | M10 | Zones and consent (F10) | `src/t1/control/zones.py` | `tests/test_retention_and_sim.py` | EXISTING |
| S04 | M10 | Retention rules in memory (F16 R1) | `src/t1/control/retention.py` | `tests/test_retention_and_sim.py` | EXISTING |
| S04 | M10 | Durable retention index and an enforcer that opens it by path, deletion receipts (F16 R1, R2) | `src/t1/storage/durable.py` | `tests/test_durable_retention.py` | EXISTING (SQLite on a host filesystem; nothing schedules the sweep) |
| S04 | M10 | Storage domain placement: erasable vs preserved, trust level, encryption, AD-01 (F16, C9) | `src/t1/storage/domains.py` | `tests/test_storage_domains.py` | EXISTING |
| S04 | M10 | Decommission crypto-erase: signed order, chain export, key-slot destruction, bound receipt (F16 R3) | `src/t1/storage/erase.py` | `tests/test_crypto_erase.py` | EXISTING (order and refusals only) |
| S04 | M10 | LUKS2 key-slot destruction (`cryptsetup luksErase`) and forensic proof of unrecoverability | — | — | MISSING |
| S04 | M10 | Supervised enforcer: the unit that runs the sweep independently of the application | — | — | MISSING |
| S05 | M11 | Session certificates verified against the Session CA: domain, signature, device, window (F18 R1) | `src/t1/control/session.py` | `tests/test_session_probe.py` | EXISTING (HMAC stands in for the CA's X.509 signature) |
| S05 | M11 | L1 does not run the P2P service (F18 R2) | `src/t1/control/session.py` | `tests/test_session_probe.py` | EXISTING (property; no build has been port-scanned) |
| S05 | M11 | Session open/close chained with user, purpose and duration (F18 R3) | `src/t1/control/session.py` | `tests/test_session_probe.py` | EXISTING |
| S05 | M11 | Live responses marked `live_onsite` and classed (F18 R4) | `src/t1/control/session.py` | `tests/test_session_probe.py` | EXISTING (label only; nothing stores or deletes them) |
| S05 | M11 | 72 h full function, then read-only until attestation *and* entitlement refresh (F18 R5, D-005) | `src/t1/control/session.py` | `tests/test_session_probe.py` | EXISTING |
| S05 | M11 | Renewal offered at 75% of TTL, earlier refused (F18) | `src/t1/control/session.py` | `tests/test_session_probe.py` | EXISTING (timing rule only; the broker signs) |
| S05 | M11 | mTLS local API serving the cloud OpenAPI paths on the LAN | — | — | MISSING |
| S05 | M11 | T2 session broker issuance and the real attestation/entitlement exchange | — | — | MISSING |
| S05 | M12 | Outbound-only bridge (F12, F14) | `src/t1/bridge/mqtt.py` | `tests/test_bridge_probe.py` | INCOMPLETE (no MQTT 5 / TLS transport) |
| S05 | M12 | Durable spool and ordered backfill (F14) | `src/t1/control/spool.py` | `tests/test_spool_probe.py` | EXISTING |
| S05 | M13 | Commissioning gate (F21) | `src/t1/control/commissioning.py` | `tests/test_commissioning_probe.py` | EXISTING |
| S05 | M13 | Desired/reported state reconciliation (F15) | — | — | MISSING |
| S05 | M14 | OTA bundles, slot switch, rollback (F15, F03) | — | — | MISSING |
| S06 | M15 | Identity, enrolment, anti-clone (F04) | — | — | MISSING |
| S06 | M15 | Capability vector and gate (F05) | `src/t1/control/capability.py` | `tests/test_class_trust.py` | EXISTING |
| S06 | M15 | Egress filter and signed policy (F12) | `src/t1/control/egress_filter.py`, `src/t1/control/policy.py` | `tests/test_egress_fuzz.py`, `tests/test_policy_floor.py`, `tests/test_class_trust.py` | EXISTING |
| S06 | M15 | Audit chain (F13) | `src/t1/control/audit_chain.py` | `tests/test_chain_tamper.py` | EXISTING |
| S06 | M15 | Kill switch (F17) | — | — | MISSING |
| S06 | M16 | Budgets and counters (F20) | `src/t1/tools/budget_report.py`, `ops/budgets.json` | `tests/test_retention_and_sim.py` | INCOMPLETE |
| S06 | M16 | Health reporting, degraded-mode surfacing | — | — | MISSING |
| S07 | M17 | On-premise GUI and local control surfaces (F22) | — | — | MISSING |

## Verification tooling

| Tool | Gate it serves |
|---|---|
| `sealed-probe` | D-006 boundary structural assertions |
| `egress-fuzz` | Hostile payloads against the egress filter |
| `chain-verify` | Audit chain tamper evidence |
| `budget-report` | Declared ceilings in `ops/budgets.json` |
| `t1-sim` | Host-side end-to-end simulation |
| `t1-bench` | Bench matrix — lists what is unproven; proves nothing on a host |
| `t1-preflight` | F01 host/site qualification |
