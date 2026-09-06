# D-010 — Four supervised units, each independently signed and released

**Status:** Resolved
**Owner:** Product with T1 Agent
**Answers:** ADR-REQ-007 (`tiers/t1/PLAN.md` §3)
**Blocks:** M04, M08, M12, M14
**Source:** approved 2026-09-05

## Problem

D9 gives modules as ownership boundaries and says nothing about processes, containers or release
artifacts. D-003 needs the egress policy to ship without shipping the runtime; D-006 needs
unredacted pixels confined to a process; F03 R4 needs a signature checked before application
containers start. None of that can be built without knowing what a *unit* is.

## Decision

T1 runs **four separately supervised units**, each with its own signed artifact and release
lifecycle:

| Unit | Owns | Notes |
|---|---|---|
| **Sealed pipeline** | unredacted frame processing, detection, age gate, redaction | no raw pixels cross its boundary (D-006) |
| **Control plane** | policy, capability, commissioning, audit, retention, lifecycle | the Python of D-009 |
| **Egress filter / policy bundle** | policy enforcement and the signed policy itself | independently releasable per D-003; the monotonic version floor prevents rollback |
| **Bridge / cloud connector** | MQTT 5 over TLS 1.3, spool and backfill, T1–T2 traffic | the only unit that talks to T2 |

Every unit has, without exception:

- an explicit process boundary;
- least-privilege credentials scoped to what that unit alone needs;
- health supervision, so a unit can be found dead rather than assumed alive;
- a versioned contract at its boundary;
- **signature verification before activation** — a unit whose artifact does not verify is not
  started, and the supervisor says which unit and why.

Native replacements sit *behind the existing Python contracts* (D-009). A unit rewritten in Rust or
C++ satisfies the same versioned boundary or it is a contract change first.

## Consequences

- ADR-REQ-007 is closed; phase 1c (M04) is unblocked, and M08, M12 and M14 inherit the unit list as
  their packaging and release boundary.
- Four artifacts, four version streams. An egress-policy tightening ships without a runtime release,
  which is the whole point of D-003, and OTA (F15) must therefore reconcile a *set* of unit versions
  rather than one image version.
- The supervisor is a real component with refusal behaviour, not an init script: unverified
  artifact, missing credential scope, or an unsealed environment for the sealed unit are each a
  named refusal to start.
- Four boundaries are four places to drift. The contracts are versioned for that reason, and a
  boundary change is reviewed as a contract change regardless of which language sits behind it.
