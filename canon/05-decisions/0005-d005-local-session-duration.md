# D-005 — Local session mode duration during a T2 outage

**Status:** Resolved
**Owner:** Platform Agent
**Blocks:** bridge agent, T3 edge auth, F18

## Decision

Adopt the proposed posture: **72 hours of full local session issuance, then read-only.**

| Elapsed since last successful T2 contact | P2P / local API behaviour |
|---|---|
| 0 – 72 h | Normal. The box issues local sessions itself against the cached Session CA and the cached entitlement bundle. Cert TTL is capped at 15 min and renewal at 75 % TTL is permitted |
| > 72 h | **Read-only.** Existing sessions run to expiry; new sessions are issued with a read-only purpose set. Writes, exports and per-clip media release are refused with `degraded_offline_readonly` |
| Reconnect | Full mode resumes only after a successful attestation and entitlement refresh, not merely after TCP connectivity |

Rationale: 72 h covers a long weekend, which is the realistic worst case for an unattended site with
a dead link. Beyond that, the cached entitlement and revocation state are too stale to authorise a
human to look at live imagery on someone else's premises — revocation is the specific thing that
cannot be inferred locally.

Constraints that hold throughout, unchanged:
- `software_bound` (L1) never runs the P2P service at all, in any mode.
- Every session is logged to the audit chain with user, purpose and duration (F18 R3) regardless of
  mode; the degraded transition is itself an audited event.
- Read-only mode is surfaced by the mode indicator in the local UI (F22), never silent.

The `session-probe` adversarial suite gains two cases: a session request at T+73 h asserting
read-only, and a write attempt on a read-only session asserting `degraded_offline_readonly`.
