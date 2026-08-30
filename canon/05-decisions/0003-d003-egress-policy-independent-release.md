# D-003 — The egress policy bundle releases independently of the OS

**Status:** Resolved
**Owner:** Security Agent
**Blocks:** release pipeline, key policy, F12

## Problem

FEATURES v1.0 F12 R5 states the filter is "a separate container, separately signed, separately
released (per D-003/D-105 resolution)" — writing an answer to a decision the SPEC still listed as
open, and citing **D-105, which does not exist in any register**. The phantom ID is deleted.

## Decision

The egress policy bundle and the privacy control set release **independently of the OS image**.

| | Path |
|---|---|
| Signing key | Privacy policy key (bundle) / privacy-set key (containers) — never the OS key |
| Approval | Two-person. **Tightening ships fast; loosening ships slow and fully audited** |
| Delivery | Desired state `privacy_policy: <version>`, artifact over HTTPS, verified per artifact class key before staging |
| Rollout | Rings, T2-orchestrated, health-gated — same machinery as OTA, different key and different approvers |
| Coupling to OS | None. An OS rollback must not roll the policy back below the version recorded in the last audit entry |

Two properties follow and are testable:

1. **A valid OS signature authorises nothing else** (frozen principle, unchanged). The
   `signing-domain` adversarial suite asserts every wrong-key permutation is refused, including an
   egress bundle signed with the OS key and an OS bundle signed with the privacy policy key.
2. **Monotonic policy floor.** The device records the highest policy version it has ever enforced in
   the audit partition (which survives rootfs rollback). A bundle whose version is below that floor
   is refused with `policy_downgrade`, so a rollback cannot be used to reinstate a looser filter.

An unparseable or unverifiable bundle disables the bridge and leaves local ingest running (F12 R2,
unchanged). The monotonic floor is checked before parsing.
