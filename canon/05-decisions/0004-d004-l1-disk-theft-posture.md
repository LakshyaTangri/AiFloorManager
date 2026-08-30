# D-004 — RTL-L1 disk-theft posture

**Status:** Resolved
**Owner:** Security Agent with Product
**Blocks:** UX, support burden, F04 R4, F06 R6, F22 disclosure surface

## Problem

On L1 there is no secure element. The LUKS2 key is wrapped by the enrolment key and stored on the
disk itself, so a stolen disk is attackable offline — SPEC v3.0 §5 says so plainly. The mitigation
offered was "holds no video and no raw data at rest", which is true for media but **not** for the
sealed credential vault: F06 R6 puts the customer's camera and device passwords on that disk.

Meanwhile F04 R4 describes L1 keys as "enrolment-bound" in a sentence about non-exportability,
which reads as a protection it is not.

Options were: accept the readable disk, or add a boot passphrase.

## Decision

**Accept the readable disk. Do not add a boot passphrase.** A passphrase on an unattended box in a
back office is either written on the box or phoned to support at 06:00 — it converts a bounded
confidentiality risk into an unbounded availability and support cost. Instead, five mitigations,
all mandatory on L1:

1. **Read-only device accounts are required on L1**, not "requested wherever possible" (F06 R6 is
   tightened for L1). A stolen L1 vault yields view-only camera credentials.
2. **Per-credential scope recorded at entry.** The UI requires the FE or customer IT to mark each
   credential read-only or read-write; a read-write credential on L1 is refused with
   `rw_credential_forbidden_l1` and the upgrade path named.
3. **Theft is an identity event.** The disk cannot re-enrol (F04), and a fingerprint change halts
   egress. T2 raises `possible_theft` on `RE_ENROLMENT_PENDING` for a device that did not have a
   scheduled hardware swap, which is the trigger for the customer to rotate device passwords.
4. **Rotation runbook.** `ops/runbooks/l1-disk-loss.md` — what to rotate, in what order, and how to
   confirm. Support cost is paid in a runbook rather than in a passphrase.
5. **Disclosure in the UI, next to the software-only kill-switch disclosure.** The trust-level chip
   on `software_bound` expands to: no secure element, software kill switch, credentials protected at
   rest only by the enrolment key. Honest capability disclosure is the L1 product's whole posture.

**F04 R4 is corrected**: keys are non-exportable on L2 (SEC-1) and L3 (TPM). On L1 they are
*enrolment-bound*, which prevents reuse of a copied identity — it does **not** protect key material
against an attacker holding the disk. The two are different claims and the spec now says so.

Revisit if L1 ever stores C4 or media. Under the current classes it stores neither.
