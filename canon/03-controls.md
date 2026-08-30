# Canon — the fourteen controls

**Version:** 1.1
**Status:** Canon. A control changes only by superseding ADR.

A control is a **mechanism**, never a convention. If the only thing standing between the product and
a breach is a caller behaving correctly, it is not a control — it is a hope, and the Security Agent
vetoes it. Every control below names the artifact that enforces it and the test that proves it.

| ID | Control | Enforced by | Proven by |
|---|---|---|---|
| **C1** | Raw stays on site. No raw personal visual information leaves the premises by any path | Sealed pipeline process (no egress route); egress filter payload cap, no blobs, no base64 | `egress-fuzz`, `sealed_no_egress` |
| **C2** | Purpose required. Every access to event or richer data carries a bound purpose | Session cert purpose binding (P2P); `purpose` field required by envelope schema | `session-probe` |
| **C3** | Dual egress enforcement. Egress is filtered locally and independently re-validated in cloud | Egress filter container (edge) + T2 server-side re-validation | `egress-fuzz` + T2 contract tests |
| **C4** | Age gate. No person estimated under 22 enters C3 or C4 by any path | Shared trunk age head inside the sealed process; suppression before tracking | `age-probe` |
| **C5** | Redaction first. Faces and legible text are irreversibly redacted before storage, before any process boundary, and before all downstream analysis | Redactor, inside the sealed process, at its boundary | `redaction` bench suite |
| **C6** | k-anonymity. Count-class emission enforces the per-metric floor, minimum k ≥ 3 | Egress filter floor check against the signed policy bundle | `k-probe` |
| **C7** | Audit and fail-closed. Every egress decision is recorded in a hash-chained log; every failure denies | Audit chain on its own append-only partition; every gate defaults to refuse | `chain-tamper`, fail-closed cases in every suite |
| **C8** | Entitlement ∧ capability. A capability runs only if T2 entitles it **and** the device's signed capability vector permits it | Capability gate (device) ahead of policy gate; entitlement bundle signature | `capability-probe` |
| **C9** | Basis per record. Every record carries a valid `lawful_basis` for its class | Egress filter basis check; consent/zone service supplies the basis | `egress-fuzz` |
| **C10** | Retention. Every record carries `retention_until` and is deleted by an enforcer independent of application state | Retention enforcer (system service, not app code); deletion receipts in the chain | Retention bench suite |
| **C11** | No store access on the P2P path. Live local access never reads the analytics store | P2P service reads the live pipeline only; no store credentials in its namespace | `session-probe` |
| **C12** | Capability vectors. A device physically cannot exceed its declared capability, whatever the control plane says | Signed local capability vector + capability gate, independent of T2 validation | `capability-probe` |
| **C13** | Offline-first. Local function never depends on the cloud | Spool, local Manager loop (L2/L3), local UI, local briefing | Offline bench suite |
| **C14** | Mode and confidence surfaced. The operator always knows what mode the system is in and how confident it is | Local UI control surfaces (F22); `confidence` + `action_threshold` in every envelope | F22 UI tests |

## The two rules that outrank everything

**Rule 1.** No raw personal visual information reaches T2 by any path.
**Rule 2.** No person estimated under 22 enters C3 or C4 by any path.

If a feature cannot be built without violating either, the feature is not built.

## What "fail closed" means here

On any failure — dependency down, signature invalid, policy unparseable, schema unknown, budget
exceeded, clock skewed — the system **denies the egress and keeps sensing locally**. It never fails
open, and it never stops being useful to the store. Those two properties together are the reason a
customer accepts an appliance that refuses things.
