# D-009 — Python is the production control plane; native code only where measured

**Status:** Resolved
**Owner:** Product with T1 Agent
**Answers:** ADR-REQ-002 (`tiers/t1/PLAN.md` §3)
**Blocks:** M03, M04, M08, and every module that consumes a control-plane contract
**Source:** approved 2026-09-05

## Problem

The repository carries a working Python control set — policy, egress filter, audit chain, capability
vector, sealed-environment types — while D8/D9 names Rust/C++ among T1's technologies. Nothing said
which of the two the Python was: the product, or an executable specification for a rewrite. Every
module from M03 onward inherits the answer, and the two readings produce different repositories.

## Decision

**Python is the production implementation of T1 control-plane logic.**

Native Rust/C++ is introduced only where a requirement is *measured*, not anticipated:

| Justification | Examples |
|---|---|
| Measured performance | inference, decode, the per-frame path inside the sealed pipeline |
| Hardware access | device drivers, secure-element and TPM interfaces, media handling |
| Security-sensitive performance paths | work that must hold a latency budget while inside the sealed boundary |

"Measured" means a recorded benchmark against the relevant budget in `ops/budgets.json` or the D-001
memory table, not a judgement that Python will be too slow.

**Process-boundary contracts are authoritative and survive any later replacement.** The existing
Python types at those boundaries — `contracts/`, the capability vector, the egress envelope, the
audit record — define the interface. A component rewritten in Rust or C++ must satisfy the same
contract, unchanged; a rewrite that needs a contract change is a contract decision first and an
implementation change second.

## Consequences

- ADR-REQ-002 is closed. Phase 1b (M02, M03) and phase 3 (M08) are unblocked on this axis; M04 still
  waits on ADR-REQ-007's container decomposition.
- The control set in `src/t1/control/` is production code and is reviewed, budgeted and released as
  such. It is not scaffolding, and it is not deleted when native components appear beside it.
- A native component is a *replacement behind a contract*, never a parallel implementation of one:
  two implementations of the same boundary is the drift D-003 exists to prevent.
- CI keeps enforcing the Python gates (`ruff`, `mypy --strict`, pytest) as release gates rather than
  as checks on a reference model.
- The choice is reversible per component and not globally: superseding this ADR is required only to
  make native the default, not to make one measured component native.
