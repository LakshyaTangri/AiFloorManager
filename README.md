# pulse-t1

T1 is the Tangri edge platform: it senses, decides and acts locally. T2 governs. Raw data stays at
the edge; meaning and metadata go up.

This repository holds the T1 source of truth and the first implementation of the controls that
make the above sentence enforceable rather than aspirational.

```
canon/            data classes, controls, and the decision register (ADRs)
contracts/t1-t2/  published schemas; closed, and checked against the runtime allowlist in CI
tiers/t1/         SPEC v3.1, FEATURES v1.1, LIFECYCLE v1.1, ARCHITECTURE, TRACEABILITY, PLAN
src/t1/platform/  M01: pre-flight host and site qualification
src/t1/sealed/    the sealed pipeline process and its structural guards
src/t1/control/   audit chain, egress filter, k-anonymity, zones, capability, sessions, retention
src/t1/sim/       host-side simulation harness
src/t1/tools/     the lifecycle CLIs
ops/budgets.json  declared L1 memory ceilings (declared, not measured)
```

## Setup

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

## The loop

```bash
.venv/bin/sealed-probe        # boundary is structurally sound
.venv/bin/egress-fuzz         # every hostile payload is refused, by name
.venv/bin/t1-sim              # full path end to end on this machine
.venv/bin/budget-report --budgets ops/budgets.json
.venv/bin/chain-verify path/to/chain.jsonl
.venv/bin/t1-preflight --json --t1-media-mb 256000   # refuses this host, with named remedies
.venv/bin/pytest && .venv/bin/ruff check . && .venv/bin/mypy
```

## What this repository does not prove

`t1-bench --list` prints the claims that only real hardware can settle: steady-state RSS on a 4 GB
host, decode throughput, the boot matrix, thermal soak, crypto-erase read-back, RTC-less clock
behaviour. They are reported as **unproven**, never as passes. A host-side green run is not bench
evidence and must not be quoted as one; `ops/budgets.json` is a declaration, not a measurement.

Field verification (F01, F02, F06, F09, F17–F21) is a separate gate again.

## Where the implementation stands

`tiers/t1/ARCHITECTURE.md` carries the approved D8/D9 module boundaries alongside the code,
`tiers/t1/TRACEABILITY.md` maps every module to its source and tests with a status, and
`tiers/t1/PLAN.md` holds the gap analysis, the phase plan and the open architecture-decision
requests. Read PLAN.md before starting a module: several phases are blocked on answers, not effort.

## Design notes worth reading first

- `canon/05-decisions/0006-sealed-pipeline-redaction-boundary.md` - why age inference runs on
  unredacted pixels inside a process with no route out, and why nothing but a boolean crosses.
- `canon/05-decisions/0001-d001-shared-trunk-and-l1-budget.md` - how L1 fits in 3.28 GB, and the
  measured adapter-cap fallback when it does not.
- `canon/05-decisions/0007-rtl-l2-som.md` - L2 is a System-on-Module, so its identity and trust do
  not depend on the attached PC.

Nothing here is frozen. A decision changes by superseding its ADR, never by editing the outcome in
place.
