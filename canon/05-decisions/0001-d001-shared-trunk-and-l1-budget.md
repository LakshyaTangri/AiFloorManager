# D-001 — RTL-L1 memory: shared detector/age-head trunk plus a measured adapter cap

**Status:** Resolved
**Owner:** ML Agent with T1 Agent
**Blocks:** model bundle pipeline, L1 datasheet, T2 `age_gate` artifact class, Phase 4d
**Supersedes:** SPEC v3.0 §7 "OPEN DECISION — D-001"

## Problem

SPEC v3.0 §7 budgets **3.54 GB** against **~3.4 GB usable** on a 4 GB L1 host. The three options
offered were A (2-adapter profile, −140 MB), B (shared detector/age-head trunk, −80 MB) and C
(single stream, −250 MB), with B recommended.

**B alone does not close the gap.** 3.54 − 0.08 = 3.46 GB, still above 3.4 GB usable, and well above
the 3.30 GB LIFECYCLE refactor trigger (which exists to leave 100 MB headroom). The recommended
option was short by roughly 160 MB against the threshold the lifecycle actually enforces.

## Decision

Adopt B **and** two further reductions, and make the adapter cap a *measured* output of pre-flight
rather than a published constant.

### Revised RTL-L1 budget

| Component | v3.0 | v3.1 | Change |
|---|---|---|---|
| Kernel + Tangri OS | 500 | 500 | |
| containerd + supervisor | 350 | 350 | |
| Privacy control set | 550 | 550 | |
| Cascade orchestrator + bridge agent | 250 | 250 | |
| Discovery + normalization | 250 | 250 | |
| Adapters ×3 | 420 | 420 | |
| Detector + age head (**shared trunk**) + ONNX Runtime | 520 | **440** | −80 |
| Decode ×2, **keyframe-only, pre-allocated pinned buffers** | 500 | **360** | −140 |
| SQLite spool (page cache capped at 32 MB, WAL bounded) | 200 | **160** | −40 |
| **Total** | **3 540** | **3 280** | **−260** |

3.28 GB against ~3.4 GB usable, and under the 3.30 GB refactor trigger. Headroom ~120 MB.

### Measured adapter cap

`adapter_cap` is no longer a fixed 3. Pre-flight (F01) measures usable RAM after kernel and emits it
in the signed `host_profile`:

```
usable ≥ 3.40 GB  → adapter_cap = 3, stream_cap = 2
usable ≥ 3.26 GB  → adapter_cap = 2, stream_cap = 2   (adapters ×2 saves 140 MB)
usable <  3.26 GB → host_not_qualified, named remedy: add RAM
```

The capability gate (F05) enforces whatever pre-flight measured, so a marginal host degrades to a
2-adapter site at commissioning time — visibly, with the upgrade path named — instead of OOMing on a
busy Saturday. The datasheet says **"up to 3 adapters"**, qualified by the measured host profile.

### Consequences

- The model bundle pipeline must produce a **single trunk with detection and age-band heads**, not
  two independent models. Joint training is now a hard requirement on the ML track.
- The trunk is one artifact but carries **two versions** in attestation (`model_bundle` and
  `age_gate_ver`) because they have different release approval paths (model bundle key vs. the
  age-gate's subgroup-metrics gate). The bundle manifest declares both.
- Decode is keyframe-only on L1, so `sampling_fps` on L1 is bounded by keyframe interval, not by the
  desired-state value. The capability gate clamps and reports the clamp.
- Bench (`t1-bench`) must measure real steady-state RSS on all three reference L1 configurations
  before the L1 datasheet is published. If measured total exceeds 3.30 GB, the fallback is the
  2-adapter profile via the measured cap — **not** a further shave of the privacy control set.

## Rejected

- **Option A as the primary answer** — publishing 2 adapters gives up the land motion's headline.
  Kept as an automatic, measured fallback instead.
- **Option C (single stream)** — halves the product.
- **Raising the L1 minimum to 8 GB RAM** — reconsider only if bench shows the 3.28 GB plan does not
  hold on real hosts. It would remove a large share of the addressable installed base.
