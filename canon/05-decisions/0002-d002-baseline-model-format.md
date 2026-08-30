# D-002 — Baseline model format and size ceiling

**Status:** Resolved
**Owner:** ML Agent
**Blocks:** Manager engine container budget (L2/L3), Phase 6

## Decision

The baseline artifact is a **signed bundle** containing:

```
baseline-<sector>-<version>/
  manifest.json      version, sector, trained_until, feature list, signature over the tree
  seasonal.onnx      seasonal + trend component, ONNX opset 17, fp32
  regressors.json    coefficient table: weather, festival/holiday, promotion,
                     school term, trading hours — one block per zone×metric
  card.md            model card: coverage, error by zone class, known gaps
```

**Ceiling: 150 MB on disk, 200 MB resident** — inside SPEC §20's "must run in < 200 MB". The
coefficient table dominates and scales with zone×metric count, so the ceiling is enforced per site
at bundle-build time in T3, not merely at runtime: a site whose zone count would breach the ceiling
gets a coarser zone grouping and the grouping is recorded in the manifest.

Rationale for the split: the seasonal component benefits from ONNX Runtime (already resident for the
detector), while the regressors are a small, human-auditable table that must be inspectable during
an accuracy dispute. Shipping them as opaque tensors would make "why did the baseline expect 40
people" unanswerable.

Delivered via desired state as `baseline_model`, signed with the **model bundle key**, versioned in
every C2 Manager contract envelope. `budget-report` fails CI if the Manager engine container exceeds
its declared ceiling with a representative bundle loaded.
