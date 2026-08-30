# D-008 — Seven review resolutions

**Status:** Resolved
**Owner:** T1 Agent
**Source:** T1 document review, 2026-08-30

Smaller corrections from the review of SPEC v3.0 / FEATURES v1.0 / LIFECYCLE v1.0. Each is small
enough not to warrant its own ADR, and each changes a document.

## 1. C3 on RTL-L1 — computed transiently, never persisted, never egressed

SPEC v3.0 §2 gave L1 a "C3 retention 7 d" while §12 said C3 is "L2/L3 only". Both statements were
in the same document.

**Resolved:** L1 runs S2 tracking (it needs tracks to count line crossings), so C3-shaped data
exists transiently in memory. L1 **does not persist and does not egress C3**. The §2 row becomes
"C3: not persisted (transient tracks only); spool 7 d". The egress filter refuses class C3 from a
`software_bound` device with `trust_level_forbids_class`, which is already a filter check — it just
needs the L1 row in the class permission table to say so. `C3 retention 7 d` survives only as the
retention enforcer's ceiling on L2's 30 d / L3's 90 d equivalents.

## 2. The minor-suppression metric is C0

F09 R4 requires per-site suppression-rate reporting with >2σ alerting, and §10 forbids "age or
gender as an analytic field". Both are right; the metric needed a class.

**Resolved:** `minor_suppression_rate` is **C0 operational** — a device health metric, not an
analytic. It is a ratio over a window, carries no per-person data, is not zone-resolved below the
site level, and is not available to T3's analytics surfaces or the Manager loop. The egress filter's
schema registry places it under `rtl.health.v1`, and the field allowlist for that schema does not
admit any age-valued field.

## 3. Per-metric k floors are canon, not a feature detail

SPEC §12 stated k≥3 flatly; F11 introduced k≥10 (corporate occupancy) and k≥20 (dwell). The floors
live in the signed policy bundle, so the SPEC must point at the bundle rather than restate a number.

**Resolved:** `canon/02-data-classes.md` carries the default floor table; the SPEC references it; the
policy bundle is authoritative at runtime and may only *raise* a floor relative to canon. A bundle
attempting to lower a floor below the canon default is refused with `floor_below_canon`.

| Metric family | Default floor |
|---|---|
| Footfall, passerby, zone flow, entry wait | k ≥ 3 |
| Occupancy — corporate sector | k ≥ 10 |
| Dwell, any duration-valued metric | k ≥ 20 |
| Group composition, repeat rate | k ≥ 3 |

## 4. Recommendation caps compose; the site cap wins

F19 R2 caps recommendations at 3 per site per day; the sample action library entry carries
`max_per_site_per_day: 1` per action.

**Resolved:** both apply, evaluated as an AND. The per-action cap limits repetition of one action;
the per-site cap of 3/day is a hard ceiling across all actions and is enforced by the Manager engine
scheduler, not by the library. A library that sums to more than 3 is valid — the scheduler selects
by confidence × expected impact and drops the rest, recording `recommendation_capped` so the
suppressed candidates are visible in outcome analysis.

## 5. F09 gains an AC for the model card's boundary error rate

SPEC §11 requires the measured boundary error rate to be documented in the model card; FEATURES v1.0
had no AC enforcing it, so nothing would have failed if it were missing.

**Resolved:** new AC on F09 — an age-gate bundle whose model card lacks a measured boundary error
rate for the 16–24 band is refused at artifact verification with `model_card_incomplete`. This makes
the documentation obligation a release gate rather than a convention.

## 6. Clock skew gets an AC

SPEC §15 requires buffering rather than publishing when NTP skew exceeds 5 minutes, with a local
alert. No feature carried it.

**Resolved:** added to F14 as R6 with an AC (skew > 5 min → aggregates buffer, `clock_skew` alert
raises, C0 health continues to publish so the fleet can see the problem), and to F20's health
metric set as `clock_skew_seconds`.

## 7. F10 moves to the pipeline track; two new features are registered

- **F10 (consent/zone service)** was in LIFECYCLE Track E, labelled "L2/L3 only". It is an
  all-profile container and gates prohibited zones on L1. It moves to **Track B, first position** —
  the prohibited-zone check is the first stage of the pipeline, so it must exist before F07.
- **F21 — Commissioning gate and Field Engineer workflow** (SPEC §18) and **F22 — Local control
  surfaces** (SPEC §17 "required control surfaces") had no feature IDs, therefore no acceptance
  criteria and no Security review, despite being referenced as blocking by F01, F02, F09 and F10.
  Both are now registered. F22 is a **Control-class** feature: a mode indicator that lies, or a
  missing k-suppressed notice, is a compliance defect, not a UI nit.
