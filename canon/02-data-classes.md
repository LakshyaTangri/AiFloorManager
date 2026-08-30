# Canon — data classes C0–C6

**Version:** 1.1
**Status:** Canon.

Every record produced by T1 belongs to exactly one class. The class determines the egress rule, the
lawful basis required, the retention ceiling, and which `trust_level` may emit it at all.

| Class | Contents | Egress | Basis required | Emitted by |
|---|---|---|---|---|
| **C0** Operational | Energy, refrigeration, HVAC, IAQ, lighting, water, doors, network, UPS, device health, `minor_suppression_rate`, `clock_skew_seconds`, weather, calendar | Free, 1 min or better | None — not personal data | L1, L2, L3 |
| **C1** Aggregate | Footfall, occupancy, passerby, group composition, repeat rate, zone flow, entry wait, `minor_suppressed_n` | Free once the floor is met | None once suppressed | L1, L2, L3 |
| **C2** Event | Queue, shelf gap, crowding, dwell anomaly, energy anomaly, refrigeration excursion, equipment fault, door held, after-hours, camera degraded, staff zone presence, derived Manager contracts | Purpose-bound | Notice | L1, L2, L3 |
| **C3** Trace | `visit_trace`, heatmap, `path_frequency`, abandonment, `browse_to_buy` — **adults only** | Purpose-bound, retention-capped | Notice + purpose | **L2, L3 only** |
| **C4** Identified | `employee_access`, `employee_attendance`, `employee_zone_time`, `desk_occupancy`, `room_usage`, `member_recognition`, `visitor_register` | Basis-gated | Consent or legitimate use, **per person** | **L2, L3 only** |
| **C5** Media | `event_clip`, `shelf_snapshot`, `checklist_photo` | **Reference only**; site-local unless per-clip export with purpose | Consent or documented legitimate use | L2, L3 (L1: none) |
| **C6** Prohibited | Minor tracking, emotion, health inference, protected-characteristic inference, productivity scoring | **Never generated** | — | none |

## C3 on RTL-L1 (D-008 §1)

L1 runs tracking because counting line crossings requires tracks. Those tracks are **transient
in-memory state**: L1 neither persists nor egresses C3. The egress filter refuses class C3 from a
`software_bound` device with `trust_level_forbids_class`. There is no C3 retention timer on L1
because there is nothing at rest to expire.

## Per-metric k floors (D-008 §3)

Defaults are canon. The signed policy bundle is authoritative at runtime and **may only raise** a
floor; a bundle that lowers one below canon is refused with `floor_below_canon`.

| Metric family | Default floor |
|---|---|
| Footfall, passerby, zone flow, entry wait | k ≥ 3 |
| Occupancy — corporate sector | k ≥ 10 |
| Dwell, and any duration-valued metric | k ≥ 20 |
| Group composition, repeat rate | k ≥ 3 |

A window below its floor is **suppressed and marked** `k_suppressed: true`. It is never emitted as a
zero — a zero is a claim about the world, and suppression is a claim about the method. Downstream
sums must remain consistent, so a suppressed window contributes nothing rather than contributing 0.

## Retention ceilings

| Class | L1 | L2 | L3 |
|---|---|---|---|
| C0, C1 | Spool only (7 d) | 30 d | 90 d |
| C2 | Spool only (7 d) | 30 d | 90 d |
| C3 | not persisted | 30 d | 90 d |
| C4 | never emitted | basis expiry | basis expiry |
| C5 | never emitted | clip policy | clip policy |

Retention is enforced by the retention enforcer, a system service that runs **independently of
application state** (C10). Expiry produces a deletion receipt in the audit chain.
