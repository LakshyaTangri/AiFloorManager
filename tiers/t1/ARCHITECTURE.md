# T1 — System and subsystem architecture (D8 / D9) as carried in this repository

**Document:** `/tiers/t1/ARCHITECTURE.md`
**Version:** 1.0
**Parent:** D7 AD-01 (locked), D8 system architecture, D9 subsystem architecture
**Applies to:** every module M01–M17 and every feature F01–F22

This file exists so that the module boundaries the code is written against are versioned with the
code. It records D8/D9 as approved; it does not restate D1–D6 and it does not modify any decision.
Where D8/D9 and the repository disagree, the disagreement is recorded in `/tiers/t1/PLAN.md` as an
architecture-decision request rather than resolved here.

## Locked boot invariant (AD-01)

```text
T1 bootloader ∈ T1 portable SSD
T1 bootloader ∉ customer internal SSD
```

The customer supplies compute, network and devices. The T1 portable NVMe supplies bootloader, OS,
runtime, models, configuration, state, analytics, audit, spool, logs, recovery and the local GUI.
The customer's internal disk is outside the T1 storage domain: T1 neither writes to it nor keeps
operational state on it, and pre-flight only ever reads from it.

## Subsystems and modules

| Subsystem | Modules | Owns |
|---|---|---|
| S01 Bootable device platform | M01 hardware/SSD, M02 boot and firmware, M03 T1 OS, M04 container runtime | The appliance itself: qualification, boot chain, rootfs slots, supervision |
| S02 Device connectivity | M05 camera/device connectivity, M06 network | Reaching customer devices; the credentials and adapters that do it |
| S03 Edge processing | M07 ingestion, M08 edge AI/vision, M09 edge analytics | Frames to detections to metrics, inside the privacy boundary |
| S04 Edge data | M10 local data and storage | Storage domains, retention, crypto-erase, spool substrate |
| S05 T1–T2 control | M11 P2P, M12 cloud connector, M13 device management, M14 OTA | Desired/reported state, the only outbound path, lifecycle |
| S06 Security and operations | M15 security, M16 observability | Identity, capability, policy, egress filter, audit, health |
| S07 Customer experience | M17 on-premise GUI | The local surfaces an on-site user is allowed to touch |

Modules are ownership boundaries. They do not imply one process or one container each; M08 in
particular is split by D-006 (below).

## Planes

```text
data     devices → connectivity → ingestion → decode → privacy → vision → analytics
                 → aggregation → audit → egress → spool → T2
control  T2 → cloud connector → device management → security → capability/policy gate
                 → OTA/runtime → T1 → reported state → T2
local    GUI → session → purpose → authorisation → capability → policy → audit → service
```

## Module ↔ feature ownership

| Module | Features owned | Notes |
|---|---|---|
| M01 hardware/SSD | F01 | Host qualification (L1) and site qualification (L2/L3) |
| M02 boot and firmware | F03 | Measured boot, A/B slots, rollback |
| M03 T1 OS | F03, F17 | Rootfs, kill switch enforcement point |
| M04 container runtime | F05, F07 | Sealed-process supervision, capability enforcement at launch |
| M05 camera/device | F02, F06 | Assessment, discovery, read-only credentials |
| M06 network | F06, F14 | Reachability, egress path, offline detection |
| M07 ingestion | F07 | Decode and cascade scheduling |
| M08 edge AI/vision | F08, F09 | **Sealed half** (trunk, age gate, redaction) and unsealed half (tracking) |
| M09 edge analytics | F11, F19 | Aggregation, k-anonymity, Edge Manager recommendations |
| M10 local data | F10, F16 | Zones/consent store, retention, crypto-erase |
| M11 P2P | F18 | Local sessions, no store access |
| M12 cloud connector | F12, F14 | The bridge: outbound-only, spool drain |
| M13 device management | F15, F21 | Desired/reported state, commissioning gate |
| M14 OTA | F03, F15 | Bundle verification, slot switch, rollback |
| M15 security | F04, F05, F12, F13, F17 | Identity, capability vector, egress filter, audit chain, kill switch |
| M16 observability | F20 | Health, budgets, counters |
| M17 on-premise GUI | F17, F22 | Local control surfaces |

F21 and F22 post-date the D8/D9 feature list (which enumerates F01–F20) and are mapped here to M13
and M17 respectively; see PLAN.md ADR-REQ-001.

## Boundaries that constrain module design

- **D-006 sealed pipeline.** Unredacted pixels, motion, the shared trunk, the age gate and
  redaction all execute inside one isolated process with no network namespace, no writable
  persistent path, no core dumps and no swap. M08 is therefore two components, not one, and the
  boundary types in `src/t1/contracts.py` are the contract between them.
- **Egress choke point.** Only M12's bridge speaks to T2, and only payloads that the M15 egress
  filter has accepted. Sealed-side code raises on any egress attempt.
- **Canon floors.** Policy may tighten k floors and may never lower them below canon, nor roll back
  below the highest version the device has enforced.
- **Storage domain.** All T1 persistence lives on the portable device. Nothing operational is
  written to customer media.
