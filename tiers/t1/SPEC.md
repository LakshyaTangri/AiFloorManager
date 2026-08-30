# T1 — Tangri Edge Platform

**Document:** `/tiers/t1/SPEC.md`
**Version:** 3.1
**Status:** Build baseline. Nothing here is frozen; changes go through `/canon/05-decisions/`
**Product:** Pulse — The AI Manager
**Sectors:** Retail, Corporate
**Jurisdiction:** India only (DPDP Act 2023 + DPDP Rules 2025)
**Supersedes:** T1 V3.0

---

## Reading order for agents

Load before any T1 task:

1. `/canon/03-controls.md` — the fourteen non-negotiables
2. `/canon/02-data-classes.md` — C0–C6
3. `/contracts/shared/envelope.yaml`, `/contracts/shared/capability-vector.yaml`
4. `/contracts/t1-t2/` — MQTT topics, shadow schema, job payloads
5. This document
6. `/tiers/t1/modules/{module}.md` for the specific task

Do not load T3 or T4 specs for a T1 task. Interface questions are answered by `/contracts`, not by reading another tier's implementation.

---

# 0. Position and mandate

T1 is Tangri's edge platform. It owns everything from silicon to local application on customer premises.

**Mandate:** T1 senses, decides and acts locally. T2 governs. Raw data stays at the edge; meaning and metadata go up.

T1 must remain fully operational when T2 is unreachable. No cloud failure degrades local function.

```
T5  COMMERCIAL & OPERATIONS
T4  EXPERIENCE
T3  SERVICES
T2  AWS CONTROL PLANE
T1  TANGRI EDGE PLATFORM   ← this document
        │
        │ MQTT/TLS 1.3 + HTTPS, outbound only, port 443
        ▼
    Customer site
```

## What changed from V3.0

All five open decisions are resolved and three review findings changed the architecture. Full
rationale in `/canon/05-decisions/`; this is the index.

| | V3.0 | V3.1 | ADR |
|---|---|---|---|
| RTL-L2 hardware | USB4 accelerator enclosure, compute = customer CPU + NPU | **System-on-Module**: own CPU, RAM, Wi-Fi, power. The PC is a peripheral | D-007 |
| L2 `trust_level` | `accelerator_attested` | **`module_attested`** — the L2→L3 gap is measured boot, not CPU ownership | D-007 |
| L2 identity | SSD serial + host DMI fingerprint | **SoM serial + SEC-1**; swapping the attached PC is not an identity event | D-007 |
| Pipeline order | Redact before S1 — unimplementable alongside the age gate | **Sealed pipeline process**; redaction boundary sits after the shared trunk and the age gate, before every process boundary | D-006 |
| L1 memory | 3.54 GB against 3.4 GB usable, unresolved | **3.28 GB**, shared trunk + keyframe decode + bounded spool cache | D-001 |
| L1 adapter cap | Fixed 3 | **Measured by pre-flight**: 3, or 2 on a marginal host, or refuse | D-001 |
| C3 on L1 | Stated both as "7 d retention" and "L2/L3 only" | **Transient tracks only; never persisted, never egressed** | D-008 |
| Open decisions | D-001…D-005 open | **All resolved** | §22 |

## What changed from V2

| | V2 | V3 |
|---|---|---|
| Purpose | Privacy-enforcing data pipeline | **AI Manager**: sense → baseline → detect → explain → recommend → measure |
| Age estimation | Forbidden | **Mandatory minor-suppression gate** |
| Recognition | Never | **L2/L3 entitlement-gated**; employees (legitimate use) and consented members only; never minors |
| Data classes | Tier A–D | **C0–C6** with `lawful_basis` and `retention_until` per record |
| k-anonymity | k = 10 | **k ≥ 3** |
| Aggregation | 15 min blanket floor | **Per-metric floors**; C0 operational at 1 min or better |
| New artifacts | — | **Action library**, **baseline model**, **age-gate model** |
| Install | Customer self-serve | **Field Engineer on-site**, signed off |

---

# 1. Layer model

```
L6  APPLICATION + LOCAL GUI
L5  CONTAINERS / EDGE RUNTIME
L4  YOCTO LINUX / KERNEL & DRIVERS
L3  BOOTLOADER
L2  FIRMWARE / TRUST
L1  HARDWARE
```

## Ownership

```
              RTL-L1        RTL-L2            RTL-L3
L6–L3        Tangri        Tangri            Tangri
L2           Client        Tangri (SEC-1)    Tangri
L1           Client        Tangri (SoM)      Tangri
```

Split ownership is an **L1-only** condition: only there does Tangri software run on hardware Tangri
does not own. It is the defining constraint of the land motion and the reason `trust_level` exists as
a first-class field. L2 and L3 are Tangri hardware; they differ in attestation depth, not ownership
(D-007).

---

# 2. Product profiles

| | RTL-L1 | RTL-L2 | RTL-L3 |
|---|---|---|---|
| Product | Boot Disk — SSD in a USB 3.0 UASP enclosure | System-on-Module on a Tangri carrier | Mini-PC appliance |
| Host | Customer PC (dedicated) boots from the Tangri SSD | **The SoM is the host.** An attached PC is optional, for local-UI access and optional power | Tangri hardware |
| Compute | Customer CPU | **SoM CPU + NPU-1** — no customer compute in the data path | CORE-X1 + NPU-1 |
| `trust_level` | `software_bound` | `module_attested` | `hardware_attested` |
| Streams | 2 | 4–6 | 8–16 |
| Adapters | **up to 3, measured by pre-flight** (D-001) | 8 | 12 |
| Normalised points | ~200 | ~1,000 | ~2,000 |
| C3 | **Not persisted** — transient tracks only (D-008) | 30 d | 90 d |
| Spool | 7 d | 30 d | 90 d |
| Local VLM/LLM | No (cloud) | SmolVLM2 or Qwen2.5-1.5B | Gemma-3-4B-it-QAT |
| P2P raw API | No | Yes | Yes |
| Recognition | **Never** | Entitlement-gated | Entitlement-gated |
| Baseline engine | Cloud (T3) | Local | Local |
| Manager engine | Cloud (T3) | Local | Local |
| Briefing generation | Cloud | Local or cloud | Local |
| Device BOM | $35–60 | $280–460 | $620–1,050 |
| Device price (INR) | ₹12,000 | ₹85,000 | ₹1,80,000 |

---

# 3. Layer 1 — Hardware

## 3.1 RTL-L1 — Boot Disk

| | Specification |
|---|---|
| Tangri supplies | 256 GB SATA SSD in USB 3.0 UASP enclosure, tamper-evident caddy, USB BLE dongle |
| Client supplies | **Dedicated** x86-64 PC: AVX2, ≥4 cores, 4 GB RAM, USB 3.0, boot-from-USB permitted, sleep/hibernate disabled, 65 W+ sustained |
| Storage layout | rootfs-A / rootfs-B / LUKS2 data / 8 GB append-only audit / spool |
| Swap | zram 512 MB, RAM-backed. **Swap on the boot SSD is prohibited** |
| Secure element | None. Host TPM used opportunistically if present |
| Kill switch | Software only, disclosed as such in the UI |
| Network | Client NIC / Wi-Fi |
| Power | From client PC USB |

### Hard ceiling — enforced locally by the capability gate

```
MAX      2 camera streams, keyframe-sampled
         3 adapters  — or 2, per measured usable RAM (D-001)
         ~200 normalised points
         CPU inference only
         7-day spool

FORBIDDEN
         Face recognition (any purpose)
         P2P raw API
         Resident VLM/LLM
         C3 persistence and C3 egress   (transient tracks only)
         C4 and C5 emission
         Read-write device credentials  (D-004)
         Raw video persistence
```

The client PC must be dedicated. A shared 4 GB host cannot run this stack alongside customer workloads; the pre-flight checker must detect and refuse.

## 3.2 RTL-L2 — System-on-Module

A Tangri System-on-Module on a Tangri carrier board. **The module is the host** — it brings its own
processor, memory, radios and power. See D-007.

| | Specification |
|---|---|
| Compute | SoM x86-64 or arm64, ≥4 cores, **8 GB LPDDR5 module RAM** |
| NPU | 13–26 TOPS, ≥8 GB accessible module memory |
| Storage | 1 TB NVMe on the carrier (site data node) |
| Security | SEC-1 secure element — the hardware trust anchor; LUKS sealed to SEC-1 |
| Network | 1× GbE + Wi-Fi 6; optional second NIC for a camera VLAN |
| Radio | 2× USB 3.0 host ports for Zigbee / Z-Wave / LoRa dongles |
| Power | 12 V DC, PoE variant available |
| Attached PC | **Optional.** Local-UI browser access and optional power only. Never a data path for camera streams |

**Interface decision (revised).** V3.0 argued "USB4, not M.2" for an accelerator that plugged into a
customer PC's compute path. A SoM does not. The remaining question was the carrier, resolved above:
self-powered, self-networked, with the PC reduced to an optional convenience. "Works with any PC" is
still true and now trivially so — the product does not depend on the PC at all.

Because the customer PC is out of the data path, the 4 GB host ceiling, the dedicated-host
requirement and the host health monitor are **L1-only** concerns.

## 3.3 RTL-L3 — Full Appliance

```
CORE-X1 x86, 32 GB DDR5
NPU-1, 26 TOPS, ≥8 GB module memory
2 TB NVMe
SEC-1 + TPM 2.0
2× GbE + 4× PoE PSE
Wi-Fi 6 / BLE
TX-40 expansion (DB-OCC, DB-ENV)
Hardware camera kill switch (DI input)
ENC-B slim wall/shelf, fanless
PoE++ or 12 V
```

First fully Tangri-controlled platform in the retail line. Built through the standard route: Vietnam EMS (black module) → India EMS (grey box) → Punjab (sector configuration, identity, image, burn-in, QA).

---

# 4. Layer 2 — Firmware and trust

```
RTL-L1   Client UEFI → MS-signed Tangri shim → opportunistic measurement
         identity = SSD controller serial + host DMI fingerprint
         → trust_level = software_bound

RTL-L2   SoM firmware → signed bootloader → SEC-1 self-attestation
         identity = SoM serial + SEC-1 device identity
         (the attached PC contributes nothing to identity)
         → trust_level = module_attested

RTL-L3   Tangri UEFI → Secure Boot (Tangri PK/KEK/db, MS key removed)
         → SEC-1 + TPM 2.0 → measured boot PCR 0–7
         fuses blown at Punjab provisioning
         → trust_level = hardware_attested
```

## Attestation scope

Every boot report includes:

```
os_version, bootloader_slot
privacy_set_version
egress_policy_version
model_bundle_hash
age_gate_model_version
action_library_version
consent_service_version
capability_vector
```

## Required host settings (L1 only)

Boot from USB enabled · boot order set or one-time key documented · sleep and hibernate disabled · virtualization on · Secure Boot on or off both supported.

L2 has no host-settings requirement: it does not boot from, or execute on, the customer's PC.

Tangri cannot update client firmware. The pre-flight checker verifies and reports; the Field Engineer configures during install.

## Anti-clone enrolment

**L1.** First boot derives an identity from SSD controller serial + host DMI fingerprint, requests one certificate, and T2 refuses any second enrolment for that disk. A host fingerprint change moves the device to `RE_ENROLMENT_PENDING` requiring human approval — never automatic trust restoration.

**L2/L3.** Identity is rooted in SEC-1 (plus TPM on L3) and is not derived from any customer hardware. Swapping or removing the attached PC is **not** an identity event and must not halt the site (D-007). A second enrolment for the same SEC-1 identity is refused exactly as on L1.

**AWS IoT certificate authentication establishes communication identity. It does not confer `trust_level`.** These are separate concepts and must not be conflated in code.

---

# 5. Layer 3 — Bootloader

## Chain

```
L1 / L2   Client UEFI → Tangri shim (MS UEFI CA signed) → GRUB2
          → signed kernel → signed initramfs → Tangri OS
          All on the Tangri USB SSD. Client internal disk untouched.

L3        Tangri UEFI → shim → GRUB2 → signed kernel → signed initramfs
```

## Requirements

| | |
|---|---|
| A/B slots | rootfs A/B, boot counter, automatic rollback after 3 failed health checks |
| Privacy-set verification | Signature checked **before app containers start**. Failure → ingest-only mode, bridge disabled |
| Audit partition | Mounted append-only before any service starts; survives rootfs rollback |
| Disk unlock (L1) | LUKS key wrapped by the enrolment key, stored on disk. **No TPM — a stolen disk is attackable.** Mitigated by holding no video and no raw data at rest |
| Disk unlock (L2) | LUKS key sealed to the SoM's SEC-1 |
| Disk unlock (L3) | LUKS key sealed to TPM PCRs |
| Hardware probe | initramfs enumerates the unknown host, selects profile from detected RAM, aborts with a named remedy if below minimum |
| Fallback | Bootable USB stick chainloads the SSD if the host will not boot USB directly |
| Recovery | Re-image from signed image; disk is field-replaceable |

## Pre-flight checker

Runs from initramfs and as a standalone live USB used by the Field Engineer before install.

Probes: CPU, AVX2, cores, RAM, NIC, USB, GPU/NPU, storage, boot mode, virtualization, sleep state.

**Plus camera assessment** — per-stream scoring for counting suitability: angle, resolution, lighting, occlusion, frame rate.

Output:

```json
{
  "host_profile": "dedicated_4gb",
  "usable_ram_mb": 3452,
  "adapter_cap": 3,
  "stream_cap": 2,
  "trust_level": "software_bound",
  "camera_scores": [
    { "stream": "cam1", "counting_score": 0.82, "issues": [] },
    { "stream": "cam3", "counting_score": 0.31, "issues": ["angle_too_shallow", "backlit"] }
  ]
}
```

`adapter_cap` is **derived from measured usable RAM**, not published as a constant (D-001):

```
usable ≥ 3.40 GB  → adapter_cap 3, stream_cap 2
usable ≥ 3.26 GB  → adapter_cap 2, stream_cap 2     remedy: add RAM for the third adapter
usable <  3.26 GB → host_not_qualified               remedy: add RAM
```

The signed `host_profile` is what the capability gate enforces for the life of the install, so a
marginal host becomes a visibly 2-adapter site at commissioning rather than an OOM on a busy
Saturday. The datasheet says "up to 3 adapters".

The camera assessment is contractually significant: it is the accuracy basis referenced in the no-refund terms. A stream scoring below threshold must be either repositioned or excluded from the accuracy commitment, and the Field Engineer records which.

---

# 6. Layer 4 — Tangri OS

| | |
|---|---|
| Distribution | Yocto (Scarthgap LTS) |
| Kernel | Linux 6.6 LTS, hardened |
| BSP | Generic x86-64 (L1/L2) — wide driver payload for unknown hosts. Fixed BSP (L3) |
| Root filesystem | Read-only squashfs + overlayfs + dm-verity |
| Encryption | LUKS2 on data partition |
| Init | systemd; **no shell in production images** |
| Partitions | rootfs A/B · data (LUKS2) · audit (append-only) · spool |

## System services

Device identity agent (mTLS to AWS IoT) · RAUC OTA client (delta, staged) · health and telemetry agent · TPM/SEC-1 credential vault · audit logger · **retention enforcer** (runs independent of app state) · **crypto-erase service** (deletion receipts) · hardware watchdog · NTP · **host health monitor** (L1/L2: thermal throttling, memory pressure, disk removal, competing workload detection).

## Drivers

Generic ethernet and Wi-Fi families · USB 3.0 / UASP · V4L2 + VA-API/QSV with software-decode fallback · BlueZ · USB dongles (Zigbee, Z-Wave, LoRa) · L2: USB4/Thunderbolt authorization, NPU kernel driver · L3: PoE PSE controller, IIO for TX-40 daughterboards.

## Networking

Dual/triple NIC where present, hard VLAN separation, nftables default-deny, no IP forwarding between camera and IT interfaces. Only the bridge agent may egress to Tangri infrastructure; all other containers are dropped by policy.

---

# 7. Memory budget — RTL-L1

The tightest constraint in the product. 4 GB dedicated host, ~3.4 GB usable after kernel.

| Component | v3.0 | **v3.1 ceiling** |
|---|---|---|
| Kernel + Tangri OS | 500 | 500 MB |
| containerd + supervisor | 350 | 350 MB |
| Privacy control set | 550 | 550 MB |
| Cascade orchestrator + bridge agent | 250 | 250 MB |
| Discovery + normalization | 250 | 250 MB |
| Adapters ×3 | 420 | 420 MB |
| **Shared trunk** (detector + age head) + ONNX Runtime | 520 | **440 MB** |
| Decode ×2, **keyframe-only, pinned pre-allocated buffers** | 500 | **360 MB** |
| SQLite spool, page cache capped 32 MB, WAL bounded | 200 | **160 MB** |
| **Total** | 3 540 | **3 280 MB** |

## D-001 — RESOLVED

V3.0 left 3.54 GB against ~3.4 GB usable and recommended option B (shared trunk, −80 MB), which does
not close the gap: 3.46 GB is still over usable and well over the 3.30 GB refactor trigger that
exists to preserve 100 MB of headroom.

Resolved as **B plus two further reductions plus a measured adapter cap** — see
`/canon/05-decisions/0001-d001-shared-trunk-and-l1-budget.md`. The result is 3.28 GB with ~120 MB
headroom, and a marginal host degrades to 2 adapters at pre-flight instead of failing in the field.

The two obligations this creates:

1. The model bundle pipeline produces **one trunk with detection and age-band heads**, jointly
   trained. The bundle manifest declares both `model_bundle` and `age_gate_ver`, which have
   different release approval paths.
2. `t1-bench` measures real steady-state RSS on all three reference L1 configurations before the L1
   datasheet is published. If the measurement exceeds 3.30 GB, the answer is the 2-adapter measured
   profile — **never** a shave of the privacy control set.

## Enforcement, whichever option is chosen

Hard per-container cgroup ceilings, not a shared pool. Decode buffers pre-allocated and pinned. Keyframe-only sampling at L1. The adapter namespace OOM-kills within itself rather than taking down the inference session.

---

# 8. Layer 5 — Edge runtime

```
┌────────────────────────────────────────────────┐
│           TANGRI EDGE RUNTIME                  │
│                                                │
│  Device identity          Local event bus      │
│  Configuration            Service supervisor   │
│  Capability gate          Health               │
│  Policy engine            Local API            │
│  Spool                    OTA agent            │
│  AWS communication adapter                     │
│  Manager loop scheduler                        │
└────────────────────────────────────────────────┘
```

Applications never manage AWS connectivity directly. All egress passes the bridge agent; the bridge agent cannot bypass the egress filter.

## Container runtime

| | L1 | L2 | L3 |
|---|---|---|---|
| Runtime | containerd + Tangri supervisor | containerd + supervisor | k3s single node |
| Registry | Local cache, cosign-verified | + local registry | + GitOps agent |
| Data services | SQLite buffer + spool | TimescaleDB, MQTT broker, local API | + NATS JetStream, MinIO |

## Container set

| Container | L1 | L2 | L3 |
|---|---|---|---|
| Discovery engine | ● | ● | ● |
| Normalization | ● | ● | ● |
| **Redactor** | ● | ● | ● |
| **Egress filter** | ● | ● | ● |
| **Consent / zone service** | ● | ● | ● |
| **Audit chain** | ● | ● | ● |
| Cascade orchestrator | ● | ● | ● |
| Bridge agent | ● | ● | ● |
| Inference server (ONNX Runtime) | ● CPU | ● NPU | ● NPU |
| Decode pipeline | ● 2 | ● 4–6 | ● 8–16 |
| **Age gate** | ● | ● | ● |
| Host health monitor (L1 only — D-007) | ● | — | — |
| Adapters | any 3 | 8 | 12 |
| **Baseline engine** | — | ● | ● |
| **Manager engine** | — | ● | ● |
| Model gateway client | — | ● | ● |
| P2P service | — | ● | ● |
| Local VLM/LLM | — | ● one | ● |
| Rules / workflow engine | — | ○ | ● |

The four privacy containers deploy as a **privacy control set** with their own signing key and their own release approval path, separate from the application release train. This separation is the control.

---

# 9. Adapters

Plug-ins, not application logic. Hot-loadable, signed, delivered from T2's driver registry.

```
              Adapter Manager
                    │
    ┌───────┬───────┼───────┬───────┐
  ONVIF   MQTT   BACnet   SNMP    POS
  RTSP            /IP            webhook
```

## V1 priority

1. ONVIF / RTSP
2. MQTT
3. POS webhook
4. BACnet/IP
5. SNMP
6. BLE
7. Modbus TCP
8. NVR/VMS re-stream (L2/L3)

L2/L3 additionally: RFID/LLRP, Zigbee, Z-Wave, BACnet MS/TP, DLMS, access control.

**L1 supports any three**, chosen at commissioning. The orchestrator refuses a fourth with a named reason and the upgrade path. No override — the failure mode is a box that works for a week then OOMs on a busy Saturday.

## Discovery

Passive first: mDNS/DNS-SD, SSDP/WS-Discovery, ARP, DHCP observation, BACnet Who-Is, MQTT topic scan. Active probing (ONVIF probe, Modbus unit-ID sweep, SNMP sysDescr) is opt-in, rate-limited, with a do-not-probe list.

Fingerprint → proposed driver with confidence → Field Engineer confirms and maps. Unmatched fingerprints and manual mappings return to T2 as metadata, growing the point-map library. Every install makes the next one faster.

## Credentials

Entered by the customer's IT into the box's local UI, stored in the TPM/SEC-1 sealed vault, **never synced to T2**, never visible to Tangri staff or agents. Read-only accounts requested wherever possible. Every use logged to the audit chain.

---

# 10. AI execution

```
              Tangri AI Engine
                     │
               ONNX Runtime
        ┌────────────┼────────────┐
       CPU        NPU/GPU       Cloud (via T2 Model Gateway)
```

## Cascade

| | S1 detector | Age head | S2 | S3 local | S4 |
|---|---|---|---|---|---|
| L1 | YOLOX-tiny trunk, CPU, keyframe-sampled 2–5 FPS | shared head on the same trunk | ByteTrack (transient — no C3 at rest) | none | cloud |
| L2 | RF-DETR-N/S trunk on NPU | shared head | ByteTrack + zone logic | SmolVLM2 / Qwen2.5-1.5B | cloud |
| L3 | RF-DETR-S trunk on NPU | shared head | full, dwell, heatmap | Gemma-3-4B-it-QAT | rare |

One trunk, two heads, **one forward pass on unredacted pixels inside the sealed process** (D-006).
Detection and age band are produced together; the age band is consumed by the gate and never
crosses the redaction boundary.

Stage gating: S0 motion → S1 only on change → S2 only on class of interest → S3 only on unresolved or low-confidence S2. Rate-limited. Decode capacity, not TOPS, is the binding constraint — publish stream counts, not TOPS, in datasheets.

## Face

| | Detection (AuraFace) | Recognition (AuraFace) |
|---|---|---|
| L1 | Redaction only | **Never** |
| L2 / L3 | Redaction only | Entitlement-gated |

Recognition requires: signed entitlement bundle from T2 **and** a live consent or legitimate-use record per enrolled person. Permitted subjects: employees (legitimate use — loss and liability protection), consented loyalty members, registered visitors. **Never** minors, never non-consenting public. Templates never leave the box. Withdrawal deletes template and derived records within 24 h with a signed receipt.

## Not shipped in any bundle

Age or gender as an analytic field · emotion or sentiment inference · cross-visit re-identification of non-consenting persons · staff-vs-customer classification · staff productivity scoring · any inference about health, caste, religion or disability.

The age head is a **gate**, not an analytic: its output is consumed inside the sealed process and
never crosses the redaction boundary. The only age-derived value that ever leaves the box is
`minor_suppression_rate`, a site-level C0 health ratio with no per-person content (D-008 §2).

---

# 11. Privacy pipeline

Mandatory order. No stage may be skipped or reordered.

V3.0 placed redaction before detection, which cannot be implemented alongside a face-based age gate
— the gate would be estimating age from pixels that had already been destroyed. Resolved by D-006:
the unredacted region of the pipeline is an explicit, sealed process that **can neither store nor
transmit**, and the redaction boundary sits at its edge.

```
=== SEALED PIPELINE PROCESS ==================================
    no network namespace . no writable persistent path
    frames in anonymous memory only . zeroed on release

    CAPTURE (decode)
      | prohibited-zone check  changing rooms, toilets, prayer
      |                        rooms, any zone declared prohibited
      |                        -- refuse instantiation
      | S0 motion
      | S1 SHARED TRUNK        detections + age bands, one pass
      | AGE GATE               estimated under 22 -> the detection
      |                        is dropped before it can become a
      |                        track; counted only as
      |                        minor_suppressed_n in C1
      | REDACT                 faces and text, irreversible
==============================================================
      |  THE REDACTION BOUNDARY
      |  crossing it: redacted frames, and detections carrying a
      |  boolean age_gate_passed -- never an age value
   S2 tracking                adults only
   ↓ C3 local store           L2/L3 only; retention timer runs
   ↓                          independent of application state
   ↓ S3 VLM/LLM               structured context; redacted crop only
   ↓ enum mapping             bounded output, no free text
   ↓ per-metric floor, k ≥ 3 suppression
   ↓ EGRESS FILTER            fails closed
   ↓ BRIDGE AGENT
   ↓ AWS
```

**Rule 1:** No raw personal visual information reaches T2 by any path.
**Rule 2:** No person estimated under 22 enters C3 or C4 by any path.

Both rules are now structural rather than procedural: Rule 1 because the only process that ever
holds raw pixels has no route out, and Rule 2 because suppression happens on detections, before any
of them can become a track.

The under-22 threshold is deliberately conservative — four years above DPDP's definition of a minor.
Age estimation is unreliable at boundaries and a false negative here is a prohibited-processing
event. The measured boundary error rate for the 16–24 band **must** be documented in the model card,
and this is a release gate rather than a convention: a bundle whose card lacks it is refused at
artifact verification with `model_card_incomplete` (D-008 §5).

The consent/zone service refuses to instantiate a stream mapped to a prohibited zone and logs the refusal.

---

# 12. Data classes

| Class | Contents | Egress | Basis required |
|---|---|---|---|
| **C0** Operational | Energy, refrigeration, HVAC, IAQ, lighting, water, doors, network, UPS, device health, weather, calendar | Free, 1 min or better | None (not personal data) |
| **C1** Aggregate | Footfall, occupancy, passerby, group composition, repeat rate, zone flow, entry wait — k ≥ 3 | Free | None once suppressed |
| **C2** Event | Queue, shelf gap, crowding, dwell anomaly, energy anomaly, refrigeration excursion, equipment fault, door held, after-hours, camera degraded, staff zone presence, **derived Manager contracts** | Purpose-bound | Notice |
| **C3** Trace | visit_trace, heatmap, path_frequency, abandonment, browse_to_buy — **adults only** | Purpose-bound, retention-capped, L2/L3 only | Notice + purpose |
| **C4** Identified | employee_access, employee_attendance, employee_zone_time, desk_occupancy, room_usage, member_recognition, visitor_register | Basis-gated, L2/L3 only | Consent or legitimate use, per person |
| **C5** Media | event_clip, shelf_snapshot, checklist_photo | **Reference only**; site-local unless per-clip export with purpose | Consent or documented legitimate use |
| **C6** Prohibited | Minor tracking, emotion, health inference, protected-characteristic inference, productivity scoring | **Never generated** | — |

Canonical definitions, per-metric k floors and retention ceilings live in
`/canon/02-data-classes.md`, which is authoritative. Two profile-specific rules:

- **C3 is L2/L3 only.** L1 tracks in memory to count line crossings but neither persists nor
  egresses C3; the filter refuses class C3 from a `software_bound` device with
  `trust_level_forbids_class` (D-008 §1).
- **C4 and C5 are L2/L3 only**, and C4 additionally requires a live per-person basis.

---

# 13. Egress filter

Own container, own signing key, own release approval. Fails closed.

```
boot
  → policy bundle signature verified against the privacy policy key
  → bundle version ≥ the monotonic policy floor in the audit partition
  → every per-metric floor ≥ the canon default          (floor_below_canon)

message
  → schema lookup (must exist in local registry)
  → class assignment
  → field allowlist for class + schema version
  → free-text rejection (by type, not content inspection)
  → aggregation floor check (per-metric, from the bundle)
  → k suppression at the metric's floor, minimum 3
  → lawful_basis present and valid for class
  → retention_until set
  → trust_level permits this class                      (C3/C4/C5 refused on L1)
  → entitlement permits this capability
  → payload size cap (no blobs, no base64 media)
  → append to hash-chained audit log
  → spool → bridge
```

The monotonic policy floor (D-003) is why an OS rollback cannot reinstate a looser filter: the
highest policy version ever enforced is recorded in the audit partition, which survives rootfs
rollback, and a lower bundle is refused with `policy_downgrade`.

Rejections are counted and reported as a health metric so a schema mismatch surfaces on the fleet dashboard rather than silently dropping data.

**An unparseable policy bundle disables the bridge and leaves local ingest running.** Never fail open.

## Message envelope

```json
{
  "device_id": "01J...",
  "boot_id": "uuid",
  "seq": 184223,
  "device_time": "2026-08-29T09:14:22.331Z",
  "schema": "rtl.event.v1",
  "class": "C2",
  "purpose": "operations",
  "lawful_basis": "notice.public_space",
  "basis_ref": "policy:acme-retail/2026-08/v1",
  "trust_level": "software_bound",
  "host_profile": "dedicated_4gb",
  "privacy_set_version": "pcs-2026.08.1",
  "policy_version": "egress-rtl-2026.08.1",
  "model_bundle": "sha256:...",
  "age_gate_ver": "1.2",
  "action_library_ver": "3.1",
  "confidence": 0.91,
  "action_threshold": 0.85,
  "retention_until": "2028-08-29",
  "payload": {}
}
```

`boot_id` + `seq` gives exactly-once semantics without server-side dedup tables. `policy_version` on every message is what lets T2 prove which filter was in force when a record was produced.

---

# 14. The AI Manager loop

Runs on L2/L3. L1 sends aggregates up; T3 computes the loop in cloud and returns the briefing.

```
SENSE       camera counts · POS · energy · IAQ · refrigeration
            · weather · calendar_context
   ↓
BASELINE    per zone, per metric, per day-of-week, per hour
            regressors: weather, festival/holiday, promotion,
            school term, trading hours
   ↓
DETECT      deviation with sigma, direction, persistence
   ↓
EXPLAIN     VLM/LLM over STRUCTURED CONTEXT ONLY
            output → bounded cause_enum + contributing_factors[]
   ↓
RECOMMEND   select and parameterise from the signed ACTION LIBRARY
            never free generation
   ↓
TASK        into the local workflow engine, assigned, SLA'd
   ↓
MEASURE     action_outcome → feeds the baseline
```

## Action library

Signed, versioned artifact delivered like a model bundle.

```yaml
library_version: 3.1
actions:
  - id: open_additional_till
    trigger:
      metric: queue.breach_count
      window: 5d
      threshold: 3
    params: [till_group, start_time, end_time]
    expected_impact: wait_time_reduction_pct
    confidence_floor: 0.7
    max_per_site_per_day: 1
    purpose: operations
```

## Constraints — enforced in code, not documentation

- Explanation output schema has **no free-text field**. `cause_enum` + `contributing_factors[]` only. The LLM physically cannot emit a person description.
- Recommendations come from the signed library. Selection and parameterisation only.
- **Maximum 3 recommendations per site per day.** A manager who receives fifteen ignores all of them.
- Every recommendation carries confidence, evidence references and expected impact.
- The measure step is mandatory. Without `action_outcome`, Pulse is an advisor, not a manager.

---

# 15. T1 ↔ T2

| | |
|---|---|
| Primary | MQTT 5 over TLS 1.3, port 443, ALPN `x-amzn-mqtt-ca` |
| Secondary | HTTPS 443 for artifacts and bulk backfill |
| Direction | **Device-initiated, outbound only. No inbound firewall rule, ever** |
| Auth | Mutual TLS, X.509 from Tangri Device CA; key in SEC-1/TPM, non-exportable (L3/L2) or enrolment-bound (L1) |
| Server cert | Pinned to Tangri Service CA. Public roots not trusted for these endpoints |
| Proxy | Honours customer HTTP proxy with auth |

TLS-inspecting proxies must allowlist the Tangri hostnames for passthrough. This is an IT ask documented on the commissioning firewall sheet, not a reason to accept a customer CA.

## Endpoints

```
mqtts://iot.pulsemanager.ai:443      control, state, telemetry, events
https://artifacts.pulsemanager.ai    signed artifacts
https://ingest.pulsemanager.ai       bulk aggregate, backfill
https://enrol.pulsemanager.ai        one-time enrolment
https://pki.pulsemanager.ai          CRL / OCSP
```

## Channels

| Channel | Direction | QoS | Rate |
|---|---|---|---|
| C1 Identity | ↑↓ | 1 | Rare — enrol, renew, attest, revoke check |
| C2 State | ↕ | 1 | Poll 15 min; report on change |
| C3 Telemetry | ↑ | 0 | 5 min |
| C4 Events + aggregates | ↑ | 1 | Events on occurrence; aggregates per floor |
| C5 Artifacts | ↓ | HTTPS | On desired-state change only |

## Desired state and convergence

AWS IoT Device Shadow carries the contract; Tangri owns the semantics.

```json
{
  "desired": {
    "edge_runtime": "2.1.4",
    "container_set": "rtl-l2-2026.08",
    "adapters": ["onvif", "mqtt", "pos_webhook"],
    "models": {
      "detector": "rf-detr-s-v3",
      "age_gate": "agegate-1.2",
      "vlm": "smolvlm2-q4"
    },
    "action_library": "3.1",
    "baseline_model": "rtl-baseline-2.0",
    "privacy_policy": "egress-rtl-2026.08.1",
    "entitlements": ["dwell", "heatmap", "shelf"],
    "recognition": false,
    "retention": { "c3_days": 30 },
    "sampling_fps": 5
  }
}
```

Delta → **capability gate** → **policy gate** → apply or reject with a named reason → reported state.

The capability gate is defence in depth. T2 validates at plan time and refuses to write an invalid shadow; T1 validates again on receipt. A compromised or misconfigured T2 must not be able to exceed a device's declared physical capability.

## OTA

AWS IoT Jobs orchestrates; RAUC executes locally.

```
IoT Job → OTA agent → RAUC → inactive slot → verify → reboot
        → post-boot health check → commit or automatic rollback
```

Every bundle signed. Delta updates. Staged rollout in rings, orchestrated by T2.

## Offline

| | L1 | L2 | L3 |
|---|---|---|---|
| Spool | 7 d | 30 d | 90 d |

Priority on overflow: **safety and security events → refrigeration excursions → operational events → aggregates → health.** Aggregates coarsen before anything drops. Health drops first.

Reconnect: exponential backoff 1 s → 15 min, **with per-device jitter derived from a hash of device_id**. Without jitter, a fleet-wide reconnect after an AWS blip is a self-inflicted denial of service.

Backfill: separate endpoint, rate-limited, marked `backfill: true` with original timestamps, routed to a distinct ingest queue.

**No raw video backlog is ever created by a T2 outage.** This is the central L1 security argument and it holds at every tier.

## Clock

Every message carries `device_time` and `boot_id`; T2 stamps `server_time` and records skew. NTP sync required; skew > 5 min → buffer rather than publish aggregates, raise a local alert. A box with a dead RTC and no NTP is a data-integrity incident.

## Certificate lifecycle

1-year lifetime, auto-renewal at 75%. Offline past expiry: a 90-day grace window permits one renewal handshake subject to attestation passing. Beyond grace: re-enrolment with human approval. Revoked: device refuses to run signed workloads on next boot.

---

# 16. Signing domains

```
Tangri Root CA (offline, HSM, ceremony-only)
 ├── OS signing key
 ├── Privacy policy key       two-person approval; tightening ships fast,
 │                            loosening ships slow and fully audited
 ├── Model bundle key         requires subgroup metrics to release
 ├── Action library key       product lead + SaaS QA
 └── Entitlement key          recognition gate lives here
```

**A valid OS signature authorises nothing else.** Four keys, four approval paths. The privacy-set key must not be usable by the application release pipeline.

---

# 17. Layer 6 — Local application and GUI

## Stack

React + TypeScript · Vite · Tailwind CSS · shadcn/ui · TanStack Router · TanStack Query · TanStack Table · Apache ECharts · React Hook Form + Zod · Zustand.

One codebase, two build variants (`SECTOR=retail|corporate`). Served by the box over mTLS on the LAN. Talks only to the box's local T3 API — a lint rule fails any absolute URL.

## Screens

| | L1 | L2 / L3 |
|---|---|---|
| Commissioning | ● | ● |
| Camera discovery, mapping, assessment scores | ● | ● |
| Zone drawing with legal basis per zone | ● | ● |
| Credentials, network, device health | ● | ● |
| **Privacy**: consent map, kill switch, audit viewer, notice status, minor-suppression stats | ● | ● |
| Briefing view | ● (cloud-generated) | ● (local) |
| Dashboard, analytics, alerts, operations | — | ● |
| Live view (P2P) | — | ● |
| AI assistant with local tools | — | ● |
| Recommendation and outcome tracking | — | ● |

## Required control surfaces

Mode indicator · confidence badge with action threshold · k-suppressed notice · data-quality banner · camera health chip · consent-zone map · kill switch (disclosed as software-only on L1) · audit viewer · notice status · minor-suppression statistic · trust-level chip (on `software_bound`, expanding to the D-004 disclosure).

These are **controls, not chrome** — a mode indicator that lies is a compliance defect. They are
specified as feature **F22**, which carries acceptance criteria and a Security review like any other
control feature (D-008 §7).

Offline is the normal case. Service worker for the shell. Every screen renders from the local API with no WAN.

---

# 18. Commissioning gate

Performed by the Tangri Field Engineer on site. Activation is blocked until every step passes.

```
Pre-flight passed (host qualified)
   ↓ Camera assessment scored and accepted
   ↓ Identity enrolled
   ↓ Cameras discovered and mapped
   ↓ Zones configured with legal basis per zone
   ↓ Privacy policy installed and verified
   ↓ AGE GATE VERIFIED OPERATIONAL
   ↓ SIGNAGE PLACED AND PHOTOGRAPHED  (English / हिन्दी / ਪੰਜਾਬੀ, QR notice live)
   ↓ Egress policy validated
   ↓ Health check passed
   ↓ Field Engineer sign-off
   ↓ ACTIVE
```

**No signage, no activation. No working age gate, no activation.**

Signage evidence is a photograph in the TG_CMS job record, not a checkbox. The Field Engineer's signed camera assessment is the accuracy basis referenced in the contract.

Installer credentials are time-boxed, commissioning-only, generated per job in TG_CMS, expiring at sign-off. Never a standing account.

---

# 19. Device lifecycle

```
MANUFACTURED → SHIPPED → ENROLLING → COMMISSIONING → ACTIVE
                                                       ↓
                    DEGRADED ← → STALE ← → SUSPENDED ← ┘
                                                       ↓
                                           REVOKED / RMA → RETIRED
```

| State | Trigger | Behaviour |
|---|---|---|
| Enrolling | First boot at site | One-time enrolment; clone rejected |
| Commissioning | Enrolled, gate incomplete | No data egress; local UI only |
| Active | Gate passed | Full function |
| Degraded | Health thresholds breached | Reports, keeps functioning |
| Stale | No heartbeat > 7 d | Flagged; app shows last-sync |
| Suspended | Non-payment or customer request | **Local sensing continues**; cloud read-only; no ingest |
| `RE_ENROLMENT_PENDING` | **L1** host fingerprint changed (L2/L3 identity is SEC-1-rooted — D-007) | Stops, waits for human approval |
| Revoked | Theft, clone, termination | Cert revoked; refuses signed workloads next boot |
| RMA | Return | Identity retired, twin unlinked, crypto-erase, receipt issued |

**Suspension must never brick hardware the customer owns.** It stops the service; the device keeps running locally.

---

# 20. Technology stack

| Domain | Choice |
|---|---|
| OS | Yocto Scarthgap |
| Kernel | Linux 6.6 LTS, hardened |
| Boot | UEFI + MS-signed shim + GRUB2, Secure Boot, dm-verity |
| Filesystem | squashfs + overlayfs |
| Encryption | LUKS2; SED OPAL where fitted |
| Container runtime | containerd + Tangri Edge Supervisor (L1/L2); k3s (L3) |
| AI runtime | ONNX Runtime |
| Computer vision | OpenCV, GStreamer |
| Detection | YOLOX-tiny (CPU), RF-DETR-N/S (NPU) |
| Tracking | ByteTrack |
| Face | AuraFace (detect + recognise) |
| Age gate | Shared trunk head, joint-trained with the detector (D-001) |
| VLM | SmolVLM2 (L2), Gemma-3-4B-it-QAT (L3) |
| LLM | Qwen2.5-1.5B-Instruct |
| Baseline | Seasonal + regressors; must run in < 200 MB |
| Local DB | SQLite (L1), TimescaleDB (L2/L3) |
| Object store | MinIO (L3) |
| Messaging | MQTT (L1/L2), NATS JetStream (L3) |
| OTA | RAUC + AWS IoT Jobs |
| Cloud | AWS IoT Core, Device Shadow, Jobs, Fleet Provisioning, Rules |
| Identity | X.509; TPM 2.0 / SEC-1 / OP-TEE |
| Telemetry | OpenTelemetry, journald |
| Policy | Signed JSON, Tangri Policy Engine |
| Local UI | React + TypeScript stack (§17) |

## Open-source foundation vs Tangri IP

```
TANGRI IP                      OPEN SOURCE FOUNDATION
─────────                      ──────────────────────
Edge runtime                   Yocto, Linux, containerd
Privacy engine                 OpenCV, ONNX Runtime
Policy engine                  ByteTrack, GStreamer
Capability gate                RAUC
Device abstraction             SQLite, TimescaleDB, MinIO
Adapter framework              MQTT, NATS
AI orchestration               React, Vite, Tailwind
Manager loop
Action library semantics       AWS
Retail/corporate edge logic    ───
Fleet semantics                IoT Core, Shadow, Jobs
                               Fleet Provisioning, Rules
```

---

# 21. Standing principles

Not frozen — nothing here is. Each changes only by superseding ADR; 5 and 11 were changed by this
revision.

1. T1 is Tangri-owned above the client hardware boundary.
2. T1 stays fully operational during T2 outages. No cloud failure degrades local function.
3. AWS IoT is control-plane infrastructure, not the edge runtime.
4. No raw personal visual information reaches T2 by any path.
5. **Redaction precedes storage, every process boundary, and all downstream analysis. Unredacted pixels exist only inside the sealed pipeline process, which can neither store nor transmit.** (amended by D-006)
6. The age gate precedes tracking. Persons estimated under 22 never enter C3 or C4.
7. Egress is enforced locally, fails closed, and is independently re-validated in cloud.
8. T2 entitlements are duplicated by hard T1 capability limits.
9. Certificate authentication is not hardware attestation.
10. L1 is software-bound and capability-limited by design, and is positioned as such — including the disclosure that its disk is readable if stolen (D-004).
11. **L1 is the only profile running on hardware Tangri does not own. L2 is a Tangri System-on-Module with a SEC-1 root; L3 adds Tangri-owned UEFI keys and measured boot. The ladder is attestation depth, not CPU ownership.** (amended by D-007)
12. IoT Jobs orchestrates; RAUC executes A/B locally.
13. Tangri owns the semantic device, state and policy model even where AWS supplies the primitive.
14. Retail and corporate share one T1 platform. Sector differentiation lives in T3/T4.
15. The AI Manager loop runs at the edge. The briefing is the product.
16. This platform must accept `/mfg` and `/hls` without redesign. Fieldbus and deterministic-timing hooks are built now, unused.

---

# 22. Decisions

All decisions outstanding at v3.0 are resolved. Rationale in `/canon/05-decisions/`.

| ID | Decision | Outcome |
|---|---|---|
| **D-001** | L1 memory | Shared trunk **+** keyframe decode **+** bounded spool cache = 3.28 GB; `adapter_cap` measured by pre-flight |
| D-002 | Baseline model format | ONNX seasonal + signed regressor JSON, ≤150 MB on disk / 200 MB resident |
| D-003 | Egress policy release path | Independent of the OS; own key, two-person approval, monotonic version floor |
| D-004 | L1 disk-theft posture | Accept the readable disk; no boot passphrase; read-only device credentials mandatory on L1; disclosed in the UI |
| D-005 | Local session duration offline | 72 h full, then read-only until attestation refreshes |
| **D-006** | Age head vs redaction order | Sealed pipeline process; redaction boundary after the trunk and the gate |
| **D-007** | RTL-L2 hardware | System-on-Module, not an accelerator enclosure; `module_attested`; SEC-1-rooted identity |
| D-008 | Seven review corrections | C3-on-L1, C0 suppression metric, canon k floors, cap composition, model-card gate, clock-skew AC, F10 track move, F21/F22 registered |

**No open decisions.** A new one is filed as an ADR before the work it blocks enters IMPLEMENT.

---

# 23. Build phases for T1

| Phase | Scope | Depends on |
|---|---|---|
| 2 | Privacy control set: redactor, egress filter, consent/zone service, audit chain | Contracts agreed |
| 4a | Yocto build, boot chain, RAUC A/B, partitions, pre-flight checker | Phase 2 |
| 4b | Edge runtime, supervisor, capability gate, spool, bridge agent | 4a, T2 Phase 3 |
| 4c | Adapters: ONVIF/RTSP, MQTT, POS webhook | 4b |
| 4d | AI cascade: shared trunk, age gate, tracker; sealed pipeline end to end | 4b, joint-trained trunk from the ML track |
| 4e | RTL-L1 complete and validated | 4a–4d |
| 4f | RTL-L2: SoM bring-up, NPU path, local data node, P2P service | 4e |
| 4g | RTL-L3: appliance build, PoE, k3s | 4f |
| 6 | Manager engine and baseline engine on L2/L3 | T3 Phase 6 |
| 7 | Local GUI: commissioning first, then dashboard | T4 Phase 7 |

**Exit criterion for Phase 4:** a real box on a real PC ingests a real camera, counts people, suppresses minors, and publishes C1 aggregates that pass both the edge filter and T2's server-side re-validation.
