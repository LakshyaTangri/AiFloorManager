# D-007 — RTL-L2 is a System-on-Module, not a USB4 accelerator enclosure

**Status:** Resolved
**Owner:** T1 Agent with Product
**Supersedes:** SPEC v3.0 §2, §3.2, §4, §8; FEATURES v1.0 F04 R1/R3
**Source:** hardware correction, 2026-08-30

## Problem

SPEC v3.0 describes RTL-L2 as a USB4 **accelerator enclosure** whose compute is "Customer CPU + NPU",
i.e. an NPU hanging off a customer PC that still runs the stack. The actual RTL-L2 is a
**System-on-Module**: it brings its own processor, its own RAM, its own Wi-Fi and its own power. The
attached PC is a peripheral, not the host.

This is not a wording fix. Four load-bearing claims were argued from the enclosure model.

## Decision

### 1. The SoM is the host

The customer PC contributes, at most: physical mounting, optional mains power, optional wired LAN,
and a browser for the local UI. All T1 compute — decode, cascade, privacy pipeline, egress, baseline
and Manager engines — runs on the SoM.

Consequences:
- The 4 GB host ceiling and the "dedicated PC" requirement are **L1-only**. L2 has its own memory
  budget against SoM RAM, not against a customer machine.
- The L1/L2 "host health monitor" container (competing workload, host thermal throttling, disk
  removal) is **L1-only**. L2 monitors its own module; there is no shared host to contend with.
- Pre-flight (F01) for L2 checks the *site* — power, network, camera reachability, mounting — not the
  PC's CPU, RAM or BIOS. The `host_not_dedicated` hard fail does not apply to L2.

### 2. Identity binds to the module

v3.0 bound L1 and L2 alike to "SSD controller serial + host DMI fingerprint". For L2 that is wrong:
it would put a site into `RE_ENROLMENT_PENDING` because someone swapped the PC on the counter.

| Profile | Identity source | Fingerprint-change behaviour |
|---|---|---|
| L1 | SSD controller serial + host DMI fingerprint | Host change → `RE_ENROLMENT_PENDING`, human approval |
| **L2** | **SoM serial + SEC-1 device identity** | Attached-PC change is **not** an identity event |
| L3 | Factory-provisioned SEC-1 + TPM 2.0 | n/a |

F04 R1 and R3 are amended accordingly; R3 applies to L1 only.

### 3. The trust ladder is re-derived, and L2's level is renamed

`accelerator_attested` described a level of trust appropriate to "customer machine plus a Tangri
accelerator". A self-contained module running the whole stack on Tangri silicon with a SEC-1 root is
materially stronger than that, and the name now misleads.

| Profile | v3.0 | v3.1 | Basis |
|---|---|---|---|
| L1 | `software_bound` | `software_bound` | No secure element; identity is enrolment-bound; disk readable (D-004) |
| L2 | `accelerator_attested` | **`module_attested`** | SEC-1 root on Tangri-owned compute; LUKS sealed to SEC-1; measured boot to the extent the module's firmware allows |
| L3 | `hardware_attested` | `hardware_attested` | Tangri UEFI, MS key removed, TPM 2.0, measured boot PCR 0–7, fuses blown at provisioning |

The gap L2 → L3 is now specifically **full measured boot and Tangri-owned UEFI keys**, not "who owns
the CPU". What each level unlocks is unchanged (recognition and P2P from L2 up, C4 from L2 up), but
the justification is now the attestation depth rather than the hardware owner.

`trust_level` remains a closed enum in `contracts/shared/capability-vector.yaml`. Since no code
predates this decision, `accelerator_attested` is removed rather than deprecated.

### 4. The USB4-not-M.2 rationale is retired

v3.0 §3.2's "universality wins — the sales premise is *works with any PC*, and most retail PCs have
no free M.2 slot" argued an interface for an accelerator. A SoM does not plug into the PC's compute
path at all. The remaining interface question is the **carrier**: how the SoM gets power, network and
a UI path.

Resolved: the SoM ships on a Tangri carrier board with 12 V DC in (with PoE variant), 1× GbE, Wi-Fi 6,
2× USB 3.0 host ports for radio dongles, and M.2 NVMe for the site data node. A USB 3.0 link to the
attached PC is **optional** and carries only local-UI traffic and optional power; it is never a data
path for camera streams. "Works with any PC" is still true, and now trivially so: the product does not
depend on the PC at all.

## Consequences for the register

- `AuraFace` recognition entitlement on L2 no longer needs the "customer CPU" caveat.
- The L2 spool (30 d) sits on the SoM's NVMe, independent of the customer's disk.
- Physical security improves: tamper-evidence now applies to a Tangri enclosure rather than to a
  USB caddy on someone's desk. D-004's disk-theft posture remains an **L1-only** problem.
