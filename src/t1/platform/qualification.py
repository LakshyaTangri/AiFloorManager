"""Pre-flight qualification (F01, C13).

The refusal path is the feature. A host either qualifies or it is refused with a named remedy the
Field Engineer can act on at the counter; there is no bare fail and no "probably fine". Two
qualifications exist and they are deliberately different types:

    qualify_host  L1 only. The customer's PC is the runtime, so it is measured and gated.
    qualify_site  L2/L3. The runtime is Tangri hardware, so the site is measured and no property
                  of any attached PC is observed, reported, or allowed to fail the run (D-007).

`adapter_cap` is derived from measured usable RAM through the canon thresholds (D-001). It is never
assumed, and a two-adapter host is an advisory rather than a refusal: commissioning offers two
adapters instead of losing the install.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

from t1.canon import HOST_DEDICATION_WINDOW_DAYS, PREFLIGHT_BUDGET_S, Profile, TrustLevel
from t1.control.capability import CapabilityVector, l1_vector
from t1.platform.probe import (
    USB3_MIN_SPEED_MBPS,
    BootMode,
    HostObservation,
    SiteObservation,
    SleepPolicy,
)

# SPEC §3.1: the client supplies a dedicated x86-64 PC with AVX2, ≥4 cores and 4 GB RAM, and
# Tangri supplies a 256 GB SSD in a USB 3.0 UASP enclosure.
MIN_CORES: Final[int] = 4
MIN_T1_MEDIA_MB: Final[int] = 240_000
SUPPORTED_ARCH: Final[frozenset[str]] = frozenset({"x86_64", "amd64", "AMD64"})

PREFLIGHT_SIGNING_DOMAIN: Final[str] = "host-profile"


class Result(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


class Finding(str, Enum):
    """Closed set. Anything the checker can say about a host is one of these."""

    ARCH_UNSUPPORTED = "arch_unsupported"
    AVX2_MISSING = "avx2_missing"
    CORES_INSUFFICIENT = "cores_insufficient"
    RAM_INSUFFICIENT = "ram_insufficient"
    NIC_MISSING = "nic_missing"
    USB3_MISSING = "usb3_missing"
    T1_MEDIA_LINK_DEGRADED = "t1_media_link_degraded"
    T1_MEDIA_LINK_UNVERIFIED = "t1_media_link_unverified"
    T1_MEDIA_TOO_SMALL = "t1_media_too_small"
    BOOT_MODE_LEGACY = "boot_mode_legacy"
    VIRTUALISATION_DISABLED = "virtualisation_disabled"
    SLEEP_ENABLED = "sleep_enabled"
    SLEEP_POLICY_UNVERIFIED = "sleep_policy_unverified"
    HOST_NOT_DEDICATED = "host_not_dedicated"
    HOST_DEDICATION_UNVERIFIED = "host_dedication_unverified"
    PREFLIGHT_TIMEOUT = "preflight_timeout"
    ADD_RAM_FOR_THIRD_ADAPTER = "add_ram_for_third_adapter"
    ACCELERATOR_ABSENT = "accelerator_absent"
    VIRTUALISED_HOST = "virtualised_host"
    SITE_POWER_UNSTABLE = "site_power_unstable"
    SITE_NETWORK_UNREACHABLE = "site_network_unreachable"
    SITE_CAMERA_UNREACHABLE = "site_camera_unreachable"
    SITE_CAMERAS_UNVERIFIED = "site_cameras_unverified"
    SITE_MOUNTING_UNSUITABLE = "site_mounting_unsuitable"


REMEDIES: Final[dict[Finding, str]] = {
    Finding.ARCH_UNSUPPORTED: "use a 64-bit x86 PC; T1 does not run on this architecture",
    Finding.AVX2_MISSING: "use a PC with an AVX2 CPU (Intel Haswell 2013 or newer)",
    Finding.CORES_INSUFFICIENT: f"use a PC with at least {MIN_CORES} CPU cores",
    Finding.RAM_INSUFFICIENT: "add RAM: T1 needs 3.26 GB usable after the customer's own load",
    Finding.NIC_MISSING: "connect the PC to the site LAN; no network interface was found",
    Finding.USB3_MISSING: "use a PC with a USB 3.0 port (blue connector)",
    Finding.T1_MEDIA_LINK_DEGRADED: (
        "move the T1 device to a USB 3.0 port: it negotiated a USB 2.0 link"
    ),
    Finding.T1_MEDIA_LINK_UNVERIFIED: (
        "re-run pre-flight from the T1 device so its own USB link speed can be measured"
    ),
    Finding.T1_MEDIA_TOO_SMALL: "replace the T1 device: 256 GB is the supplied qualified capacity",
    Finding.BOOT_MODE_LEGACY: "enable UEFI boot in BIOS > Boot > Boot Mode and disable CSM",
    Finding.VIRTUALISATION_DISABLED: "enable virtualization (VT-x / AMD-V) in BIOS > Advanced",
    Finding.SLEEP_ENABLED: "disable sleep and hibernate in BIOS > Power",
    Finding.SLEEP_POLICY_UNVERIFIED: (
        "confirm sleep and hibernate are disabled in BIOS > Power, then record it on the checklist"
    ),
    Finding.HOST_NOT_DEDICATED: (
        "this PC is in daily use; T1 needs a dedicated host with no other operating system in use"
    ),
    Finding.HOST_DEDICATION_UNVERIFIED: (
        "run the dedication check from the pre-flight menu; an unchecked host cannot be qualified"
    ),
    Finding.PREFLIGHT_TIMEOUT: "re-run pre-flight; this host did not complete the checks in time",
    Finding.ADD_RAM_FOR_THIRD_ADAPTER: "add RAM to reach 3.40 GB usable to run a third adapter",
    Finding.ACCELERATOR_ABSENT: "no GPU/NPU found; T1 will run on CPU at reduced stream throughput",
    Finding.VIRTUALISED_HOST: "this host is a virtual machine; report before commissioning",
    Finding.SITE_POWER_UNSTABLE: "provide a switched, protected mains outlet at the mounting point",
    Finding.SITE_NETWORK_UNREACHABLE: "provide a working LAN drop or uplink at the mounting point",
    Finding.SITE_CAMERA_UNREACHABLE: "check camera power, cabling and VLAN for the named streams",
    Finding.SITE_CAMERAS_UNVERIFIED: (
        "survey the site's cameras: qualification needs the expected stream list, not an empty one"
    ),
    Finding.SITE_MOUNTING_UNSUITABLE: "provide a ventilated, secured mounting position",
}

ADVISORY: Final[frozenset[Finding]] = frozenset(
    {Finding.ADD_RAM_FOR_THIRD_ADAPTER, Finding.ACCELERATOR_ABSENT, Finding.VIRTUALISED_HOST}
)


@dataclass(frozen=True)
class Remedy:
    finding: Finding
    remedy: str
    hard: bool


def _remedies(findings: tuple[Finding, ...]) -> tuple[Remedy, ...]:
    """R3: no finding may ever surface without the sentence that fixes it."""
    return tuple(Remedy(f, REMEDIES[f], f not in ADVISORY) for f in findings)


@dataclass(frozen=True)
class HostProfile:
    """The signed L1 pre-flight output (R2)."""

    result: Result
    findings: tuple[Finding, ...]
    usable_ram_mb: int
    adapter_cap: int
    stream_cap: int
    trust_level: TrustLevel
    elapsed_s: float
    profile: Profile = Profile.L1
    signing_domain: str = PREFLIGHT_SIGNING_DOMAIN

    @property
    def remedies(self) -> tuple[Remedy, ...]:
        return _remedies(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.value,
            "result": self.result.value,
            "findings": [f.value for f in self.findings],
            "remedies": [
                {"finding": r.finding.value, "remedy": r.remedy, "hard": r.hard}
                for r in self.remedies
            ],
            "usable_ram_mb": self.usable_ram_mb,
            "adapter_cap": self.adapter_cap,
            "stream_cap": self.stream_cap,
            "trust_level": self.trust_level.value,
            "elapsed_s": round(self.elapsed_s, 3),
            "signing_domain": self.signing_domain,
        }

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()

    def sign(self, key: bytes) -> str:
        return hmac.new(key, self.to_bytes(), hashlib.sha256).hexdigest()

    def capability(self) -> CapabilityVector | None:
        """The vector F05 will enforce. A refused host has no vector to sign."""
        if self.result is not Result.PASS:
            return None
        return CapabilityVector(
            profile=self.profile,
            trust_level=self.trust_level,
            adapter_cap=self.adapter_cap,
            stream_cap=self.stream_cap,
        )


@dataclass(frozen=True)
class SiteProfile:
    """The L2/L3 pre-flight output (R6). Structurally incapable of naming the attached PC."""

    result: Result
    findings: tuple[Finding, ...]
    cameras_reachable: tuple[str, ...]
    cameras_unreachable: tuple[str, ...]
    elapsed_s: float
    profile: Profile
    signing_domain: str = PREFLIGHT_SIGNING_DOMAIN

    @property
    def remedies(self) -> tuple[Remedy, ...]:
        return _remedies(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.value,
            "result": self.result.value,
            "findings": [f.value for f in self.findings],
            "remedies": [
                {"finding": r.finding.value, "remedy": r.remedy, "hard": r.hard}
                for r in self.remedies
            ],
            "cameras_reachable": list(self.cameras_reachable),
            "cameras_unreachable": list(self.cameras_unreachable),
            "elapsed_s": round(self.elapsed_s, 3),
            "signing_domain": self.signing_domain,
        }

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()

    def sign(self, key: bytes) -> str:
        return hmac.new(key, self.to_bytes(), hashlib.sha256).hexdigest()


def _host_findings(obs: HostObservation, elapsed_s: float) -> list[Finding]:
    findings: list[Finding] = []
    if obs.arch not in SUPPORTED_ARCH:
        findings.append(Finding.ARCH_UNSUPPORTED)
    if not obs.avx2:
        findings.append(Finding.AVX2_MISSING)
    if obs.cores < MIN_CORES:
        findings.append(Finding.CORES_INSUFFICIENT)
    if not obs.nic_present:
        findings.append(Finding.NIC_MISSING)
    if not obs.usb3_port_present:
        findings.append(Finding.USB3_MISSING)
    if obs.t1_media_link_mbps is None:
        findings.append(Finding.T1_MEDIA_LINK_UNVERIFIED)
    elif obs.t1_media_link_mbps < USB3_MIN_SPEED_MBPS:
        findings.append(Finding.T1_MEDIA_LINK_DEGRADED)
    if obs.t1_media_mb < MIN_T1_MEDIA_MB:
        findings.append(Finding.T1_MEDIA_TOO_SMALL)
    if obs.boot_mode is not BootMode.UEFI:
        findings.append(Finding.BOOT_MODE_LEGACY)
    if not obs.virtualisation_enabled:
        findings.append(Finding.VIRTUALISATION_DISABLED)
    if obs.sleep_policy is SleepPolicy.ENABLED:
        findings.append(Finding.SLEEP_ENABLED)
    elif obs.sleep_policy is SleepPolicy.UNVERIFIED:
        findings.append(Finding.SLEEP_POLICY_UNVERIFIED)
    if obs.internal_os_last_boot_days is None:
        findings.append(Finding.HOST_DEDICATION_UNVERIFIED)
    elif obs.internal_os_last_boot_days < HOST_DEDICATION_WINDOW_DAYS:
        findings.append(Finding.HOST_NOT_DEDICATED)
    if elapsed_s > PREFLIGHT_BUDGET_S:
        findings.append(Finding.PREFLIGHT_TIMEOUT)
    if not obs.accelerator_present:
        findings.append(Finding.ACCELERATOR_ABSENT)
    if obs.virtualised:
        findings.append(Finding.VIRTUALISED_HOST)
    return findings


def qualify_host(obs: HostObservation, *, elapsed_s: float = 0.0) -> HostProfile:
    """L1 host qualification. Never call this for L2/L3: see `qualify_site` and D-007."""
    findings = _host_findings(obs, elapsed_s)

    vector = l1_vector(obs.usable_ram_mb)
    if vector is None:
        findings.append(Finding.RAM_INSUFFICIENT)
        adapter_cap, stream_cap = 0, 0
    else:
        adapter_cap, stream_cap = vector.adapter_cap, vector.stream_cap
        if adapter_cap < 3:
            findings.append(Finding.ADD_RAM_FOR_THIRD_ADAPTER)

    ordered = tuple(f for f in Finding if f in set(findings))
    hard = [f for f in ordered if f not in ADVISORY]
    return HostProfile(
        result=Result.FAIL if hard else Result.PASS,
        findings=ordered,
        usable_ram_mb=obs.usable_ram_mb,
        adapter_cap=adapter_cap,
        stream_cap=stream_cap,
        trust_level=TrustLevel.SOFTWARE_BOUND,
        elapsed_s=elapsed_s,
    )


def qualify_site(obs: SiteObservation, *, profile: Profile, elapsed_s: float = 0.0) -> SiteProfile:
    """L2/L3 site qualification (R6). `host_not_dedicated` is unreachable from here by design."""
    if profile is Profile.L1:
        raise ValueError("site_qualification_not_applicable_to_l1")

    findings: list[Finding] = []
    if not obs.power_stable:
        findings.append(Finding.SITE_POWER_UNSTABLE)
    if not obs.network_reachable:
        findings.append(Finding.SITE_NETWORK_UNREACHABLE)
    if not obs.cameras_expected:
        findings.append(Finding.SITE_CAMERAS_UNVERIFIED)
    elif obs.cameras_unreachable:
        findings.append(Finding.SITE_CAMERA_UNREACHABLE)
    if not obs.mounting_suitable:
        findings.append(Finding.SITE_MOUNTING_UNSUITABLE)
    if elapsed_s > PREFLIGHT_BUDGET_S:
        findings.append(Finding.PREFLIGHT_TIMEOUT)

    ordered = tuple(f for f in Finding if f in set(findings))
    hard = [f for f in ordered if f not in ADVISORY]
    return SiteProfile(
        result=Result.FAIL if hard else Result.PASS,
        findings=ordered,
        cameras_reachable=obs.cameras_reachable,
        cameras_unreachable=obs.cameras_unreachable,
        elapsed_s=elapsed_s,
        profile=profile,
    )
