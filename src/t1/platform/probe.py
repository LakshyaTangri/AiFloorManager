"""Read-only observation of the customer's host (F01 R1).

Every function here reads and nothing here writes. The customer's internal disk is outside the T1
storage domain (AD-01), so the probe never mounts it and never opens a path for writing; the
dedication evidence that F01 R5 needs is supplied by the caller and is refused when absent rather
than inferred.

The distinction this module is careful about is capability versus configuration. `/sys` reports what
the kernel can do, not what the firmware is configured to do: a host listing `mem` in
`/sys/power/state` may have suspend fully disabled in BIOS, and a host with a USB 3.0 port somewhere
may still have the T1 device negotiated at USB 2.0. Where only capability is observable the probe
says `unverified`, and qualification refuses that rather than guessing in either direction.

The sysroot is a parameter so the probe can be exercised against a fixture tree on a host that is
not the host under test.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

USB3_MIN_SPEED_MBPS = 5000
VIRTUALISATION_MARKERS = ("virtualbox", "vmware", "kvm", "qemu", "bochs", "hyper-v", "xen")
VIRTUALISATION_FLAGS = frozenset({"vmx", "svm"})
SLEEP_STATES = frozenset({"mem", "disk", "standby"})
SLEEP_UNITS = ("sleep.target", "suspend.target", "hibernate.target", "hybrid-sleep.target")


class BootMode(str, Enum):
    UEFI = "uefi"
    LEGACY = "legacy"


class SleepPolicy(str, Enum):
    """Whether this host can suspend itself — a question `/sys/power/state` does not answer."""

    DISABLED = "disabled"
    ENABLED = "enabled"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class HostObservation:
    """Measured facts about one customer PC. No verdicts, no remedies."""

    arch: str
    avx2: bool
    cores: int
    usable_ram_mb: int
    nic_present: bool
    usb3_port_present: bool
    accelerator_present: bool
    t1_media_mb: int
    boot_mode: BootMode
    virtualised: bool
    virtualisation_enabled: bool
    sleep_policy: SleepPolicy
    t1_media_link_mbps: float | None = None
    """Negotiated speed of the port the T1 device is attached to. A USB 3.0 port elsewhere on the
    machine says nothing about this one (SPEC §3.1: USB 3.0 UASP enclosure)."""
    internal_os_last_boot_days: float | None = None
    """Days since the host's installed OS last booted. `None` means unmeasured, which F01 R5
    treats as a refusal rather than as a dedicated host."""


@dataclass(frozen=True)
class SiteObservation:
    """L2/L3 site facts (F01 R6). Carries no property of any attached PC."""

    power_stable: bool
    network_reachable: bool
    cameras_expected: tuple[str, ...]
    """The inventory the site was surveyed against. Empty means the check never ran."""
    cameras_reachable: tuple[str, ...]
    mounting_suitable: bool

    @property
    def cameras_unreachable(self) -> tuple[str, ...]:
        reachable = set(self.cameras_reachable)
        return tuple(camera for camera in self.cameras_expected if camera not in reachable)


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _cpuinfo_flags(sysroot: Path) -> frozenset[str]:
    for line in _read(sysroot / "proc/cpuinfo").splitlines():
        if line.startswith("flags") and ":" in line:
            return frozenset(line.split(":", 1)[1].split())
    return frozenset()


def _core_count(sysroot: Path) -> int:
    return sum(
        1 for line in _read(sysroot / "proc/cpuinfo").splitlines() if line.startswith("processor")
    )


def _meminfo_kb(sysroot: Path, key: str) -> int:
    for line in _read(sysroot / "proc/meminfo").splitlines():
        if line.startswith(f"{key}:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return 0


def _usable_ram_mb(sysroot: Path) -> int:
    """MemAvailable, not MemTotal: D-001 caps adapters on what the runtime can actually have."""
    available = _meminfo_kb(sysroot, "MemAvailable") or _meminfo_kb(sysroot, "MemFree")
    return available // 1024


def _nic_present(sysroot: Path) -> bool:
    net = sysroot / "sys/class/net"
    if not net.is_dir():
        return False
    return any(iface.name != "lo" for iface in net.iterdir())


def _usb3_port_present(sysroot: Path) -> bool:
    """Any USB 3.0-capable port on the machine: necessary, and on its own not sufficient."""
    devices = sysroot / "sys/bus/usb/devices"
    if not devices.is_dir():
        return False
    for device in devices.iterdir():
        raw = _read(device / "speed").strip()
        try:
            if float(raw) >= USB3_MIN_SPEED_MBPS:
                return True
        except ValueError:
            continue
    return False


def _accelerator_present(sysroot: Path) -> bool:
    drm = sysroot / "sys/class/drm"
    return drm.is_dir() and any(card.name.startswith("card") for card in drm.iterdir())


def _boot_mode(sysroot: Path) -> BootMode:
    return BootMode.UEFI if (sysroot / "sys/firmware/efi").is_dir() else BootMode.LEGACY


def _virtualised(sysroot: Path) -> bool:
    dmi = sysroot / "sys/class/dmi/id"
    text = " ".join(_read(dmi / name) for name in ("product_name", "sys_vendor", "board_vendor"))
    return any(marker in text.lower() for marker in VIRTUALISATION_MARKERS)


def _sleep_policy(sysroot: Path) -> SleepPolicy:
    """`/sys/power/state` is a capability list, so a host offering `mem` is not a host that will
    suspend. Only two configurations are decidable from a running system: a kernel that offers no
    sleep state at all, and systemd sleep units masked to /dev/null. Everything else — BIOS power
    settings above all — is `UNVERIFIED` and must be established by the FE."""
    states = set(_read(sysroot / "sys/power/state").split())
    if not states & SLEEP_STATES:
        return SleepPolicy.DISABLED

    units = sysroot / "etc/systemd/system"
    masked = 0
    for unit in SLEEP_UNITS:
        path = units / unit
        if path.is_symlink() and os.readlink(path) == "/dev/null":
            masked += 1
    return SleepPolicy.DISABLED if masked == len(SLEEP_UNITS) else SleepPolicy.UNVERIFIED


def probe_host(
    sysroot: Path = Path("/"),
    *,
    t1_media_mb: int,
    t1_media_link_mbps: float | None = None,
    sleep_policy: SleepPolicy | None = None,
    internal_os_last_boot_days: float | None = None,
) -> HostObservation:
    """Observe the running host.

    `t1_media_mb` and `t1_media_link_mbps` describe the T1 device the caller booted from, and
    `sleep_policy` lets the FE record a firmware setting the running system cannot see. Each
    defaults to unmeasured, which qualification refuses.
    """
    flags = _cpuinfo_flags(sysroot)
    return HostObservation(
        arch=platform.machine(),
        avx2="avx2" in flags,
        cores=_core_count(sysroot) or 0,
        usable_ram_mb=_usable_ram_mb(sysroot),
        nic_present=_nic_present(sysroot),
        usb3_port_present=_usb3_port_present(sysroot),
        accelerator_present=_accelerator_present(sysroot),
        t1_media_mb=t1_media_mb,
        boot_mode=_boot_mode(sysroot),
        virtualised=_virtualised(sysroot),
        virtualisation_enabled=bool(flags & VIRTUALISATION_FLAGS),
        sleep_policy=sleep_policy or _sleep_policy(sysroot),
        t1_media_link_mbps=t1_media_link_mbps,
        internal_os_last_boot_days=internal_os_last_boot_days,
    )
