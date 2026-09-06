"""On-device storage layout and its invariants (M02/M03, F03 R5, SPEC §3.1, §5, §6).

The layout is data, not prose, so that AD-01 and the SPEC's storage rules can be *checked* rather
than remembered. Two of those rules are the reason this module exists at all:

    AD-01     every volume T1 writes lives on the T1 device. A layout that places any volume on
              another disk is refused here, before an installer can act on it.
    Audit     its own partition, mounted append-only, so a rootfs rollback cannot take the chain
              with it (F03 R5). `Volume` makes that structural rather than conventional.

`validate_layout` returns findings in a closed set with a remedy each, in the same shape as
pre-flight: a layout is refused by name, never by a bare failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

AUDIT_MIN_MB: Final[int] = 8_192
ZRAM_SIZE_MB: Final[int] = 512


class Volume(str, Enum):
    """SPEC §3.1: rootfs-A / rootfs-B / LUKS2 data / append-only audit / spool, plus the ESP the
    shim chain boots from (§5)."""

    ESP = "esp"
    ROOTFS_A = "rootfs_a"
    ROOTFS_B = "rootfs_b"
    DATA = "data"
    AUDIT = "audit"
    SPOOL = "spool"


ROOT_SLOTS: Final[frozenset[Volume]] = frozenset({Volume.ROOTFS_A, Volume.ROOTFS_B})
ENCRYPTED_VOLUMES: Final[frozenset[Volume]] = frozenset({Volume.DATA, Volume.SPOOL})
READ_ONLY_VOLUMES: Final[frozenset[Volume]] = ROOT_SLOTS


@dataclass(frozen=True)
class Partition:
    volume: Volume
    device: str
    size_mb: int
    encrypted: bool = False
    read_only: bool = False
    append_only: bool = False


@dataclass(frozen=True)
class DiskLayout:
    """`t1_device` is the Tangri portable SSD. Every partition must be on it (AD-01)."""

    t1_device: str
    partitions: tuple[Partition, ...]
    swap_devices: tuple[str, ...] = ()
    zram_mb: int = ZRAM_SIZE_MB

    def partition(self, volume: Volume) -> Partition | None:
        return next((p for p in self.partitions if p.volume is volume), None)


class LayoutFinding(str, Enum):
    """Closed set. Every refusal a layout can earn."""

    VOLUME_MISSING = "volume_missing"
    VOLUME_OFF_T1_DEVICE = "volume_off_t1_device"
    DATA_NOT_ENCRYPTED = "data_not_encrypted"
    ROOTFS_WRITABLE = "rootfs_writable"
    AUDIT_NOT_APPEND_ONLY = "audit_not_append_only"
    AUDIT_TOO_SMALL = "audit_too_small"
    SWAP_ON_DISK = "swap_on_disk"
    ZRAM_ABSENT = "zram_absent"


LAYOUT_REMEDIES: Final[dict[LayoutFinding, str]] = {
    LayoutFinding.VOLUME_MISSING: "re-image the device: the SPEC §3.1 layout is not complete",
    LayoutFinding.VOLUME_OFF_T1_DEVICE: (
        "move the volume onto the T1 device; T1 never writes to the customer's disk (AD-01)"
    ),
    LayoutFinding.DATA_NOT_ENCRYPTED: "re-image with LUKS2 on the data and spool volumes",
    LayoutFinding.ROOTFS_WRITABLE: "mount both root slots read-only; updates land through RAUC",
    LayoutFinding.AUDIT_NOT_APPEND_ONLY: (
        "mount the audit volume append-only before any service starts"
    ),
    LayoutFinding.AUDIT_TOO_SMALL: f"size the audit partition at {AUDIT_MIN_MB} MB or more",
    LayoutFinding.SWAP_ON_DISK: (
        "remove the swap device: swap on the boot SSD is prohibited; zram is the only swap"
    ),
    LayoutFinding.ZRAM_ABSENT: f"configure {ZRAM_SIZE_MB} MB of zram as the sole swap",
}


def validate_layout(layout: DiskLayout) -> tuple[LayoutFinding, ...]:
    """Refusals only. An empty result is the sole statement that a layout is installable."""
    findings: list[LayoutFinding] = []

    if any(layout.partition(volume) is None for volume in Volume):
        findings.append(LayoutFinding.VOLUME_MISSING)
    if any(p.device != layout.t1_device for p in layout.partitions):
        findings.append(LayoutFinding.VOLUME_OFF_T1_DEVICE)

    for volume in sorted(ENCRYPTED_VOLUMES, key=lambda v: v.value):
        partition = layout.partition(volume)
        if partition is not None and not partition.encrypted:
            findings.append(LayoutFinding.DATA_NOT_ENCRYPTED)
            break
    for volume in sorted(READ_ONLY_VOLUMES, key=lambda v: v.value):
        partition = layout.partition(volume)
        if partition is not None and not partition.read_only:
            findings.append(LayoutFinding.ROOTFS_WRITABLE)
            break

    audit = layout.partition(Volume.AUDIT)
    if audit is not None:
        if not audit.append_only:
            findings.append(LayoutFinding.AUDIT_NOT_APPEND_ONLY)
        if audit.size_mb < AUDIT_MIN_MB:
            findings.append(LayoutFinding.AUDIT_TOO_SMALL)

    if layout.swap_devices:
        findings.append(LayoutFinding.SWAP_ON_DISK)
    if layout.zram_mb <= 0:
        findings.append(LayoutFinding.ZRAM_ABSENT)

    return tuple(findings)
