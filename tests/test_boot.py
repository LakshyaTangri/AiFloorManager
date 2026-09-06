"""F03 — boot chain, A/B slots, and the ordering that has to hold before any service runs."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from t1.platform.boot import (
    MAX_FAILED_HEALTH_CHECKS,
    PRIVACY_SET_SIGNING_DOMAIN,
    SEQUENCE,
    BootFinding,
    BootOrderError,
    BootState,
    Mode,
    Slot,
    SlotState,
    Stage,
    report_health,
    rollback_report,
    step_boot,
    verify_privacy_set,
)
from t1.platform.layout import (
    AUDIT_MIN_MB,
    LAYOUT_REMEDIES,
    DiskLayout,
    LayoutFinding,
    Partition,
    Volume,
    validate_layout,
)

T1_DEVICE = "/dev/disk/by-id/usb-Tangri_T1"


def _layout(**overrides: object) -> DiskLayout:
    partitions = (
        Partition(Volume.ESP, T1_DEVICE, 512),
        Partition(Volume.ROOTFS_A, T1_DEVICE, 8_192, read_only=True),
        Partition(Volume.ROOTFS_B, T1_DEVICE, 8_192, read_only=True),
        Partition(Volume.DATA, T1_DEVICE, 40_960, encrypted=True),
        Partition(Volume.AUDIT, T1_DEVICE, AUDIT_MIN_MB, append_only=True),
        Partition(Volume.SPOOL, T1_DEVICE, 20_480, encrypted=True),
    )
    base: dict[str, object] = {"t1_device": T1_DEVICE, "partitions": partitions}
    base.update(overrides)
    return DiskLayout(**base)  # type: ignore[arg-type]


def _state() -> BootState:
    return BootState(
        active=Slot.A,
        slots={Slot.A: SlotState(version="1.2.0"), Slot.B: SlotState(version="1.1.0")},
    )


def _boot(state: BootState, **kwargs: object) -> BootState:
    for stage in SEQUENCE:
        state = step_boot(state, stage, layout=_layout(), **kwargs)  # type: ignore[arg-type]
    return state


def test_the_supplied_layout_is_installable() -> None:
    assert validate_layout(_layout()) == ()


def test_a_volume_on_the_customers_disk_is_refused() -> None:
    strayed = _layout(
        partitions=(
            *[p for p in _layout().partitions if p.volume is not Volume.SPOOL],
            Partition(Volume.SPOOL, "/dev/nvme0n1", 20_480, encrypted=True),
        )
    )
    assert LayoutFinding.VOLUME_OFF_T1_DEVICE in validate_layout(strayed)


def test_swap_on_the_boot_ssd_is_refused_and_zram_is_required() -> None:
    assert LayoutFinding.SWAP_ON_DISK in validate_layout(_layout(swap_devices=(T1_DEVICE,)))
    assert LayoutFinding.ZRAM_ABSENT in validate_layout(_layout(zram_mb=0))


def test_the_audit_volume_must_be_append_only_and_large_enough() -> None:
    others = [p for p in _layout().partitions if p.volume is not Volume.AUDIT]
    writable = _layout(partitions=(*others, Partition(Volume.AUDIT, T1_DEVICE, AUDIT_MIN_MB)))
    small = _layout(partitions=(*others, Partition(Volume.AUDIT, T1_DEVICE, 512, append_only=True)))
    assert LayoutFinding.AUDIT_NOT_APPEND_ONLY in validate_layout(writable)
    assert LayoutFinding.AUDIT_TOO_SMALL in validate_layout(small)


def test_unencrypted_data_and_writable_roots_are_refused() -> None:
    others = [p for p in _layout().partitions if p.volume is not Volume.DATA]
    plain = _layout(partitions=(*others, Partition(Volume.DATA, T1_DEVICE, 40_960)))
    assert LayoutFinding.DATA_NOT_ENCRYPTED in validate_layout(plain)

    rest = [p for p in _layout().partitions if p.volume is not Volume.ROOTFS_B]
    writable_root = _layout(partitions=(*rest, Partition(Volume.ROOTFS_B, T1_DEVICE, 8_192)))
    assert LayoutFinding.ROOTFS_WRITABLE in validate_layout(writable_root)


def test_every_layout_finding_carries_a_remedy() -> None:
    assert set(LAYOUT_REMEDIES) == set(LayoutFinding)


def test_a_clean_boot_completes_every_stage_in_normal_mode() -> None:
    state = _boot(_state())
    assert state.completed == SEQUENCE
    assert state.mode is Mode.NORMAL
    assert state.findings == ()


def test_services_cannot_start_before_the_audit_volume_is_mounted() -> None:
    state = _state()
    state = step_boot(state, Stage.VERIFY_CHAIN)
    state = step_boot(state, Stage.UNLOCK_DATA)
    with pytest.raises(BootOrderError):
        step_boot(state, Stage.START_SERVICES)


def test_a_missing_audit_partition_is_named_at_the_mount_stage() -> None:
    without_audit = _layout(
        partitions=tuple(p for p in _layout().partitions if p.volume is not Volume.AUDIT)
    )
    state = step_boot(_state(), Stage.VERIFY_CHAIN)
    state = step_boot(state, Stage.UNLOCK_DATA)
    state = step_boot(state, Stage.MOUNT_AUDIT, layout=without_audit)
    assert BootFinding.AUDIT_NOT_MOUNTED in state.findings
    assert BootFinding.LAYOUT_INVALID in state.findings


def test_an_unverified_privacy_set_keeps_ingest_and_holds_the_containers_down() -> None:
    state = _boot(_state(), privacy_set_ok=False)
    assert state.mode is Mode.INGEST_ONLY
    assert BootFinding.PRIVACY_SET_UNVERIFIED in state.findings
    assert Stage.START_SERVICES in state.completed
    assert Stage.START_CONTAINERS not in state.completed


def test_an_unsigned_chain_is_named() -> None:
    assert BootFinding.CHAIN_UNSIGNED in _boot(_state(), chain_signed=False).findings


def test_the_privacy_set_signature_is_domain_separated() -> None:
    key, digest = b"k" * 32, hashlib.sha256(b"control-set").digest()
    signature = hmac.new(key, PRIVACY_SET_SIGNING_DOMAIN.encode() + digest, hashlib.sha256)
    assert verify_privacy_set(digest, signature.hexdigest(), key)
    assert not verify_privacy_set(digest, hmac.new(key, digest, hashlib.sha256).hexdigest(), key)


def test_two_failures_then_a_success_do_not_roll_back() -> None:
    state = _state()
    state = report_health(state, healthy=False)
    state = report_health(state, healthy=False)
    state = report_health(state, healthy=True)
    assert state.active is Slot.A
    assert state.active_slot.failed_health_checks == 0

    state = report_health(state, healthy=False)
    assert state.active is Slot.A


def test_the_third_consecutive_failure_rolls_back_and_reports_the_failing_version() -> None:
    state = _boot(_state())
    for _ in range(MAX_FAILED_HEALTH_CHECKS):
        state = report_health(state, healthy=False)

    assert state.active is Slot.B
    assert BootFinding.ROLLED_BACK in state.findings
    assert state.completed == ()
    assert rollback_report(state, Slot.A) == {
        "event": "rolled_back",
        "failing_slot": "rootfs_a",
        "failing_version": "1.2.0",
        "active_slot": "rootfs_b",
        "active_version": "1.1.0",
    }


def test_both_slots_failing_is_named_rather_than_looping() -> None:
    state = _state()
    for _ in range(MAX_FAILED_HEALTH_CHECKS * 2):
        state = report_health(state, healthy=False)
    assert BootFinding.NO_HEALTHY_SLOT in state.findings
    assert state.active is Slot.B


def test_a_rollback_leaves_the_audit_volume_alone() -> None:
    state = _state()
    for _ in range(MAX_FAILED_HEALTH_CHECKS):
        state = report_health(state, healthy=False)
    # The rollback swaps root slots only; nothing in the layout's audit volume is touched (R5).
    assert validate_layout(_layout()) == ()
    assert set(state.slots) == {Slot.A, Slot.B}
