"""Domain placement (M10, F16, C9): a class may only live where it can be forgotten."""

from __future__ import annotations

from t1.canon import DataClass, Profile
from t1.platform.layout import AUDIT_MIN_MB, DiskLayout, Partition, Volume
from t1.storage.domains import (
    CRYPTO_ERASABLE,
    ERASABLE_CLASSES,
    PRESERVED_ON_ERASE,
    REMEDY,
    Domain,
    PlacementRefusal,
    check_placement,
)

T1_DEVICE = "/dev/t1"


def _layout(*, data_encrypted: bool = True, data_device: str = T1_DEVICE) -> DiskLayout:
    return DiskLayout(
        t1_device=T1_DEVICE,
        partitions=(
            Partition(Volume.ESP, T1_DEVICE, 512),
            Partition(Volume.ROOTFS_A, T1_DEVICE, 8_192, read_only=True),
            Partition(Volume.ROOTFS_B, T1_DEVICE, 8_192, read_only=True),
            Partition(Volume.DATA, data_device, 32_768, encrypted=data_encrypted),
            Partition(Volume.AUDIT, T1_DEVICE, AUDIT_MIN_MB, append_only=True),
            Partition(Volume.SPOOL, T1_DEVICE, 4_096, encrypted=True),
        ),
    )


def test_aggregates_go_to_the_spool_and_traces_to_the_data_domain() -> None:
    assert check_placement(DataClass.C1_AGGREGATE, Domain.SPOOL, Profile.L2) is None
    assert check_placement(DataClass.C3_TRACE, Domain.DATA, Profile.L2) is None


def test_a_class_written_to_the_wrong_domain_is_refused() -> None:
    assert (
        check_placement(DataClass.C3_TRACE, Domain.SPOOL, Profile.L2)
        is PlacementRefusal.WRONG_DOMAIN
    )


def test_nothing_forgettable_may_live_on_the_preserved_audit_domain() -> None:
    for data_class in sorted(ERASABLE_CLASSES, key=lambda c: c.value):
        refusal = check_placement(data_class, Domain.AUDIT, Profile.L3)
        assert refusal is not None
    assert not (CRYPTO_ERASABLE & PRESERVED_ON_ERASE)


def test_l1_may_not_store_a_trace_anywhere() -> None:
    assert (
        check_placement(DataClass.C3_TRACE, Domain.DATA, Profile.L1)
        is PlacementRefusal.CLASS_FORBIDDEN_AT_TRUST_LEVEL
    )


def test_c6_is_stored_by_no_profile() -> None:
    assert (
        check_placement(DataClass.C6_PROHIBITED, Domain.DATA, Profile.L3)
        is PlacementRefusal.CLASS_NEVER_STORED
    )


def test_an_unencrypted_data_volume_refuses_the_write() -> None:
    refusal = check_placement(
        DataClass.C3_TRACE, Domain.DATA, Profile.L2, _layout(data_encrypted=False)
    )
    assert refusal is PlacementRefusal.DOMAIN_NOT_ENCRYPTED


def test_a_domain_on_the_customers_disk_refuses_the_write() -> None:
    refusal = check_placement(
        DataClass.C3_TRACE, Domain.DATA, Profile.L2, _layout(data_device="/dev/internal")
    )
    assert refusal is PlacementRefusal.DOMAIN_OFF_T1_DEVICE


def test_every_refusal_names_a_remedy() -> None:
    assert set(REMEDY) == set(PlacementRefusal)
