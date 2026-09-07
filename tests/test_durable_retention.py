"""Durable retention (M10, F16 R1/R2): the enforcer runs with the application stopped."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from t1.canon import DataClass, Profile
from t1.control.audit_chain import AuditChain
from t1.storage.domains import PlacementRefusal
from t1.storage.durable import AdmitRefusal, ClipPolicy, DurableStore, RecordRef, RetentionService

NOW = datetime(2026, 1, 1, 12, 0, 0)


@pytest.fixture
def index(tmp_path: Path) -> Path:
    return tmp_path / "data" / "retained.db"


@pytest.fixture
def chain(tmp_path: Path) -> AuditChain:
    return AuditChain(tmp_path / "audit" / "chain.jsonl")


def _trace(record_id: str = "r1", days: int = 90) -> RecordRef:
    return RecordRef(
        record_id=record_id,
        data_class=DataClass.C3_TRACE,
        created_at=NOW,
        retention_until=NOW + timedelta(days=days),
    )


def test_the_profile_ceiling_is_applied_when_the_record_is_written(index: Path) -> None:
    store = DurableStore(index, Profile.L2)
    assert store.admit(_trace(days=365)) is None
    written = store.get("r1")
    assert written is not None
    assert written.retention_until == NOW + timedelta(days=30)
    store.close()


def test_the_enforcer_deletes_with_the_writer_closed_and_leaves_a_receipt(
    index: Path, chain: AuditChain
) -> None:
    store = DurableStore(index, Profile.L2)
    store.admit(_trace(days=30))
    store.close()

    service = RetentionService(index, chain)
    assert service.sweep(NOW + timedelta(days=30, seconds=1)) == ["r1"]

    receipts = [r for r in chain.records() if r.kind == "deletion_receipt"]
    assert [r.body["record_id"] for r in receipts] == ["r1"]
    assert chain.verify().ok

    reopened = DurableStore(index, Profile.L2)
    assert reopened.count() == 0
    reopened.close()


def test_an_unexpired_record_survives_the_sweep(index: Path, chain: AuditChain) -> None:
    store = DurableStore(index, Profile.L3)
    store.admit(_trace(days=90))
    store.close()

    assert RetentionService(index, chain).sweep(NOW + timedelta(days=89)) == []
    assert [r for r in chain.records() if r.kind == "deletion_receipt"] == []


def test_a_crash_between_receipt_and_delete_does_not_produce_a_second_receipt(
    index: Path, chain: AuditChain
) -> None:
    store = DurableStore(index, Profile.L2)
    store.admit(_trace(days=1))
    store.close()

    # The state a crash leaves behind: receipt written, row still marked and present.
    chain.append("deletion_receipt", {"record_id": "r1", "class": "C3"}, NOW.isoformat())
    db = sqlite3.connect(index)
    db.execute("UPDATE retained SET pending_delete = 1")
    db.commit()
    db.close()

    assert RetentionService(index, chain).sweep(NOW + timedelta(days=2)) == ["r1"]
    assert len([r for r in chain.records() if r.kind == "deletion_receipt"]) == 1


def test_a_clip_is_refused_where_no_clip_policy_states_how_long_it_lives(index: Path) -> None:
    store = DurableStore(index, Profile.L3)
    clip = RecordRef(
        record_id="c1",
        data_class=DataClass.C5_MEDIA,
        created_at=NOW,
        retention_until=NOW + timedelta(days=7),
        blob_path="/data/clips/c1.mp4",
    )
    assert store.admit(clip) is AdmitRefusal.CLIP_POLICY_ABSENT
    store.close()

    with_policy = DurableStore(index, Profile.L3, ClipPolicy(max_age_days=3, purpose="safety"))
    assert with_policy.admit(clip) is None
    written = with_policy.get("c1")
    assert written is not None
    assert written.retention_until == NOW + timedelta(days=3)
    with_policy.close()


def test_an_identified_record_without_a_basis_reference_is_refused(index: Path) -> None:
    store = DurableStore(index, Profile.L3)
    refusal = store.admit(
        RecordRef(
            record_id="i1",
            data_class=DataClass.C4_IDENTIFIED,
            created_at=NOW,
            retention_until=NOW + timedelta(days=1),
        )
    )
    assert refusal is AdmitRefusal.BASIS_EXPIRY_MISSING
    store.close()


def test_l1_cannot_persist_a_trace_through_the_durable_store(index: Path) -> None:
    store = DurableStore(index, Profile.L1)
    assert store.admit(_trace()) is PlacementRefusal.CLASS_FORBIDDEN_AT_TRUST_LEVEL
    assert store.count() == 0
    store.close()


def test_the_clip_blob_is_unlinked_when_its_index_row_expires(
    index: Path, chain: AuditChain
) -> None:
    store = DurableStore(index, Profile.L3, ClipPolicy(max_age_days=1, purpose="safety"))
    store.admit(
        RecordRef(
            record_id="c1",
            data_class=DataClass.C5_MEDIA,
            created_at=NOW,
            retention_until=NOW + timedelta(days=1),
            blob_path="/data/clips/c1.mp4",
        )
    )
    store.close()

    unlinked: list[str] = []
    service = RetentionService(index, chain, unlink=unlinked.append)
    service.sweep(NOW + timedelta(days=2))
    assert unlinked == ["/data/clips/c1.mp4"]
