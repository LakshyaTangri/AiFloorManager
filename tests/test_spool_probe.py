"""Spool and offline behaviour (F14).

The interesting assertions are about what the spool *sheds*, because that is the decision nobody
makes consciously until the partition is full at 19:00 on a Saturday.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from t1.canon import CLOCK_SKEW_TOLERANCE_MS, DataClass, Priority, Profile
from t1.control.spool import Spool, SpoolItem, SpoolRefused, measure_offset

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def make_spool(tmp_path: Path, capacity_bytes: int = 64 * 1024) -> Spool:
    return Spool(
        path=tmp_path / "spool" / "spool.db",
        profile=Profile.L1,
        boot_id="boot-1",
        capacity_bytes=capacity_bytes,
    )


def health(at: datetime, n: int = 0) -> SpoolItem:
    return SpoolItem(
        schema="rtl.health.v1",
        data_class=DataClass.C0_OPERATIONAL,
        priority=Priority.HEALTH,
        device_time=at,
        payload={"cpu_pct": 40, "mem_mb": 2100, "pad": "x" * 200, "n": n},
    )


def excursion(at: datetime) -> SpoolItem:
    return SpoolItem(
        schema="rtl.event.v1",
        data_class=DataClass.C2_EVENT,
        priority=Priority.REFRIGERATION,
        device_time=at,
        payload={"event_code": "fridge_excursion", "zone_id": "z1", "severity": "high"},
    )


def aggregate(at: datetime, value: int, metric: str = "footfall") -> SpoolItem:
    return SpoolItem(
        schema="rtl.aggregate.v1",
        data_class=DataClass.C1_AGGREGATE,
        priority=Priority.AGGREGATE,
        device_time=at,
        payload={
            "metric": metric,
            "value": value,
            "window_start": at.isoformat(),
            "k_suppressed": False,
        },
        metric=metric,
        window_seconds=300,
        k_value=12,
    )


def test_raw_media_never_enters_the_spool(tmp_path: Path) -> None:
    """F14 R4: a T2 outage must not create a video backlog, so the refusal is at admission."""
    spool = make_spool(tmp_path)
    item = SpoolItem(
        schema="rtl.event.v1",
        data_class=DataClass.C2_EVENT,
        priority=Priority.SAFETY_SECURITY,
        device_time=NOW,
        payload={"event_code": "intrusion", "clip_b64": "AAAA"},
    )
    with pytest.raises(SpoolRefused) as exc:
        spool.enqueue(item)
    assert exc.value.reason == "raw_media_never_spooled"
    assert spool.depth() == 0


def test_health_drops_before_a_refrigeration_excursion(tmp_path: Path) -> None:
    spool = make_spool(tmp_path, capacity_bytes=2_000)
    for n in range(6):
        spool.enqueue(health(NOW + timedelta(seconds=n), n))
    spool.enqueue(excursion(NOW + timedelta(seconds=10)))

    for n in range(6, 12):
        spool.enqueue(health(NOW + timedelta(seconds=n), n))

    kinds = [r.priority for r in spool.drain(100)]
    assert Priority.REFRIGERATION in kinds
    assert spool.dropped["dropped_health"] > 0
    assert "dropped_refrigeration" not in spool.dropped


def test_aggregates_coarsen_before_anything_is_dropped(tmp_path: Path) -> None:
    spool = make_spool(tmp_path, capacity_bytes=400)
    for n in range(8):
        spool.enqueue(aggregate(NOW + timedelta(minutes=5 * n), value=n + 1))

    assert spool.coarsened_count > 0
    assert not [k for k in spool.dropped if k.startswith("dropped_")]

    coarse = [r for r in spool.drain(100) if r.coarsened]
    assert coarse
    assert all(r.window_seconds is not None and r.window_seconds > 300 for r in coarse)
    # Coarsening loses resolution, not counts.
    assert sum(int(r.payload["value"]) for r in spool.drain(100)) == sum(range(1, 9))


def test_a_lower_priority_record_yields_rather_than_evicting_its_betters(tmp_path: Path) -> None:
    spool = make_spool(tmp_path, capacity_bytes=300)
    spool.enqueue(excursion(NOW))
    with pytest.raises(SpoolRefused) as exc:
        for n in range(20):
            spool.enqueue(health(NOW + timedelta(seconds=n), n))
    assert exc.value.reason == "spool_full"
    assert [r.priority for r in spool.drain(100)].count(Priority.REFRIGERATION) == 1


def test_sequence_is_monotonic_across_drain_and_reboot(tmp_path: Path) -> None:
    spool = make_spool(tmp_path)
    first = [spool.enqueue(aggregate(NOW + timedelta(minutes=n), n)).seq for n in range(3)]
    spool.ack(first)
    assert spool.depth() == 0
    spool.close()

    rebooted = Spool(
        path=tmp_path / "spool" / "spool.db",
        profile=Profile.L1,
        boot_id="boot-2",
        capacity_bytes=64 * 1024,
    )
    after = rebooted.enqueue(aggregate(NOW + timedelta(hours=1), 9))
    assert after.seq > max(first)
    assert after.boot_id == "boot-2"


def test_drain_is_ordered_and_unacked_records_redeliver(tmp_path: Path) -> None:
    spool = make_spool(tmp_path)
    for n in range(5):
        spool.enqueue(aggregate(NOW + timedelta(minutes=n), n))

    batch = spool.drain(3)
    assert [r.seq for r in batch] == sorted(r.seq for r in batch)
    assert spool.depth() == 5

    spool.ack([batch[0].seq])
    assert next(r.seq for r in spool.drain(10)) == batch[1].seq


def test_prune_enforces_the_profile_horizon(tmp_path: Path) -> None:
    spool = make_spool(tmp_path)
    spool.enqueue(aggregate(NOW - timedelta(days=8), 1))
    spool.enqueue(aggregate(NOW - timedelta(days=6), 2))

    assert spool.prune(NOW) == 1
    assert [r.payload["value"] for r in spool.drain(10)] == [2]


def test_offset_beyond_tolerance_marks_windows_uncertain() -> None:
    """F14 R6: the offset is measured and stamped; device_time itself is never rewritten."""
    inside = measure_offset(NOW, NOW + timedelta(milliseconds=CLOCK_SKEW_TOLERANCE_MS - 1))
    assert not inside.time_uncertain
    assert inside.alert is None

    dead_rtc = measure_offset(NOW - timedelta(days=6), NOW)
    assert dead_rtc.time_uncertain
    assert dead_rtc.alert == "clock_skew"
    assert dead_rtc.clock_offset_ms == 6 * 86_400_000
