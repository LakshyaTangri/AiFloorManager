"""Bridge behaviour (SPEC §15, F12, F14).

"Outbound only" and "everything passes the filter" are claims about code paths, so these tests
attack the paths rather than the configuration.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from t1.bridge import backoff
from t1.bridge.mqtt import (
    INGEST_ENDPOINT,
    MQTT_ENDPOINT,
    Bridge,
    BridgeRefused,
    assert_outbound_only,
)
from t1.canon import DataClass, Priority, Profile, TrustLevel
from t1.contracts import Envelope
from t1.control.audit_chain import AuditChain
from t1.control.egress_filter import EgressFilter
from t1.control.policy import PolicyBundle, PolicyRejected, PolicyStore, sign
from t1.control.spool import ClockStamp, Spool, SpoolItem, measure_offset
from t1.sim.harness import DEV_KEY

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
DEVICE = "rtl-l1-0001"


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bytes]] = []

    def send(self, endpoint: str, topic: str, body: bytes) -> None:
        self.calls.append((endpoint, topic, body))


class ListeningTransport(FakeTransport):
    def listen(self, port: int) -> None:  # pragma: no cover - must never be reachable
        raise AssertionError("inbound")


def make_bridge(egress: EgressFilter, transport: FakeTransport) -> Bridge:
    return Bridge(
        device_id=DEVICE,
        trust_level=TrustLevel.SOFTWARE_BOUND,
        egress=egress,
        transport=transport,
    )


def aggregate_envelope(policy_version: str = "3", **over: object) -> Envelope:
    base = {
        "device_id": DEVICE,
        "boot_id": "boot-1",
        "seq": 1,
        "device_time": NOW.isoformat(),
        "schema": "rtl.aggregate.v1",
        "data_class": DataClass.C1_AGGREGATE,
        "purpose": "operations",
        "trust_level": TrustLevel.SOFTWARE_BOUND,
        "payload": {
            "metric": "footfall",
            "value": 41,
            "window_start": NOW.isoformat(),
            "k_suppressed": False,
        },
        "metric": "footfall",
        "k_value": 12,
        "policy_version": policy_version,
    }
    base.update(over)
    return Envelope(**base)  # type: ignore[arg-type]


def spool_with(tmp_path: Path, items: list[SpoolItem]) -> Spool:
    spool = Spool(tmp_path / "spool.db", Profile.L1, boot_id="boot-1")
    for item in items:
        spool.enqueue(item)
    return spool


def aggregate_item(at: datetime, value: int) -> SpoolItem:
    return SpoolItem(
        schema="rtl.aggregate.v1",
        data_class=DataClass.C1_AGGREGATE,
        priority=Priority.AGGREGATE,
        device_time=at,
        payload={
            "metric": "footfall",
            "value": value,
            "window_start": at.isoformat(),
            "k_suppressed": False,
        },
        metric="footfall",
        window_seconds=300,
        k_value=12,
    )


def test_a_transport_that_can_listen_is_refused(egress: EgressFilter) -> None:
    with pytest.raises(BridgeRefused) as exc:
        make_bridge(egress, ListeningTransport())
    assert exc.value.reason == "inbound_capability_present"


def test_the_bridge_exposes_no_inbound_surface(egress: EgressFilter) -> None:
    bridge = make_bridge(egress, FakeTransport())
    assert bridge.accepts_inbound is False
    assert not any(hasattr(bridge, name) for name in ("bind", "listen", "accept", "serve_forever"))
    assert_outbound_only(bridge.transport)


@pytest.mark.parametrize(
    ("endpoint", "reason"),
    [
        ("mqtt://iot.pulsemanager.ai:1883", "scheme_forbidden"),
        ("mqtts://iot.pulsemanager.ai:8883", "port_forbidden"),
        ("http://iot.pulsemanager.ai:443", "scheme_forbidden"),
    ],
)
def test_only_443_and_only_tls_schemes(egress: EgressFilter, endpoint: str, reason: str) -> None:
    with pytest.raises(BridgeRefused) as exc:
        Bridge(
            device_id=DEVICE,
            trust_level=TrustLevel.SOFTWARE_BOUND,
            egress=egress,
            transport=FakeTransport(),
            mqtt_endpoint=endpoint,
        )
    assert exc.value.reason == reason


def test_publish_is_filtered_before_it_is_sent(egress: EgressFilter) -> None:
    transport = FakeTransport()
    bridge = make_bridge(egress, transport)

    good = bridge.publish(aggregate_envelope())
    assert good.verdict.accepted
    assert transport.calls[0][0] == MQTT_ENDPOINT

    hostile = bridge.publish(
        aggregate_envelope(
            payload={"metric": "footfall", "value": 3, "note": "man in a red jacket loitering"}
        )
    )
    assert hostile.verdict.reason == "field_not_allowed"
    assert hostile.endpoint is None
    assert len(transport.calls) == 1


def test_an_unloadable_policy_takes_the_bridge_down(tmp_path: Path) -> None:
    """F12 R2: bridge disabled, nothing published - and local ingest is untouched by this path."""
    store = PolicyStore(key=DEV_KEY, floor_path=tmp_path / "audit" / "floor")
    tampered = PolicyBundle(
        version=4,
        floors={"footfall": 3},
        allowed_schemas={"rtl.aggregate.v1": DataClass.C1_AGGREGATE.value},
        field_allowlist={"rtl.aggregate.v1": ("metric", "value")},
    )
    with pytest.raises(PolicyRejected):
        store.load(tampered, sign(tampered, b"attacker-key"))

    transport = FakeTransport()
    bridge = make_bridge(
        EgressFilter(policy=store, chain=AuditChain(tmp_path / "chain.jsonl")), transport
    )
    result = bridge.publish(aggregate_envelope())
    assert result.verdict.reason == "policy_invalid"
    assert transport.calls == []


def test_backfill_preserves_order_and_original_timestamps(
    egress: EgressFilter, tmp_path: Path
) -> None:
    times = [NOW - timedelta(days=7) + timedelta(hours=n) for n in range(4)]
    spool = spool_with(tmp_path, [aggregate_item(t, n) for n, t in enumerate(times)])
    transport = FakeTransport()
    bridge = make_bridge(egress, transport)

    stamp = measure_offset(NOW - timedelta(days=6), NOW)
    results = bridge.backfill(spool, stamp)

    assert [r.envelope.device_time for r in results] == [t.isoformat() for t in times]
    assert all(r.envelope.backfill for r in results)
    assert all(r.envelope.clock_offset_ms == stamp.clock_offset_ms for r in results)
    assert all(r.envelope.time_uncertain for r in results)
    assert {call[0] for call in transport.calls} == {INGEST_ENDPOINT}
    assert spool.depth() == 0


def test_rejected_backfill_stays_in_the_spool(egress: EgressFilter, tmp_path: Path) -> None:
    """An accepted record is acked; a refused one is kept, not silently discarded."""
    bad = aggregate_item(NOW - timedelta(days=1), 1)
    spool = spool_with(tmp_path, [bad])
    spool.enqueue(
        SpoolItem(
            schema="rtl.unknown.v1",
            data_class=DataClass.C1_AGGREGATE,
            priority=Priority.AGGREGATE,
            device_time=NOW,
            payload={"metric": "footfall"},
            metric="footfall",
            k_value=12,
        )
    )
    bridge = make_bridge(egress, FakeTransport())
    results = bridge.backfill(spool, ClockStamp(0, False))

    assert [r.verdict.reason for r in results] == [None, "schema_unknown"]
    assert [r.schema for r in spool.drain(10)] == ["rtl.unknown.v1"]


def test_backfill_is_rate_limited_per_batch(egress: EgressFilter, tmp_path: Path) -> None:
    spool = spool_with(tmp_path, [aggregate_item(NOW - timedelta(minutes=n), n) for n in range(10)])
    bridge = make_bridge(egress, FakeTransport())
    assert len(bridge.backfill(spool, ClockStamp(0, False), limit=4)) == 4
    assert spool.depth() == 6


def test_backoff_window_doubles_and_caps() -> None:
    assert backoff.window_seconds(0) == 1.0
    assert backoff.window_seconds(4) == 16.0
    assert backoff.window_seconds(40) == 900.0


def test_jitter_is_stable_per_device_and_spread_across_a_fleet() -> None:
    """F14 AC3: 1,000 devices reconnecting must not land in the same second."""
    ids = [f"rtl-l1-{n:05d}" for n in range(1000)]
    assert backoff.next_delay(9, ids[0]) == backoff.next_delay(9, ids[0])

    buckets = Counter(int(backoff.next_delay(9, device_id)) for device_id in ids)
    assert max(buckets.values()) / len(ids) <= 0.05
