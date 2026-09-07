"""M08 unsealed half: tracks are built from post-gate detections only, and are transient on L1."""

from __future__ import annotations

import inspect
from dataclasses import fields

from t1.analytics import tracking
from t1.analytics.tracking import REMEDY, ClosedTrack, Refusal, Tracker, iou
from t1.canon import TrustLevel
from t1.contracts import BoundaryDetection

BUNDLE = "det-age-trunk-2026.09.1"


def _detection(
    ts_ms: int, bbox: tuple[int, int, int, int] = (0, 0, 10, 20), stream: str = "cam-1"
) -> BoundaryDetection:
    return BoundaryDetection(
        stream_id=stream,
        ts_ms=ts_ms,
        bbox=bbox,
        confidence=0.9,
        age_gate_passed=True,
        model_bundle=BUNDLE,
    )


def test_a_moving_person_stays_one_track() -> None:
    tracker = Tracker()
    for step in range(4):
        tracker.update((_detection(step * 500, (step * 2, 0, 10, 20)),), now_ms=step * 500)
    assert tracker.started == 1
    assert len(tracker.open_tracks) == 1


def test_a_second_person_elsewhere_in_frame_is_a_second_track() -> None:
    tracker = Tracker()
    tracker.update((_detection(0, (0, 0, 10, 20)), _detection(0, (400, 0, 10, 20))), now_ms=0)
    assert tracker.started == 2


def test_two_overlapping_shoppers_are_two_visits_not_one() -> None:
    """Both boxes overlap the same open track; one detection may not take a track twice."""
    tracker = Tracker()
    tracker.update((_detection(0, (0, 0, 10, 20)),), now_ms=0)
    tracker.update(
        (_detection(200, (1, 0, 10, 20)), _detection(200, (2, 0, 10, 20))),
        now_ms=200,
    )
    assert tracker.started == 2
    assert len(tracker.open_tracks) == 2


def test_a_gap_closes_the_track_and_yields_a_dwell() -> None:
    tracker = Tracker()
    tracker.update((_detection(0),), now_ms=0)
    tracker.update((_detection(1_000, (1, 0, 10, 20)),), now_ms=1_000)
    closed = tracker.close_stale(now_ms=9_000)
    assert len(closed) == 1
    assert closed[0].dwell_ms == 1_000
    assert closed[0].counts is True
    assert tracker.closed == 1


def test_a_single_stray_detection_does_not_count_as_a_visit() -> None:
    tracker = Tracker()
    tracker.update((_detection(0),), now_ms=0)
    closed = tracker.close_stale(now_ms=9_000)
    assert closed[0].samples == 1
    assert closed[0].counts is False


def test_the_same_box_on_a_different_stream_is_a_different_person() -> None:
    tracker = Tracker()
    tracker.update((_detection(0, stream="cam-1"),), now_ms=0)
    tracker.update((_detection(100, stream="cam-2"),), now_ms=100)
    assert tracker.started == 2


def test_close_all_drains_the_tracker() -> None:
    tracker = Tracker()
    tracker.update((_detection(0), _detection(0, (400, 0, 10, 20))), now_ms=0)
    assert len(tracker.close_all()) == 2
    assert tracker.open_tracks == ()


def test_l1_refuses_to_persist_a_trace() -> None:
    tracker = Tracker(trust_level=TrustLevel.SOFTWARE_BOUND)
    tracker.update((_detection(0),), now_ms=0)
    tracker.update((_detection(500, (1, 0, 10, 20)),), now_ms=500)
    (track,) = tracker.close_stale(now_ms=9_000)
    assert tracker.persist(track) is Refusal.C3_FORBIDDEN_AT_REST


def test_an_attested_profile_may_persist_a_trace() -> None:
    tracker = Tracker(trust_level=TrustLevel.MODULE_ATTESTED)
    tracker.update((_detection(0),), now_ms=0)
    (track,) = tracker.close_all()
    assert tracker.persist(track) is None


def test_a_closed_track_carries_no_person_and_no_pixels() -> None:
    names = {f.name for f in fields(ClosedTrack)}
    assert names == {"track_id", "stream_id", "first_ms", "last_ms", "samples"}
    assert "age" not in " ".join(names)


def test_tracking_cannot_be_fed_anything_from_the_sealed_side() -> None:
    """No public entry point here accepts a Frame or a SealedDetection."""
    sealed_names = {"Frame", "SealedDetection", "SealedOutput", "AgeBand"}
    for name, member in inspect.getmembers(tracking, callable):
        if name.startswith("_"):
            continue
        annotations = " ".join(str(p.annotation) for p in _params(member))
        assert not sealed_names & set(annotations.replace("[", " ").split()), name


def _params(member: object) -> tuple[inspect.Parameter, ...]:
    try:
        return tuple(inspect.signature(member).parameters.values())  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return ()


def test_iou_is_zero_for_disjoint_boxes() -> None:
    assert iou((0, 0, 10, 10), (100, 100, 10, 10)) == 0.0
    assert iou((0, 0, 10, 10), (0, 0, 10, 10)) == 1.0


def test_every_refusal_has_a_remedy() -> None:
    assert set(REMEDY) == set(Refusal)
    assert all(REMEDY[r].strip() for r in Refusal)
