"""M09 / F11: windows emit k_suppressed, never a zero, and carry their own coverage."""

from __future__ import annotations

from t1.analytics.aggregation import DWELL_TIME, FOOTFALL, AggregationWindow
from t1.analytics.tracking import ClosedTrack
from t1.canon import CLOCK_SKEW_TOLERANCE_MS


def _tracks(n: int, dwell_ms: int = 60_000) -> tuple[ClosedTrack, ...]:
    return tuple(ClosedTrack(f"t{i}", "cam-1", 0, dwell_ms, samples=4) for i in range(n))


def _window(**kwargs: object) -> AggregationWindow:
    base: dict[str, object] = {"window_start": "2026-09-05T10:00:00Z"}
    base.update(kwargs)
    return AggregationWindow(**base)  # type: ignore[arg-type]


def test_a_busy_window_reports_both_metrics() -> None:
    window = _window()
    window.add(_tracks(25, dwell_ms=120_000))
    footfall, dwell = window.close()
    assert footfall.metric == FOOTFALL
    assert footfall.value == 25
    assert dwell.metric == DWELL_TIME
    assert dwell.value == 120


def test_a_thin_window_suppresses_rather_than_reporting_zero() -> None:
    window = _window()
    window.add(_tracks(2))
    footfall, _ = window.close()
    assert footfall.k_suppressed is True
    assert footfall.value is None
    assert footfall.floor == 3


def test_dwell_holds_a_far_higher_floor_than_footfall() -> None:
    window = _window()
    window.add(_tracks(5))
    footfall, dwell = window.close()
    # Five visits is enough to count people and nowhere near enough to publish how long they stayed.
    assert footfall.k_suppressed is False
    assert dwell.k_suppressed is True
    assert dwell.floor == 20


def test_a_signed_policy_may_raise_a_floor_but_not_lower_it() -> None:
    window = _window()
    window.add(_tracks(5))
    raised, _ = window.close(floors={FOOTFALL: 10})
    assert raised.floor == 10
    assert raised.k_suppressed is True

    lowered, _ = window.close(floors={FOOTFALL: 1})
    assert lowered.floor == 3


def test_a_suppressed_payload_is_marked_not_silently_zeroed() -> None:
    window = _window()
    window.add(_tracks(1))
    payload = window.close()[0].payload()
    assert payload["k_suppressed"] is True
    assert payload["value"] == 0
    assert "track_id" not in payload


def test_uncounted_tracks_do_not_inflate_footfall() -> None:
    window = _window()
    window.add((ClosedTrack("t1", "cam-1", 0, 10, samples=1), *_tracks(4)))
    footfall, _ = window.close()
    assert footfall.value == 4


def test_coverage_travels_with_every_metric_the_window_emits() -> None:
    window = _window(coverage=0.62)
    window.add(_tracks(30))
    for metric in window.close():
        assert metric.coverage == 0.62
        assert metric.degraded is True
        assert metric.payload()["coverage"] == 0.62


def test_a_window_measured_off_a_drifted_clock_says_so() -> None:
    window = _window(clock_offset_ms=CLOCK_SKEW_TOLERANCE_MS + 1)
    window.add(_tracks(30))
    footfall, _ = window.close()
    assert footfall.time_uncertain is True
    assert footfall.degraded is True
    # The value is still reported: the window happened, only its placement in time is uncertain.
    assert footfall.value == 30


def test_an_empty_window_is_suppressed_not_reported_as_zero_footfall() -> None:
    footfall, _ = _window().close()
    assert footfall.k_suppressed is True
    assert footfall.value is None


def test_median_dwell_is_used_so_one_loiterer_does_not_move_the_number() -> None:
    window = _window()
    window.add((*_tracks(20, dwell_ms=60_000), ClosedTrack("x", "cam-1", 0, 9_000_000, samples=9)))
    _, dwell = window.close()
    assert dwell.value == 60
