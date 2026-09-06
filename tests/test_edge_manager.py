"""M09 / F19: the local loop, its closed vocabulary, and the caps that keep it credible."""

from __future__ import annotations

from dataclasses import replace

from t1.analytics.edge_manager import (
    REMEDY,
    Action,
    ActionLibrary,
    Cause,
    Deviation,
    EdgeManager,
    Explanation,
    Factor,
    Recommendation,
    Refusal,
    explain,
    sign_library,
)
from t1.canon import MAX_RECOMMENDATIONS_PER_SITE_PER_DAY

KEY = b"action-library-test-key"

STAFFING = Action(
    action_id="open_second_till",
    metric="entry_wait",
    threshold=2.0,
    params=("zone_id", "from_time"),
    expected_impact="entry_wait -25%",
    confidence_floor=0.7,
    max_per_site_per_day=1,
)
QUEUE = replace(STAFFING, action_id="reposition_greeter", metric="dwell_time")
ZONING = replace(STAFFING, action_id="reopen_side_aisle", metric="zone_flow")


def _library(actions: tuple[Action, ...] = (STAFFING, QUEUE, ZONING)) -> ActionLibrary:
    return ActionLibrary(library_version="actions-2026.09.1", actions=actions)


def _manager(library: ActionLibrary | None = None, key: bytes = KEY) -> EdgeManager:
    lib = library or _library()
    return EdgeManager(
        key=KEY, library=lib, library_signature=sign_library(lib, key), day="2026-09-05"
    )


def _deviation(metric: str = "entry_wait", windows: int = 3, observed: float = 240.0) -> Deviation:
    return Deviation(
        metric=metric,
        zone_id="entrance",
        observed=observed,
        baseline=120.0,
        sigma=30.0,
        windows=windows,
    )


def _explanation(confidence: float = 0.82) -> Explanation:
    return Explanation(Cause.STAFFING_SHORTFALL, (Factor.TILL_COUNT_LOW,), confidence)


def test_a_persistent_significant_deviation_is_detected() -> None:
    deviation = _deviation()
    assert deviation.sigmas == 4.0
    assert deviation.direction == "above"
    assert deviation.significant is True
    assert deviation.persistent is True


def test_a_single_window_excursion_is_not_acted_on() -> None:
    manager = _manager()
    result = manager.recommend(_deviation(windows=1), _explanation(), {}, ("w1",))
    assert result is Refusal.NOT_PERSISTENT


def test_an_explanation_is_enums_only() -> None:
    payload = _explanation().as_dict()
    assert payload["cause_enum"] == "staffing_shortfall"
    assert payload["contributing_factors"] == ["till_count_low"]
    assert all(not isinstance(v, str) or v in {"staffing_shortfall"} for v in payload.values())


def test_a_free_text_cause_is_replaced_not_sanitised() -> None:
    result = explain("man in a red jacket blocking the aisle", [], 0.9)
    assert result.cause is Cause.UNKNOWN
    assert result.factors == ()
    assert result.confidence == 0.30


def test_one_off_set_factor_invalidates_the_whole_explanation() -> None:
    result = explain("staffing_shortfall", ["till_count_low", "customer wore a hoodie"], 0.9)
    assert result.cause is Cause.UNKNOWN


def test_a_valid_recommendation_carries_impact_evidence_and_library_version() -> None:
    manager = _manager()
    result = manager.recommend(
        _deviation(), _explanation(), {"zone_id": "entrance", "from_time": "10:00"}, ("w1", "w2")
    )
    assert isinstance(result, Recommendation)
    payload = result.as_dict()
    assert payload["action_id"] == "open_second_till"
    assert payload["action_library_ver"] == "actions-2026.09.1"
    assert payload["expected_impact"] == "entry_wait -25%"
    assert payload["evidence_refs"] == ["w1", "w2"]


def test_params_outside_the_signed_action_are_dropped() -> None:
    manager = _manager()
    result = manager.recommend(
        _deviation(), _explanation(), {"zone_id": "entrance", "note": "the tall man"}, ("w1",)
    )
    assert isinstance(result, Recommendation)
    assert result.params == {"zone_id": "entrance"}


def test_no_recommendation_is_issued_from_an_unsigned_library() -> None:
    manager = _manager(key=b"someone-elses-key")
    assert manager.library_valid is False
    assert (
        manager.recommend(_deviation(), _explanation(), {}, ()) is Refusal.LIBRARY_SIGNATURE_INVALID
    )


def test_a_trigger_with_no_matching_signed_action_is_refused() -> None:
    manager = _manager(library=_library((QUEUE,)))
    assert manager.recommend(_deviation(), _explanation(), {}, ()) is Refusal.ACTION_NOT_IN_LIBRARY


def test_weak_evidence_reports_the_deviation_without_advising() -> None:
    manager = _manager()
    assert (
        manager.recommend(_deviation(), _explanation(confidence=0.4), {}, ())
        is Refusal.CONFIDENCE_BELOW_FLOOR
    )
    briefing = manager.brief((_deviation(),), (_explanation(0.4),), t2_reachable=True)
    assert briefing.recommendations == ()
    assert len(briefing.as_dict()["deviations"]) == 1  # type: ignore[arg-type]


def test_the_same_action_is_not_repeated_within_a_day() -> None:
    manager = _manager()
    assert isinstance(manager.recommend(_deviation(), _explanation(), {}, ()), Recommendation)
    assert manager.recommend(_deviation(), _explanation(), {}, ()) is Refusal.ACTION_DAILY_CAP


def test_the_site_cap_holds_across_different_actions() -> None:
    extra = replace(STAFFING, action_id="fourth_action", metric="footfall")
    manager = _manager(library=_library((STAFFING, QUEUE, ZONING, extra)))
    for metric in ("entry_wait", "dwell_time", "zone_flow"):
        assert isinstance(
            manager.recommend(_deviation(metric=metric), _explanation(), {}, ()), Recommendation
        )
    assert len(manager.issued) == MAX_RECOMMENDATIONS_PER_SITE_PER_DAY
    assert (
        manager.recommend(_deviation(metric="footfall"), _explanation(), {}, ())
        is Refusal.SITE_DAILY_CAP
    )


def test_the_cap_resets_with_the_day() -> None:
    manager = _manager()
    manager.recommend(_deviation(), _explanation(), {}, ())
    manager.new_day("2026-09-06")
    assert isinstance(manager.recommend(_deviation(), _explanation(), {}, ()), Recommendation)
    assert manager.day == "2026-09-06"


def test_the_briefing_renders_with_t2_unreachable() -> None:
    manager = _manager()
    manager.recommend(_deviation(), _explanation(), {}, ("w1",))
    briefing = manager.brief((_deviation(),), (_explanation(),), t2_reachable=False)
    assert briefing.generated_offline is True
    assert len(briefing.recommendations) == 1
    assert briefing.as_dict()["day"] == "2026-09-05"


def test_every_refusal_has_a_remedy() -> None:
    assert set(REMEDY) == set(Refusal)
    assert all(REMEDY[r].strip() for r in Refusal)
