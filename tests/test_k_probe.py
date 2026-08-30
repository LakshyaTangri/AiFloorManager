"""k-probe suite: per-metric floors, suppression semantics, and the canon floor as a hard bound."""

from __future__ import annotations

from pathlib import Path

import pytest

from t1.canon import CANON_FLOORS, DataClass, TrustLevel
from t1.contracts import Envelope
from t1.control.egress_filter import EgressFilter
from t1.control.kanon import Window, apply, canonical_floor, effective_floor
from t1.control.policy import PolicyBundle, PolicyRejected, PolicyStore, sign
from t1.sim.harness import DEV_KEY, default_bundle

from .conftest import NOW_ISO


@pytest.mark.parametrize(("metric", "floor"), sorted(CANON_FLOORS.items()))
def test_canonical_floor_matches_canon(metric: str, floor: int) -> None:
    assert canonical_floor(metric) == floor


def test_dwell_floor_is_higher_than_footfall_floor() -> None:
    assert canonical_floor("dwell_time") > canonical_floor("footfall")


def test_policy_may_raise_a_floor() -> None:
    assert effective_floor("footfall", policy_floor=8) == 8


def test_policy_may_not_lower_a_floor() -> None:
    assert effective_floor("dwell_time", policy_floor=3) == CANON_FLOORS["dwell_time"]


def test_suppressed_window_has_no_value_rather_than_zero() -> None:
    result = apply(Window("footfall", NOW_ISO, value=2, k=2))
    assert result.k_suppressed is True
    assert result.value is None


def test_window_at_the_floor_is_released() -> None:
    result = apply(Window("footfall", NOW_ISO, value=3, k=3))
    assert result.k_suppressed is False
    assert result.value == 3


def test_bundle_below_canon_floor_is_refused(tmp_path: Path) -> None:
    bad = PolicyBundle(
        version=4,
        floors={"dwell_time": 5},
        allowed_schemas=default_bundle().allowed_schemas,
        field_allowlist=default_bundle().field_allowlist,
    )
    store = PolicyStore(key=DEV_KEY, floor_path=tmp_path / "floor")
    with pytest.raises(PolicyRejected) as exc:
        store.load(bad, sign(bad, DEV_KEY))
    assert exc.value.reason == "floor_below_canon"
    assert store.bridge_enabled is False


def test_unknown_metric_falls_back_to_the_default_floor(egress: EgressFilter) -> None:
    env = Envelope(
        device_id="d",
        boot_id="b",
        seq=1,
        device_time=NOW_ISO,
        schema="rtl.aggregate.v1",
        data_class=DataClass.C1_AGGREGATE,
        purpose="analytics",
        trust_level=TrustLevel.SOFTWARE_BOUND,
        payload={
            "metric": "unlisted_metric",
            "value": 1,
            "window_start": NOW_ISO,
            "k_suppressed": False,
        },
        policy_version="3",
        metric="unlisted_metric",
        k_value=1,
    )
    assert egress.evaluate(env).reason == "k_below_floor"
