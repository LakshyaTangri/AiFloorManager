"""age-probe suite (F09, D-006).

The gate is only worth anything if the suppression happens *before* a track exists and if no age
value survives the boundary. Both are asserted structurally, not by inspecting output strings.
"""

from __future__ import annotations

import dataclasses
import typing

import pytest

from t1.canon import AGE_GATE_THRESHOLD
from t1.contracts import BOUNDARY_CROSSING, AgeBand, BoundaryDetection, Frame, SealedDetection
from t1.sealed.guard import BoundaryViolation, assert_boundary_clean
from t1.sealed.pipeline import SealedPipeline, band_for_age, tracks_from


def _pipeline(ages: tuple[float, ...]) -> SealedPipeline:
    def trunk(frame: Frame) -> list[SealedDetection]:
        return [
            SealedDetection(
                frame.stream_id, frame.ts_ms, (0, 0, 10, 10), 0.9, band_for_age(age), age
            )
            for age in ages
        ]

    return SealedPipeline(
        trunk=trunk,
        redactor=lambda f: Frame(f.stream_id, f.ts_ms, b"redacted", redacted=True),
        model_bundle="test-trunk",
        redaction_version="test-redact",
    )


@pytest.mark.parametrize("age", [0.0, 5.0, 15.0, 21.0, 21.9])
def test_under_threshold_never_becomes_a_track(age: float) -> None:
    pipeline = _pipeline((age,))
    out = pipeline.process(Frame("cam-1", 0, b"pixels"))
    assert out is not None
    assert out.detections == ()
    assert tracks_from(iter([out])) == []
    assert pipeline.counters.minor_suppressed_n == 1


@pytest.mark.parametrize("age", [22.0, 30.0, 74.0])
def test_adult_passes_the_gate(age: float) -> None:
    out = _pipeline((age,)).process(Frame("cam-1", 0, b"pixels"))
    assert out is not None
    assert len(out.detections) == 1
    assert out.detections[0].age_gate_passed is True


def test_threshold_is_22_not_18() -> None:
    assert AGE_GATE_THRESHOLD == 22
    assert band_for_age(21.99) is AgeBand.UNDER_22
    assert band_for_age(22.0) is AgeBand.ADULT


def test_indeterminate_is_suppressed() -> None:
    def trunk(frame: Frame) -> list[SealedDetection]:
        return [SealedDetection(frame.stream_id, 0, (0, 0, 1, 1), 0.4, AgeBand.INDETERMINATE, 0.0)]

    pipeline = SealedPipeline(
        trunk=trunk,
        redactor=lambda f: Frame(f.stream_id, f.ts_ms, b"r", redacted=True),
        model_bundle="t",
        redaction_version="r",
    )
    out = pipeline.process(Frame("cam-1", 0, b"pixels"))
    assert out is not None and out.detections == ()


def test_boundary_types_carry_no_age_value() -> None:
    assert_boundary_clean()
    fields = {f.name for f in dataclasses.fields(BoundaryDetection)}
    assert "age_gate_passed" in fields
    assert not {f for f in fields if "age" in f and f != "age_gate_passed"}
    assert typing.get_type_hints(BoundaryDetection)["age_gate_passed"] is bool


def test_guard_catches_an_age_field_added_to_a_boundary_type() -> None:
    @dataclasses.dataclass(frozen=True)
    class Leaky:
        stream_id: str
        age_band: AgeBand

    with pytest.raises(BoundaryViolation):
        assert_boundary_clean([Leaky])


def test_guard_catches_an_age_typed_field_under_another_name() -> None:
    @dataclasses.dataclass(frozen=True)
    class Sneaky:
        stream_id: str
        bucket: AgeBand | None

    with pytest.raises(BoundaryViolation):
        assert_boundary_clean([Sneaky])


def test_sealed_detection_is_not_a_boundary_type() -> None:
    assert SealedDetection not in BOUNDARY_CROSSING
    assert BoundaryDetection in BOUNDARY_CROSSING


def test_suppression_rate_is_a_ratio_with_no_per_person_content() -> None:
    pipeline = _pipeline((17.0, 40.0, 19.0, 55.0))
    pipeline.process(Frame("cam-1", 0, b"pixels"))
    assert pipeline.counters.minor_suppression_rate == 0.5
