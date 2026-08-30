"""sealed-probe suite (D-006, F07, F08): topology, not diligence."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from t1.contracts import AgeBand, Frame, SealedDetection
from t1.sealed.guard import SealedEgressError, SealedEnvironment, attempt_egress
from t1.sealed.pipeline import ProhibitedZone, SealedPipeline, SealedPipelineDown
from t1.tools.sealed_probe import run as probe_run


def _detection(frame: Frame) -> list[SealedDetection]:
    return [SealedDetection(frame.stream_id, frame.ts_ms, (0, 0, 1, 1), 0.9, AgeBand.ADULT, 40.0)]


def _ok_redactor(frame: Frame) -> Frame:
    return Frame(frame.stream_id, frame.ts_ms, b"redacted", redacted=True)


def _pipeline(
    trunk: Callable[[Frame], list[SealedDetection]] = _detection,
    redactor: Callable[[Frame], Frame | None] = _ok_redactor,
    zone_allows: Callable[[str], bool] = lambda _stream_id: True,
    environment: SealedEnvironment | None = None,
) -> SealedPipeline:
    return SealedPipeline(
        trunk=trunk,
        redactor=redactor,
        model_bundle="t",
        redaction_version="r",
        zone_allows=zone_allows,
        environment=environment or SealedEnvironment(),
    )


def test_probe_cli_all_checks_pass() -> None:
    assert {name: reason for name, reason in probe_run().items() if reason} == {}


@pytest.mark.parametrize(
    ("env", "reason"),
    [
        (SealedEnvironment(network_namespace=True), "sealed_process_has_network"),
        (
            SealedEnvironment(writable_persistent_paths=("/data",)),
            "sealed_process_has_writable_path",
        ),
        (SealedEnvironment(core_dumps_enabled=True), "sealed_process_core_dumps_enabled"),
        (SealedEnvironment(swap_enabled=True), "sealed_process_swap_enabled"),
    ],
)
def test_pipeline_refuses_to_start_in_an_unsealed_environment(
    env: SealedEnvironment, reason: str
) -> None:
    with pytest.raises(SealedEgressError) as exc:
        _pipeline(environment=env)
    assert reason in str(exc.value)


def test_egress_attempt_from_inside_raises() -> None:
    with pytest.raises(SealedEgressError):
        attempt_egress("https://ingest.example.invalid")


def test_redaction_failure_drops_the_frame() -> None:
    pipeline = _pipeline(redactor=lambda _f: None)
    assert pipeline.process(Frame("cam-1", 0, b"pixels")) is None
    assert pipeline.counters.frames_dropped_redaction == 1


def test_a_redactor_that_lies_about_redacting_is_not_trusted() -> None:
    pipeline = _pipeline(redactor=lambda f: Frame(f.stream_id, f.ts_ms, f.pixels, redacted=False))
    assert pipeline.process(Frame("cam-1", 0, b"pixels")) is None
    assert pipeline.counters.frames_dropped_redaction == 1


def test_redactor_crash_stops_the_stream_with_no_unsealed_fallback() -> None:
    def boom(_frame: Frame) -> Frame:
        raise RuntimeError("segfault-equivalent")

    pipeline = _pipeline(redactor=boom)
    with pytest.raises(SealedPipelineDown):
        pipeline.process(Frame("cam-1", 0, b"pixels"))
    assert pipeline.healthy is False
    with pytest.raises(SealedPipelineDown):
        pipeline.process(Frame("cam-1", 1, b"pixels"))


def test_trunk_crash_fails_closed() -> None:
    def boom(_frame: Frame) -> list[SealedDetection]:
        raise RuntimeError("model load failure")

    pipeline = _pipeline(trunk=boom)
    with pytest.raises(SealedPipelineDown):
        pipeline.process(Frame("cam-1", 0, b"pixels"))


def test_prohibited_zone_refuses_instantiation() -> None:
    pipeline = _pipeline(zone_allows=lambda stream_id: stream_id != "changing-room")
    with pytest.raises(ProhibitedZone):
        pipeline.instantiate("changing-room")
    with pytest.raises(ProhibitedZone):
        pipeline.process(Frame("changing-room", 0, b"pixels"))
    assert pipeline.counters.frames_in == 0


def test_only_redacted_pixels_cross() -> None:
    out = _pipeline().process(Frame("cam-1", 0, b"raw-pixels"))
    assert out is not None
    assert out.frame.pixels == b"redacted"
    assert out.frame.redaction_version == "r"
