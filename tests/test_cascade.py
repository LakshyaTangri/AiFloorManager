"""M07 / F07: admission, stage gating and what overload may never skip."""

from __future__ import annotations

from t1.canon import Profile, TrustLevel
from t1.contracts import AgeBand, Frame, SealedDetection
from t1.control.capability import CapabilityVector
from t1.pipeline.cascade import (
    REMEDY,
    Cascade,
    Drop,
    Refusal,
    Stage,
)
from t1.sealed.pipeline import SealedPipeline

BUNDLE = "det-age-trunk-2026.09.1"


def _detections(frame: Frame, confidence: float = 0.9) -> list[SealedDetection]:
    return [
        SealedDetection(frame.stream_id, frame.ts_ms, (0, 0, 10, 20), confidence, AgeBand.ADULT, 40)
    ]


def _cascade(
    *,
    stream_cap: int = 2,
    profile: Profile = Profile.L1,
    budget_fps: float = 5.0,
    motion: bool = True,
    confidence: float = 0.9,
    redaction_fails: bool = False,
) -> Cascade:
    pipeline = SealedPipeline(
        trunk=lambda frame: _detections(frame, confidence),
        redactor=lambda frame: (
            None
            if redaction_fails
            else Frame(frame.stream_id, frame.ts_ms, b"redacted", redacted=True)
        ),
        model_bundle=BUNDLE,
        redaction_version="redact-1",
        motion=lambda _frame: motion,
    )
    return Cascade(
        pipeline=pipeline,
        capability=CapabilityVector(
            profile=profile,
            trust_level=TrustLevel.SOFTWARE_BOUND,
            adapter_cap=3,
            stream_cap=stream_cap,
        ),
        model_bundle=BUNDLE,
        budget_fps=budget_fps,
    )


def test_stream_cap_is_enforced_before_any_frame_is_decoded() -> None:
    cascade = _cascade(stream_cap=2)
    assert cascade.admit("cam-1") is None
    assert cascade.admit("cam-2") is None
    assert cascade.admit("cam-3") is Refusal.STREAM_CAP_EXCEEDED
    assert cascade.admitted == frozenset({"cam-1", "cam-2"})
    assert cascade.counters.offered == 0


def test_admitting_the_same_stream_twice_does_not_consume_a_slot() -> None:
    cascade = _cascade(stream_cap=1)
    assert cascade.admit("cam-1") is None
    assert cascade.admit("cam-1") is None


def test_an_unadmitted_stream_is_refused_by_name() -> None:
    cascade = _cascade()
    result = cascade.offer(Frame("cam-9", 0, b"pixels"))
    assert result.refusal is Refusal.STREAM_NOT_ADMITTED
    assert result.output is None


def test_l1_decodes_keyframes_only() -> None:
    cascade = _cascade(profile=Profile.L1)
    cascade.admit("cam-1")
    assert cascade.keyframe_only is True
    assert cascade.offer(Frame("cam-1", 0, b"pixels"), keyframe=False).drop is Drop.NON_KEYFRAME
    assert cascade.counters.entered.get(Stage.S1_TRUNK) is None


def test_l3_is_not_keyframe_limited() -> None:
    cascade = _cascade(profile=Profile.L3)
    cascade.admit("cam-1")
    assert cascade.keyframe_only is False
    assert cascade.offer(Frame("cam-1", 0, b"pixels"), keyframe=False).processed is True


def test_no_motion_means_the_trunk_does_not_run() -> None:
    cascade = _cascade(motion=False)
    cascade.admit("cam-1")
    for index in range(4):
        assert cascade.offer(Frame("cam-1", index * 1000, b"pixels")).drop is Drop.NO_MOTION
    assert cascade.counters.entered[Stage.S0_MOTION] == 4
    assert Stage.S1_TRUNK not in cascade.counters.entered


def test_overload_drops_frames_and_never_skips_a_sealed_stage() -> None:
    cascade = _cascade(budget_fps=2)
    cascade.admit("cam-1")
    results = [cascade.offer(Frame("cam-1", 100 * i, b"pixels")) for i in range(6)]

    processed = [r for r in results if r.processed]
    dropped = [r for r in results if r.drop is Drop.OVERLOAD]
    assert len(processed) == 2
    assert len(dropped) == 4
    # Every processed frame went through all four sealed stages; none was decoded and shortcut.
    for stage in (Stage.S0_MOTION, Stage.S1_TRUNK, Stage.AGE_GATE, Stage.REDACT):
        assert cascade.counters.entered[stage] == len(processed)


def test_coverage_falls_under_overload_and_is_reported() -> None:
    cascade = _cascade(budget_fps=2)
    cascade.admit("cam-1")
    for i in range(10):
        cascade.offer(Frame("cam-1", 100 * i, b"pixels"))

    quality = cascade.data_quality()
    assert quality.frames_offered == 10
    assert quality.coverage < 1.0
    assert quality.degraded is True
    assert quality.as_dict()["frames_processed"] == quality.frames_processed


def test_budget_recovers_once_the_second_has_passed() -> None:
    cascade = _cascade(budget_fps=2)
    cascade.admit("cam-1")
    assert cascade.offer(Frame("cam-1", 0, b"pixels")).processed is True
    assert cascade.offer(Frame("cam-1", 10, b"pixels")).processed is True
    assert cascade.offer(Frame("cam-1", 20, b"pixels")).drop is Drop.OVERLOAD
    assert cascade.offer(Frame("cam-1", 5_000, b"pixels")).processed is True


def test_redaction_failure_is_a_drop_not_a_passthrough() -> None:
    cascade = _cascade(redaction_fails=True)
    cascade.admit("cam-1")
    result = cascade.offer(Frame("cam-1", 0, b"pixels"))
    assert result.drop is Drop.REDACTION_FAILED
    assert result.output is None


def test_a_dead_sealed_process_stops_the_stream_with_no_unsealed_path() -> None:
    cascade = _cascade()
    cascade.admit("cam-1")
    cascade.pipeline.crash()

    result = cascade.offer(Frame("cam-1", 0, b"pixels"))
    assert result.refusal is Refusal.SEALED_PIPELINE_DOWN
    assert result.output is None
    assert cascade.admitted == frozenset()
    # The stream stays stopped: the next frame is refused too, and never processed.
    assert cascade.offer(Frame("cam-1", 1, b"pixels")).refusal is Refusal.STREAM_NOT_ADMITTED
    assert cascade.counters.processed == 0


def test_provenance_carries_bundle_and_confidence() -> None:
    cascade = _cascade()
    cascade.admit("cam-1")
    result = cascade.offer(Frame("cam-1", 0, b"pixels"))
    assert [p.as_dict() for p in result.provenance] == [
        {"stage": Stage.S1_TRUNK.value, "model_bundle": BUNDLE, "confidence": 0.9}
    ]


def test_s3_sees_only_what_s2_left_unresolved() -> None:
    cascade = _cascade(confidence=0.9)
    cascade.admit("cam-1")
    confident = cascade.offer(Frame("cam-1", 0, b"pixels"))
    assert confident.output is not None
    resolved = cascade.s2_candidates(confident.output)
    assert cascade.s3_candidates(resolved) == ()
    assert Stage.S3_RESOLVE not in cascade.counters.entered

    unsure = _cascade(confidence=0.4)
    unsure.admit("cam-1")
    weak = unsure.offer(Frame("cam-1", 0, b"pixels"))
    assert weak.output is not None
    assert len(unsure.s3_candidates(unsure.s2_candidates(weak.output))) == 1
    assert unsure.counters.entered[Stage.S3_RESOLVE] == 1


def test_every_refusal_has_a_remedy() -> None:
    assert set(REMEDY) == set(Refusal)
    assert all(REMEDY[r].strip() for r in Refusal)
