"""Decode admission and cascade orchestration (F07, M07).

The cascade is a sequence of gates, and the only interesting property is which gate may be skipped
under load:

    S0 motion -> S1 trunk -> AGE GATE -> REDACT || boundary || S2 tracking -> S3 resolve
    \\_______________ sealed process (D-006) ______________/

F07 R4 says overload degrades by dropping *frames*, never by skipping stages. So a frame is either
refused at admission — before a single pixel is decoded — or it goes through every sealed stage. The
code has no path that decodes a frame and then bypasses the gate or the redactor, which is why
`admit` and `process` are separate calls: the load decision is taken where no pixel exists yet.

Dropping frames costs coverage, and coverage is reported rather than hidden: `data_quality()`
returns the fraction of offered frames that were actually processed, which is what makes a busy
Saturday visible as a data-quality note instead of as a quiet undercount.

This module does not decode. There is no demuxer, no keyframe parser and no scheduler thread; it
decides what a decoder must do and counts what it did.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Final

from t1.canon import Profile
from t1.contracts import BoundaryDetection, Frame
from t1.control.capability import CapabilityVector
from t1.sealed.pipeline import SealedOutput, SealedPipeline, SealedPipelineDown

# L1 decodes keyframes only (D-001): the RAM budget assumes it, so it is not a tuning knob.
KEYFRAME_ONLY: Final[frozenset[Profile]] = frozenset({Profile.L1})

# F07 R1: S3 only runs on what S2 could not resolve.
S3_CONFIDENCE_CEILING: Final[float] = 0.55


class Stage(str, Enum):
    S0_MOTION = "s0_motion"
    S1_TRUNK = "s1_trunk"
    AGE_GATE = "age_gate"
    REDACT = "redact"
    S2_TRACKING = "s2_tracking"
    S3_RESOLVE = "s3_resolve"


# The stages inside the sealed process. Every one of them runs on every processed frame.
SEALED_STAGES: Final[tuple[Stage, ...]] = (
    Stage.S0_MOTION,
    Stage.S1_TRUNK,
    Stage.AGE_GATE,
    Stage.REDACT,
)


class Refusal(str, Enum):
    STREAM_CAP_EXCEEDED = "stream_cap_exceeded"
    STREAM_NOT_ADMITTED = "stream_not_admitted"
    SEALED_PIPELINE_DOWN = "sealed_pipeline_down"


class Drop(str, Enum):
    NON_KEYFRAME = "non_keyframe"
    OVERLOAD = "overload"
    NO_MOTION = "no_motion"
    REDACTION_FAILED = "redaction_failed"


REMEDY: Final[Mapping[Refusal, str]] = MappingProxyType(
    {
        Refusal.STREAM_CAP_EXCEEDED: (
            "The host profile permits fewer streams than were mapped. Add RAM and re-run "
            "pre-flight, or map the extra camera to a second device"
        ),
        Refusal.STREAM_NOT_ADMITTED: (
            "The stream was never admitted. Admit it through commissioning so the cap is "
            "enforced before frames arrive"
        ),
        Refusal.SEALED_PIPELINE_DOWN: (
            "The sealed process is down. The stream stays stopped; restart the sealed unit. "
            "There is no unsealed path and frames are not processed meanwhile"
        ),
    }
)


@dataclass(frozen=True)
class Provenance:
    """F07 R3: every inference output says which bundle produced it, and at which stage."""

    stage: Stage
    model_bundle: str
    confidence: float

    def as_dict(self) -> dict[str, str | float]:
        return {
            "stage": self.stage.value,
            "model_bundle": self.model_bundle,
            "confidence": round(self.confidence, 3),
        }


@dataclass
class StageCounters:
    offered: int = 0
    processed: int = 0
    entered: dict[Stage, int] = field(default_factory=dict)
    dropped: dict[Drop, int] = field(default_factory=dict)

    def enter(self, stage: Stage) -> None:
        self.entered[stage] = self.entered.get(stage, 0) + 1

    def drop(self, reason: Drop) -> None:
        self.dropped[reason] = self.dropped.get(reason, 0) + 1

    @property
    def frames_dropped(self) -> int:
        return sum(self.dropped.values())


@dataclass(frozen=True)
class DataQuality:
    """What the aggregate windows must carry when the box could not keep up."""

    coverage: float
    frames_offered: int
    frames_processed: int
    degraded: bool

    def as_dict(self) -> dict[str, float | int | bool]:
        return {
            "coverage": self.coverage,
            "frames_offered": self.frames_offered,
            "frames_processed": self.frames_processed,
            "degraded": self.degraded,
        }


@dataclass(frozen=True)
class FrameResult:
    """One offered frame's fate. Exactly one of `output`, `drop` and `refusal` is set."""

    output: SealedOutput | None = None
    drop: Drop | None = None
    refusal: Refusal | None = None
    provenance: tuple[Provenance, ...] = ()

    @property
    def processed(self) -> bool:
        return self.output is not None


@dataclass
class Cascade:
    """Admission and stage gating around one sealed pipeline.

    `budget_fps` is the measured rate at which this host can carry a frame through every sealed
    stage. It is a measurement, not a target: exceeding it drops the next frame rather than
    starting work the box cannot finish.
    """

    pipeline: SealedPipeline
    capability: CapabilityVector
    model_bundle: str
    budget_fps: float = 5.0
    counters: StageCounters = field(default_factory=StageCounters)
    _admitted: set[str] = field(default_factory=set)
    _recent_ms: list[int] = field(default_factory=list)

    @property
    def keyframe_only(self) -> bool:
        return self.capability.profile in KEYFRAME_ONLY

    @property
    def admitted(self) -> frozenset[str]:
        return frozenset(self._admitted)

    def admit(self, stream_id: str) -> Refusal | None:
        """F07 R2: the cap comes from the signed host profile, so it is enforced before decode."""
        if stream_id in self._admitted:
            return None
        if len(self._admitted) >= self.capability.stream_cap:
            return Refusal.STREAM_CAP_EXCEEDED
        self._admitted.add(stream_id)
        return None

    def offer(self, frame: Frame, *, keyframe: bool = True) -> FrameResult:
        """Offer one decoded-or-decodable frame.

        Every refusal and every drop happens here, before the sealed stages run. Once `process` is
        called the frame goes through motion, trunk, gate and redaction without exception.
        """
        self.counters.offered += 1

        if frame.stream_id not in self._admitted:
            return FrameResult(refusal=Refusal.STREAM_NOT_ADMITTED)
        if self.keyframe_only and not keyframe:
            self.counters.drop(Drop.NON_KEYFRAME)
            return FrameResult(drop=Drop.NON_KEYFRAME)
        if self._over_budget(frame.ts_ms):
            # F07 R4: shed the frame whole. The alternative — decoding it and skipping a stage —
            # is the one thing the cascade may never do.
            self.counters.drop(Drop.OVERLOAD)
            return FrameResult(drop=Drop.OVERLOAD)

        before_no_motion = self.pipeline.counters.frames_no_motion
        before_redaction = self.pipeline.counters.frames_dropped_redaction
        self.counters.enter(Stage.S0_MOTION)

        try:
            output = self.pipeline.process(frame)
        except SealedPipelineDown:
            # F07 R1a: the stream stops. It does not continue on an unsealed path.
            self._admitted.discard(frame.stream_id)
            return FrameResult(refusal=Refusal.SEALED_PIPELINE_DOWN)

        if output is None:
            # The sealed pipeline returns nothing for exactly two reasons, and they mean opposite
            # things: a quiet street, or a redactor that could not do its job.
            no_motion = self.pipeline.counters.frames_no_motion > before_no_motion
            redaction_failed = self.pipeline.counters.frames_dropped_redaction > before_redaction
            reason = Drop.NO_MOTION if no_motion or not redaction_failed else Drop.REDACTION_FAILED
            self.counters.drop(reason)
            return FrameResult(drop=reason)

        self._recent_ms.append(frame.ts_ms)
        self.counters.processed += 1
        for stage in SEALED_STAGES[1:]:  # S0 was counted above, before the frame was handed over
            self.counters.enter(stage)

        return FrameResult(output=output, provenance=self._provenance(output))

    def s2_candidates(self, output: SealedOutput) -> tuple[BoundaryDetection, ...]:
        """F07 R1: S2 runs on classes of interest only, and only post-gate detections exist here."""
        if not output.detections:
            return ()
        self.counters.enter(Stage.S2_TRACKING)
        return output.detections

    def s3_candidates(
        self, detections: tuple[BoundaryDetection, ...]
    ) -> tuple[BoundaryDetection, ...]:
        """F07 R1: S3 is the expensive stage, so it sees only what S2 left unresolved."""
        unresolved = tuple(d for d in detections if d.confidence < S3_CONFIDENCE_CEILING)
        if unresolved:
            self.counters.enter(Stage.S3_RESOLVE)
        return unresolved

    def data_quality(self) -> DataQuality:
        offered = self.counters.offered
        processed = self.counters.processed
        coverage = 1.0 if offered == 0 else round(processed / offered, 3)
        return DataQuality(
            coverage=coverage,
            frames_offered=offered,
            frames_processed=processed,
            degraded=coverage < 1.0,
        )

    def _provenance(self, output: SealedOutput) -> tuple[Provenance, ...]:
        return tuple(
            Provenance(Stage.S1_TRUNK, self.model_bundle, d.confidence) for d in output.detections
        )

    def _over_budget(self, ts_ms: int) -> bool:
        """One second of processed frames, counted on stream time rather than wall clock."""
        cutoff = ts_ms - 1000
        self._recent_ms = [t for t in self._recent_ms if t > cutoff]
        return len(self._recent_ms) >= self.budget_fps
