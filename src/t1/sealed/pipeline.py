"""The sealed pipeline process (D-006).

Everything that touches unredacted pixels happens here: motion, the shared trunk, the age gate and
redaction. The process has no route out, so "no raw personal visual information reaches T2" is a
property of the topology rather than of the code being careful.

Ordering, and why it is not the v3.0 ordering:

    S0 motion -> S1 shared trunk -> AGE GATE -> REDACT -> || boundary ||

The gate runs on unredacted pixels because it cannot work on destroyed ones, and it runs *before*
redaction rather than after so that an under-22 detection is dropped before anything downstream can
observe it. Redaction is still the last thing that happens before the boundary, which is what C5
actually requires.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from t1.canon import AGE_GATE_THRESHOLD
from t1.contracts import AgeBand, BoundaryDetection, Frame, RedactedFrame, SealedDetection
from t1.sealed.guard import SealedEnvironment

Trunk = Callable[[Frame], list[SealedDetection]]
Redactor = Callable[[Frame], Frame | None]


class SealedPipelineDown(RuntimeError):
    """The sealed process failed. The stream stops; there is no unsealed fallback."""


class ProhibitedZone(RuntimeError):
    """A stream was mapped to a zone that may never be instantiated."""


@dataclass
class PipelineCounters:
    frames_in: int = 0
    frames_no_motion: int = 0
    frames_dropped_redaction: int = 0
    detections_total: int = 0
    minor_suppressed_n: int = 0
    adults_passed: int = 0

    @property
    def minor_suppression_rate(self) -> float:
        """Class C0 site health ratio. No per-person content (D-008 s2)."""
        if self.detections_total == 0:
            return 0.0
        return self.minor_suppressed_n / self.detections_total


@dataclass
class SealedOutput:
    """Everything, and only what, crosses the boundary for one frame."""

    frame: RedactedFrame
    detections: tuple[BoundaryDetection, ...]


@dataclass
class SealedPipeline:
    trunk: Trunk
    redactor: Redactor
    model_bundle: str
    redaction_version: str
    zone_allows: Callable[[str], bool] = lambda _stream_id: True
    motion: Callable[[Frame], bool] = lambda _frame: True
    environment: SealedEnvironment = field(default_factory=SealedEnvironment)
    counters: PipelineCounters = field(default_factory=PipelineCounters)
    _healthy: bool = True

    def __post_init__(self) -> None:
        self.environment.assert_sealed()

    @property
    def healthy(self) -> bool:
        return self._healthy

    def instantiate(self, stream_id: str) -> None:
        """F10 R1 / F07: a stream in a prohibited zone is refused, not filtered later."""
        if not self.zone_allows(stream_id):
            raise ProhibitedZone(f"prohibited_zone:{stream_id}")

    def process(self, frame: Frame) -> SealedOutput | None:
        if not self._healthy:
            raise SealedPipelineDown("sealed_pipeline_down")
        self.instantiate(frame.stream_id)
        self.counters.frames_in += 1

        if not self.motion(frame):
            self.counters.frames_no_motion += 1
            return None

        try:
            detections = self.trunk(frame)
        except Exception as exc:  # trunk failure is a sealed-process failure: fail closed
            self._healthy = False
            raise SealedPipelineDown("trunk_failed") from exc

        self.counters.detections_total += len(detections)
        adults = [d for d in detections if self._age_gate_passes(d)]
        self.counters.minor_suppressed_n += len(detections) - len(adults)
        self.counters.adults_passed += len(adults)

        try:
            redacted = self.redactor(frame)
        except Exception as exc:
            self._healthy = False
            raise SealedPipelineDown("redactor_failed") from exc

        if redacted is None or not redacted.redacted:
            # F08 R3: redaction failure drops the frame. It never passes through unredacted.
            self.counters.frames_dropped_redaction += 1
            return None

        return SealedOutput(
            frame=RedactedFrame(
                stream_id=redacted.stream_id,
                ts_ms=redacted.ts_ms,
                pixels=redacted.pixels,
                redaction_version=self.redaction_version,
            ),
            detections=tuple(
                BoundaryDetection(
                    stream_id=d.stream_id,
                    ts_ms=d.ts_ms,
                    bbox=d.bbox,
                    confidence=d.confidence,
                    age_gate_passed=True,
                    model_bundle=self.model_bundle,
                )
                for d in adults
            ),
        )

    def crash(self) -> None:
        """Bench and test hook: everything after this raises rather than degrading."""
        self._healthy = False

    @staticmethod
    def _age_gate_passes(detection: SealedDetection) -> bool:
        """Indeterminate is suppressed. The conservative side of the threshold is the safe one."""
        return detection.age_band is AgeBand.ADULT


def band_for_age(estimated_age: float) -> AgeBand:
    if estimated_age < AGE_GATE_THRESHOLD:
        return AgeBand.UNDER_22
    return AgeBand.ADULT


def tracks_from(outputs: Iterator[SealedOutput]) -> list[BoundaryDetection]:
    """S2 input. It is typed to accept nothing but post-gate, post-redaction detections."""
    collected: list[BoundaryDetection] = []
    for out in outputs:
        collected.extend(out.detections)
    return collected
