"""S2 tracking and dwell — the unsealed half of M08 (F07 R1, D-006, D-008 §1).

This is the first code outside the sealed process, and the type system is what keeps it honest:
`update` accepts `BoundaryDetection` only, so a track cannot be built from anything that has not
already passed the age gate and the redactor. There is no constructor here that takes a `Frame` or
a `SealedDetection`; the age of a tracked person is not merely unused, it is unavailable.

Tracks are transient on L1 (SPEC §11: "ByteTrack — transient, no C3 at rest"). A closed track
yields its dwell to the aggregate and is then dropped; `persist` exists so that the attempt to
write a trace on a software-bound device is refused by name rather than silently allowed by a
missing check.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Final

from t1.canon import CLASSES_PERMITTED, DataClass, TrustLevel
from t1.contracts import BoundaryDetection

# Association thresholds. Deliberately loose on IoU and tight on time: a keyframe-sampled L1 stream
# moves a person a long way between frames, but a two-second gap is a different visit.
IOU_MATCH: Final[float] = 0.20
MAX_GAP_MS: Final[int] = 2_000

# Below this, a "track" is one stray detection and counting it inflates footfall.
MIN_SAMPLES: Final[int] = 2


class Refusal(str, Enum):
    C3_FORBIDDEN_AT_REST = "c3_forbidden_at_rest"


REMEDY: Final[Mapping[Refusal, str]] = MappingProxyType(
    {
        Refusal.C3_FORBIDDEN_AT_REST: (
            "This trust level permits no C3 trace at rest. Tracks stay in memory and contribute "
            "to aggregates only; storing the path needs an attested profile (L2/L3)"
        ),
    }
)


def iou(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> float:
    """Boxes are (x, y, w, h)."""
    ax, ay, aw, ah = a
    bx, by, bw, bh = b
    left, right = max(ax, bx), min(ax + aw, bx + bw)
    top, bottom = max(ay, by), min(ay + ah, by + bh)
    if right <= left or bottom <= top:
        return 0.0
    overlap = (right - left) * (bottom - top)
    union = aw * ah + bw * bh - overlap
    return 0.0 if union <= 0 else overlap / union


@dataclass
class OpenTrack:
    track_id: str
    stream_id: str
    first_ms: int
    last_ms: int
    bbox: tuple[int, int, int, int]
    samples: int = 1


@dataclass(frozen=True)
class ClosedTrack:
    """What survives S2: a duration and a count, with no path and no person."""

    track_id: str
    stream_id: str
    first_ms: int
    last_ms: int
    samples: int

    @property
    def dwell_ms(self) -> int:
        return self.last_ms - self.first_ms

    @property
    def counts(self) -> bool:
        """A single stray detection is not a visit."""
        return self.samples >= MIN_SAMPLES

    def as_dict(self) -> dict[str, str | int | bool]:
        return {
            "track_id": self.track_id,
            "stream_id": self.stream_id,
            "dwell_ms": self.dwell_ms,
            "samples": self.samples,
            "counts": self.counts,
        }


@dataclass
class Tracker:
    trust_level: TrustLevel = TrustLevel.SOFTWARE_BOUND
    max_gap_ms: int = MAX_GAP_MS
    _open: dict[str, OpenTrack] = field(default_factory=dict)
    _next_id: int = 0
    started: int = 0
    closed: int = 0

    @property
    def open_tracks(self) -> tuple[OpenTrack, ...]:
        return tuple(self._open.values())

    def update(
        self, detections: tuple[BoundaryDetection, ...], now_ms: int
    ) -> tuple[ClosedTrack, ...]:
        """Associate this frame's detections, then close whatever has aged out.

        Association is one-to-one against the tracks that existed *before* this frame: two
        overlapping shoppers standing close enough to share an IoU must become two visits, and a
        track that has already taken a detection from this frame is no longer a candidate for the
        next one. Matching against live state instead would merge them and undercount footfall.
        """
        candidates = list(self._open.values())
        taken: set[str] = set()
        for detection in detections:
            match = self._best_match(detection, candidates, taken)
            if match is None:
                track_id = self._new_id()
                self._open[track_id] = OpenTrack(
                    track_id=track_id,
                    stream_id=detection.stream_id,
                    first_ms=detection.ts_ms,
                    last_ms=detection.ts_ms,
                    bbox=detection.bbox,
                )
                self.started += 1
            else:
                taken.add(match.track_id)
                match.last_ms = detection.ts_ms
                match.bbox = detection.bbox
                match.samples += 1
        return self.close_stale(now_ms)

    def close_stale(self, now_ms: int) -> tuple[ClosedTrack, ...]:
        stale = [t for t in self._open.values() if now_ms - t.last_ms > self.max_gap_ms]
        return self._close(stale)

    def close_all(self) -> tuple[ClosedTrack, ...]:
        return self._close(list(self._open.values()))

    def persist(self, _track: ClosedTrack) -> Refusal | None:
        """D-008 §1: the trust level decides, before any entitlement or schema is consulted."""
        if DataClass.C3_TRACE not in CLASSES_PERMITTED[self.trust_level]:
            return Refusal.C3_FORBIDDEN_AT_REST
        return None

    def _close(self, tracks: list[OpenTrack]) -> tuple[ClosedTrack, ...]:
        out: list[ClosedTrack] = []
        for track in tracks:
            del self._open[track.track_id]
            self.closed += 1
            out.append(
                ClosedTrack(
                    track_id=track.track_id,
                    stream_id=track.stream_id,
                    first_ms=track.first_ms,
                    last_ms=track.last_ms,
                    samples=track.samples,
                )
            )
        return tuple(out)

    def _best_match(
        self,
        detection: BoundaryDetection,
        candidates: list[OpenTrack],
        taken: set[str],
    ) -> OpenTrack | None:
        best: OpenTrack | None = None
        best_iou = IOU_MATCH
        for track in candidates:
            if track.track_id in taken or track.stream_id != detection.stream_id:
                continue
            if detection.ts_ms - track.last_ms > self.max_gap_ms:
                continue
            score = iou(track.bbox, detection.bbox)
            if score >= best_iou:
                best, best_iou = track, score
        return best

    def _new_id(self) -> str:
        self._next_id += 1
        return f"t{self._next_id}"
