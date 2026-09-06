"""Camera assessment: the contractual basis for a counting accuracy claim (M05, F02).

The score exists so that an accuracy dispute is settled by a record made at install time. That
only works if the record is closed-set and cannot be talked around later: issues are enums, an
unmeasured property scores nothing, and a below-threshold stream must be either re-scored or
explicitly excluded from the accuracy commitment before commissioning closes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final

# F02 R2 speaks of a published threshold; SPEC does not yet publish a number, so this is the
# working value recorded as ADR-REQ-010 and is deliberately in code rather than in policy.
COUNTING_THRESHOLD: Final[float] = 0.60

MIN_DEPRESSION_DEGREES: Final[float] = 20.0
MIN_HEIGHT_PX: Final[int] = 720
MIN_FPS: Final[float] = 5.0
MAX_OCCLUSION: Final[float] = 0.30
MIN_LENS_CLARITY: Final[float] = 0.70


class Issue(str, Enum):
    ANGLE_TOO_SHALLOW = "angle_too_shallow"
    BACKLIT = "backlit"
    OCCLUDED = "occluded"
    LOW_RESOLUTION = "low_resolution"
    FPS_BELOW_MIN = "fps_below_min"
    LENS_DIRTY = "lens_dirty"
    IR_GLARE = "ir_glare"


REMEDY: Final[Mapping[Issue, str]] = MappingProxyType(
    {
        Issue.ANGLE_TOO_SHALLOW: "raise the camera or tilt it down to at least "
        f"{MIN_DEPRESSION_DEGREES:.0f} degrees of depression",
        Issue.BACKLIT: "re-aim away from the light source, or add fill light at the entrance",
        Issue.OCCLUDED: "clear the fixture or shelving blocking the counting line",
        Issue.LOW_RESOLUTION: f"select a stream profile of at least {MIN_HEIGHT_PX}p",
        Issue.FPS_BELOW_MIN: f"raise the stream to at least {MIN_FPS:.0f} fps, or fix the "
        "network path that is dropping it",
        Issue.LENS_DIRTY: "clean the lens or dome and re-score",
        Issue.IR_GLARE: "disable the camera's IR illuminator or move it off the glass",
    }
)

# Weights say what actually breaks counting: geometry and cadence beat cosmetics.
WEIGHTS: Final[Mapping[str, float]] = MappingProxyType(
    {"angle": 0.30, "resolution": 0.20, "lighting": 0.15, "occlusion": 0.20, "fps": 0.15}
)

# Penalties are multiplicative and severe enough that a single named issue drops the stream below
# the threshold. A stream cannot carry an issue and still be sold as suitable: the flag and the
# number have to agree, or the record is worthless in a dispute.
ISSUE_PENALTY: Final[Mapping[Issue, float]] = MappingProxyType(
    {
        Issue.ANGLE_TOO_SHALLOW: 0.50,
        Issue.BACKLIT: 0.70,
        Issue.OCCLUDED: 0.60,
        Issue.LOW_RESOLUTION: 0.60,
        Issue.FPS_BELOW_MIN: 0.50,
        Issue.LENS_DIRTY: 0.80,
        Issue.IR_GLARE: 0.80,
    }
)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


@dataclass(frozen=True)
class Stream:
    """One candidate stream as measured on site. Nothing here is inferred from the model name."""

    stream_id: str
    depression_degrees: float
    height_px: int
    achieved_fps: float
    occlusion_fraction: float
    lens_clarity: float
    backlit: bool = False
    ir_glare: bool = False

    def _components(self) -> Mapping[str, float]:
        return {
            "angle": _clamp(self.depression_degrees / 45.0),
            "resolution": _clamp(self.height_px / 1080.0),
            "lighting": _clamp(
                self.lens_clarity
                - (0.35 if self.backlit else 0.0)
                - (0.25 if self.ir_glare else 0.0)
            ),
            "occlusion": _clamp(1.0 - self.occlusion_fraction),
            "fps": _clamp(self.achieved_fps / 10.0),
        }

    def issues(self) -> tuple[Issue, ...]:
        found: list[Issue] = []
        if self.depression_degrees < MIN_DEPRESSION_DEGREES:
            found.append(Issue.ANGLE_TOO_SHALLOW)
        if self.backlit:
            found.append(Issue.BACKLIT)
        if self.occlusion_fraction > MAX_OCCLUSION:
            found.append(Issue.OCCLUDED)
        if self.height_px < MIN_HEIGHT_PX:
            found.append(Issue.LOW_RESOLUTION)
        if self.achieved_fps < MIN_FPS:
            found.append(Issue.FPS_BELOW_MIN)
        if self.lens_clarity < MIN_LENS_CLARITY:
            found.append(Issue.LENS_DIRTY)
        if self.ir_glare:
            found.append(Issue.IR_GLARE)
        return tuple(found)

    def score(self) -> float:
        components = self._components()
        total = sum(WEIGHTS[name] * value for name, value in components.items())
        for issue in self.issues():
            total *= ISSUE_PENALTY[issue]
        return round(_clamp(total), 2)


@dataclass(frozen=True)
class Score:
    stream_id: str
    counting_score: float
    issues: tuple[Issue, ...]

    @property
    def suitable(self) -> bool:
        return self.counting_score >= COUNTING_THRESHOLD

    def to_json_obj(self) -> dict[str, object]:
        return {
            "stream": self.stream_id,
            "counting_score": self.counting_score,
            "issues": [issue.value for issue in self.issues],
            "not_suitable_for_counting": not self.suitable,
        }


def assess(stream: Stream) -> Score:
    return Score(stream.stream_id, stream.score(), stream.issues())


class CommitmentRefusal(str, Enum):
    UNRESOLVED_LOW_SCORE = "unresolved_low_score_stream"
    EXCLUDED_STREAM_UNKNOWN = "excluded_stream_not_assessed"


@dataclass(frozen=True)
class AccuracyCommitment:
    """What the install actually promises, and the evidence it rests on."""

    scores: tuple[Score, ...]
    excluded: frozenset[str]

    @property
    def covered(self) -> tuple[str, ...]:
        return tuple(
            score.stream_id for score in self.scores if score.stream_id not in self.excluded
        )

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "camera_scores": [score.to_json_obj() for score in self.scores],
                "excluded_from_accuracy_commitment": sorted(self.excluded),
                "threshold": COUNTING_THRESHOLD,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def sign(self, key: bytes) -> str:
        return hmac.new(key, self.to_bytes(), hashlib.sha256).hexdigest()


def commit(
    scores: tuple[Score, ...], excluded: frozenset[str]
) -> AccuracyCommitment | CommitmentRefusal:
    """F02 R2: a below-threshold stream is repositioned and re-scored, or named as excluded."""
    assessed = {score.stream_id for score in scores}
    if not excluded <= assessed:
        return CommitmentRefusal.EXCLUDED_STREAM_UNKNOWN
    unresolved = [
        score.stream_id
        for score in scores
        if not score.suitable and score.stream_id not in excluded
    ]
    if unresolved:
        return CommitmentRefusal.UNRESOLVED_LOW_SCORE
    return AccuracyCommitment(scores=scores, excluded=excluded)
