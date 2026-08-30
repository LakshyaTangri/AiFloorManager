"""Types, split by which side of the redaction boundary they live on.

The split is the point. `SEALED_ONLY` types may hold unredacted pixels and age information;
`BOUNDARY_CROSSING` types may not, and `t1.sealed.guard.assert_boundary_clean` proves it by
inspecting the annotations rather than trusting the reviewer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from t1.canon import DataClass, TrustLevel


class AgeBand(str, Enum):
    """Sealed-side only. Never appears in a boundary-crossing type."""

    UNDER_22 = "under_22"
    ADULT = "adult"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class Frame:
    """Unredacted pixels. Exists only inside the sealed process."""

    stream_id: str
    ts_ms: int
    pixels: bytes
    redacted: bool = False


@dataclass(frozen=True)
class SealedDetection:
    """Trunk output, sealed side: one forward pass yields both the box and the age band."""

    stream_id: str
    ts_ms: int
    bbox: tuple[int, int, int, int]
    confidence: float
    age_band: AgeBand
    age_score: float


@dataclass(frozen=True)
class RedactedFrame:
    """Crosses the boundary. Faces and legible text are irreversibly destroyed."""

    stream_id: str
    ts_ms: int
    pixels: bytes
    redaction_version: str


@dataclass(frozen=True)
class BoundaryDetection:
    """Crosses the boundary.

    Carries the gate *verdict* and nothing else about age: no band, no score, no threshold
    distance. Anything under-22 was dropped inside the sealed process and never reaches here.
    """

    stream_id: str
    ts_ms: int
    bbox: tuple[int, int, int, int]
    confidence: float
    age_gate_passed: bool
    model_bundle: str


@dataclass(frozen=True)
class Envelope:
    """The unit the egress filter judges."""

    device_id: str
    boot_id: str
    seq: int
    device_time: str
    schema: str
    data_class: DataClass
    purpose: str
    trust_level: TrustLevel
    payload: dict[str, Any]
    lawful_basis: str | None = None
    basis_ref: str | None = None
    retention_until: str | None = None
    policy_version: str | None = None
    age_gate_ver: str | None = None
    k_value: int | None = None
    metric: str | None = None
    clock_offset_ms: int = 0
    time_uncertain: bool = False
    backfill: bool = False
    entitlements: tuple[str, ...] = ()


@dataclass(frozen=True)
class Track:
    """Adults only, by construction: it can only be built from a BoundaryDetection."""

    track_id: str
    stream_id: str
    detections: tuple[BoundaryDetection, ...] = field(default_factory=tuple)


SEALED_ONLY: tuple[type, ...] = (Frame, SealedDetection)
BOUNDARY_CROSSING: tuple[type, ...] = (RedactedFrame, BoundaryDetection, Envelope, Track)
