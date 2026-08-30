"""Per-metric k-anonymity (F11, C6).

A suppressed window emits a marker, never a zero. Zeros are indistinguishable from real zeros and
they poison every downstream sum; `k_suppressed` keeps the series honest about what it does not
know.
"""

from __future__ import annotations

from dataclasses import dataclass

from t1.canon import CANON_FLOORS, DEFAULT_FLOOR


@dataclass(frozen=True)
class Window:
    metric: str
    window_start: str
    value: int
    k: int


@dataclass(frozen=True)
class SuppressionResult:
    metric: str
    window_start: str
    value: int | None
    k_suppressed: bool
    floor: int


def canonical_floor(metric: str) -> int:
    return CANON_FLOORS.get(metric, DEFAULT_FLOOR)


def effective_floor(metric: str, policy_floor: int | None = None) -> int:
    """Policy may raise a floor. It may never lower it below canon (D-008 s3)."""
    canon = canonical_floor(metric)
    if policy_floor is None:
        return canon
    return max(canon, policy_floor)


def apply(window: Window, policy_floor: int | None = None) -> SuppressionResult:
    floor = effective_floor(window.metric, policy_floor)
    suppressed = window.k < floor
    return SuppressionResult(
        metric=window.metric,
        window_start=window.window_start,
        value=None if suppressed else window.value,
        k_suppressed=suppressed,
        floor=floor,
    )
