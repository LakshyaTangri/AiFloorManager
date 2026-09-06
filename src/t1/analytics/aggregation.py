"""Aggregation windows (F11, F19, M09).

Windows are where tracks stop being tracks. A closed window emits one value per metric with the
`k` that produced it, and `t1.control.kanon` decides whether that value may leave: below the
per-metric floor the window emits `k_suppressed`, never a zero, because a zero is indistinguishable
from a real zero and poisons every sum downstream.

Two things are deliberately carried alongside the value:

    coverage        the cascade's processed/offered ratio for the window (F07 R4)
    time_uncertain  the clock was too far off to trust the window's boundaries (F14 R6)

Both are properties of the window, not of the metric, so they are attached once and travel with
every metric the window emits. A window that counted 40 people at 62% coverage is not a 40; it is a
40 that the analyst must be able to see was measured through a busy Saturday.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final

from t1.analytics.tracking import ClosedTrack
from t1.canon import CLOCK_SKEW_TOLERANCE_MS
from t1.control.kanon import Window, apply

WINDOW_SECONDS: Final[int] = 900

FOOTFALL: Final[str] = "footfall"
DWELL_TIME: Final[str] = "dwell_time"

# Below this the window is worth reporting only as degraded: it is a sample, not a count.
COVERAGE_DEGRADED_BELOW: Final[float] = 0.95


@dataclass(frozen=True)
class MetricValue:
    """One metric from one window, already judged against its floor."""

    metric: str
    window_start: str
    window_seconds: int
    value: int | None
    k: int
    k_suppressed: bool
    floor: int
    coverage: float
    time_uncertain: bool

    @property
    def degraded(self) -> bool:
        return self.coverage < COVERAGE_DEGRADED_BELOW or self.time_uncertain

    def payload(self) -> dict[str, object]:
        """Exactly the fields the aggregate schema allows. No track ids, no per-person anything."""
        return {
            "metric": self.metric,
            "value": self.value if self.value is not None else 0,
            "window_start": self.window_start,
            "window_seconds": self.window_seconds,
            "k_suppressed": self.k_suppressed,
            "coverage": self.coverage,
            "time_uncertain": self.time_uncertain,
        }


@dataclass
class AggregationWindow:
    """Accumulates closed tracks; emits metrics when the window closes."""

    window_start: str
    window_seconds: int = WINDOW_SECONDS
    coverage: float = 1.0
    clock_offset_ms: int = 0
    _dwells_ms: list[int] = field(default_factory=list)
    _visits: int = 0

    @property
    def time_uncertain(self) -> bool:
        """F14 R6: past the tolerance the window cannot say when it happened."""
        return abs(self.clock_offset_ms) > CLOCK_SKEW_TOLERANCE_MS

    def add(self, tracks: Iterable[ClosedTrack]) -> None:
        for track in tracks:
            if not track.counts:
                continue
            self._visits += 1
            self._dwells_ms.append(track.dwell_ms)

    def close(self, floors: Mapping[str, int] | None = None) -> tuple[MetricValue, ...]:
        """Emit footfall and dwell. Each is judged against its own floor, which differ by 17."""
        policy = dict(floors or {})
        median_dwell_s = round(_median(self._dwells_ms) / 1000) if self._dwells_ms else 0
        raw = (
            (FOOTFALL, self._visits, self._visits),
            (DWELL_TIME, median_dwell_s, len(self._dwells_ms)),
        )
        return tuple(self._judge(metric, value, k, policy.get(metric)) for metric, value, k in raw)

    def _judge(self, metric: str, value: int, k: int, policy_floor: int | None) -> MetricValue:
        result = apply(Window(metric, self.window_start, value, k), policy_floor)
        return MetricValue(
            metric=metric,
            window_start=self.window_start,
            window_seconds=self.window_seconds,
            value=result.value,
            k=k,
            k_suppressed=result.k_suppressed,
            floor=result.floor,
            coverage=self.coverage,
            time_uncertain=self.time_uncertain,
        )


def _median(values: list[int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2
