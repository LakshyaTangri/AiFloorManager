"""The Edge Manager loop (F19, M09, SPEC §14).

    BASELINE -> DETECT -> EXPLAIN -> RECOMMEND -> BRIEF

Two constraints shape the code more than the loop does.

*No free text.* `Explanation` has no string field an explainer could write into: the cause is an
enum and the contributing factors are enums. An explainer that proposes anything outside the set
does not get its string sanitised — the explanation is rejected and replaced with `UNKNOWN` at
reduced confidence, which is the honest answer and is also unusable as a channel for a person
description.

*Recommendations come from a signed library.* `recommend` selects and parameterises library
entries; it cannot generate one. The caps compose (D-008 §4): each action has its own daily cap and
the site has an overall cap of three, and the site cap is checked last so a single noisy trigger
cannot consume the day's whole allowance.

The loop runs locally on L2/L3 and the briefing renders with T2 unreachable (F19 R3), which is why
nothing here takes a transport, a clock from the network, or a T2 response.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Final

from t1.canon import MAX_RECOMMENDATIONS_PER_SITE_PER_DAY

ACTION_LIBRARY_SIGNING_DOMAIN: Final[str] = "action-library"

# F19 R1: a deviation is only a deviation if it persists. One 15-minute window is noise.
MIN_PERSISTENCE_WINDOWS: Final[int] = 2
DEVIATION_SIGMAS: Final[float] = 2.0

# F19 R2 fallback: an unusable explanation still reports, at a confidence that says so.
UNKNOWN_CAUSE_CONFIDENCE: Final[float] = 0.30


class Cause(str, Enum):
    """The closed set. There is no `other`, because `other` is free text with extra steps."""

    STAFFING_SHORTFALL = "staffing_shortfall"
    QUEUE_BREACH = "queue_breach"
    PROMOTION_EFFECT = "promotion_effect"
    WEATHER = "weather"
    FESTIVAL_OR_HOLIDAY = "festival_or_holiday"
    STOCK_OUT = "stock_out"
    CAMERA_DEGRADED = "camera_degraded"
    UNKNOWN = "unknown"


class Factor(str, Enum):
    RAIN = "rain"
    SCHOOL_TERM = "school_term"
    TRADING_HOURS_CHANGE = "trading_hours_change"
    PROMOTION_ACTIVE = "promotion_active"
    TILL_COUNT_LOW = "till_count_low"
    COVERAGE_DEGRADED = "coverage_degraded"


class Refusal(str, Enum):
    LIBRARY_SIGNATURE_INVALID = "library_signature_invalid"
    ACTION_NOT_IN_LIBRARY = "action_not_in_library"
    CONFIDENCE_BELOW_FLOOR = "confidence_below_floor"
    ACTION_DAILY_CAP = "action_daily_cap"
    SITE_DAILY_CAP = "site_daily_cap"
    NOT_PERSISTENT = "not_persistent"


REMEDY: Final[Mapping[Refusal, str]] = MappingProxyType(
    {
        Refusal.LIBRARY_SIGNATURE_INVALID: (
            "The action library does not verify. No recommendation is issued; the loop still "
            "detects and briefs, because refusing to advise is safe and refusing to measure is not"
        ),
        Refusal.ACTION_NOT_IN_LIBRARY: (
            "The trigger matched no signed action. Add the action to the library and re-release; "
            "recommendations are never generated locally"
        ),
        Refusal.CONFIDENCE_BELOW_FLOOR: (
            "The evidence is below this action's confidence floor. The deviation is still "
            "reported in the briefing without a recommendation"
        ),
        Refusal.ACTION_DAILY_CAP: (
            "This action has already been recommended its maximum times today"
        ),
        Refusal.SITE_DAILY_CAP: (
            f"The site has already received {MAX_RECOMMENDATIONS_PER_SITE_PER_DAY} recommendations "
            "today. A manager who receives fifteen ignores all of them"
        ),
        Refusal.NOT_PERSISTENT: (
            "The deviation lasted fewer than the required consecutive windows. It is reported as "
            "an observation, not acted on"
        ),
    }
)


@dataclass(frozen=True)
class Deviation:
    """DETECT: how far from this zone's own baseline, in which direction, for how long."""

    metric: str
    zone_id: str
    observed: float
    baseline: float
    sigma: float
    windows: int

    @property
    def sigmas(self) -> float:
        if self.sigma <= 0.0:
            return 0.0
        return (self.observed - self.baseline) / self.sigma

    @property
    def direction(self) -> str:
        return "above" if self.observed >= self.baseline else "below"

    @property
    def significant(self) -> bool:
        return abs(self.sigmas) >= DEVIATION_SIGMAS

    @property
    def persistent(self) -> bool:
        return self.windows >= MIN_PERSISTENCE_WINDOWS


@dataclass(frozen=True)
class Explanation:
    """EXPLAIN: enums only. There is no field here that can hold a sentence."""

    cause: Cause
    factors: tuple[Factor, ...]
    confidence: float

    def as_dict(self) -> dict[str, object]:
        return {
            "cause_enum": self.cause.value,
            "contributing_factors": [f.value for f in self.factors],
            "confidence": round(self.confidence, 3),
        }


def explain(proposed_cause: str, proposed_factors: Sequence[str], confidence: float) -> Explanation:
    """Validate an explainer's output. Anything off-set becomes `unknown`, not a cleaned string."""
    try:
        cause = Cause(proposed_cause)
    except ValueError:
        return Explanation(Cause.UNKNOWN, (), UNKNOWN_CAUSE_CONFIDENCE)

    factors: list[Factor] = []
    for raw in proposed_factors:
        try:
            factors.append(Factor(raw))
        except ValueError:
            # A single off-set factor makes the whole output untrusted: it is evidence that the
            # explainer is not constrained the way the contract assumes.
            return Explanation(Cause.UNKNOWN, (), UNKNOWN_CAUSE_CONFIDENCE)
    return Explanation(cause, tuple(factors), confidence)


@dataclass(frozen=True)
class Action:
    action_id: str
    metric: str
    threshold: float
    params: tuple[str, ...]
    expected_impact: str
    confidence_floor: float = 0.7
    max_per_site_per_day: int = 1


@dataclass(frozen=True)
class ActionLibrary:
    library_version: str
    actions: tuple[Action, ...]
    signing_domain: str = ACTION_LIBRARY_SIGNING_DOMAIN

    def for_metric(self, metric: str) -> Action | None:
        for action in self.actions:
            if action.metric == metric:
                return action
        return None

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "library_version": self.library_version,
                "signing_domain": self.signing_domain,
                "actions": [
                    {
                        "action_id": a.action_id,
                        "metric": a.metric,
                        "threshold": a.threshold,
                        "params": list(a.params),
                        "expected_impact": a.expected_impact,
                        "confidence_floor": a.confidence_floor,
                        "max_per_site_per_day": a.max_per_site_per_day,
                    }
                    for a in self.actions
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


def sign_library(library: ActionLibrary, key: bytes) -> str:
    return hmac.new(key, library.to_bytes(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Recommendation:
    action_id: str
    library_version: str
    zone_id: str
    params: Mapping[str, str]
    confidence: float
    expected_impact: str
    evidence_refs: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "action_id": self.action_id,
            "action_library_ver": self.library_version,
            "zone_id": self.zone_id,
            "params": dict(self.params),
            "confidence": round(self.confidence, 3),
            "expected_impact": self.expected_impact,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class Briefing:
    """F19 R3: renders locally, offline, and syncs later as derived C2."""

    day: str
    deviations: tuple[Deviation, ...]
    explanations: tuple[Explanation, ...]
    recommendations: tuple[Recommendation, ...]
    generated_offline: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "day": self.day,
            "deviations": [
                {
                    "metric": d.metric,
                    "zone_id": d.zone_id,
                    "sigmas": round(d.sigmas, 2),
                    "direction": d.direction,
                    "windows": d.windows,
                }
                for d in self.deviations
            ],
            "explanations": [e.as_dict() for e in self.explanations],
            "recommendations": [r.as_dict() for r in self.recommendations],
            "generated_offline": self.generated_offline,
        }


@dataclass
class EdgeManager:
    """One site-day of the loop. Caps are per day, so the counters reset with `new_day`."""

    key: bytes
    library: ActionLibrary
    library_signature: str
    day: str
    _issued: list[Recommendation] = field(default_factory=list)
    _per_action: dict[str, int] = field(default_factory=dict)
    refusals: dict[Refusal, int] = field(default_factory=dict)

    @property
    def library_valid(self) -> bool:
        if self.library.signing_domain != ACTION_LIBRARY_SIGNING_DOMAIN:
            return False
        return hmac.compare_digest(sign_library(self.library, self.key), self.library_signature)

    @property
    def issued(self) -> tuple[Recommendation, ...]:
        return tuple(self._issued)

    def new_day(self, day: str) -> None:
        self.day = day
        self._issued.clear()
        self._per_action.clear()

    def recommend(
        self,
        deviation: Deviation,
        explanation: Explanation,
        params: Mapping[str, str],
        evidence_refs: tuple[str, ...],
    ) -> Recommendation | Refusal:
        if not self.library_valid:
            return self._refuse(Refusal.LIBRARY_SIGNATURE_INVALID)
        if not deviation.persistent:
            return self._refuse(Refusal.NOT_PERSISTENT)

        action = self.library.for_metric(deviation.metric)
        if action is None or abs(deviation.sigmas) < action.threshold:
            return self._refuse(Refusal.ACTION_NOT_IN_LIBRARY)
        if explanation.confidence < action.confidence_floor:
            return self._refuse(Refusal.CONFIDENCE_BELOW_FLOOR)
        if self._per_action.get(action.action_id, 0) >= action.max_per_site_per_day:
            return self._refuse(Refusal.ACTION_DAILY_CAP)
        # Site cap last: the per-action cap should absorb a repeating trigger before the site cap
        # has to (D-008 §4).
        if len(self._issued) >= MAX_RECOMMENDATIONS_PER_SITE_PER_DAY:
            return self._refuse(Refusal.SITE_DAILY_CAP)

        recommendation = Recommendation(
            action_id=action.action_id,
            library_version=self.library.library_version,
            zone_id=deviation.zone_id,
            params={k: v for k, v in params.items() if k in action.params},
            confidence=explanation.confidence,
            expected_impact=action.expected_impact,
            evidence_refs=evidence_refs,
        )
        self._issued.append(recommendation)
        self._per_action[action.action_id] = self._per_action.get(action.action_id, 0) + 1
        return recommendation

    def brief(
        self,
        deviations: tuple[Deviation, ...],
        explanations: tuple[Explanation, ...],
        *,
        t2_reachable: bool,
    ) -> Briefing:
        """The briefing is produced whether or not T2 answers; only the marker differs."""
        return Briefing(
            day=self.day,
            deviations=deviations,
            explanations=explanations,
            recommendations=self.issued,
            generated_offline=not t2_reachable,
        )

    def _refuse(self, refusal: Refusal) -> Refusal:
        self.refusals[refusal] = self.refusals.get(refusal, 0) + 1
        return refusal
