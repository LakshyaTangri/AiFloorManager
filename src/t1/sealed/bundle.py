"""Model bundle verification and the age-gate release gate (F09 R3/R6, D-002, D-008 §5).

A model bundle is the artifact that decides who is a minor, so it is gated on more than a valid
signature. F09 R6 makes the *model card* part of the contract: a bundle whose card does not state
the measured boundary error rate for the 16-24 band is refused with `model_card_incomplete` and the
previously active bundle stays in force. That is the one refusal that cannot be argued away at
3 a.m., because the number it demands is the only evidence that the gate was measured near the
threshold where it actually matters.

Three refusals that are easy to conflate:

    signature_invalid       bytes do not match the model-bundle signing domain
    model_card_incomplete   the card omits the 16-24 boundary error rate (F09 R6)
    bundle_downgrade        older than the version this device has already run

Activation is a swap, not a mutation: `ModelStore.activate` either installs the new bundle or
leaves the old one running. There is no state in which the device has no active bundle because a
candidate failed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Final

MODEL_SIGNING_DOMAIN: Final[str] = "model-bundle"

# F09 R6: the card must state error at the boundary, not only in aggregate. An age gate that is
# 99% accurate overall and blind between 16 and 24 is the failure mode this catches.
BOUNDARY_BAND: Final[str] = "16_24"


class Refusal(str, Enum):
    SIGNATURE_INVALID = "signature_invalid"
    WRONG_SIGNING_DOMAIN = "wrong_signing_domain"
    MODEL_CARD_INCOMPLETE = "model_card_incomplete"
    BUNDLE_DOWNGRADE = "bundle_downgrade"


REMEDY: Final[Mapping[Refusal, str]] = MappingProxyType(
    {
        Refusal.SIGNATURE_INVALID: (
            "The bundle does not verify against the model-bundle key. Re-fetch the artifact; "
            "the active bundle keeps running meanwhile"
        ),
        Refusal.WRONG_SIGNING_DOMAIN: (
            "The bundle was signed in another domain (policy or release). Model bundles are "
            "signed with the model-bundle key only"
        ),
        Refusal.MODEL_CARD_INCOMPLETE: (
            f"The model card states no measured boundary error rate for the {BOUNDARY_BAND} band. "
            "Publish the measurement in the card and re-release; the age gate is not installable "
            "without it"
        ),
        Refusal.BUNDLE_DOWNGRADE: (
            "The candidate is older than a bundle this device has already run. Release a higher "
            "version; a rollback cannot reinstate a superseded age gate"
        ),
    }
)


@dataclass(frozen=True)
class ModelCard:
    """The human-readable half of the bundle, checked by machine (D-002)."""

    coverage: str
    known_gaps: tuple[str, ...] = ()
    boundary_error_rate: Mapping[str, float] = field(default_factory=dict)

    @property
    def states_boundary_error(self) -> bool:
        return BOUNDARY_BAND in self.boundary_error_rate

    def as_dict(self) -> dict[str, object]:
        return {
            "coverage": self.coverage,
            "known_gaps": list(self.known_gaps),
            "boundary_error_rate": dict(self.boundary_error_rate),
        }


@dataclass(frozen=True)
class ModelBundle:
    """Detector trunk plus the age head that shares it: one artifact, one version (D-001)."""

    bundle_id: str
    version: int
    age_gate_version: str
    digest: str
    card: ModelCard
    signing_domain: str = MODEL_SIGNING_DOMAIN

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "bundle_id": self.bundle_id,
                "version": self.version,
                "age_gate_version": self.age_gate_version,
                "digest": self.digest,
                "card": self.card.as_dict(),
                "signing_domain": self.signing_domain,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


def digest_of(contents: bytes) -> str:
    return "sha256:" + hashlib.sha256(contents).hexdigest()


def sign(bundle: ModelBundle, key: bytes) -> str:
    return hmac.new(key, bundle.to_bytes(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class SuppressionBaseline:
    """The site's own minor-suppression rate, as the yardstick for the next release (F09 R4).

    The comparison is against this site rather than the fleet: a school-adjacent store legitimately
    suppresses far more than an airport lounge, so a fleet-wide expectation would either alert on
    every honest site or hide a real regression at the busy ones.
    """

    mean: float
    sigma: float
    sigmas: float = 2.0

    def deviation(self, observed_rate: float) -> float:
        if self.sigma <= 0.0:
            return 0.0 if observed_rate == self.mean else float("inf")
        return abs(observed_rate - self.mean) / self.sigma

    def anomalous(self, observed_rate: float) -> bool:
        return self.deviation(observed_rate) > self.sigmas


@dataclass
class ModelStore:
    """Holds the active bundle and the highest version this device has ever activated."""

    key: bytes
    active: ModelBundle | None = None
    version_floor: int = 0
    refusals: dict[Refusal, int] = field(default_factory=dict)

    def verify(self, candidate: ModelBundle, signature: str) -> Refusal | None:
        if candidate.signing_domain != MODEL_SIGNING_DOMAIN:
            return Refusal.WRONG_SIGNING_DOMAIN
        if not hmac.compare_digest(sign(candidate, self.key), signature):
            return Refusal.SIGNATURE_INVALID
        if not candidate.card.states_boundary_error:
            return Refusal.MODEL_CARD_INCOMPLETE
        if candidate.version < self.version_floor:
            return Refusal.BUNDLE_DOWNGRADE
        return None

    def activate(self, candidate: ModelBundle, signature: str) -> Refusal | None:
        """Install, or refuse by name and leave the running bundle exactly where it was."""
        refusal = self.verify(candidate, signature)
        if refusal is not None:
            self.refusals[refusal] = self.refusals.get(refusal, 0) + 1
            return refusal
        self.active = candidate
        self.version_floor = max(self.version_floor, candidate.version)
        return None

    def rollout_halts(self, observed_rate: float, baseline: SuppressionBaseline) -> bool:
        """F09 R4: a suppression shift is a compliance event, so it stops the rollout itself."""
        return baseline.anomalous(observed_rate)

    def attestation(self) -> dict[str, str | int | float | None]:
        """F09 R3: the age-gate version travels with every envelope, not only with the release."""
        if self.active is None:
            return {"model_bundle": None, "age_gate_ver": None, "boundary_error_16_24": None}
        return {
            "model_bundle": self.active.digest,
            "age_gate_ver": self.active.age_gate_version,
            "boundary_error_16_24": self.active.card.boundary_error_rate[BOUNDARY_BAND],
        }
