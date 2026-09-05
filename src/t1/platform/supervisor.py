"""Unit supervision and activation refusal (M04, D-010, F03 R4, C3/C8/C14).

D-010 names four separately signed units. This module is the thing that refuses to start them: a
unit activates only when its artifact signature verifies, its credential scope is a subset of what
that unit is allowed to hold, its dependencies are already running, and — for the sealed unit — the
environment it is being handed is actually sealed.

The ordering matters and is not incidental. `EGRESS_FILTER` starts before `BRIDGE` so no path to T2
exists before the policy that constrains it is live, and `SEALED_PIPELINE` starts last because it
is the only unit that ever holds unredacted pixels.

Refusals are named per unit. `activate` never raises to signal a policy outcome; it returns the
state with a `UnitFinding` attached, because the supervisor's job on a customer site is to keep the
rest of the device running and say precisely what did not come up.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, replace
from enum import Enum
from typing import Final

from t1.sealed.guard import SealedEnvironment

ARTIFACT_SIGNING_DOMAIN: Final[str] = "t1-unit-artifact"


class Unit(str, Enum):
    """D-010's four units, in start order."""

    CONTROL_PLANE = "control_plane"
    EGRESS_FILTER = "egress_filter"
    BRIDGE = "bridge"
    SEALED_PIPELINE = "sealed_pipeline"


START_ORDER: Final[tuple[Unit, ...]] = tuple(Unit)

DEPENDENCIES: Final[dict[Unit, frozenset[Unit]]] = {
    Unit.CONTROL_PLANE: frozenset(),
    Unit.EGRESS_FILTER: frozenset({Unit.CONTROL_PLANE}),
    # The bridge may not exist before the filter that constrains what it can send.
    Unit.BRIDGE: frozenset({Unit.CONTROL_PLANE, Unit.EGRESS_FILTER}),
    Unit.SEALED_PIPELINE: frozenset({Unit.CONTROL_PLANE}),
}

# Least privilege as a closed set: a unit may hold these scopes and no others.
PERMITTED_SCOPES: Final[dict[Unit, frozenset[str]]] = {
    Unit.CONTROL_PLANE: frozenset({"policy:read", "audit:append", "state:write", "unit:supervise"}),
    Unit.EGRESS_FILTER: frozenset({"policy:read", "audit:append"}),
    Unit.BRIDGE: frozenset({"mqtt:publish", "mqtt:subscribe", "spool:write", "audit:append"}),
    Unit.SEALED_PIPELINE: frozenset({"camera:read", "model:read"}),
}


class UnitState(str, Enum):
    STOPPED = "stopped"
    RUNNING = "running"
    REFUSED = "refused"
    FAILED = "failed"


class UnitFinding(str, Enum):
    """Closed set. Every reason a unit is not running."""

    SIGNATURE_INVALID = "signature_invalid"
    VERSION_UNKNOWN = "version_unknown"
    SCOPE_EXCEEDED = "scope_exceeded"
    DEPENDENCY_NOT_RUNNING = "dependency_not_running"
    SEALED_ENVIRONMENT_UNSEALED = "sealed_environment_unsealed"
    HEALTH_LOST = "health_lost"


UNIT_REMEDIES: Final[dict[UnitFinding, str]] = {
    UnitFinding.SIGNATURE_INVALID: "re-install the unit from a signed release; do not override",
    UnitFinding.VERSION_UNKNOWN: "the artifact declares no version; rebuild it through release",
    UnitFinding.SCOPE_EXCEEDED: "narrow the unit's credentials to its permitted scopes",
    UnitFinding.DEPENDENCY_NOT_RUNNING: "start the unit's dependencies first; check their refusals",
    UnitFinding.SEALED_ENVIRONMENT_UNSEALED: (
        "the sealed unit was offered network, writable paths, core dumps or swap; fix the sandbox"
    ),
    UnitFinding.HEALTH_LOST: "the unit stopped answering health checks; inspect its logs",
}


@dataclass(frozen=True)
class Artifact:
    """A released unit. `version` participates in the signature, so a downgrade is a forgery."""

    unit: Unit
    version: str
    digest: bytes
    signature: str

    def verify(self, key: bytes) -> bool:
        payload = f"{ARTIFACT_SIGNING_DOMAIN}:{self.unit.value}:{self.version}".encode()
        expected = hmac.new(key, payload + self.digest, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)


def sign_artifact(unit: Unit, version: str, digest: bytes, key: bytes) -> Artifact:
    payload = f"{ARTIFACT_SIGNING_DOMAIN}:{unit.value}:{version}".encode()
    signature = hmac.new(key, payload + digest, hashlib.sha256).hexdigest()
    return Artifact(unit=unit, version=version, digest=digest, signature=signature)


@dataclass(frozen=True)
class UnitStatus:
    unit: Unit
    state: UnitState = UnitState.STOPPED
    version: str | None = None
    finding: UnitFinding | None = None


@dataclass(frozen=True)
class Supervisor:
    """Immutable. Every transition returns a new supervisor, so a refused activation cannot leave
    half-applied state behind."""

    key: bytes
    units: dict[Unit, UnitStatus]

    @classmethod
    def stopped(cls, key: bytes) -> Supervisor:
        return cls(key=key, units={unit: UnitStatus(unit) for unit in START_ORDER})

    def state(self, unit: Unit) -> UnitState:
        return self.units[unit].state

    @property
    def running(self) -> frozenset[Unit]:
        return frozenset(u for u, s in self.units.items() if s.state is UnitState.RUNNING)

    def _with(self, status: UnitStatus) -> Supervisor:
        return replace(self, units={**self.units, status.unit: status})

    def activate(
        self,
        artifact: Artifact,
        *,
        scopes: frozenset[str],
        sealed_environment: SealedEnvironment | None = None,
    ) -> Supervisor:
        """Start one unit, or refuse it by name. Checked cheapest-and-hardest first."""
        unit = artifact.unit
        finding = self._refusal(artifact, scopes, sealed_environment)
        if finding is not None:
            return self._with(UnitStatus(unit, UnitState.REFUSED, artifact.version, finding))
        return self._with(UnitStatus(unit, UnitState.RUNNING, artifact.version))

    def _refusal(
        self,
        artifact: Artifact,
        scopes: frozenset[str],
        sealed_environment: SealedEnvironment | None,
    ) -> UnitFinding | None:
        if not artifact.version:
            return UnitFinding.VERSION_UNKNOWN
        if not artifact.verify(self.key):
            return UnitFinding.SIGNATURE_INVALID
        if not scopes <= PERMITTED_SCOPES[artifact.unit]:
            return UnitFinding.SCOPE_EXCEEDED
        if not DEPENDENCIES[artifact.unit] <= self.running:
            return UnitFinding.DEPENDENCY_NOT_RUNNING
        unsealed = sealed_environment is None or bool(sealed_environment.violations())
        if artifact.unit is Unit.SEALED_PIPELINE and unsealed:
            return UnitFinding.SEALED_ENVIRONMENT_UNSEALED
        return None

    def report_health(self, unit: Unit, *, healthy: bool) -> Supervisor:
        """A unit found dead is `FAILED`, never quietly assumed alive."""
        status = self.units[unit]
        if healthy:
            return self
        return self._with(
            UnitStatus(unit, UnitState.FAILED, status.version, UnitFinding.HEALTH_LOST)
        )

    def refusals(self) -> tuple[tuple[Unit, UnitFinding], ...]:
        return tuple(
            (unit, status.finding)
            for unit, status in self.units.items()
            if status.finding is not None
        )
