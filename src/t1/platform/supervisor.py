"""Unit supervision and activation refusal (M04, D-010, F03 R4, C3/C8/C14).

D-010 names four separately signed units. This module is the thing that refuses to start them: a
unit activates only when the bytes on disk hash to the digest its release signature covers, that
signature verifies under *that unit's* release key, its credential scope is a subset of what the
unit is allowed to hold, its dependencies are running, and — for the sealed unit — the environment
it is being handed is actually sealed.

Two properties are worth stating because their absence is the usual way a supervisor fails open:

    Content binding   the signature covers a digest, so the digest must be *measured* from the
                      artifact rather than taken from its metadata. `activate` hashes the bytes.
    Dependency decay  a running unit whose dependency stops is not still supervised. When the
                      egress filter dies the bridge goes with it, or traffic outlives the policy
                      that constrains it.

Refusals are named per unit. `activate` never raises to signal a policy outcome; it returns the
state with a `UnitFinding` attached, because the supervisor's job on a customer site is to keep the
rest of the device running and say precisely what did not come up.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
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

DEPENDENCIES: Final[Mapping[Unit, frozenset[Unit]]] = MappingProxyType(
    {
        Unit.CONTROL_PLANE: frozenset(),
        Unit.EGRESS_FILTER: frozenset({Unit.CONTROL_PLANE}),
        # The bridge may not exist before the filter that constrains what it can send.
        Unit.BRIDGE: frozenset({Unit.CONTROL_PLANE, Unit.EGRESS_FILTER}),
        # Deliberately not the bridge: F03 R4's ingest-only mode keeps the sealed pipeline
        # processing with the bridge down, so a dependency on it would make that mode unreachable.
        Unit.SEALED_PIPELINE: frozenset({Unit.CONTROL_PLANE}),
    }
)

# Least privilege as a closed set: a unit may hold these scopes and no others.
PERMITTED_SCOPES: Final[Mapping[Unit, frozenset[str]]] = MappingProxyType(
    {
        Unit.CONTROL_PLANE: frozenset(
            {"policy:read", "audit:append", "state:write", "unit:supervise"}
        ),
        Unit.EGRESS_FILTER: frozenset({"policy:read", "audit:append"}),
        Unit.BRIDGE: frozenset({"mqtt:publish", "mqtt:subscribe", "spool:write", "audit:append"}),
        Unit.SEALED_PIPELINE: frozenset({"camera:read", "model:read"}),
    }
)


class UnitState(str, Enum):
    STOPPED = "stopped"
    RUNNING = "running"
    REFUSED = "refused"
    FAILED = "failed"


class UnitFinding(str, Enum):
    """Closed set. Every reason a unit is not running."""

    SIGNATURE_INVALID = "signature_invalid"
    CONTENT_MISMATCH = "content_mismatch"
    VERSION_UNKNOWN = "version_unknown"
    SCOPE_EXCEEDED = "scope_exceeded"
    DEPENDENCY_NOT_RUNNING = "dependency_not_running"
    DEPENDENCY_LOST = "dependency_lost"
    SEALED_ENVIRONMENT_UNSEALED = "sealed_environment_unsealed"
    HEALTH_LOST = "health_lost"


UNIT_REMEDIES: Final[Mapping[UnitFinding, str]] = MappingProxyType(
    {
        UnitFinding.SIGNATURE_INVALID: "re-install the unit from a signed release; do not override",
        UnitFinding.CONTENT_MISMATCH: (
            "the artifact's bytes do not hash to its signed digest; re-fetch the release"
        ),
        UnitFinding.VERSION_UNKNOWN: "the artifact declares no version; rebuild it through release",
        UnitFinding.SCOPE_EXCEEDED: "narrow the unit's credentials to its permitted scopes",
        UnitFinding.DEPENDENCY_NOT_RUNNING: (
            "start the unit's dependencies first; see their refusals"
        ),
        UnitFinding.DEPENDENCY_LOST: (
            "a dependency stopped, so this unit was stopped with it; recover the dependency first"
        ),
        UnitFinding.SEALED_ENVIRONMENT_UNSEALED: (
            "the sealed unit was offered network, writable paths, core dumps or swap;"
            " fix the sandbox"
        ),
        UnitFinding.HEALTH_LOST: "the unit stopped answering health checks; inspect its logs",
    }
)


@dataclass(frozen=True)
class Artifact:
    """A released unit. `unit` and `version` are inside the signed payload, so re-labelling a signed
    artifact as an older version produces a forgery rather than a downgrade."""

    unit: Unit
    version: str
    digest: bytes
    signature: str

    def signed_payload(self) -> bytes:
        return f"{ARTIFACT_SIGNING_DOMAIN}:{self.unit.value}:{self.version}".encode() + self.digest

    def verify(self, key: bytes) -> bool:
        """Verifies the *claim*. It says nothing about the bytes on disk — `covers` does that, and
        `Supervisor.activate` requires both."""
        expected = hmac.new(key, self.signed_payload(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    def covers(self, contents: bytes) -> bool:
        return hmac.compare_digest(self.digest, hashlib.sha256(contents).digest())


def sign_artifact(unit: Unit, version: str, contents: bytes, key: bytes) -> Artifact:
    """Signs what the release actually contains: the digest is measured here, never supplied."""
    artifact = Artifact(unit, version, hashlib.sha256(contents).digest(), signature="")
    signature = hmac.new(key, artifact.signed_payload(), hashlib.sha256).hexdigest()
    return replace(artifact, signature=signature)


@dataclass(frozen=True)
class UnitStatus:
    unit: Unit
    state: UnitState = UnitState.STOPPED
    version: str | None = None
    finding: UnitFinding | None = None


@dataclass(frozen=True)
class Supervisor:
    """Immutable, including `units`: every transition returns a new supervisor, so a refused
    activation cannot leave half-applied state behind and an earlier snapshot cannot be edited
    through a shared dict.

    `keys` is per unit. D-010 gives each unit its own release lifecycle, and one key across all four
    would make a single compromised release key sufficient to forge every trust domain on the box.
    """

    keys: Mapping[Unit, bytes]
    units: Mapping[Unit, UnitStatus]

    def __post_init__(self) -> None:
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))
        object.__setattr__(self, "units", MappingProxyType(dict(self.units)))

    @classmethod
    def stopped(cls, keys: Mapping[Unit, bytes]) -> Supervisor:
        missing = set(START_ORDER) - set(keys)
        if missing:
            raise ValueError(f"no release key for {sorted(u.value for u in missing)}")
        return cls(keys=keys, units={unit: UnitStatus(unit) for unit in START_ORDER})

    def state(self, unit: Unit) -> UnitState:
        return self.units[unit].state

    @property
    def running(self) -> frozenset[Unit]:
        return frozenset(u for u, s in self.units.items() if s.state is UnitState.RUNNING)

    def activate(
        self,
        artifact: Artifact,
        contents: bytes,
        *,
        scopes: frozenset[str],
        sealed_environment: SealedEnvironment | None = None,
    ) -> Supervisor:
        """Start one unit, or refuse it by name. `contents` is the artifact as it sits on disk; its
        digest is measured here rather than trusted from the artifact's metadata."""
        finding = self._refusal(artifact, contents, scopes, sealed_environment)
        status = (
            UnitStatus(artifact.unit, UnitState.REFUSED, artifact.version, finding)
            if finding is not None
            else UnitStatus(artifact.unit, UnitState.RUNNING, artifact.version)
        )
        return self._with(status)

    def report_health(self, unit: Unit, *, healthy: bool) -> Supervisor:
        """A unit found dead is `FAILED`, never quietly assumed alive."""
        if healthy:
            return self
        status = self.units[unit]
        return self._with(
            UnitStatus(unit, UnitState.FAILED, status.version, UnitFinding.HEALTH_LOST)
        )

    def refusals(self) -> tuple[tuple[Unit, UnitFinding], ...]:
        return tuple(
            (unit, status.finding)
            for unit, status in self.units.items()
            if status.finding is not None
        )

    def _refusal(
        self,
        artifact: Artifact,
        contents: bytes,
        scopes: frozenset[str],
        sealed_environment: SealedEnvironment | None,
    ) -> UnitFinding | None:
        if not artifact.version:
            return UnitFinding.VERSION_UNKNOWN
        if not artifact.verify(self.keys[artifact.unit]):
            return UnitFinding.SIGNATURE_INVALID
        if not artifact.covers(contents):
            return UnitFinding.CONTENT_MISMATCH
        if not scopes <= PERMITTED_SCOPES[artifact.unit]:
            return UnitFinding.SCOPE_EXCEEDED
        if not DEPENDENCIES[artifact.unit] <= self.running:
            return UnitFinding.DEPENDENCY_NOT_RUNNING
        unsealed = sealed_environment is None or bool(sealed_environment.violations())
        if artifact.unit is Unit.SEALED_PIPELINE and unsealed:
            return UnitFinding.SEALED_ENVIRONMENT_UNSEALED
        return None

    def _with(self, status: UnitStatus) -> Supervisor:
        units = {**self.units, status.unit: status}
        return replace(self, units=_stop_orphans(units))


def _stop_orphans(units: dict[Unit, UnitStatus]) -> dict[Unit, UnitStatus]:
    """A unit whose dependency is no longer running is stopped with it, transitively. Supervision
    that leaves the bridge up after the egress filter dies is supervision that fails open."""
    while True:
        running = {unit for unit, status in units.items() if status.state is UnitState.RUNNING}
        orphans = [unit for unit in running if not DEPENDENCIES[unit] <= running]
        if not orphans:
            return units
        for unit in orphans:
            units[unit] = UnitStatus(
                unit, UnitState.STOPPED, units[unit].version, UnitFinding.DEPENDENCY_LOST
            )
