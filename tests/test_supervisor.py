"""M04 — the four D-010 units, and every way the supervisor refuses to start one."""

from __future__ import annotations

import hashlib

from t1.platform.supervisor import (
    PERMITTED_SCOPES,
    START_ORDER,
    UNIT_REMEDIES,
    Artifact,
    Supervisor,
    Unit,
    UnitFinding,
    UnitState,
    sign_artifact,
)
from t1.sealed.guard import SealedEnvironment

KEY = b"release-signing-key"
SEALED = SealedEnvironment()


def _artifact(unit: Unit, version: str = "1.0.0") -> Artifact:
    return sign_artifact(unit, version, hashlib.sha256(unit.value.encode()).digest(), KEY)


def _bring_up(supervisor: Supervisor, *units: Unit) -> Supervisor:
    for unit in units:
        supervisor = supervisor.activate(
            _artifact(unit),
            scopes=PERMITTED_SCOPES[unit],
            sealed_environment=SEALED if unit is Unit.SEALED_PIPELINE else None,
        )
    return supervisor


def test_the_four_units_come_up_in_order_with_no_refusals() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEY), *START_ORDER)
    assert supervisor.running == frozenset(Unit)
    assert supervisor.refusals() == ()


def test_the_bridge_cannot_start_before_the_egress_filter() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEY), Unit.CONTROL_PLANE)
    supervisor = supervisor.activate(_artifact(Unit.BRIDGE), scopes=PERMITTED_SCOPES[Unit.BRIDGE])

    assert supervisor.state(Unit.BRIDGE) is UnitState.REFUSED
    assert supervisor.refusals() == ((Unit.BRIDGE, UnitFinding.DEPENDENCY_NOT_RUNNING),)


def test_an_unsigned_or_tampered_artifact_is_refused() -> None:
    forged = Artifact(Unit.CONTROL_PLANE, "1.0.0", b"digest", "0" * 64)
    supervisor = Supervisor.stopped(KEY).activate(forged, scopes=frozenset())
    assert supervisor.refusals() == ((Unit.CONTROL_PLANE, UnitFinding.SIGNATURE_INVALID),)


def test_the_version_is_inside_the_signature_so_a_downgrade_is_a_forgery() -> None:
    released = _artifact(Unit.EGRESS_FILTER, "2.0.0")
    downgraded = Artifact(released.unit, "1.0.0", released.digest, released.signature)

    supervisor = _bring_up(Supervisor.stopped(KEY), Unit.CONTROL_PLANE)
    supervisor = supervisor.activate(downgraded, scopes=PERMITTED_SCOPES[Unit.EGRESS_FILTER])
    assert supervisor.state(Unit.EGRESS_FILTER) is UnitState.REFUSED
    assert supervisor.refusals() == ((Unit.EGRESS_FILTER, UnitFinding.SIGNATURE_INVALID),)


def test_a_missing_version_is_named_rather_than_signed_around() -> None:
    supervisor = Supervisor.stopped(KEY).activate(
        _artifact(Unit.CONTROL_PLANE, ""), scopes=frozenset()
    )
    assert supervisor.refusals() == ((Unit.CONTROL_PLANE, UnitFinding.VERSION_UNKNOWN),)


def test_a_unit_asking_for_a_scope_it_may_not_hold_is_refused() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEY), Unit.CONTROL_PLANE, Unit.EGRESS_FILTER)
    supervisor = supervisor.activate(
        _artifact(Unit.BRIDGE),
        scopes=PERMITTED_SCOPES[Unit.BRIDGE] | {"camera:read"},
    )
    assert supervisor.refusals() == ((Unit.BRIDGE, UnitFinding.SCOPE_EXCEEDED),)


def test_the_sealed_unit_refuses_an_unsealed_environment() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEY), Unit.CONTROL_PLANE)
    for environment in (
        None,
        SealedEnvironment(network_namespace=True),
        SealedEnvironment(writable_persistent_paths=("/var/lib/t1",)),
        SealedEnvironment(core_dumps_enabled=True),
        SealedEnvironment(swap_enabled=True),
    ):
        attempted = supervisor.activate(
            _artifact(Unit.SEALED_PIPELINE),
            scopes=PERMITTED_SCOPES[Unit.SEALED_PIPELINE],
            sealed_environment=environment,
        )
        assert attempted.state(Unit.SEALED_PIPELINE) is UnitState.REFUSED
        assert attempted.refusals() == (
            (Unit.SEALED_PIPELINE, UnitFinding.SEALED_ENVIRONMENT_UNSEALED),
        )


def test_the_sealed_unit_may_not_hold_a_network_scope() -> None:
    assert not PERMITTED_SCOPES[Unit.SEALED_PIPELINE] & {"mqtt:publish", "mqtt:subscribe"}
    assert PERMITTED_SCOPES[Unit.SEALED_PIPELINE].isdisjoint(PERMITTED_SCOPES[Unit.BRIDGE])


def test_a_unit_that_stops_answering_is_failed_not_assumed_alive() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEY), *START_ORDER)
    supervisor = supervisor.report_health(Unit.BRIDGE, healthy=True)
    assert supervisor.state(Unit.BRIDGE) is UnitState.RUNNING

    supervisor = supervisor.report_health(Unit.BRIDGE, healthy=False)
    assert supervisor.state(Unit.BRIDGE) is UnitState.FAILED
    assert supervisor.refusals() == ((Unit.BRIDGE, UnitFinding.HEALTH_LOST),)


def test_a_refused_activation_leaves_the_other_units_untouched() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEY), Unit.CONTROL_PLANE, Unit.EGRESS_FILTER)
    after = supervisor.activate(
        Artifact(Unit.BRIDGE, "1.0.0", b"x", "0" * 64), scopes=PERMITTED_SCOPES[Unit.BRIDGE]
    )
    assert after.running == frozenset({Unit.CONTROL_PLANE, Unit.EGRESS_FILTER})
    assert supervisor.state(Unit.BRIDGE) is UnitState.STOPPED


def test_every_unit_finding_carries_a_remedy() -> None:
    assert set(UNIT_REMEDIES) == set(UnitFinding)
