"""M04 — the four D-010 units, and every way the supervisor refuses to start or keep one."""

from __future__ import annotations

import hashlib

import pytest

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

KEYS = {unit: f"release-key-{unit.value}".encode() for unit in Unit}
SEALED = SealedEnvironment()


def _contents(unit: Unit, version: str = "1.0.0") -> bytes:
    return f"{unit.value}-{version}-bytes".encode()


def _artifact(unit: Unit, version: str = "1.0.0") -> Artifact:
    return sign_artifact(unit, version, _contents(unit, version), KEYS[unit])


def _bring_up(supervisor: Supervisor, *units: Unit) -> Supervisor:
    for unit in units:
        supervisor = supervisor.activate(
            _artifact(unit),
            _contents(unit),
            scopes=PERMITTED_SCOPES[unit],
            sealed_environment=SEALED if unit is Unit.SEALED_PIPELINE else None,
        )
    return supervisor


def test_the_four_units_come_up_in_order_with_no_refusals() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEYS), *START_ORDER)
    assert supervisor.running == frozenset(Unit)
    assert supervisor.refusals() == ()


def test_the_bridge_cannot_start_before_the_egress_filter() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEYS), Unit.CONTROL_PLANE)
    supervisor = supervisor.activate(
        _artifact(Unit.BRIDGE), _contents(Unit.BRIDGE), scopes=PERMITTED_SCOPES[Unit.BRIDGE]
    )

    assert supervisor.state(Unit.BRIDGE) is UnitState.REFUSED
    assert supervisor.refusals() == ((Unit.BRIDGE, UnitFinding.DEPENDENCY_NOT_RUNNING),)


def test_the_sealed_pipeline_does_not_depend_on_the_bridge() -> None:
    # F03 R4: ingest-only mode runs the sealed pipeline with the bridge down. A dependency on the
    # bridge would make that mode unreachable.
    supervisor = _bring_up(Supervisor.stopped(KEYS), Unit.CONTROL_PLANE, Unit.SEALED_PIPELINE)
    assert supervisor.running == frozenset({Unit.CONTROL_PLANE, Unit.SEALED_PIPELINE})


def test_an_unsigned_or_tampered_artifact_is_refused() -> None:
    forged = Artifact(Unit.CONTROL_PLANE, "1.0.0", b"digest", "0" * 64)
    supervisor = Supervisor.stopped(KEYS).activate(forged, b"anything", scopes=frozenset())
    assert supervisor.refusals() == ((Unit.CONTROL_PLANE, UnitFinding.SIGNATURE_INVALID),)


def test_the_signature_binds_the_artifacts_bytes_not_just_its_metadata() -> None:
    released = _artifact(Unit.CONTROL_PLANE)
    supervisor = Supervisor.stopped(KEYS).activate(
        released, b"substituted binary", scopes=PERMITTED_SCOPES[Unit.CONTROL_PLANE]
    )
    assert supervisor.state(Unit.CONTROL_PLANE) is UnitState.REFUSED
    assert supervisor.refusals() == ((Unit.CONTROL_PLANE, UnitFinding.CONTENT_MISMATCH),)


def test_one_units_release_key_cannot_sign_another_unit() -> None:
    contents = _contents(Unit.BRIDGE)
    cross_signed = sign_artifact(Unit.BRIDGE, "1.0.0", contents, KEYS[Unit.CONTROL_PLANE])

    supervisor = _bring_up(Supervisor.stopped(KEYS), Unit.CONTROL_PLANE, Unit.EGRESS_FILTER)
    supervisor = supervisor.activate(cross_signed, contents, scopes=PERMITTED_SCOPES[Unit.BRIDGE])
    assert supervisor.refusals() == ((Unit.BRIDGE, UnitFinding.SIGNATURE_INVALID),)


def test_a_supervisor_without_a_key_for_every_unit_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match="bridge"):
        Supervisor.stopped({unit: KEYS[unit] for unit in Unit if unit is not Unit.BRIDGE})


def test_the_version_is_inside_the_signature_so_a_downgrade_is_a_forgery() -> None:
    released = _artifact(Unit.EGRESS_FILTER, "2.0.0")
    downgraded = Artifact(released.unit, "1.0.0", released.digest, released.signature)

    supervisor = _bring_up(Supervisor.stopped(KEYS), Unit.CONTROL_PLANE)
    supervisor = supervisor.activate(
        downgraded,
        _contents(Unit.EGRESS_FILTER, "2.0.0"),
        scopes=PERMITTED_SCOPES[Unit.EGRESS_FILTER],
    )
    assert supervisor.state(Unit.EGRESS_FILTER) is UnitState.REFUSED
    assert supervisor.refusals() == ((Unit.EGRESS_FILTER, UnitFinding.SIGNATURE_INVALID),)


def test_a_missing_version_is_named_rather_than_signed_around() -> None:
    supervisor = Supervisor.stopped(KEYS).activate(
        _artifact(Unit.CONTROL_PLANE, ""), _contents(Unit.CONTROL_PLANE, ""), scopes=frozenset()
    )
    assert supervisor.refusals() == ((Unit.CONTROL_PLANE, UnitFinding.VERSION_UNKNOWN),)


def test_a_unit_asking_for_a_scope_it_may_not_hold_is_refused() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEYS), Unit.CONTROL_PLANE, Unit.EGRESS_FILTER)
    supervisor = supervisor.activate(
        _artifact(Unit.BRIDGE),
        _contents(Unit.BRIDGE),
        scopes=PERMITTED_SCOPES[Unit.BRIDGE] | {"camera:read"},
    )
    assert supervisor.refusals() == ((Unit.BRIDGE, UnitFinding.SCOPE_EXCEEDED),)


def test_the_sealed_unit_refuses_an_unsealed_environment() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEYS), Unit.CONTROL_PLANE)
    for environment in (
        None,
        SealedEnvironment(network_namespace=True),
        SealedEnvironment(writable_persistent_paths=("/var/lib/t1",)),
        SealedEnvironment(core_dumps_enabled=True),
        SealedEnvironment(swap_enabled=True),
    ):
        attempted = supervisor.activate(
            _artifact(Unit.SEALED_PIPELINE),
            _contents(Unit.SEALED_PIPELINE),
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
    supervisor = _bring_up(Supervisor.stopped(KEYS), *START_ORDER)
    supervisor = supervisor.report_health(Unit.BRIDGE, healthy=True)
    assert supervisor.state(Unit.BRIDGE) is UnitState.RUNNING

    supervisor = supervisor.report_health(Unit.BRIDGE, healthy=False)
    assert supervisor.state(Unit.BRIDGE) is UnitState.FAILED
    assert supervisor.refusals() == ((Unit.BRIDGE, UnitFinding.HEALTH_LOST),)


def test_the_bridge_does_not_outlive_the_filter_that_constrains_it() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEYS), *START_ORDER)
    supervisor = supervisor.report_health(Unit.EGRESS_FILTER, healthy=False)

    assert supervisor.state(Unit.EGRESS_FILTER) is UnitState.FAILED
    assert supervisor.state(Unit.BRIDGE) is UnitState.STOPPED
    assert dict(supervisor.refusals())[Unit.BRIDGE] is UnitFinding.DEPENDENCY_LOST
    # The sealed pipeline does not depend on the bridge and keeps running (F03 R4).
    assert supervisor.state(Unit.SEALED_PIPELINE) is UnitState.RUNNING


def test_losing_the_control_plane_takes_every_dependent_with_it() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEYS), *START_ORDER)
    supervisor = supervisor.report_health(Unit.CONTROL_PLANE, healthy=False)
    assert supervisor.running == frozenset()


def test_refusing_a_replacement_artifact_for_a_running_unit_stops_its_dependents() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEYS), *START_ORDER)
    supervisor = supervisor.activate(
        Artifact(Unit.EGRESS_FILTER, "2.0.0", hashlib.sha256(b"x").digest(), "0" * 64),
        b"x",
        scopes=PERMITTED_SCOPES[Unit.EGRESS_FILTER],
    )
    assert supervisor.state(Unit.EGRESS_FILTER) is UnitState.REFUSED
    assert supervisor.state(Unit.BRIDGE) is UnitState.STOPPED


def test_a_refused_activation_leaves_the_other_units_untouched() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEYS), Unit.CONTROL_PLANE, Unit.EGRESS_FILTER)
    after = supervisor.activate(
        Artifact(Unit.BRIDGE, "1.0.0", b"x", "0" * 64), b"x", scopes=PERMITTED_SCOPES[Unit.BRIDGE]
    )
    assert after.running == frozenset({Unit.CONTROL_PLANE, Unit.EGRESS_FILTER})
    assert supervisor.state(Unit.BRIDGE) is UnitState.STOPPED


def test_an_earlier_snapshot_cannot_be_edited_through_shared_state() -> None:
    supervisor = _bring_up(Supervisor.stopped(KEYS), Unit.CONTROL_PLANE)
    later = _bring_up(supervisor, Unit.EGRESS_FILTER)

    with pytest.raises(TypeError):
        supervisor.units[Unit.CONTROL_PLANE] = supervisor.units[Unit.BRIDGE]  # type: ignore[index]
    assert supervisor.running == frozenset({Unit.CONTROL_PLANE})
    assert later.running == frozenset({Unit.CONTROL_PLANE, Unit.EGRESS_FILTER})


def test_every_unit_finding_carries_a_remedy() -> None:
    assert set(UNIT_REMEDIES) == set(UnitFinding)
