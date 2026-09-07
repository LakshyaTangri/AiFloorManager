"""Kill switch (M15, F17): killing is cheap, un-killing is authorised, both are durable."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from t1.canon import Profile
from t1.control.audit_chain import AuditChain
from t1.security.kill_switch import Kill, KillRefusal, KillScope, KillSwitch, Role

NOW = datetime(2026, 4, 1, 9, 0, 0)
LATER = NOW + timedelta(hours=2)


@pytest.fixture
def chain(tmp_path: Path) -> AuditChain:
    return AuditChain(tmp_path / "audit" / "chain.jsonl")


def _switch(chain: AuditChain, tmp_path: Path, profile: Profile = Profile.L1) -> KillSwitch:
    return KillSwitch(profile=profile, chain=chain, state_path=tmp_path / "state" / "kills.json")


def test_a_killed_camera_stays_killed_across_a_restart(chain: AuditChain, tmp_path: Path) -> None:
    switch = _switch(chain, tmp_path)
    killed = switch.kill(KillScope.CAMERA, "cam-2", "sm@site", "customer complaint", NOW)
    assert isinstance(killed, Kill)
    assert not switch.stream_allowed("cam-2")

    rebooted = _switch(chain, tmp_path)
    assert not rebooted.stream_allowed("cam-2")
    assert rebooted.stream_allowed("cam-1")

    reported = rebooted.reported_state()
    assert reported["kills"] == [
        {
            "scope": "camera",
            "target": "cam-2",
            "actor": "sm@site",
            "reason": "customer complaint",
            "at": NOW.isoformat(),
        }
    ]
    assert [record.kind for record in chain.records()] == ["kill_asserted"]


def test_a_zone_or_capability_kill_stops_the_streams_under_it(
    chain: AuditChain, tmp_path: Path
) -> None:
    switch = _switch(chain, tmp_path)
    switch.kill(KillScope.ZONE, "pharmacy", "sm@site", "pharmacy counter", NOW)
    switch.kill(KillScope.CAPABILITY, "dwell_time", "sm@site", "works council", NOW)

    assert not switch.stream_allowed("cam-1", zone_id="pharmacy")
    assert switch.stream_allowed("cam-1", zone_id="entrance")
    assert not switch.stream_allowed("cam-1", zone_id="entrance", capabilities=("dwell_time",))


def test_un_kill_requires_ta_authorisation(chain: AuditChain, tmp_path: Path) -> None:
    switch = _switch(chain, tmp_path)
    switch.kill(KillScope.CAMERA, "cam-2", "sm@site", "customer complaint", NOW)

    refusal = switch.unkill(KillScope.CAMERA, "cam-2", "sm@site", Role.STORE_MANAGER, LATER)
    assert refusal is KillRefusal.TA_AUTHORISATION_REQUIRED
    assert not switch.stream_allowed("cam-2")
    assert not _switch(chain, tmp_path).stream_allowed("cam-2")

    assert switch.unkill(KillScope.CAMERA, "cam-2", "ta@tenant", Role.TENANT_ADMIN, LATER) is None
    assert switch.stream_allowed("cam-2")
    assert _switch(chain, tmp_path).stream_allowed("cam-2")


def test_a_kill_without_a_reason_is_refused_and_audited(chain: AuditChain, tmp_path: Path) -> None:
    switch = _switch(chain, tmp_path)
    assert switch.kill(KillScope.CAMERA, "cam-2", "sm@site", "", NOW) is KillRefusal.REASON_MISSING
    assert switch.kill(KillScope.CAMERA, "cam-2", "", "reason", NOW) is KillRefusal.ACTOR_MISSING
    assert switch.stream_allowed("cam-2")
    assert [record.kind for record in chain.records()] == ["kill_refused", "kill_refused"]


def test_an_asserted_hardware_input_cannot_be_cleared_in_software(
    chain: AuditChain, tmp_path: Path
) -> None:
    switch = _switch(chain, tmp_path, profile=Profile.L3)
    switch.kill(KillScope.CAMERA, "cam-2", "sm@site", "maintenance", NOW)
    assert switch.assert_hardware(NOW) is None

    assert not switch.stream_allowed("cam-1")
    refusal = switch.unkill(KillScope.CAMERA, "cam-2", "ta@tenant", Role.TENANT_ADMIN, LATER)
    assert refusal is KillRefusal.HARDWARE_KILL_ASSERTED
    assert not switch.stream_allowed("cam-2")

    switch.release_hardware(LATER)
    assert switch.stream_allowed("cam-1")
    assert not switch.stream_allowed("cam-2")


def test_l1_has_no_hardware_input_and_discloses_it(chain: AuditChain, tmp_path: Path) -> None:
    switch = _switch(chain, tmp_path)
    assert switch.software_only
    assert switch.assert_hardware(NOW) is KillRefusal.HARDWARE_KILL_UNAVAILABLE
    assert not switch.hardware_asserted
    assert not _switch(chain, tmp_path, profile=Profile.L3).software_only


def test_releasing_a_camera_that_was_never_killed_is_refused(
    chain: AuditChain, tmp_path: Path
) -> None:
    switch = _switch(chain, tmp_path)
    refusal = switch.unkill(KillScope.CAMERA, "cam-9", "ta@tenant", Role.TENANT_ADMIN, NOW)
    assert refusal is KillRefusal.NOT_KILLED
    assert chain.verify().ok
