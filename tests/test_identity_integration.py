"""Identity and the kill switch where they bite: egress and the commissioning gate (M15)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from t1.canon import DataClass, Profile, TrustLevel
from t1.contracts import Envelope
from t1.control.audit_chain import AuditChain
from t1.control.commissioning import ActivationRefused, CommissioningGate, GateItem
from t1.control.egress_filter import EgressFilter
from t1.control.policy import PolicyStore
from t1.security.gate_evidence import exercise_kill_switch, record_identity
from t1.security.identity import (
    DeviceIdentity,
    FleetRegistry,
    HardwareFacts,
    ReEnrolmentApproval,
    host_fingerprint,
    sign_approval,
)
from t1.security.kill_switch import KillScope, KillSwitch, Role

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(days=1)
T2_KEY = b"dev-only-t2-exception-key"
FACTS = HardwareFacts(disk_serial="SSD-CTRL-0001", host_dmi="dmi-host-a")
MOVED = HardwareFacts(disk_serial="SSD-CTRL-0001", host_dmi="dmi-host-b")
TA = "ta@tenant"


@pytest.fixture
def identity(chain: AuditChain) -> DeviceIdentity:
    device = DeviceIdentity(
        profile=Profile.L1, chain=chain, registry=FleetRegistry(), t2_key=T2_KEY
    )
    device.enrol(FACTS, NOW)
    return device


def _footfall() -> Envelope:
    return Envelope(
        device_id="d",
        boot_id="b",
        seq=1,
        device_time=NOW.isoformat(),
        schema="rtl.aggregate.v1",
        data_class=DataClass.C1_AGGREGATE,
        purpose="analytics",
        trust_level=TrustLevel.SOFTWARE_BOUND,
        payload={
            "metric": "footfall",
            "value": 12,
            "window_start": NOW.isoformat(),
            "k_suppressed": False,
        },
        policy_version="3",
        metric="footfall",
        k_value=7,
    )


def test_a_pending_re_enrolment_stops_egress_and_approval_resumes_it(
    store: PolicyStore, chain: AuditChain, identity: DeviceIdentity
) -> None:
    filt = EgressFilter(policy=store, chain=chain, identity=identity)
    assert filt.evaluate(_footfall()).accepted

    identity.observe_boot(MOVED, LATER)
    verdict = filt.evaluate(_footfall())
    assert verdict.rejected
    assert verdict.reason == "identity_not_enrolled"

    approval = ReEnrolmentApproval(
        device_id=str(identity.device_id),
        fingerprint=str(host_fingerprint(Profile.L1, MOVED)),
        approver=TA,
        issued_at=LATER.isoformat(),
    )
    identity.approve_re_enrolment(approval, sign_approval(approval, T2_KEY), LATER)
    assert filt.evaluate(_footfall()).accepted


def test_the_identity_item_cannot_be_ticked_before_enrolment(chain: AuditChain) -> None:
    gate = CommissioningGate(device_id="rtl-l1-0001", chain=chain, t2_key=T2_KEY)
    unenrolled = DeviceIdentity(
        profile=Profile.L1, chain=chain, registry=FleetRegistry(), t2_key=T2_KEY
    )

    with pytest.raises(ActivationRefused) as refused:
        record_identity(gate, unenrolled, "fe-207", NOW)
    assert refused.value.reason == "identity_not_enrolled"
    assert GateItem.IDENTITY not in gate.passed

    unenrolled.enrol(FACTS, NOW)
    record_identity(gate, unenrolled, "fe-207", NOW)
    assert GateItem.IDENTITY in gate.passed


def test_the_kill_switch_item_is_an_exercise_not_a_tick(chain: AuditChain, tmp_path: Path) -> None:
    gate = CommissioningGate(device_id="rtl-l1-0001", chain=chain, t2_key=T2_KEY)
    switch = KillSwitch(profile=Profile.L1, chain=chain, state_path=tmp_path / "kills.json")

    exercise_kill_switch(gate, switch, "cam-1", TA, NOW)
    assert GateItem.KILL_SWITCH in gate.passed
    assert switch.stream_allowed("cam-1")
    kinds = [record.kind for record in chain.records()]
    assert kinds == ["kill_asserted", "kill_released", "commissioning_item"]


def test_a_camera_left_killed_cannot_stand_in_for_the_exercise(
    chain: AuditChain, tmp_path: Path
) -> None:
    gate = CommissioningGate(device_id="rtl-l1-0001", chain=chain, t2_key=T2_KEY)
    switch = KillSwitch(profile=Profile.L1, chain=chain, state_path=tmp_path / "kills.json")
    switch.kill(KillScope.CAMERA, "cam-1", TA, "already off", NOW)

    with pytest.raises(ActivationRefused):
        exercise_kill_switch(gate, switch, "cam-1", TA, NOW)
    assert GateItem.KILL_SWITCH not in gate.passed
    assert switch.unkill(KillScope.CAMERA, "cam-1", TA, Role.TENANT_ADMIN, LATER) is None
