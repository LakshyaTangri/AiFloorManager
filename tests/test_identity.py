"""Device identity and anti-clone enrolment (M15, F04)."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from t1.canon import Profile, TrustLevel
from t1.control.audit_chain import AuditChain
from t1.security.identity import (
    Certificate,
    DeviceIdentity,
    FleetRegistry,
    HardwareFacts,
    IdentityRefusal,
    IdentityState,
    KeyProtection,
    ReEnrolmentApproval,
    host_fingerprint,
    sign_approval,
)

NOW = datetime(2026, 4, 1, 8, 0, 0)
LATER = NOW + timedelta(days=30)
T2_KEY = b"t2-approval-key"

L1_FACTS = HardwareFacts(disk_serial="SSD-CTRL-0001", host_dmi="dmi-host-a")
L1_ON_NEW_HOST = HardwareFacts(disk_serial="SSD-CTRL-0001", host_dmi="dmi-host-b")
L2_FACTS = HardwareFacts(module_serial="SOM-0001", host_dmi="dmi-host-a")


@pytest.fixture
def chain(tmp_path: Path) -> AuditChain:
    return AuditChain(tmp_path / "audit" / "chain.jsonl")


def _egress(device: DeviceIdentity) -> bool:
    """Read through a call so a refusal earlier in a test does not narrow the later assertion."""
    return bool(device.egress_allowed)


def _identity(
    chain: AuditChain, registry: FleetRegistry, profile: Profile = Profile.L1
) -> DeviceIdentity:
    return DeviceIdentity(profile=profile, chain=chain, registry=registry, t2_key=T2_KEY)


def test_first_boot_enrols_once_and_binds_the_host(chain: AuditChain) -> None:
    device = _identity(chain, FleetRegistry())
    certificate = device.enrol(L1_FACTS, NOW)

    assert isinstance(certificate, Certificate)
    assert device.state is IdentityState.ENROLLED
    assert _egress(device)
    assert device.bound_fingerprint == host_fingerprint(Profile.L1, L1_FACTS)
    assert device.enrol(L1_FACTS, LATER) is IdentityRefusal.ALREADY_ENROLLED


def test_a_copied_disk_is_refused_at_enrolment_and_alerts_sec(chain: AuditChain) -> None:
    """The clone reaches T2 with the same identity; the original keeps its certificate."""
    registry = FleetRegistry()
    original = _identity(chain, registry)
    original.enrol(L1_FACTS, NOW)

    clone = _identity(chain, registry)
    refusal = clone.enrol(L1_ON_NEW_HOST, LATER)

    assert refusal is IdentityRefusal.CLONE_ATTEMPT
    assert clone.state is IdentityState.UNENROLLED
    assert not _egress(clone)
    assert [alert.device_id for alert in registry.clone_alerts] == [original.device_id]
    assert _egress(original)


def test_a_host_swap_on_l1_halts_egress_until_a_human_approves(chain: AuditChain) -> None:
    device = _identity(chain, FleetRegistry())
    device.enrol(L1_FACTS, NOW)

    assert device.observe_boot(L1_ON_NEW_HOST, LATER) is IdentityRefusal.RE_ENROLMENT_PENDING
    assert device.state.value == IdentityState.RE_ENROLMENT_PENDING.value
    assert not _egress(device)

    # A reboot on the new host does not restore trust on its own.
    assert device.observe_boot(L1_ON_NEW_HOST, LATER) is IdentityRefusal.RE_ENROLMENT_PENDING
    assert not _egress(device)

    approval = ReEnrolmentApproval(
        device_id=str(device.device_id),
        fingerprint=str(host_fingerprint(Profile.L1, L1_ON_NEW_HOST)),
        approver="ta@site",
        issued_at=LATER.isoformat(),
    )
    assert device.approve_re_enrolment(approval, sign_approval(approval, T2_KEY), LATER) is None
    assert _egress(device)
    assert device.observe_boot(L1_ON_NEW_HOST, LATER) is None


def test_an_unsigned_approval_does_not_restore_trust(chain: AuditChain) -> None:
    device = _identity(chain, FleetRegistry())
    device.enrol(L1_FACTS, NOW)
    device.observe_boot(L1_ON_NEW_HOST, LATER)

    approval = ReEnrolmentApproval(
        device_id=str(device.device_id),
        fingerprint=str(host_fingerprint(Profile.L1, L1_ON_NEW_HOST)),
        approver="ta@site",
        issued_at=LATER.isoformat(),
    )
    assert (
        device.approve_re_enrolment(approval, "0" * 64, LATER) is IdentityRefusal.APPROVAL_INVALID
    )
    assert device.state is IdentityState.RE_ENROLMENT_PENDING


def test_an_approval_for_a_different_host_is_refused(chain: AuditChain) -> None:
    """Approving one swap must not pre-authorise the next machine the disk is plugged into."""
    device = _identity(chain, FleetRegistry())
    device.enrol(L1_FACTS, NOW)
    device.observe_boot(L1_ON_NEW_HOST, LATER)

    approval = ReEnrolmentApproval(
        device_id=str(device.device_id),
        fingerprint=str(host_fingerprint(Profile.L1, HardwareFacts(host_dmi="dmi-host-c"))),
        approver="ta@site",
        issued_at=LATER.isoformat(),
    )
    refusal = device.approve_re_enrolment(approval, sign_approval(approval, T2_KEY), LATER)
    assert refusal is IdentityRefusal.APPROVAL_FOR_ANOTHER_FINGERPRINT
    assert device.state is IdentityState.RE_ENROLMENT_PENDING


def test_swapping_the_attached_pc_on_l2_is_not_an_identity_event(chain: AuditChain) -> None:
    device = _identity(chain, FleetRegistry(), profile=Profile.L2)
    device.enrol(L2_FACTS, NOW)
    before = len(chain.records())

    moved = HardwareFacts(module_serial="SOM-0001", host_dmi="dmi-host-b")
    assert device.observe_boot(moved, LATER) is None
    assert device.observe_boot(HardwareFacts(module_serial="SOM-0001"), LATER) is None
    assert device.state is IdentityState.ENROLLED
    assert _egress(device)
    assert len(chain.records()) == before


def test_the_certificate_never_confers_a_trust_level(chain: AuditChain) -> None:
    l1 = _identity(chain, FleetRegistry())
    l1.enrol(L1_FACTS, NOW)
    l2 = _identity(chain, FleetRegistry(), profile=Profile.L2)
    l2.enrol(L2_FACTS, NOW)

    assert l1.trust_level is TrustLevel.SOFTWARE_BOUND
    assert l2.trust_level is TrustLevel.MODULE_ATTESTED
    assert l1.key_protection is KeyProtection.ENROLMENT_BOUND
    assert l1.disclosure_required
    assert not l2.disclosure_required


def test_an_unenrolled_device_has_no_egress(chain: AuditChain) -> None:
    device = _identity(chain, FleetRegistry())
    assert device.observe_boot(L1_FACTS, NOW) is IdentityRefusal.NOT_ENROLLED
    assert not _egress(device)


def test_enrolment_without_a_host_fingerprint_is_refused_on_l1(chain: AuditChain) -> None:
    device = _identity(chain, FleetRegistry())
    facts = HardwareFacts(disk_serial="SSD-CTRL-0001")
    assert device.enrol(facts, NOW) is IdentityRefusal.HOST_FINGERPRINT_MISSING
    assert device.enrol(HardwareFacts(host_dmi="dmi-host-a"), NOW) is IdentityRefusal.ROOT_MISSING


def test_every_identity_decision_is_audited(chain: AuditChain) -> None:
    device = _identity(chain, FleetRegistry())
    device.enrol(L1_FACTS, NOW)
    device.observe_boot(L1_ON_NEW_HOST, LATER)

    kinds = [record.kind for record in chain.records()]
    assert kinds == ["enrolled", "identity_refused"]
    assert chain.verify().ok
