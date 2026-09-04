"""Commissioning gate (F21).

The gate is only worth having if it refuses, so most of these tests are refusals: the whole job
done except the signage photo, the whole job done except the age-gate verification, and a Field
Engineer who would very much like to activate anyway.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from t1.control.audit_chain import AuditChain
from t1.control.commissioning import (
    GATE_ORDER,
    REFUSAL,
    ActivationRefused,
    CommissioningGate,
    DeviceState,
    Exception2P,
    GateItem,
    sign_exception,
)

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
T2_KEY = b"dev-only-t2-exception-key"
PHOTO = "job-4411/signage-front-door.jpg"
FE = "fe-207"


def gate(chain: AuditChain) -> CommissioningGate:
    return CommissioningGate(device_id="rtl-l1-0001", chain=chain, t2_key=T2_KEY)


def complete(g: CommissioningGate, *, skip: GateItem | None = None) -> CommissioningGate:
    for item in GATE_ORDER:
        if item is skip:
            continue
        g.record_pass(item, NOW, actor=FE, photo_ref=PHOTO if item is GateItem.NOTICE else None)
    return g


def kinds(chain: AuditChain) -> list[str]:
    return [record.kind for record in chain.records()]


@pytest.mark.parametrize("missing", list(GATE_ORDER))
def test_every_missing_item_refuses_activation_by_name(
    chain: AuditChain, missing: GateItem
) -> None:
    g = complete(gate(chain), skip=missing)
    with pytest.raises(ActivationRefused) as exc:
        g.activate(NOW)

    assert exc.value.reason == REFUSAL[missing]
    assert exc.value.item is missing
    assert exc.value.remedy
    assert g.state is DeviceState.COMMISSIONING
    assert not g.processing_allowed
    assert "activation_refused" in kinds(chain)


def test_signage_needs_a_photograph_not_a_tick(chain: AuditChain) -> None:
    g = gate(chain)
    with pytest.raises(ActivationRefused) as exc:
        g.record_pass(GateItem.NOTICE, NOW, actor=FE)
    assert exc.value.reason == "notice_missing"
    assert GateItem.NOTICE not in g.passed


def test_blockers_lists_the_whole_remaining_job(chain: AuditChain) -> None:
    g = complete(gate(chain), skip=GateItem.AGE_GATE)
    assert g.blockers(NOW) == [GateItem.AGE_GATE]


def test_a_full_gate_activates_offline_and_lands_in_the_chain(chain: AuditChain) -> None:
    """F21 R5: no T2 round trip anywhere in this test - the upload is queued afterwards."""
    g = complete(gate(chain))
    record_hash = g.activate(NOW)

    assert g.state is DeviceState.ACTIVE
    assert g.processing_allowed
    assert record_hash
    assert chain.verify().ok
    completion = [r for r in chain.records() if r.kind == "commissioning_complete"]
    assert len(completion) == 1
    assert completion[0].body["notice_photo_ref"] == PHOTO
    assert completion[0].body["actors"][GateItem.AGE_GATE.value] == FE


def test_gate_state_cannot_be_written_from_outside(chain: AuditChain) -> None:
    """The cheapest bypass is an assignment, so the fields are views rather than attributes."""
    g = complete(gate(chain), skip=GateItem.AGE_GATE)
    with pytest.raises(AttributeError):
        g.state = DeviceState.ACTIVE  # type: ignore[misc]
    with pytest.raises(AttributeError):
        g.passed = frozenset(GATE_ORDER)  # type: ignore[misc]
    with pytest.raises(TypeError):
        g.exceptions[GateItem.AGE_GATE] = Exception2P(  # type: ignore[index]
            GateItem.AGE_GATE, ("a", "b"), NOW + timedelta(days=1)
        )
    assert not g.processing_allowed


def test_a_field_waiver_has_no_accepting_path_and_is_audited(chain: AuditChain) -> None:
    g = complete(gate(chain), skip=GateItem.NOTICE)
    with pytest.raises(ActivationRefused) as exc:
        g.attempt_local_waiver(GateItem.NOTICE, actor="fe-207", now=NOW)

    assert exc.value.reason == "waiver_not_available_in_field"
    assert "waiver_attempt_refused" in kinds(chain)
    with pytest.raises(ActivationRefused):
        g.activate(NOW)


def signed(exc: Exception2P) -> str:
    return sign_exception(exc, T2_KEY)


def test_a_two_person_t2_exception_opens_exactly_one_item(chain: AuditChain) -> None:
    g = complete(gate(chain), skip=GateItem.CAMERA_ASSESSMENT)
    exc = Exception2P(
        item=GateItem.CAMERA_ASSESSMENT,
        approvers=("ops-lead", "security-agent"),
        not_after=NOW + timedelta(days=7),
    )
    g.apply_exception(exc, signed(exc), NOW)

    g.activate(NOW)
    assert g.state is DeviceState.ACTIVE
    assert "exception_applied" in kinds(chain)


@pytest.mark.parametrize(
    ("exception", "signature_key", "reason"),
    [
        (
            Exception2P(GateItem.NOTICE, ("ops-lead", "security-agent"), NOW - timedelta(days=1)),
            T2_KEY,
            "exception_expired",
        ),
        (
            Exception2P(GateItem.NOTICE, ("ops-lead", "ops-lead"), NOW + timedelta(days=1)),
            T2_KEY,
            "two_person_control_required",
        ),
        (
            Exception2P(GateItem.NOTICE, ("ops-lead", "security-agent"), NOW + timedelta(days=1)),
            b"forged",
            "exception_invalid",
        ),
        (
            Exception2P(
                GateItem.NOTICE,
                ("ops-lead", "security-agent"),
                NOW + timedelta(days=1),
                signing_domain="model-bundle",
            ),
            T2_KEY,
            "wrong_signing_domain",
        ),
    ],
    ids=["expired", "one_approver", "forged", "wrong_domain"],
)
def test_bad_exceptions_are_refused_and_audited(
    chain: AuditChain, exception: Exception2P, signature_key: bytes, reason: str
) -> None:
    g = gate(chain)
    with pytest.raises(ActivationRefused) as exc:
        g.apply_exception(exception, sign_exception(exception, signature_key), NOW)
    assert exc.value.reason == reason
    assert g.exceptions == {}
    assert "exception_refused" in kinds(chain)


def test_an_expiring_exception_closes_the_item_again(chain: AuditChain) -> None:
    g = complete(gate(chain), skip=GateItem.CREDENTIALS)
    exc = Exception2P(
        item=GateItem.CREDENTIALS,
        approvers=("ops-lead", "security-agent"),
        not_after=NOW + timedelta(hours=1),
    )
    g.apply_exception(exc, signed(exc), NOW)
    assert g.blockers(NOW) == []
    assert g.blockers(NOW + timedelta(hours=2)) == [GateItem.CREDENTIALS]
