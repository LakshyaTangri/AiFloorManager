"""session-probe suite (F18, D-005) and consent/zone checks (F10).

The suite is adversarial by design: most of it is somebody trying to get a write out of the box -
with a forged certificate, another device's certificate, the right certificate and the wrong
purpose, an early renewal, or simply by waiting until T2 has been unreachable long enough.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from t1.canon import DataClass, TrustLevel
from t1.control.audit_chain import AuditChain
from t1.control.session import (
    LIVE_MODE,
    CloseReason,
    SessionCert,
    SessionRefused,
    SessionService,
    sign_session,
)
from t1.control.zones import ConsentRecord, Zone, ZoneRefused, ZoneService

from .conftest import NOW

CA_KEY = b"dev-only-session-ca-key"
TTL = timedelta(minutes=15)


def _service(
    chain: AuditChain,
    trust: TrustLevel = TrustLevel.MODULE_ATTESTED,
) -> SessionService:
    return SessionService(
        device_id="dev-1",
        trust_level=trust,
        chain=chain,
        session_ca_key=CA_KEY,
        last_attestation=NOW,
    )


def _cert(
    at: datetime = NOW,
    purpose: str = "operations",
    device_id: str = "dev-1",
    read_only: bool = False,
) -> tuple[SessionCert, str]:
    """Certificates come from the T2 broker; the test plays the broker with its key."""
    cert = SessionCert(
        subject="op-1",
        purpose=purpose,
        device_id=device_id,
        not_before=at,
        not_after=at + TTL,
        read_only=read_only,
    )
    return cert, sign_session(cert, CA_KEY)


def test_l1_does_not_listen_at_all(chain: AuditChain) -> None:
    service = _service(chain, TrustLevel.SOFTWARE_BOUND)
    cert, signature = _cert()
    assert service.listening is False
    with pytest.raises(SessionRefused) as exc:
        service.open(cert, signature, NOW)
    assert exc.value.reason == "p2p_not_available_on_software_bound"
    with pytest.raises(SessionRefused):
        service.authorize(cert, signature, "operations", NOW)


def test_a_certificate_the_session_ca_did_not_sign_is_refused(chain: AuditChain) -> None:
    """The box verifies; it cannot mint. A device offline from T2 cannot issue itself access."""
    service = _service(chain)
    cert, _ = _cert()
    forged = sign_session(cert, b"attacker-key")
    with pytest.raises(SessionRefused) as exc:
        service.open(cert, forged, NOW)
    assert exc.value.reason == "session_cert_untrusted"


def test_a_certificate_edited_after_signing_is_refused(chain: AuditChain) -> None:
    service = _service(chain)
    cert, signature = _cert(read_only=True)
    escalated = replace(cert, read_only=False)
    with pytest.raises(SessionRefused) as exc:
        service.authorize(escalated, signature, "operations", NOW, write=True)
    assert exc.value.reason == "session_cert_untrusted"


def test_a_signature_from_another_domain_does_not_carry(chain: AuditChain) -> None:
    service = _service(chain)
    cert = SessionCert(
        subject="op-1",
        purpose="operations",
        device_id="dev-1",
        not_before=NOW,
        not_after=NOW + TTL,
        signing_domain="commissioning-exception",
    )
    with pytest.raises(SessionRefused) as exc:
        service.open(cert, sign_session(cert, CA_KEY), NOW)
    assert exc.value.reason == "wrong_signing_domain"


def test_session_expires_at_its_ttl(chain: AuditChain) -> None:
    service = _service(chain)
    cert, signature = _cert()
    service.authorize(cert, signature, "operations", NOW + timedelta(minutes=14))
    with pytest.raises(SessionRefused) as exc:
        service.authorize(cert, signature, "operations", NOW + timedelta(minutes=16))
    assert exc.value.reason == "session_expired"


def test_purpose_is_bound_to_the_certificate(chain: AuditChain) -> None:
    service = _service(chain)
    cert, signature = _cert()
    with pytest.raises(SessionRefused) as exc:
        service.authorize(cert, signature, "marketing", NOW + timedelta(minutes=1))
    assert exc.value.reason == "purpose_violation"


def test_certificate_from_another_device_is_refused(chain: AuditChain) -> None:
    cert, signature = _cert(device_id="dev-2")
    with pytest.raises(SessionRefused) as exc:
        _service(chain).open(cert, signature, NOW)
    assert exc.value.reason == "wrong_device"


def test_renewal_is_refused_before_three_quarters_of_the_ttl(chain: AuditChain) -> None:
    service = _service(chain)
    cert, signature = _cert()
    with pytest.raises(SessionRefused) as exc:
        service.renew(cert, signature, NOW + timedelta(minutes=10))
    assert exc.value.reason == "renewal_too_early"

    renewed, renewed_sig = service.renew(cert, signature, NOW + timedelta(minutes=12))
    assert renewed.not_after == NOW + timedelta(minutes=12) + TTL
    service.authorize(renewed, renewed_sig, "operations", NOW + timedelta(minutes=20))


def test_full_function_for_the_first_72_hours_offline(chain: AuditChain) -> None:
    service = _service(chain)
    at = NOW + timedelta(hours=71)
    cert, signature = _cert(at)
    assert service.read_only_at(at) is False
    service.authorize(cert, signature, "operations", at + timedelta(minutes=1), write=True)


def test_read_only_after_72_hours(chain: AuditChain) -> None:
    service = _service(chain)
    at = NOW + timedelta(hours=73)
    cert, signature = _cert(at)
    assert service.read_only_at(at) is True
    with pytest.raises(SessionRefused) as exc:
        service.authorize(cert, signature, "operations", at + timedelta(minutes=1), write=True)
    assert exc.value.reason == "local_session_readonly"
    service.authorize(cert, signature, "operations", at + timedelta(minutes=1))


def test_connectivity_alone_does_not_restore_write_access(chain: AuditChain) -> None:
    """Reachability is not attestation, and attestation without entitlements is not authority."""
    service = _service(chain)
    service.attestation_fresh = False
    at = NOW + timedelta(hours=1)
    assert service.read_only_at(at) is True

    service.reattest(at, entitlements_refreshed=False)
    assert service.read_only_at(at) is True

    service.reattest(at)
    assert service.read_only_at(at) is False


def test_a_session_is_chained_with_its_user_purpose_and_duration(chain: AuditChain) -> None:
    service = _service(chain)
    cert, signature = _cert()
    session = service.open(cert, signature, NOW)
    service.close(session, NOW + timedelta(minutes=5), CloseReason.OPERATOR)

    records = chain.records()
    assert [record.kind for record in records] == ["session_opened", "session_closed"]
    assert records[1].body == {
        "subject": "op-1",
        "purpose": "operations",
        "duration_s": 300,
        "reason": "operator",
    }
    assert chain.verify().ok


def test_an_abandoned_session_is_closed_at_its_expiry_not_left_open(chain: AuditChain) -> None:
    service = _service(chain)
    cert, signature = _cert()
    service.open(cert, signature, NOW)

    assert service.expire_due(NOW + timedelta(minutes=10)) == []
    expired = service.expire_due(NOW + timedelta(minutes=30))
    assert len(expired) == 1
    assert service.open_sessions == {}

    closed = chain.records()[-1]
    assert closed.body["reason"] == "expired"
    assert closed.body["duration_s"] == int(TTL.total_seconds())


def test_the_same_certificate_cannot_open_two_sessions(chain: AuditChain) -> None:
    service = _service(chain)
    cert, signature = _cert()
    service.open(cert, signature, NOW)
    with pytest.raises(SessionRefused) as exc:
        service.open(cert, signature, NOW + timedelta(minutes=1))
    assert exc.value.reason == "session_already_open"


def test_a_live_answer_is_labelled_and_classed(chain: AuditChain) -> None:
    service = _service(chain)
    cert, signature = _cert()
    response = service.respond(cert, signature, "operations", {"queue_len": 4}, NOW)
    assert response.mode == LIVE_MODE
    assert response.data_class is DataClass.C2_EVENT

    with pytest.raises(SessionRefused):
        service.respond(cert, signature, "marketing", {"queue_len": 4}, NOW)


def test_prohibited_zone_cannot_be_mapped_to_a_stream() -> None:
    zones = ZoneService()
    zones.register_zone(Zone("changing-room", prohibited=True))
    with pytest.raises(ZoneRefused) as exc:
        zones.map_stream("cam-9", "changing-room")
    assert exc.value.reason == "prohibited_zone"
    assert zones.allows("cam-9") is False


def test_zone_without_a_lawful_basis_is_refused() -> None:
    with pytest.raises(ZoneRefused) as exc:
        ZoneService().register_zone(Zone("atrium", prohibited=False))
    assert exc.value.reason == "zone_basis_missing"


def test_unmapped_stream_is_not_allowed_by_default() -> None:
    assert ZoneService().allows("cam-unknown") is False


def test_absence_of_consent_is_not_consent() -> None:
    assert ZoneService().may_match("subject-1", NOW) is False


def test_withdrawal_takes_effect_and_sets_a_deletion_deadline() -> None:
    zones = ZoneService()
    zones.consents["subject-1"] = ConsentRecord("subject-1", "consent.explicit", NOW)
    assert zones.may_match("subject-1", NOW + timedelta(hours=1)) is True
    deadline = zones.withdraw("subject-1", NOW + timedelta(hours=2))
    assert deadline == NOW + timedelta(hours=26)
    assert zones.may_match("subject-1", NOW + timedelta(hours=3)) is False
