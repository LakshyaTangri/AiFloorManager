"""session-probe suite (F18, D-005) and consent/zone checks (F10)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from t1.canon import TrustLevel
from t1.control.session import SessionRefused, SessionService
from t1.control.zones import ConsentRecord, Zone, ZoneRefused, ZoneService

from .conftest import NOW


def _service(trust: TrustLevel = TrustLevel.MODULE_ATTESTED) -> SessionService:
    return SessionService(device_id="dev-1", trust_level=trust, last_attestation=NOW)


def test_l1_does_not_listen_at_all() -> None:
    service = _service(TrustLevel.SOFTWARE_BOUND)
    assert service.listening is False
    with pytest.raises(SessionRefused) as exc:
        service.issue("op", "support", NOW)
    assert exc.value.reason == "p2p_not_available_on_software_bound"


def test_session_expires_at_its_ttl() -> None:
    service = _service()
    cert = service.issue("op", "support", NOW, ttl_minutes=15)
    service.authorize(cert, "support", NOW + timedelta(minutes=14))
    with pytest.raises(SessionRefused) as exc:
        service.authorize(cert, "support", NOW + timedelta(minutes=16))
    assert exc.value.reason == "session_expired"


def test_purpose_is_bound_to_the_certificate() -> None:
    service = _service()
    cert = service.issue("op", "support", NOW)
    with pytest.raises(SessionRefused) as exc:
        service.authorize(cert, "analytics", NOW + timedelta(minutes=1))
    assert exc.value.reason == "purpose_violation"


def test_certificate_from_another_device_is_refused() -> None:
    other = SessionService(
        device_id="dev-2", trust_level=TrustLevel.MODULE_ATTESTED, last_attestation=NOW
    )
    cert = other.issue("op", "support", NOW)
    with pytest.raises(SessionRefused) as exc:
        _service().authorize(cert, "support", NOW + timedelta(minutes=1))
    assert exc.value.reason == "wrong_device"


def test_full_function_for_the_first_72_hours_offline() -> None:
    service = _service()
    at = NOW + timedelta(hours=71)
    cert = service.issue("op", "support", at)
    assert cert.read_only is False
    service.authorize(cert, "support", at + timedelta(minutes=1), write=True)


def test_read_only_after_72_hours() -> None:
    service = _service()
    at = NOW + timedelta(hours=73)
    cert = service.issue("op", "support", at)
    assert cert.read_only is True
    with pytest.raises(SessionRefused) as exc:
        service.authorize(cert, "support", at + timedelta(minutes=1), write=True)
    assert exc.value.reason == "local_session_readonly"


def test_connectivity_alone_does_not_restore_write_access() -> None:
    service = _service()
    service.attestation_fresh = False
    at = NOW + timedelta(hours=1)
    assert service.read_only_at(at) is True
    service.reattest(at)
    assert service.read_only_at(at) is False


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
