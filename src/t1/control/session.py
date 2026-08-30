"""Local P2P sessions (F18, D-005, C2, C11).

Two rules that are easy to get wrong:

    L1 does not run the service at all - not "refuses requests", does not listen.
    Full function returns on attestation, not on connectivity. A device that can reach T2 but has
    not re-attested is still read-only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from t1.canon import OFFLINE_FULL_SESSION_HOURS, TrustLevel


class SessionRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SessionCert:
    subject: str
    purpose: str
    device_id: str
    not_after: datetime
    read_only: bool = False


@dataclass
class SessionService:
    device_id: str
    trust_level: TrustLevel
    last_attestation: datetime
    attestation_fresh: bool = True

    @property
    def listening(self) -> bool:
        return self.trust_level is not TrustLevel.SOFTWARE_BOUND

    def read_only_at(self, now: datetime) -> bool:
        if not self.attestation_fresh:
            return True
        return now - self.last_attestation > timedelta(hours=OFFLINE_FULL_SESSION_HOURS)

    def issue(
        self, subject: str, purpose: str, now: datetime, ttl_minutes: int = 15
    ) -> SessionCert:
        self._require_listening()
        return SessionCert(
            subject=subject,
            purpose=purpose,
            device_id=self.device_id,
            not_after=now + timedelta(minutes=ttl_minutes),
            read_only=self.read_only_at(now),
        )

    def authorize(
        self, cert: SessionCert, purpose: str, now: datetime, write: bool = False
    ) -> None:
        self._require_listening()
        if cert.device_id != self.device_id:
            raise SessionRefused("wrong_device")
        if now >= cert.not_after:
            raise SessionRefused("session_expired")
        if cert.purpose != purpose:
            raise SessionRefused("purpose_violation")
        if write and (cert.read_only or self.read_only_at(now)):
            raise SessionRefused("local_session_readonly")

    def reattest(self, now: datetime) -> None:
        self.last_attestation = now
        self.attestation_fresh = True

    def _require_listening(self) -> None:
        if not self.listening:
            raise SessionRefused("p2p_not_available_on_software_bound")
