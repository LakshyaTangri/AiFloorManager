"""Local P2P sessions (F18, D-005, C2, C11, C12).

Two rules that are easy to get wrong:

    L1 does not run the service at all - not "refuses requests", does not listen.
    Full function returns on attestation *and* entitlement refresh, not on connectivity. A device
    that can reach T2 but has not re-attested is still read-only.

The device does not issue its own authority. Session certificates are minted by the T2 session
broker and carry a signature in their own domain; the box only ever verifies. That is what stops
the offline case from becoming a hole: a device cut off from T2 cannot mint itself a session, so
72 h of outage degrades access rather than opening it.

A session is a period, not a request. `open` starts one and `close` ends it, and only the close
knows the duration F18 R3 wants in the chain - so an operator who walks away without closing leaves
a session that the next expiry sweep closes for them, and the record says so.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from t1.canon import OFFLINE_FULL_SESSION_HOURS, DataClass, TrustLevel
from t1.control.audit_chain import AuditChain

SESSION_SIGNING_DOMAIN = "session-cert"

# F18: renewal is offered late in the life of a certificate, so a long-lived operator refreshes
# instead of holding one credential open, and an early renewal cannot extend a session forever.
RENEWAL_FRACTION = 0.75

LIVE_MODE = "live_onsite"


class SessionRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class CloseReason(str, Enum):
    OPERATOR = "operator"
    EXPIRED = "expired"


@dataclass(frozen=True)
class SessionCert:
    subject: str
    purpose: str
    device_id: str
    not_before: datetime
    not_after: datetime
    read_only: bool = False
    signing_domain: str = SESSION_SIGNING_DOMAIN

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "subject": self.subject,
                "purpose": self.purpose,
                "device_id": self.device_id,
                "not_before": self.not_before.isoformat(),
                "not_after": self.not_after.isoformat(),
                "read_only": self.read_only,
                "signing_domain": self.signing_domain,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def ttl(self) -> timedelta:
        return self.not_after - self.not_before

    def renewable_from(self) -> datetime:
        return self.not_before + self.ttl * RENEWAL_FRACTION


def sign_session(cert: SessionCert, key: bytes) -> str:
    return hmac.new(key, cert.to_bytes(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class LiveResponse:
    """F18 R4: a live answer is labelled as one and carries the class that bounds keeping it."""

    payload: dict[str, str | int | float | bool]
    mode: str = LIVE_MODE
    data_class: DataClass = DataClass.C2_EVENT


@dataclass
class Session:
    cert: SessionCert
    opened_at: datetime
    closed: bool = False


@dataclass
class SessionService:
    device_id: str
    trust_level: TrustLevel
    chain: AuditChain
    session_ca_key: bytes
    last_attestation: datetime
    attestation_fresh: bool = True
    entitlements_fresh: bool = True
    open_sessions: dict[str, Session] = field(default_factory=dict)

    @property
    def listening(self) -> bool:
        """L2/L3 only. On L1 there is no socket to scan, not a socket that says no (F18 R2)."""
        return self.trust_level is not TrustLevel.SOFTWARE_BOUND

    def read_only_at(self, now: datetime) -> bool:
        if not (self.attestation_fresh and self.entitlements_fresh):
            return True
        return now - self.last_attestation > timedelta(hours=OFFLINE_FULL_SESSION_HOURS)

    def open(self, cert: SessionCert, signature: str, now: datetime) -> Session:
        self._verify(cert, signature, now)
        key = self._key(cert)
        if key in self.open_sessions and not self.open_sessions[key].closed:
            raise SessionRefused("session_already_open")
        session = Session(cert=cert, opened_at=now)
        self.open_sessions[key] = session
        self.chain.append(
            "session_opened",
            {
                "subject": cert.subject,
                "purpose": cert.purpose,
                "read_only": cert.read_only or self.read_only_at(now),
            },
            now.isoformat(),
        )
        return session

    def authorize(
        self,
        cert: SessionCert,
        signature: str,
        purpose: str,
        now: datetime,
        write: bool = False,
    ) -> None:
        self._verify(cert, signature, now)
        if cert.purpose != purpose:
            raise SessionRefused("purpose_violation")
        if write and (cert.read_only or self.read_only_at(now)):
            raise SessionRefused("local_session_readonly")

    def respond(
        self,
        cert: SessionCert,
        signature: str,
        purpose: str,
        payload: dict[str, str | int | float | bool],
        now: datetime,
    ) -> LiveResponse:
        self.authorize(cert, signature, purpose, now)
        return LiveResponse(payload=payload)

    def renew(self, cert: SessionCert, signature: str, now: datetime) -> tuple[SessionCert, str]:
        """The broker's signing key is not on the box; renewal is modelled, not authorised here."""
        self._verify(cert, signature, now)
        if now < cert.renewable_from():
            raise SessionRefused("renewal_too_early")
        renewed = SessionCert(
            subject=cert.subject,
            purpose=cert.purpose,
            device_id=cert.device_id,
            not_before=now,
            not_after=now + cert.ttl,
            read_only=cert.read_only or self.read_only_at(now),
        )
        return renewed, sign_session(renewed, self.session_ca_key)

    def close(self, session: Session, now: datetime, reason: CloseReason) -> None:
        if session.closed:
            return
        session.closed = True
        self.open_sessions.pop(self._key(session.cert), None)
        self.chain.append(
            "session_closed",
            {
                "subject": session.cert.subject,
                "purpose": session.cert.purpose,
                "duration_s": int((now - session.opened_at).total_seconds()),
                "reason": reason.value,
            },
            now.isoformat(),
        )

    def expire_due(self, now: datetime) -> list[Session]:
        """An abandoned session still has to yield a duration to the chain (F18 R3, R5)."""
        due = [s for s in self.open_sessions.values() if now >= s.cert.not_after]
        for session in due:
            self.close(session, session.cert.not_after, CloseReason.EXPIRED)
        return due

    def reattest(self, now: datetime, entitlements_refreshed: bool = True) -> None:
        self.last_attestation = now
        self.attestation_fresh = True
        self.entitlements_fresh = entitlements_refreshed

    def _verify(self, cert: SessionCert, signature: str, now: datetime) -> None:
        self._require_listening()
        if cert.signing_domain != SESSION_SIGNING_DOMAIN:
            raise SessionRefused("wrong_signing_domain")
        if not hmac.compare_digest(sign_session(cert, self.session_ca_key), signature):
            raise SessionRefused("session_cert_untrusted")
        if cert.device_id != self.device_id:
            raise SessionRefused("wrong_device")
        if now < cert.not_before:
            raise SessionRefused("session_not_yet_valid")
        if now >= cert.not_after:
            raise SessionRefused("session_expired")

    def _key(self, cert: SessionCert) -> str:
        return f"{cert.subject}:{cert.purpose}:{cert.not_after.isoformat()}"

    def _require_listening(self) -> None:
        if not self.listening:
            raise SessionRefused("p2p_not_available_on_software_bound")
