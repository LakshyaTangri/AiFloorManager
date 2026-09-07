"""Device identity, one-time enrolment and anti-clone (M15, F04, C12, SPEC §4).

Two SPEC statements shape the model here.

*Identity is rooted in the part Tangri ships.* On L1 that is the SSD controller serial; on L2/L3 it
is the SoM/SEC-1 identity. SPEC writes the L1 identity as "SSD controller serial + host DMI
fingerprint", but the two components do not play the same role: T2 refuses a second enrolment *for
that disk*, and a host change moves the device to `RE_ENROLMENT_PENDING` rather than making it a
different device. So the disk serial is the root of `device_id` and the host fingerprint is a
binding recorded against it. Deriving the id from both would make a legitimate PC swap indis-
tinguishable from a new device, which is the one distinction F04 R3 exists to draw.

*A certificate is not a trust level.* AWS IoT authentication establishes who the device is talking
as; the trust level comes from the profile and nothing else, which is why `trust_level` reads the
profile and never takes a certificate.

A host fingerprint is only an identity input on L1. On L2/L3 the attached PC contributes nothing,
so swapping or removing it is not observed at all: no state change, no alert, no interruption
(D-007).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Final

from t1.canon import PROFILE_TRUST, Profile, TrustLevel
from t1.control.audit_chain import AuditChain

APPROVAL_SIGNING_DOMAIN: Final[str] = "re-enrolment-approval"


class IdentityRefusal(str, Enum):
    ROOT_MISSING = "identity_root_missing"
    HOST_FINGERPRINT_MISSING = "host_fingerprint_missing"
    ALREADY_ENROLLED = "already_enrolled"
    CLONE_ATTEMPT = "clone_attempt"
    NOT_ENROLLED = "not_enrolled"
    RE_ENROLMENT_PENDING = "re_enrolment_pending"
    IDENTITY_ROOT_CHANGED = "identity_root_changed"
    NOT_PENDING = "not_pending"
    WRONG_SIGNING_DOMAIN = "wrong_signing_domain"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_FOR_ANOTHER_DEVICE = "approval_for_another_device"
    APPROVAL_FOR_ANOTHER_FINGERPRINT = "approval_for_another_fingerprint"


class IdentityState(str, Enum):
    UNENROLLED = "UNENROLLED"
    ENROLLED = "ENROLLED"
    RE_ENROLMENT_PENDING = "RE_ENROLMENT_PENDING"


class KeyProtection(str, Enum):
    """L1 is enrolment-bound, not protected: a copied identity is useless, a stolen disk is not."""

    ENROLMENT_BOUND = "enrolment_bound"
    NON_EXPORTABLE_SEC1 = "non_exportable_sec1"
    NON_EXPORTABLE_TPM = "non_exportable_tpm"


KEY_PROTECTION: Final[dict[Profile, KeyProtection]] = {
    Profile.L1: KeyProtection.ENROLMENT_BOUND,
    Profile.L2: KeyProtection.NON_EXPORTABLE_SEC1,
    Profile.L3: KeyProtection.NON_EXPORTABLE_TPM,
}


def trust_level(profile: Profile) -> TrustLevel:
    """Takes no certificate on purpose: authentication and trust level are separate (SPEC §4)."""
    return PROFILE_TRUST[profile]


@dataclass(frozen=True)
class HardwareFacts:
    """What the device can read about itself at boot."""

    disk_serial: str | None = None
    host_dmi: str | None = None
    module_serial: str | None = None


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def identity_root(profile: Profile, facts: HardwareFacts) -> str | IdentityRefusal:
    if profile is Profile.L1:
        if not facts.disk_serial:
            return IdentityRefusal.ROOT_MISSING
        return _digest(profile.value, facts.disk_serial)
    if not facts.module_serial:
        return IdentityRefusal.ROOT_MISSING
    return _digest(profile.value, facts.module_serial)


def host_fingerprint(profile: Profile, facts: HardwareFacts) -> str | None:
    """`None` on L2/L3: the attached PC is not part of the identity, so it is not fingerprinted."""
    if profile is not Profile.L1:
        return None
    if not facts.host_dmi:
        return None
    return _digest("dmi", facts.host_dmi)


@dataclass(frozen=True)
class Certificate:
    """Communication identity issued once per device by T2 Fleet Provisioning (F04 R2)."""

    device_id: str
    serial: str
    issued_at: str


@dataclass(frozen=True)
class CloneAlert:
    device_id: str
    fingerprint: str | None
    at: str


@dataclass
class FleetRegistry:
    """The T2 side of enrolment, kept here so the refusal can be exercised end to end.

    One certificate per identity, forever. A second request for an identity that already holds one
    is a clone attempt, not a retry: the device that already enrolled keeps working and the second
    one gets nothing.
    """

    issued: dict[str, Certificate] = field(default_factory=dict)
    bindings: dict[str, str | None] = field(default_factory=dict)
    clone_alerts: list[CloneAlert] = field(default_factory=list)

    def enrol(
        self, device_id: str, fingerprint: str | None, now: datetime
    ) -> Certificate | IdentityRefusal:
        if device_id in self.issued:
            self.clone_alerts.append(CloneAlert(device_id, fingerprint, now.isoformat()))
            return IdentityRefusal.CLONE_ATTEMPT
        certificate = Certificate(
            device_id=device_id,
            serial=_digest("cert", device_id, now.isoformat())[:32],
            issued_at=now.isoformat(),
        )
        self.issued[device_id] = certificate
        self.bindings[device_id] = fingerprint
        return certificate

    def rebind(self, device_id: str, fingerprint: str | None) -> None:
        """Applied only after a human approval; re-enrolment never issues a second certificate."""
        self.bindings[device_id] = fingerprint


@dataclass(frozen=True)
class ReEnrolmentApproval:
    """Human approval in T2. Trust is restored by this record, never by a reboot (SPEC §4)."""

    device_id: str
    fingerprint: str
    approver: str
    issued_at: str
    signing_domain: str = APPROVAL_SIGNING_DOMAIN

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "device_id": self.device_id,
                "fingerprint": self.fingerprint,
                "approver": self.approver,
                "issued_at": self.issued_at,
                "signing_domain": self.signing_domain,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


def sign_approval(approval: ReEnrolmentApproval, key: bytes) -> str:
    return hmac.new(key, approval.to_bytes(), hashlib.sha256).hexdigest()


@dataclass
class DeviceIdentity:
    profile: Profile
    chain: AuditChain
    registry: FleetRegistry
    t2_key: bytes
    state: IdentityState = IdentityState.UNENROLLED
    device_id: str | None = None
    certificate: Certificate | None = None
    bound_fingerprint: str | None = None
    refusals: dict[IdentityRefusal, int] = field(default_factory=dict)
    _pending_fingerprint: str | None = None

    @property
    def trust_level(self) -> TrustLevel:
        return trust_level(self.profile)

    @property
    def key_protection(self) -> KeyProtection:
        return KEY_PROTECTION[self.profile]

    @property
    def disclosure_required(self) -> bool:
        """D-004: L1 must say in the local UI that a stolen disk is attackable."""
        return self.key_protection is KeyProtection.ENROLMENT_BOUND

    @property
    def egress_allowed(self) -> bool:
        """Pending re-enrolment halts egress; local ingest is a separate decision (F04 R3)."""
        return self.state is IdentityState.ENROLLED

    def enrol(self, facts: HardwareFacts, now: datetime) -> Certificate | IdentityRefusal:
        if self.state is not IdentityState.UNENROLLED:
            return self._refuse(IdentityRefusal.ALREADY_ENROLLED, now, {})
        root = identity_root(self.profile, facts)
        if isinstance(root, IdentityRefusal):
            return self._refuse(root, now, {})
        fingerprint = host_fingerprint(self.profile, facts)
        if self.profile is Profile.L1 and fingerprint is None:
            return self._refuse(IdentityRefusal.HOST_FINGERPRINT_MISSING, now, {})

        result = self.registry.enrol(root, fingerprint, now)
        if isinstance(result, IdentityRefusal):
            return self._refuse(result, now, {"device_id": root})

        self.device_id = root
        self.certificate = result
        self.bound_fingerprint = fingerprint
        self.state = IdentityState.ENROLLED
        self.chain.append(
            "enrolled",
            {
                "device_id": root,
                "certificate_serial": result.serial,
                "trust_level": self.trust_level.value,
                "key_protection": self.key_protection.value,
            },
            now.isoformat(),
        )
        return result

    def observe_boot(self, facts: HardwareFacts, now: datetime) -> IdentityRefusal | None:
        """Called on every boot. On L2/L3 the attached PC is not an input, so a swap is silent."""
        if self.state is IdentityState.UNENROLLED:
            return self._refuse(IdentityRefusal.NOT_ENROLLED, now, {})

        root = identity_root(self.profile, facts)
        if isinstance(root, IdentityRefusal):
            return self._refuse(root, now, {})
        if root != self.device_id:
            return self._halt(IdentityRefusal.IDENTITY_ROOT_CHANGED, now)

        fingerprint = host_fingerprint(self.profile, facts)
        if fingerprint is not None and fingerprint != self.bound_fingerprint:
            return self._halt(IdentityRefusal.RE_ENROLMENT_PENDING, now, fingerprint)
        if self.state is IdentityState.RE_ENROLMENT_PENDING:
            return self._refuse(IdentityRefusal.RE_ENROLMENT_PENDING, now, {})
        return None

    def approve_re_enrolment(
        self, approval: ReEnrolmentApproval, signature: str, now: datetime
    ) -> IdentityRefusal | None:
        if self.state is not IdentityState.RE_ENROLMENT_PENDING:
            return self._refuse(IdentityRefusal.NOT_PENDING, now, {})
        if approval.signing_domain != APPROVAL_SIGNING_DOMAIN:
            return self._refuse(IdentityRefusal.WRONG_SIGNING_DOMAIN, now, {})
        if not hmac.compare_digest(sign_approval(approval, self.t2_key), signature):
            return self._refuse(IdentityRefusal.APPROVAL_INVALID, now, {})
        if approval.device_id != self.device_id:
            return self._refuse(IdentityRefusal.APPROVAL_FOR_ANOTHER_DEVICE, now, {})
        if approval.fingerprint != self._pending_fingerprint:
            return self._refuse(IdentityRefusal.APPROVAL_FOR_ANOTHER_FINGERPRINT, now, {})

        self.bound_fingerprint = approval.fingerprint
        self._pending_fingerprint = None
        self.state = IdentityState.ENROLLED
        self.registry.rebind(str(self.device_id), approval.fingerprint)
        self.chain.append(
            "re_enrolled",
            {
                "device_id": str(self.device_id),
                "fingerprint": approval.fingerprint,
                "approver": approval.approver,
            },
            now.isoformat(),
        )
        return None

    def _halt(
        self, refusal: IdentityRefusal, now: datetime, fingerprint: str | None = None
    ) -> IdentityRefusal:
        self.state = IdentityState.RE_ENROLMENT_PENDING
        self._pending_fingerprint = fingerprint
        return self._refuse(refusal, now, {"device_id": str(self.device_id)})

    def _refuse(
        self, refusal: IdentityRefusal, now: datetime, body: dict[str, str]
    ) -> IdentityRefusal:
        self.refusals[refusal] = self.refusals.get(refusal, 0) + 1
        self.chain.append(
            "identity_refused",
            {"reason": refusal.value, "state": self.state.value, **body},
            now.isoformat(),
        )
        return refusal
