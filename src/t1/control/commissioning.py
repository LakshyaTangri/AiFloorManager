"""Commissioning gate (F21, SPEC §18, C2/C7/C9/C14).

The gate exists so that activation is *refusable*. Everything here is arranged around that: the
items are checked in a fixed order, the first failure names itself and its remedy, and there is no
partially-active state to fall into - either every item passes and the device becomes ACTIVE, or it
stays in COMMISSIONING and no stream is processed.

There is deliberately no local override. `attempt_local_waiver` exists only to be refused and
audited; the sole way past an item is a T2-issued exception carrying two distinct approvers and an
expiry, which is checked here and recorded in the chain (F21 R4).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType

from t1.control.audit_chain import AuditChain

EXCEPTION_SIGNING_DOMAIN = "commissioning-exception"


class GateItem(str, Enum):
    """Ordered as the Field Engineer works the site, and refused in the same order."""

    PREFLIGHT = "preflight"
    CAMERA_ASSESSMENT = "camera_assessment"
    IDENTITY = "identity"
    CAMERA_MAP = "camera_map"
    ZONES = "zones"
    PRIVACY_POLICY = "privacy_policy"
    AGE_GATE = "age_gate"
    NOTICE = "notice"
    KILL_SWITCH = "kill_switch"
    CREDENTIALS = "credentials"
    EGRESS_POLICY = "egress_policy"
    HEALTH = "health"
    SIGN_OFF = "sign_off"


GATE_ORDER: tuple[GateItem, ...] = tuple(GateItem)

REFUSAL: dict[GateItem, str] = {
    GateItem.PREFLIGHT: "preflight_failed",
    GateItem.CAMERA_ASSESSMENT: "camera_assessment_incomplete",
    GateItem.IDENTITY: "identity_not_enrolled",
    GateItem.CAMERA_MAP: "cameras_unmapped",
    GateItem.ZONES: "zone_basis_missing",
    GateItem.PRIVACY_POLICY: "privacy_policy_not_installed",
    GateItem.AGE_GATE: "age_gate_unverified",
    GateItem.NOTICE: "notice_missing",
    GateItem.KILL_SWITCH: "kill_switch_unexercised",
    GateItem.CREDENTIALS: "credentials_not_read_only",
    GateItem.EGRESS_POLICY: "egress_policy_unvalidated",
    GateItem.HEALTH: "health_check_failed",
    GateItem.SIGN_OFF: "sign_off_missing",
}

REMEDY: dict[GateItem, str] = {
    GateItem.PREFLIGHT: "Re-run pre-flight; a host under the two-adapter threshold is unqualified",
    GateItem.CAMERA_ASSESSMENT: "Score every stream or exclude it from the accuracy commitment",
    GateItem.IDENTITY: "Complete one-time enrolment",
    GateItem.CAMERA_MAP: "Discover and map every camera to a zone",
    GateItem.ZONES: "Record a legal basis on every zone",
    GateItem.PRIVACY_POLICY: "Install and verify the signed egress policy bundle",
    GateItem.AGE_GATE: "Run the age-gate functional verification",
    GateItem.NOTICE: "Place signage and attach the photograph to the job record",
    GateItem.KILL_SWITCH: "Exercise the kill switch and confirm streams stop",
    GateItem.CREDENTIALS: "Store camera credentials read-only where the profile requires it",
    GateItem.EGRESS_POLICY: "Run egress validation against the installed policy",
    GateItem.HEALTH: "Clear the failing health checks",
    GateItem.SIGN_OFF: "Field Engineer sign-off",
}


class ActivationRefused(Exception):
    def __init__(self, reason: str, item: GateItem, remedy: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.item = item
        self.remedy = remedy


class DeviceState(str, Enum):
    COMMISSIONING = "COMMISSIONING"
    ACTIVE = "ACTIVE"


@dataclass(frozen=True)
class Exception2P:
    """A T2-issued, expiring, two-person-approved waiver. The only way past an item."""

    item: GateItem
    approvers: tuple[str, str]
    not_after: datetime
    signing_domain: str = EXCEPTION_SIGNING_DOMAIN

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "item": self.item.value,
                "approvers": sorted(self.approvers),
                "not_after": self.not_after.isoformat(),
                "signing_domain": self.signing_domain,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


def sign_exception(exc: Exception2P, key: bytes) -> str:
    return hmac.new(key, exc.to_bytes(), hashlib.sha256).hexdigest()


class CommissioningGate:
    """Gate state is private on purpose.

    `passed`, `exceptions` and `state` are read-only views. If they were plain attributes, the
    shortest path past the whole gate would be `gate.state = ACTIVE` - one line, no signature, no
    audit record - and every check above would be decoration.
    """

    def __init__(self, device_id: str, chain: AuditChain, t2_key: bytes) -> None:
        self.device_id = device_id
        self.chain = chain
        self._t2_key = t2_key
        self._passed: dict[GateItem, str] = {}
        self._exceptions: dict[GateItem, Exception2P] = {}
        self._state = DeviceState.COMMISSIONING
        self._notice_photo_ref: str | None = None

    @property
    def state(self) -> DeviceState:
        return self._state

    @property
    def passed(self) -> frozenset[GateItem]:
        return frozenset(self._passed)

    @property
    def exceptions(self) -> Mapping[GateItem, Exception2P]:
        return MappingProxyType(self._exceptions)

    @property
    def notice_photo_ref(self) -> str | None:
        return self._notice_photo_ref

    @property
    def processing_allowed(self) -> bool:
        """No stream is processed while the gate is open, whatever else is configured."""
        return self._state is DeviceState.ACTIVE

    def record_pass(
        self,
        item: GateItem,
        now: datetime,
        actor: str,
        photo_ref: str | None = None,
    ) -> None:
        """`actor` is attribution, not authorisation: every item names who claimed it."""
        if not actor:
            raise ActivationRefused("actor_missing", item, "Record who performed the check")
        if item is GateItem.NOTICE:
            # Signage evidence is a photograph, not a checkbox (SPEC §18).
            if not photo_ref:
                raise ActivationRefused(
                    REFUSAL[item], item, "Attach the signage photograph, not a tick"
                )
            self._notice_photo_ref = photo_ref
        self._passed[item] = actor
        self.chain.append(
            "commissioning_item",
            {"item": item.value, "actor": actor, "photo_ref": photo_ref},
            now.isoformat(),
        )

    def blockers(self, now: datetime) -> list[GateItem]:
        """Every remaining item, so the FE sees the whole list before leaving site (F21 story)."""
        return [item for item in GATE_ORDER if not self._satisfied(item, now)]

    def apply_exception(self, exc: Exception2P, signature: str, now: datetime) -> None:
        reason = self._exception_reason(exc, signature, now)
        if reason is not None:
            self.chain.append(
                "exception_refused",
                {"item": exc.item.value, "reason": reason},
                now.isoformat(),
            )
            raise ActivationRefused(reason, exc.item, REMEDY[exc.item])
        self._exceptions[exc.item] = exc
        self.chain.append(
            "exception_applied",
            {
                "item": exc.item.value,
                "approvers": sorted(exc.approvers),
                "not_after": exc.not_after.isoformat(),
            },
            now.isoformat(),
        )

    def attempt_local_waiver(self, item: GateItem, actor: str, now: datetime) -> None:
        """There is no code path that accepts this. The attempt is audited (F21 AC4)."""
        self.chain.append(
            "waiver_attempt_refused",
            {"item": item.value, "actor": actor},
            now.isoformat(),
        )
        raise ActivationRefused("waiver_not_available_in_field", item, REMEDY[item])

    def activate(self, now: datetime) -> str:
        for item in GATE_ORDER:
            if not self._satisfied(item, now):
                self.chain.append(
                    "activation_refused",
                    {"item": item.value, "reason": REFUSAL[item]},
                    now.isoformat(),
                )
                raise ActivationRefused(REFUSAL[item], item, REMEDY[item])

        record = self.chain.append(
            "commissioning_complete",
            {
                "device_id": self.device_id,
                "items": [item.value for item in GATE_ORDER],
                "notice_photo_ref": self._notice_photo_ref,
                "actors": {item.value: actor for item, actor in sorted(self._passed.items())},
                "exceptions": sorted(item.value for item in self._exceptions),
            },
            now.isoformat(),
        )
        self._state = DeviceState.ACTIVE
        # The upload is queued, not awaited: the gate runs end to end offline (F21 R5).
        return record.hash

    def _satisfied(self, item: GateItem, now: datetime) -> bool:
        if item in self._passed:
            return True
        exc = self._exceptions.get(item)
        return exc is not None and now < exc.not_after

    def _exception_reason(self, exc: Exception2P, signature: str, now: datetime) -> str | None:
        if exc.signing_domain != EXCEPTION_SIGNING_DOMAIN:
            return "wrong_signing_domain"
        if not hmac.compare_digest(sign_exception(exc, self._t2_key), signature):
            return "exception_invalid"
        if len({a for a in exc.approvers if a}) < 2:
            return "two_person_control_required"
        if now >= exc.not_after:
            return "exception_expired"
        return None
