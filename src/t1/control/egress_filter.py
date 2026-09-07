"""The egress filter (F12, C3, C6, C7).

Every byte leaving the box passes through here, in a fixed order, and the order matters: the
cheapest structural refusals run first so that a hostile payload is rejected before anything
expensive parses it, and the audit append happens last so that only accepted messages are chained.

The filter fails closed everywhere. If the policy bundle will not load, the bridge is disabled and
local ingest keeps running - a site that cannot report is still a site that counts, alerts and
enforces retention.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from t1.canon import (
    CLASSES_PERMITTED,
    CLASSES_REQUIRING_BASIS,
    ENTITLEMENT_FOR_CLASS,
    MAX_PAYLOAD_BYTES,
    VALID_LAWFUL_BASIS,
    DataClass,
)
from t1.contracts import Envelope
from t1.control.audit_chain import AuditChain
from t1.control.kanon import effective_floor
from t1.control.policy import PolicyStore
from t1.security.identity import DeviceIdentity

MAX_ENUM_LEN = 64

# A bounded token: enum values, ids, refs, ISO timestamps. Anything a human would call a sentence
# fails it, and so does anything long enough to hide one.
ENUM_SHAPE = re.compile(rf"^[A-Za-z0-9_.:+/-]{{1,{MAX_ENUM_LEN}}}$")


@dataclass(frozen=True)
class Verdict:
    accepted: bool
    reason: str | None = None

    @property
    def rejected(self) -> bool:
        return not self.accepted


ACCEPTED = Verdict(True)


def _payload_size(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, separators=(",", ":"), default=str).encode())


def _is_free_text(value: object) -> bool:
    """Rejection is by shape, not by content inspection.

    Reading the string to decide whether it looks personal would be exactly the analysis the
    control exists to prevent. Instead every string field must be a bounded token; a sentence is
    refused whatever it says, and so is a 70 kB blob of prose.
    """
    return isinstance(value, str) and ENUM_SHAPE.match(value) is None


def contains_media(payload: dict[str, Any]) -> bool:
    for key, value in payload.items():
        if isinstance(value, bytes):
            return True
        if isinstance(value, str) and (
            key.endswith(("_b64", "_image", "_clip", "_frame")) or value.startswith("data:")
        ):
            return True
        if isinstance(value, dict) and contains_media(value):
            return True
    return False


def _has_age_field(payload: dict[str, Any]) -> bool:
    for key, value in payload.items():
        if "age" in key and key != "age_gate_ver":
            return True
        if isinstance(value, dict) and _has_age_field(value):
            return True
    return False


@dataclass
class EgressFilter:
    policy: PolicyStore
    chain: AuditChain
    identity: DeviceIdentity | None = None
    rejections: dict[str, int] = field(default_factory=dict)
    accepted_count: int = 0

    def evaluate(self, env: Envelope) -> Verdict:
        verdict = self._checks(env)
        if verdict.rejected:
            reason = verdict.reason or "unknown"
            self.rejections[reason] = self.rejections.get(reason, 0) + 1
            return verdict
        self.chain.append(
            "egress_accept",
            {
                "schema": env.schema,
                "class": env.data_class.value,
                "seq": env.seq,
                "policy_version": env.policy_version,
                "age_gate_ver": env.age_gate_ver,
            },
            env.device_time,
        )
        self.accepted_count += 1
        return ACCEPTED

    def _checks(self, env: Envelope) -> Verdict:
        # A device whose host binding changed keeps counting locally but says nothing outward
        # until a human re-approves it (F04 R3).
        if self.identity is not None and not self.identity.egress_allowed:
            return Verdict(False, "identity_not_enrolled")

        bundle = self.policy.active
        if bundle is None or not self.policy.bridge_enabled:
            return Verdict(False, self.policy.last_reason or "policy_invalid")

        if env.data_class is DataClass.C6_PROHIBITED:
            return Verdict(False, "prohibited_class")

        if env.schema not in bundle.allowed_schemas:
            return Verdict(False, "schema_unknown")

        if bundle.allowed_schemas[env.schema] != env.data_class.value:
            return Verdict(False, "class_mismatch")

        # C3/C4/C5 on software_bound are refused here even with a valid basis and entitlement.
        if env.data_class not in CLASSES_PERMITTED[env.trust_level]:
            return Verdict(False, "trust_level_forbids_class")

        entitlement = ENTITLEMENT_FOR_CLASS.get(env.data_class)
        if entitlement is not None and entitlement not in env.entitlements:
            return Verdict(False, "entitlement_missing")

        allowlist = bundle.field_allowlist.get(env.schema)
        if allowlist is None:
            return Verdict(False, "schema_unknown")
        for key in env.payload:
            if key not in allowlist:
                return Verdict(False, "field_not_allowed")

        # Media is checked before free text: a data: URI is both, and "media_forbidden" is the
        # reason an operator needs to see on the dashboard.
        if contains_media(env.payload):
            return Verdict(False, "media_forbidden")

        for value in env.payload.values():
            if _is_free_text(value):
                return Verdict(False, "free_text_forbidden")

        if _has_age_field(env.payload):
            return Verdict(False, "age_field_forbidden")

        if env.metric is not None or env.k_value is not None:
            floor = effective_floor(env.metric or "", bundle.floor_for(env.metric))
            if env.k_value is None:
                return Verdict(False, "k_missing")
            if env.k_value < floor:
                return Verdict(False, "k_below_floor")

        if env.data_class in CLASSES_REQUIRING_BASIS:
            if env.lawful_basis is None:
                return Verdict(False, "basis_missing")
            if env.lawful_basis not in VALID_LAWFUL_BASIS:
                return Verdict(False, "basis_invalid")
            if env.retention_until is None:
                return Verdict(False, "retention_missing")

        if not env.purpose:
            return Verdict(False, "purpose_missing")

        if env.policy_version != str(bundle.version):
            return Verdict(False, "policy_version_mismatch")

        if _payload_size(env.payload) > MAX_PAYLOAD_BYTES:
            return Verdict(False, "payload_too_large")

        return ACCEPTED

    def reject_rate(self) -> dict[str, int]:
        """C0 health metric: a schema mismatch should surface on the fleet dashboard, not vanish."""
        return dict(self.rejections)
