"""Kill switch (M15, F17, C14).

A kill is durable state, not a runtime flag: it is written before it is reported, so a reboot — or
a crash halfway through a shift — cannot quietly resume a camera somebody switched off. The state
file is reloaded on construction, which is what "survives reboot" means for a process that is
restarted by supervision.

Killing needs a reason and an actor and nothing else; un-killing needs TA authorisation (F17 R3).
That asymmetry is deliberate: stopping processing is always safe, resuming it is a privacy
decision.

On L3 a hardware DI input can assert the kill directly. While it is asserted no software path can
start a stream and no software un-kill clears it — the operator releases the input. On L1 there is
no such input, and `software_only` says so, because the local UI has to disclose that the kill is
a software promise rather than a cut line (D-004).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from t1.canon import Profile
from t1.control.audit_chain import AuditChain


class KillScope(str, Enum):
    CAMERA = "camera"
    ZONE = "zone"
    CAPABILITY = "capability"


class Role(str, Enum):
    STORE_MANAGER = "store_manager"
    FIELD_ENGINEER = "field_engineer"
    TENANT_ADMIN = "tenant_admin"


class KillRefusal(str, Enum):
    ACTOR_MISSING = "actor_missing"
    REASON_MISSING = "reason_missing"
    TA_AUTHORISATION_REQUIRED = "ta_authorisation_required"
    HARDWARE_KILL_ASSERTED = "hardware_kill_asserted"
    HARDWARE_KILL_UNAVAILABLE = "hardware_kill_unavailable"
    NOT_KILLED = "not_killed"


@dataclass(frozen=True)
class Kill:
    scope: KillScope
    target: str
    actor: str
    reason: str
    at: str

    @property
    def key(self) -> str:
        return f"{self.scope.value}:{self.target}"


@dataclass
class KillSwitch:
    profile: Profile
    chain: AuditChain
    state_path: Path
    hardware_asserted: bool = False
    _kills: dict[str, Kill] = field(default_factory=dict)
    refusals: dict[KillRefusal, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if self.state_path.exists():
            self._kills = {
                str(raw["scope"]) + ":" + str(raw["target"]): Kill(
                    scope=KillScope(raw["scope"]),
                    target=str(raw["target"]),
                    actor=str(raw["actor"]),
                    reason=str(raw["reason"]),
                    at=str(raw["at"]),
                )
                for raw in json.loads(self.state_path.read_text(encoding="utf-8"))
            }

    @property
    def software_only(self) -> bool:
        """L1 has no DI input; the UI states that the kill is enforced in software (F17 R1)."""
        return self.profile is not Profile.L3

    def kill(
        self, scope: KillScope, target: str, actor: str, reason: str, now: datetime
    ) -> Kill | KillRefusal:
        if not actor:
            return self._refuse(KillRefusal.ACTOR_MISSING, now, scope, target, actor)
        if not reason:
            return self._refuse(KillRefusal.REASON_MISSING, now, scope, target, actor)
        entry = Kill(scope=scope, target=target, actor=actor, reason=reason, at=now.isoformat())
        self._kills[entry.key] = entry
        self._persist()
        self.chain.append(
            "kill_asserted",
            {"scope": scope.value, "target": target, "actor": actor, "reason": reason},
            now.isoformat(),
        )
        return entry

    def unkill(
        self, scope: KillScope, target: str, actor: str, role: Role, now: datetime
    ) -> KillRefusal | None:
        if not actor:
            return self._refuse(KillRefusal.ACTOR_MISSING, now, scope, target, actor)
        if role is not Role.TENANT_ADMIN:
            return self._refuse(KillRefusal.TA_AUTHORISATION_REQUIRED, now, scope, target, actor)
        if self.hardware_asserted:
            return self._refuse(KillRefusal.HARDWARE_KILL_ASSERTED, now, scope, target, actor)
        key = f"{scope.value}:{target}"
        if key not in self._kills:
            return self._refuse(KillRefusal.NOT_KILLED, now, scope, target, actor)
        del self._kills[key]
        self._persist()
        self.chain.append(
            "kill_released",
            {"scope": scope.value, "target": target, "actor": actor, "role": role.value},
            now.isoformat(),
        )
        return None

    def assert_hardware(self, now: datetime) -> KillRefusal | None:
        if self.profile is not Profile.L3:
            return self._refuse(
                KillRefusal.HARDWARE_KILL_UNAVAILABLE, now, KillScope.CAMERA, "*", "hardware"
            )
        self.hardware_asserted = True
        self.chain.append(
            "hardware_kill_asserted", {"profile": self.profile.value}, now.isoformat()
        )
        return None

    def release_hardware(self, now: datetime) -> None:
        self.hardware_asserted = False
        self.chain.append(
            "hardware_kill_released", {"profile": self.profile.value}, now.isoformat()
        )

    def killed(self, scope: KillScope, target: str) -> bool:
        return f"{scope.value}:{target}" in self._kills

    def stream_allowed(
        self, camera_id: str, zone_id: str | None = None, capabilities: tuple[str, ...] = ()
    ) -> bool:
        if self.hardware_asserted:
            return False
        if self.killed(KillScope.CAMERA, camera_id):
            return False
        if zone_id is not None and self.killed(KillScope.ZONE, zone_id):
            return False
        return not any(self.killed(KillScope.CAPABILITY, name) for name in capabilities)

    def reported_state(self) -> dict[str, object]:
        """F17 R2: the kill set propagates to reported-state rather than living only on the box."""
        return {
            "hardware_asserted": self.hardware_asserted,
            "software_only": self.software_only,
            "kills": [
                {
                    "scope": kill.scope.value,
                    "target": kill.target,
                    "actor": kill.actor,
                    "reason": kill.reason,
                    "at": kill.at,
                }
                for kill in sorted(self._kills.values(), key=lambda k: k.key)
            ],
        }

    def _persist(self) -> None:
        payload = json.dumps(
            [
                {
                    "scope": kill.scope.value,
                    "target": kill.target,
                    "actor": kill.actor,
                    "reason": kill.reason,
                    "at": kill.at,
                }
                for kill in sorted(self._kills.values(), key=lambda k: k.key)
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, self.state_path)

    def _refuse(
        self, refusal: KillRefusal, now: datetime, scope: KillScope, target: str, actor: str
    ) -> KillRefusal:
        self.refusals[refusal] = self.refusals.get(refusal, 0) + 1
        self.chain.append(
            "kill_refused",
            {
                "reason": refusal.value,
                "scope": scope.value,
                "target": target,
                "actor": actor,
            },
            now.isoformat(),
        )
        return refusal
