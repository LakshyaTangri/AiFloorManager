"""Signed capability vector and the gate that enforces it (F05, C8, C12).

The gate is deliberately duplicated with T2's plan-time validation. A compromised control plane
should be unable to over-drive a device, so the device holds its own signed ceiling and rejects
with a named reason per key rather than silently clamping.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from t1.canon import ADAPTER_CAP_THRESHOLDS, Profile, TrustLevel


@dataclass(frozen=True)
class CapabilityVector:
    profile: Profile
    trust_level: TrustLevel
    adapter_cap: int
    stream_cap: int
    recognition: bool = False
    p2p: bool = False
    local_vlm: bool = False
    c3_persistence: bool = False

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "profile": self.profile.value,
                "trust_level": self.trust_level.value,
                "adapter_cap": self.adapter_cap,
                "stream_cap": self.stream_cap,
                "recognition": self.recognition,
                "p2p": self.p2p,
                "local_vlm": self.local_vlm,
                "c3_persistence": self.c3_persistence,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def sign(self, key: bytes) -> str:
        return hmac.new(key, self.to_bytes(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Rejection:
    key: str
    reason: str


def l1_vector(usable_ram_mb: int) -> CapabilityVector | None:
    """D-001: the L1 adapter cap is a measured pre-flight output, never an assumption."""
    cap = 0
    for threshold, adapters in ADAPTER_CAP_THRESHOLDS:
        if usable_ram_mb >= threshold:
            cap = adapters
            break
    if cap == 0:
        return None  # host_not_qualified
    return CapabilityVector(
        profile=Profile.L1,
        trust_level=TrustLevel.SOFTWARE_BOUND,
        adapter_cap=cap,
        stream_cap=2,
    )


class CapabilityGate:
    def __init__(self, vector: CapabilityVector, key: bytes, signature: str) -> None:
        if not hmac.compare_digest(vector.sign(key), signature):
            raise ValueError("capability_vector_unsigned")
        self.vector = vector

    def evaluate(self, desired: dict[str, Any]) -> list[Rejection]:
        """Return every rejection, not just the first: the operator fixes one plan, not five."""
        rejections: list[Rejection] = []
        v = self.vector

        adapters = desired.get("adapters")
        if isinstance(adapters, list) and len(adapters) > v.adapter_cap:
            rejections.append(Rejection("adapters", "adapter_cap_exceeded"))

        streams = desired.get("streams")
        if isinstance(streams, list) and len(streams) > v.stream_cap:
            rejections.append(Rejection("streams", "stream_cap_exceeded"))

        for key, allowed in (
            ("recognition", v.recognition),
            ("p2p", v.p2p),
            ("local_vlm", v.local_vlm),
            ("c3_persistence", v.c3_persistence),
        ):
            if desired.get(key) and not allowed:
                reason = (
                    "trust_level_insufficient"
                    if v.trust_level is TrustLevel.SOFTWARE_BOUND
                    else "capability_not_entitled"
                )
                rejections.append(Rejection(key, reason))

        return rejections

    def accepts(self, desired: dict[str, Any]) -> bool:
        return not self.evaluate(desired)
