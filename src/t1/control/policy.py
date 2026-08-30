"""Signed egress policy bundle (F12, D-003).

Three separate refusals live here, and they are easy to conflate:

    policy_invalid     signature or parse failure  -> bridge disabled, ingest continues
    policy_downgrade   older than the recorded floor -> a rootfs rollback cannot loosen the filter
    floor_below_canon  a k floor below the canon default -> policy may tighten, never loosen

Signing uses HMAC with a development key. Production uses the privacy-policy signing domain; the
verification *shape* is what matters here, and `signing_domain` is checked explicitly so that a
bundle signed with the model key is refused the way F15 R3 requires.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from t1.canon import CANON_FLOORS, DEFAULT_FLOOR

POLICY_SIGNING_DOMAIN = "privacy-policy"


class PolicyRejected(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class PolicyBundle:
    version: int
    floors: dict[str, int]
    allowed_schemas: dict[str, str]
    field_allowlist: dict[str, tuple[str, ...]]
    signing_domain: str = POLICY_SIGNING_DOMAIN

    def floor_for(self, metric: str | None) -> int:
        if metric is None:
            return DEFAULT_FLOOR
        return self.floors.get(metric, CANON_FLOORS.get(metric, DEFAULT_FLOOR))

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "version": self.version,
                "floors": self.floors,
                "allowed_schemas": self.allowed_schemas,
                "field_allowlist": {k: list(v) for k, v in self.field_allowlist.items()},
                "signing_domain": self.signing_domain,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


def sign(bundle: PolicyBundle, key: bytes) -> str:
    return hmac.new(key, bundle.to_bytes(), hashlib.sha256).hexdigest()


@dataclass
class PolicyStore:
    """Holds the active bundle and the monotonic version floor.

    The floor is persisted on the audit partition, which survives rootfs rollback. That is the
    whole mechanism behind D-003's "tightening ships fast, loosening ships slow": a device that has
    ever enforced version N refuses anything below N.
    """

    key: bytes
    floor_path: Path
    active: PolicyBundle | None = None
    bridge_enabled: bool = False
    last_reason: str | None = None
    rejections: dict[str, int] = field(default_factory=dict)

    @property
    def version_floor(self) -> int:
        if not self.floor_path.exists():
            return 0
        return int(self.floor_path.read_text().strip() or 0)

    def load(self, bundle: PolicyBundle, signature: str) -> PolicyBundle:
        try:
            self._verify(bundle, signature)
        except PolicyRejected as exc:
            # Fail closed: the bridge goes down, local ingest keeps running (F12 R2).
            self.bridge_enabled = False
            self.last_reason = exc.reason
            self.rejections[exc.reason] = self.rejections.get(exc.reason, 0) + 1
            raise

        self.active = bundle
        self.bridge_enabled = True
        self.last_reason = None
        self.floor_path.parent.mkdir(parents=True, exist_ok=True)
        self.floor_path.write_text(str(max(self.version_floor, bundle.version)))
        return bundle

    def _verify(self, bundle: PolicyBundle, signature: str) -> None:
        if bundle.signing_domain != POLICY_SIGNING_DOMAIN:
            raise PolicyRejected("wrong_signing_domain")
        if not hmac.compare_digest(sign(bundle, self.key), signature):
            raise PolicyRejected("policy_invalid")
        if bundle.version < self.version_floor:
            raise PolicyRejected("policy_downgrade")
        for metric, canon_floor in CANON_FLOORS.items():
            if bundle.floors.get(metric, canon_floor) < canon_floor:
                raise PolicyRejected("floor_below_canon")
        for metric, floor in bundle.floors.items():
            if floor < CANON_FLOORS.get(metric, DEFAULT_FLOOR):
                raise PolicyRejected("floor_below_canon")


def parse_bundle(raw: dict[str, Any]) -> PolicyBundle:
    return PolicyBundle(
        version=int(raw["version"]),
        floors={str(k): int(v) for k, v in raw.get("floors", {}).items()},
        allowed_schemas={str(k): str(v) for k, v in raw.get("allowed_schemas", {}).items()},
        field_allowlist={
            str(k): tuple(str(f) for f in v) for k, v in raw.get("field_allowlist", {}).items()
        },
        signing_domain=str(raw.get("signing_domain", POLICY_SIGNING_DOMAIN)),
    )
