"""Decommission and crypto-erase (M10, F16 R3).

Crypto-erase destroys the LUKS2 key slots of the erasable domains; it does not overwrite sectors.
That is the strongest thing a portable SSD can honestly offer, and it is only true if the volume
key was never escrowed off the device — which is why this module refuses to erase a device whose
key it is told is escrowed rather than emitting a receipt that would overstate what happened.

The order is the requirement, not an implementation preference:

    1. authorise   a signed decommission order naming *this* device; a generic order is refused.
    2. verify      the audit chain, before anything is destroyed, so a broken chain is discovered
                   while the evidence still exists.
    3. export      the chain off the device. On L1 the audit partition is preserved and exported
                   before erase, so the chain survives the device (F16 R3).
    4. erase       the key slots of the erasable domains only. The audit domain is never passed to
                   the eraser, and neither is anything off the T1 device (AD-01).
    5. receipt     bound to the device identity and to the export hash, appended to the preserved
                   chain and returned for T2 to match.

A domain that fails to erase does not produce a success receipt: the result is `partial`, the
device stays decommissioning, and the operator has a named domain to deal with. Erase is terminal —
a device that has been erased refuses to be erased again rather than emitting a second receipt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Final

from t1.control.audit_chain import AuditChain
from t1.storage.domains import CRYPTO_ERASABLE, PRESERVED_ON_ERASE, Domain

DECOMMISSION_SIGNING_DOMAIN: Final[str] = "decommission-order"


class EraseRefusal(str, Enum):
    WRONG_SIGNING_DOMAIN = "wrong_signing_domain"
    SIGNATURE_INVALID = "signature_invalid"
    ORDER_FOR_ANOTHER_DEVICE = "order_for_another_device"
    IDENTITY_UNKNOWN = "identity_unknown"
    AUDIT_CHAIN_BROKEN = "audit_chain_broken"
    AUDIT_NOT_EXPORTED = "audit_not_exported"
    KEY_ESCROWED = "key_escrowed"
    ALREADY_ERASED = "already_erased"


class EraseOutcome(str, Enum):
    ERASED = "erased"
    PARTIAL = "partial"


@dataclass(frozen=True)
class DecommissionOrder:
    device_id: str
    reason: str
    issued_at: str
    signing_domain: str = DECOMMISSION_SIGNING_DOMAIN

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "device_id": self.device_id,
                "reason": self.reason,
                "issued_at": self.issued_at,
                "signing_domain": self.signing_domain,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


def sign(order: DecommissionOrder, key: bytes) -> str:
    return hmac.new(key, order.to_bytes(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class AuditExport:
    """Proof the chain left the device before the data did."""

    records: int
    head_hash: str
    destination: str

    @property
    def export_hash(self) -> str:
        material = f"{self.records}:{self.head_hash}:{self.destination}"
        return hashlib.sha256(material.encode()).hexdigest()


@dataclass(frozen=True)
class EraseReceipt:
    device_id: str
    outcome: EraseOutcome
    domains_erased: tuple[Domain, ...]
    domains_failed: tuple[Domain, ...]
    audit_export_hash: str
    ts: str
    chain_hash: str


@dataclass
class Decommissioner:
    """`erase_key_slots` returns True when the slots for that domain are gone.

    It is injected because destroying key slots is a `cryptsetup` call against a real header; this
    module owns the order and the refusals, not the device operation.
    """

    device_id: str | None
    key: bytes
    chain: AuditChain
    erase_key_slots: Callable[[Domain], bool]
    key_escrowed: bool = False
    erased: bool = False
    attempted: list[Domain] = field(default_factory=list)
    refusals: dict[EraseRefusal, int] = field(default_factory=dict)

    def authorise(self, order: DecommissionOrder, signature: str) -> EraseRefusal | None:
        if self.erased:
            return self._refuse(EraseRefusal.ALREADY_ERASED)
        if self.device_id is None:
            # A receipt has to be bound to an identity; an unenrolled device cannot produce one.
            return self._refuse(EraseRefusal.IDENTITY_UNKNOWN)
        if order.signing_domain != DECOMMISSION_SIGNING_DOMAIN:
            return self._refuse(EraseRefusal.WRONG_SIGNING_DOMAIN)
        if not hmac.compare_digest(sign(order, self.key), signature):
            return self._refuse(EraseRefusal.SIGNATURE_INVALID)
        if order.device_id != self.device_id:
            return self._refuse(EraseRefusal.ORDER_FOR_ANOTHER_DEVICE)
        if self.key_escrowed:
            return self._refuse(EraseRefusal.KEY_ESCROWED)
        return None

    def export_audit(self, destination: str) -> AuditExport | EraseRefusal:
        result = self.chain.verify()
        if not result.ok:
            return self._refuse(EraseRefusal.AUDIT_CHAIN_BROKEN)
        records = self.chain.records()
        head = records[-1].hash if records else ""
        return AuditExport(records=len(records), head_hash=head, destination=destination)

    def erase(
        self,
        order: DecommissionOrder,
        signature: str,
        export: AuditExport | None,
        now: datetime,
    ) -> EraseReceipt | EraseRefusal:
        refusal = self.authorise(order, signature)
        if refusal is not None:
            return refusal
        if export is None:
            # The chain is the only thing that outlives the device; losing it to save a step turns
            # a decommission into a disappearance.
            return self._refuse(EraseRefusal.AUDIT_NOT_EXPORTED)

        erased: list[Domain] = []
        failed: list[Domain] = []
        for domain in sorted(CRYPTO_ERASABLE, key=lambda d: d.value):
            self.attempted.append(domain)
            if self.erase_key_slots(domain):
                erased.append(domain)
            else:
                failed.append(domain)

        outcome = EraseOutcome.ERASED if not failed else EraseOutcome.PARTIAL
        body = {
            "device_id": str(self.device_id),
            "outcome": outcome.value,
            "domains_erased": [d.value for d in erased],
            "domains_failed": [d.value for d in failed],
            "domains_preserved": sorted(d.value for d in PRESERVED_ON_ERASE),
            "audit_export_hash": export.export_hash,
            "reason": order.reason,
        }
        record = self.chain.append("decommission_receipt", body, now.isoformat())
        self.erased = outcome is EraseOutcome.ERASED
        return EraseReceipt(
            device_id=str(self.device_id),
            outcome=outcome,
            domains_erased=tuple(erased),
            domains_failed=tuple(failed),
            audit_export_hash=export.export_hash,
            ts=now.isoformat(),
            chain_hash=record.hash,
        )

    def _refuse(self, refusal: EraseRefusal) -> EraseRefusal:
        self.refusals[refusal] = self.refusals.get(refusal, 0) + 1
        return refusal
