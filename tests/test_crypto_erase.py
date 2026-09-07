"""Decommission crypto-erase (M10, F16 R3): the chain leaves before the data dies."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from t1.control.audit_chain import AuditChain
from t1.storage.domains import CRYPTO_ERASABLE, Domain
from t1.storage.erase import (
    Decommissioner,
    DecommissionOrder,
    EraseOutcome,
    EraseRefusal,
    sign,
)

NOW = datetime(2026, 3, 1, 9, 0, 0)
KEY = b"decommission-key"
DEVICE = "t1-0001"


@pytest.fixture
def chain(tmp_path: Path) -> AuditChain:
    chain = AuditChain(tmp_path / "audit" / "chain.jsonl")
    chain.append("egress", {"schema": "footfall"}, NOW.isoformat())
    return chain


def _order(device_id: str = DEVICE) -> tuple[DecommissionOrder, str]:
    order = DecommissionOrder(device_id=device_id, reason="rma", issued_at=NOW.isoformat())
    return order, sign(order, KEY)


def _decommissioner(
    chain: AuditChain,
    *,
    erased: set[Domain] | None = None,
    fails: frozenset[Domain] = frozenset(),
    device_id: str | None = DEVICE,
    key_escrowed: bool = False,
) -> Decommissioner:
    seen = erased if erased is not None else set()

    def erase_key_slots(domain: Domain) -> bool:
        if domain in fails:
            return False
        seen.add(domain)
        return True

    return Decommissioner(
        device_id=device_id,
        key=KEY,
        chain=chain,
        erase_key_slots=erase_key_slots,
        key_escrowed=key_escrowed,
    )


def test_erase_destroys_the_erasable_domains_and_leaves_a_bound_receipt(chain: AuditChain) -> None:
    erased: set[Domain] = set()
    dec = _decommissioner(chain, erased=erased)
    order, signature = _order()
    export = dec.export_audit("t2://custody/t1-0001")
    assert not isinstance(export, EraseRefusal)

    receipt = dec.erase(order, signature, export, NOW)
    assert not isinstance(receipt, EraseRefusal)
    assert receipt.outcome is EraseOutcome.ERASED
    assert erased == set(CRYPTO_ERASABLE)
    assert receipt.device_id == DEVICE
    assert receipt.audit_export_hash == export.export_hash


def test_the_audit_domain_is_never_offered_to_the_eraser(chain: AuditChain) -> None:
    dec = _decommissioner(chain)
    order, signature = _order()
    export = dec.export_audit("t2://custody/t1-0001")
    assert not isinstance(export, EraseRefusal)
    dec.erase(order, signature, export, NOW)

    assert Domain.AUDIT not in dec.attempted
    assert chain.verify().ok
    assert [r.kind for r in chain.records()] == ["egress", "decommission_receipt"]


def test_erase_without_an_export_is_refused(chain: AuditChain) -> None:
    dec = _decommissioner(chain)
    order, signature = _order()
    assert dec.erase(order, signature, None, NOW) is EraseRefusal.AUDIT_NOT_EXPORTED
    assert dec.attempted == []


def test_a_broken_chain_is_discovered_before_anything_is_destroyed(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "chain.jsonl"
    chain = AuditChain(path)
    chain.append("egress", {"schema": "footfall"}, NOW.isoformat())
    path.write_text(path.read_text().replace("footfall", "dwell"))

    dec = _decommissioner(chain)
    assert dec.export_audit("t2://custody") is EraseRefusal.AUDIT_CHAIN_BROKEN
    assert dec.attempted == []


def test_an_order_for_another_device_is_refused(chain: AuditChain) -> None:
    dec = _decommissioner(chain)
    order, signature = _order(device_id="t1-9999")
    export = dec.export_audit("t2://custody")
    assert not isinstance(export, EraseRefusal)
    assert dec.erase(order, signature, export, NOW) is EraseRefusal.ORDER_FOR_ANOTHER_DEVICE


def test_a_forged_order_is_refused(chain: AuditChain) -> None:
    dec = _decommissioner(chain)
    order, _ = _order()
    export = dec.export_audit("t2://custody")
    assert not isinstance(export, EraseRefusal)
    assert dec.erase(order, "00" * 32, export, NOW) is EraseRefusal.SIGNATURE_INVALID


def test_an_order_signed_in_another_domain_is_refused(chain: AuditChain) -> None:
    dec = _decommissioner(chain)
    order = DecommissionOrder(
        device_id=DEVICE, reason="rma", issued_at=NOW.isoformat(), signing_domain="privacy-policy"
    )
    export = dec.export_audit("t2://custody")
    assert not isinstance(export, EraseRefusal)
    assert dec.erase(order, sign(order, KEY), export, NOW) is EraseRefusal.WRONG_SIGNING_DOMAIN


def test_an_unenrolled_device_cannot_produce_a_receipt(chain: AuditChain) -> None:
    dec = _decommissioner(chain, device_id=None)
    order, signature = _order()
    export = dec.export_audit("t2://custody")
    assert not isinstance(export, EraseRefusal)
    assert dec.erase(order, signature, export, NOW) is EraseRefusal.IDENTITY_UNKNOWN


def test_an_escrowed_key_makes_crypto_erase_a_claim_the_device_will_not_make(
    chain: AuditChain,
) -> None:
    dec = _decommissioner(chain, key_escrowed=True)
    order, signature = _order()
    export = dec.export_audit("t2://custody")
    assert not isinstance(export, EraseRefusal)
    assert dec.erase(order, signature, export, NOW) is EraseRefusal.KEY_ESCROWED


def test_a_domain_that_fails_to_erase_yields_partial_not_success(chain: AuditChain) -> None:
    dec = _decommissioner(chain, fails=frozenset({Domain.SPOOL}))
    order, signature = _order()
    export = dec.export_audit("t2://custody")
    assert not isinstance(export, EraseRefusal)

    receipt = dec.erase(order, signature, export, NOW)
    assert not isinstance(receipt, EraseRefusal)
    assert receipt.outcome is EraseOutcome.PARTIAL
    assert receipt.domains_failed == (Domain.SPOOL,)
    assert dec.erased is False


def test_erase_is_terminal(chain: AuditChain) -> None:
    dec = _decommissioner(chain)
    order, signature = _order()
    export = dec.export_audit("t2://custody")
    assert not isinstance(export, EraseRefusal)
    dec.erase(order, signature, export, NOW)

    assert dec.erase(order, signature, export, NOW) is EraseRefusal.ALREADY_ERASED
