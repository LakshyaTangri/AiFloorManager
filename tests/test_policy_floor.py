"""policy-floor and signing-domain suites (F12, F15 R3, D-003).

The interesting case is the rollback one: a device that has enforced version 5 must refuse version
4 even though version 4 is correctly signed, because a rootfs rollback is a legitimate way to get
an old-but-valid bundle back onto the box.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from t1.canon import DataClass, TrustLevel
from t1.contracts import Envelope
from t1.control.audit_chain import AuditChain
from t1.control.egress_filter import EgressFilter
from t1.control.policy import PolicyBundle, PolicyRejected, PolicyStore, sign
from t1.sim.harness import DEV_KEY, default_bundle

from .conftest import NOW_ISO

MODEL_KEY = b"model-signing-key-not-the-policy-key"


def _store(tmp_path: Path) -> PolicyStore:
    return PolicyStore(key=DEV_KEY, floor_path=tmp_path / "audit" / "policy_floor")


def test_valid_bundle_enables_the_bridge(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bundle = default_bundle(version=5)
    store.load(bundle, sign(bundle, DEV_KEY))
    assert store.bridge_enabled and store.version_floor == 5


def test_forged_signature_is_refused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bundle = default_bundle(version=5)
    with pytest.raises(PolicyRejected) as exc:
        store.load(bundle, sign(bundle, MODEL_KEY))
    assert exc.value.reason == "policy_invalid"
    assert store.bridge_enabled is False


def test_wrong_signing_domain_is_refused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bundle = PolicyBundle(
        version=5,
        floors=default_bundle().floors,
        allowed_schemas=default_bundle().allowed_schemas,
        field_allowlist=default_bundle().field_allowlist,
        signing_domain="model-artifact",
    )
    with pytest.raises(PolicyRejected) as exc:
        store.load(bundle, sign(bundle, DEV_KEY))
    assert exc.value.reason == "wrong_signing_domain"


def test_downgrade_after_rollback_is_refused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    new = default_bundle(version=5)
    store.load(new, sign(new, DEV_KEY))

    rolled_back = _store(tmp_path)  # fresh process, same audit partition
    old = default_bundle(version=4)
    with pytest.raises(PolicyRejected) as exc:
        rolled_back.load(old, sign(old, DEV_KEY))
    assert exc.value.reason == "policy_downgrade"
    assert rolled_back.bridge_enabled is False


def test_same_version_reload_is_allowed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bundle = default_bundle(version=5)
    store.load(bundle, sign(bundle, DEV_KEY))
    store.load(bundle, sign(bundle, DEV_KEY))
    assert store.bridge_enabled


def test_bridge_down_means_nothing_egresses(tmp_path: Path) -> None:
    store = _store(tmp_path)
    chain = AuditChain(tmp_path / "chain.jsonl")
    filt = EgressFilter(policy=store, chain=chain)
    env = Envelope(
        device_id="d",
        boot_id="b",
        seq=1,
        device_time=NOW_ISO,
        schema="rtl.health.v1",
        data_class=DataClass.C0_OPERATIONAL,
        purpose="operations",
        trust_level=TrustLevel.SOFTWARE_BOUND,
        payload={"cpu_pct": 12, "mem_mb": 900},
        policy_version="3",
    )
    assert filt.evaluate(env).reason == "policy_invalid"
    assert chain.verify().records == 0
