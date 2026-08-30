from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest

from t1.control.audit_chain import AuditChain
from t1.control.egress_filter import EgressFilter
from t1.control.policy import PolicyBundle, PolicyStore, sign
from t1.sim.harness import DEV_KEY, default_bundle

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
NOW_ISO = NOW.isoformat()


@pytest.fixture
def chain(tmp_path: Path) -> AuditChain:
    return AuditChain(tmp_path / "chain.jsonl")


@pytest.fixture
def bundle() -> PolicyBundle:
    return default_bundle()


@pytest.fixture
def store(tmp_path: Path, bundle: PolicyBundle) -> Iterator[PolicyStore]:
    store = PolicyStore(key=DEV_KEY, floor_path=tmp_path / "audit" / "policy_floor")
    store.load(bundle, sign(bundle, DEV_KEY))
    yield store


@pytest.fixture
def egress(store: PolicyStore, chain: AuditChain) -> EgressFilter:
    return EgressFilter(policy=store, chain=chain)
