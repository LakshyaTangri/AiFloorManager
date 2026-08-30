"""Retention enforcement (F16), budget report, and the end-to-end simulation."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from t1.canon import DataClass, Profile
from t1.control.audit_chain import AuditChain
from t1.control.retention import RetentionEnforcer, StoredRecord
from t1.sim.harness import SimFrameSpec, Simulation
from t1.tools.budget_report import load
from t1.tools.budget_report import main as budget_main
from t1.tools.sim import default_scenario

from .conftest import NOW

BUDGETS = Path(__file__).resolve().parents[1] / "ops" / "budgets.json"


def test_l1_refuses_c3_persistence(chain: AuditChain) -> None:
    enforcer = RetentionEnforcer(profile=Profile.L1, chain=chain)
    with pytest.raises(ValueError, match="c3_persistence_forbidden"):
        enforcer.admit(StoredRecord("r1", DataClass.C3_TRACE, NOW, NOW + timedelta(days=1)))
    assert enforcer.store == {}


def test_l2_clamps_c3_retention_to_the_profile_ceiling(chain: AuditChain) -> None:
    enforcer = RetentionEnforcer(profile=Profile.L2, chain=chain)
    enforcer.admit(StoredRecord("r1", DataClass.C3_TRACE, NOW, NOW + timedelta(days=365)))
    assert enforcer.store["r1"].retention_until == NOW + timedelta(days=30)


def test_expiry_deletes_and_writes_a_receipt(chain: AuditChain) -> None:
    enforcer = RetentionEnforcer(profile=Profile.L2, chain=chain)
    enforcer.admit(StoredRecord("r1", DataClass.C2_EVENT, NOW, NOW + timedelta(days=1)))
    assert enforcer.run(NOW + timedelta(hours=1)) == []
    assert enforcer.run(NOW + timedelta(days=2)) == ["r1"]
    assert enforcer.store == {}
    kinds = [r.kind for r in chain.records()]
    assert kinds == ["deletion_receipt"]
    assert chain.verify().ok


def test_budget_file_is_within_its_declared_ceiling() -> None:
    profile, total_ceiling, usable, lines = load(BUDGETS)
    declared = sum(line.ceiling_mb for line in lines)
    assert profile == "RTL-L1"
    assert declared == total_ceiling
    assert declared < usable
    assert budget_main(["--budgets", str(BUDGETS)]) == 0


def test_simulation_suppresses_minors_and_emits_nothing_unredacted(tmp_path: Path) -> None:
    report = Simulation(workdir=tmp_path).run(default_scenario())
    assert report.frames == 6
    assert report.minors_suppressed == 3
    assert report.adults_tracked == 6
    assert report.frames_dropped == 2  # one no-motion, one redaction failure
    assert report.chain_ok is True
    assert report.egress_accepted == report.chain_records


def test_simulation_with_only_minors_emits_no_track(tmp_path: Path) -> None:
    report = Simulation(workdir=tmp_path).run([SimFrameSpec("cam-1", (12.0, 15.0, 19.0))])
    assert report.adults_tracked == 0
    assert report.minors_suppressed == 3
    assert report.minor_suppression_rate == 1.0
