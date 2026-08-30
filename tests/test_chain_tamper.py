"""chain-tamper suite (F13): the chain must detect edits, deletions, reorders and truncation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from t1.control.audit_chain import AuditChain
from t1.tools.chain_verify import main as chain_verify_main

from .conftest import NOW_ISO


def _seeded(path: Path, n: int = 5) -> AuditChain:
    chain = AuditChain(path)
    for i in range(n):
        chain.append("egress_accept", {"seq": i}, NOW_ISO)
    return chain


def _lines(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _write(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))


def test_intact_chain_verifies(tmp_path: Path) -> None:
    result = _seeded(tmp_path / "c.jsonl").verify()
    assert result.ok and result.records == 5


def test_edited_body_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    _seeded(path)
    records = _lines(path)
    body = records[2]["body"]
    assert isinstance(body, dict)
    body["seq"] = 99
    _write(path, records)
    result = AuditChain(path).verify()
    assert not result.ok
    assert result.broken_at == 3  # seq is 1-based; records[2] is seq 3


def test_deleted_record_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    _seeded(path)
    records = _lines(path)
    del records[2]
    _write(path, records)
    assert not AuditChain(path).verify().ok


def test_reordered_records_are_detected(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    _seeded(path)
    records = _lines(path)
    records[1], records[3] = records[3], records[1]
    _write(path, records)
    assert not AuditChain(path).verify().ok


def test_truncation_of_the_tail_is_survivable_but_reported(tmp_path: Path) -> None:
    """A truncated tail still verifies as a shorter chain; the count is what T2 cross-checks."""
    path = tmp_path / "c.jsonl"
    _seeded(path)
    records = _lines(path)
    _write(path, records[:3])
    result = AuditChain(path).verify()
    assert result.ok and result.records == 3


def test_appending_after_tamper_does_not_repair_it(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    _seeded(path)
    records = _lines(path)
    records[0]["kind"] = "policy_load"
    _write(path, records)
    AuditChain(path).append("egress_accept", {"seq": 100}, NOW_ISO)
    assert not AuditChain(path).verify().ok


def test_export_range_is_verifiable(tmp_path: Path) -> None:
    chain = _seeded(tmp_path / "c.jsonl")
    exported = chain.export(since_seq=2)
    assert [r.seq for r in exported] == [3, 4, 5]


def test_cli_returns_nonzero_on_a_broken_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "c.jsonl"
    _seeded(path)
    assert chain_verify_main([str(path)]) == 0
    records = _lines(path)
    body = records[1]["body"]
    assert isinstance(body, dict)
    body["seq"] = -1
    _write(path, records)
    assert chain_verify_main([str(path)]) == 1
    assert "FAIL" in capsys.readouterr().out
