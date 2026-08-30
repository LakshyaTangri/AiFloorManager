"""Append-only hash-chained audit log (F13, C7).

The chain lives on its own partition so that a rootfs rollback cannot rewrite history, and
verification localises the break rather than just reporting "invalid" - an auditor needs to know
which record was touched.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(prev_hash: str, seq: int, kind: str, body: dict[str, Any], ts: str) -> str:
    material = json.dumps(
        {"prev": prev_hash, "seq": seq, "kind": kind, "body": body, "ts": ts},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode()).hexdigest()


@dataclass(frozen=True)
class Record:
    seq: int
    kind: str
    body: dict[str, Any]
    ts: str
    prev_hash: str
    hash: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "seq": self.seq,
                "kind": self.kind,
                "body": self.body,
                "ts": self.ts,
                "prev_hash": self.prev_hash,
                "hash": self.hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def from_json(line: str) -> Record:
        raw = json.loads(line)
        return Record(
            seq=int(raw["seq"]),
            kind=str(raw["kind"]),
            body=dict(raw["body"]),
            ts=str(raw["ts"]),
            prev_hash=str(raw["prev_hash"]),
            hash=str(raw["hash"]),
        )


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    broken_at: int | None = None
    reason: str | None = None


class AuditChain:
    """One file, one line per record, opened append-only."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def append(self, kind: str, body: dict[str, Any], ts: str) -> Record:
        seq, prev_hash = self._head()
        record = Record(
            seq=seq + 1,
            kind=kind,
            body=body,
            ts=ts,
            prev_hash=prev_hash,
            hash=_digest(prev_hash, seq + 1, kind, body, ts),
        )
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(record.to_json() + "\n")
        return record

    def records(self) -> list[Record]:
        with self.path.open(encoding="utf-8") as handle:
            return [Record.from_json(line) for line in handle if line.strip()]

    def verify(self) -> VerifyResult:
        prev_hash = GENESIS
        expected_seq = 1
        count = 0
        for record in self.records():
            count += 1
            if record.seq != expected_seq:
                return VerifyResult(False, count, record.seq, "sequence_gap")
            if record.prev_hash != prev_hash:
                return VerifyResult(False, count, record.seq, "chain_break")
            recomputed = _digest(record.prev_hash, record.seq, record.kind, record.body, record.ts)
            if recomputed != record.hash:
                return VerifyResult(False, count, record.seq, "record_tampered")
            prev_hash = record.hash
            expected_seq += 1
        return VerifyResult(True, count)

    def export(self, since_seq: int = 0) -> list[Record]:
        return [r for r in self.records() if r.seq > since_seq]

    def _head(self) -> tuple[int, str]:
        records = self.records()
        if not records:
            return 0, GENESIS
        last = records[-1]
        return last.seq, last.hash
