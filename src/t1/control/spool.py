"""Durable spool and offline operation (F14, C13).

The spool is bounded in bytes, not in rows, because the thing that kills an edge box is a full
partition and rows are a poor proxy for bytes. When it is full it does not stop accepting: it
sheds in the canonical order - health first, aggregates coarsened before they are dropped, safety
and security events last. A store that drops a refrigeration excursion to keep a CPU-usage packet
has failed at the only job the spool has.

Two invariants the tests hold it to:

    Raw media never enters the spool. A T2 outage must not create a video backlog (F14 R4), so the
    refusal is at admission, not at drain.
    `device_time` is never rewritten. On reconnect the measured offset is *stamped alongside* it
    (F14 R6); a record that was misdated stays misdated and says so, because silently correcting a
    timestamp destroys the evidence that the clock was wrong.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from t1.canon import CLOCK_SKEW_TOLERANCE_MS, SPOOL_DAYS, DataClass, Priority, Profile
from t1.control.egress_filter import contains_media

# Aggregates coarsen once before they become droppable: a coarser window is still a true answer to
# a coarser question, whereas a dropped window is a hole.
COARSEN_FACTOR = 4


class SpoolRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SpoolItem:
    schema: str
    data_class: DataClass
    priority: Priority
    device_time: datetime
    payload: dict[str, Any]
    purpose: str = "operations"
    metric: str | None = None
    window_seconds: int | None = None
    k_value: int | None = None


@dataclass(frozen=True)
class SpooledRecord:
    seq: int
    boot_id: str
    schema: str
    data_class: DataClass
    priority: Priority
    device_time: datetime
    payload: dict[str, Any]
    purpose: str
    metric: str | None
    window_seconds: int | None
    k_value: int | None
    coarsened: bool

    @property
    def size_bytes(self) -> int:
        return _encoded_size(self.payload)


@dataclass(frozen=True)
class ClockStamp:
    """The result of meeting trusted time again after an outage."""

    clock_offset_ms: int
    time_uncertain: bool

    @property
    def alert(self) -> str | None:
        return "clock_skew" if self.time_uncertain else None


def _encoded_size(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode())


def measure_offset(device_now: datetime, trusted_now: datetime) -> ClockStamp:
    offset_ms = int((trusted_now - device_now).total_seconds() * 1000)
    return ClockStamp(offset_ms, abs(offset_ms) > CLOCK_SKEW_TOLERANCE_MS)


class Spool:
    """SQLite-backed, ordered by `seq`, drained oldest first.

    `seq` is monotonic across boots: it continues from whatever the table already holds, so a
    reboot mid-outage cannot produce two records with the same sequence number and T2 can detect a
    gap rather than silently interleaving two boots.
    """

    def __init__(
        self,
        path: Path,
        profile: Profile,
        boot_id: str,
        capacity_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self.profile = profile
        self.boot_id = boot_id
        self.capacity_bytes = capacity_bytes
        self.dropped: dict[str, int] = {}
        self.coarsened_count = 0
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS spool (
                seq INTEGER PRIMARY KEY,
                boot_id TEXT NOT NULL,
                schema TEXT NOT NULL,
                data_class TEXT NOT NULL,
                priority INTEGER NOT NULL,
                device_time TEXT NOT NULL,
                payload TEXT NOT NULL,
                purpose TEXT NOT NULL,
                metric TEXT,
                window_seconds INTEGER,
                k_value INTEGER,
                coarsened INTEGER NOT NULL DEFAULT 0,
                size_bytes INTEGER NOT NULL
            )
            """
        )
        self._db.execute("CREATE TABLE IF NOT EXISTS spool_meta (last_seq INTEGER NOT NULL)")
        if self._db.execute("SELECT COUNT(*) FROM spool_meta").fetchone()[0] == 0:
            self._db.execute("INSERT INTO spool_meta VALUES (0)")
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    @property
    def used_bytes(self) -> int:
        row = self._db.execute("SELECT COALESCE(SUM(size_bytes), 0) FROM spool").fetchone()
        return int(row[0])

    def depth(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM spool").fetchone()[0])

    def enqueue(self, item: SpoolItem) -> SpooledRecord:
        if contains_media(item.payload):
            raise SpoolRefused("raw_media_never_spooled")

        size = _encoded_size(item.payload)
        if size > self.capacity_bytes:
            raise SpoolRefused("record_exceeds_capacity")
        self._make_room(size, item.priority)

        seq = self._next_seq()
        self._db.execute(
            "INSERT INTO spool VALUES (?,?,?,?,?,?,?,?,?,?,?,0,?)",
            (
                seq,
                self.boot_id,
                item.schema,
                item.data_class.value,
                int(item.priority),
                item.device_time.isoformat(),
                json.dumps(item.payload, separators=(",", ":"), sort_keys=True, default=str),
                item.purpose,
                item.metric,
                item.window_seconds,
                item.k_value,
                size,
            ),
        )
        self._db.commit()
        return self._record(seq)

    def prune(self, now: datetime) -> int:
        """Depth is a time horizon, not just a size: 7 d on L1, 30 d on L2, 90 d on L3."""
        horizon = (now - timedelta(days=SPOOL_DAYS[self.profile])).isoformat()
        cursor = self._db.execute("DELETE FROM spool WHERE device_time < ?", (horizon,))
        self._db.commit()
        removed = int(cursor.rowcount)
        if removed:
            self._count_drop("spool_expired", removed)
        return removed

    def drain(self, limit: int) -> list[SpooledRecord]:
        """Peek in sequence order. Records leave only on `ack`, so a failed publish re-delivers."""
        rows = self._db.execute(
            "SELECT seq FROM spool ORDER BY seq ASC LIMIT ?", (limit,)
        ).fetchall()
        return [self._record(int(row[0])) for row in rows]

    def ack(self, seqs: Iterable[int]) -> int:
        seq_list = list(seqs)
        if not seq_list:
            return 0
        placeholders = ",".join("?" * len(seq_list))
        cursor = self._db.execute(
            f"DELETE FROM spool WHERE seq IN ({placeholders})",
            seq_list,
        )
        self._db.commit()
        return int(cursor.rowcount)

    def _make_room(self, needed: int, incoming: Priority) -> None:
        while self.used_bytes + needed > self.capacity_bytes:
            if self._coarsen_oldest_aggregate():
                continue
            victim = self._db.execute(
                "SELECT seq, priority, size_bytes FROM spool ORDER BY priority DESC, seq ASC "
                "LIMIT 1"
            ).fetchone()
            if victim is None or int(victim[1]) < int(incoming):
                # Everything left outranks the incoming record: the new record yields instead.
                raise SpoolRefused("spool_full")
            self._db.execute("DELETE FROM spool WHERE seq = ?", (victim[0],))
            self._db.commit()
            self._count_drop(f"dropped_{Priority(int(victim[1])).name.lower()}", 1)

    def _coarsen_oldest_aggregate(self) -> bool:
        """Merge the oldest run of same-metric aggregate windows into one coarser window.

        This is what "coarsen before dropping" has to mean physically: rewriting one record in
        place frees nothing, so N fine windows become one coarse window of the same metric. The
        count is preserved; only the resolution is lost.
        """
        rows = self._db.execute(
            "SELECT seq, payload, window_seconds, metric, device_time FROM spool "
            "WHERE priority = ? AND metric IS NOT NULL "
            "ORDER BY metric ASC, seq ASC",
            (int(Priority.AGGREGATE),),
        ).fetchall()
        groups: dict[str, list[tuple[Any, ...]]] = {}
        for row in rows:
            groups.setdefault(str(row[3]), []).append(row)
        group = next((g for g in groups.values() if len(g) >= 2), None)
        if group is None:
            return False

        merged = group[:COARSEN_FACTOR]
        payloads = [json.loads(r[1]) for r in merged]
        window = sum(int(r[2] or 0) for r in merged)
        head = merged[0]
        payload: dict[str, Any] = dict(payloads[0])
        payload["value"] = sum(int(p.get("value", 0)) for p in payloads)
        payload["window_seconds"] = window
        payload["coarsened"] = True
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)

        self.ack(int(r[0]) for r in merged[1:])
        self._db.execute(
            "UPDATE spool SET payload = ?, window_seconds = ?, coarsened = 1, size_bytes = ? "
            "WHERE seq = ?",
            (encoded, window, len(encoded.encode()), head[0]),
        )
        self._db.commit()
        self.coarsened_count += len(merged)
        return True

    def _next_seq(self) -> int:
        """Counter, not MAX(seq): draining the spool empty must not restart the sequence."""
        self._db.execute("UPDATE spool_meta SET last_seq = last_seq + 1")
        row = self._db.execute("SELECT last_seq FROM spool_meta").fetchone()
        return int(row[0])

    def _record(self, seq: int) -> SpooledRecord:
        row = self._db.execute("SELECT * FROM spool WHERE seq = ?", (seq,)).fetchone()
        return SpooledRecord(
            seq=int(row[0]),
            boot_id=str(row[1]),
            schema=str(row[2]),
            data_class=DataClass(row[3]),
            priority=Priority(int(row[4])),
            device_time=datetime.fromisoformat(str(row[5])),
            payload=json.loads(row[6]),
            purpose=str(row[7]),
            metric=None if row[8] is None else str(row[8]),
            window_seconds=None if row[9] is None else int(row[9]),
            k_value=None if row[10] is None else int(row[10]),
            coarsened=bool(row[11]),
        )

    def _count_drop(self, reason: str, n: int) -> None:
        self.dropped[reason] = self.dropped.get(reason, 0) + n
