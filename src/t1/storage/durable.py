"""Durable record index on the data domain, and retention enforced independently of it (M10, F16).

`t1.control.retention` holds the retention *rules* against an in-memory store. That is enough to
state the policy and not enough to enforce it: F16 R1 requires an enforcer that is not application
code, and its acceptance criterion is a trace deleted "with the application stopped". So the index
lives in SQLite on the data domain and `RetentionService` opens it by path. Nothing hands it a
handle, and a crashed writer therefore cannot extend a retention period by being unavailable.

Two design points that are not obvious from the schema:

    Ceilings are applied at admission, not at sweep. A record whose caller asked for a year is
    clamped to the profile ceiling when it is written, so the row on disk is already the truth even
    if the enforcer never runs again.
    Deletion is two-phase. The receipt (F16 R2) is written *before* the row goes, with the row
    marked `pending_delete`, because a crash that loses a receipt breaks the audit requirement
    whereas a crash between the two leaves a marked row the next sweep finishes without emitting a
    second receipt.

The index records where a payload lives and when it dies; it is not the payload. Blob deletion is
delegated to an injected `unlink` so the same rules apply to clips on disk, and the caller supplies
it — this module does not decide the filesystem.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

from t1.canon import C3_RETENTION_DAYS, DataClass, Profile
from t1.control.audit_chain import AuditChain
from t1.storage.domains import DOMAIN_FOR_CLASS, Domain, PlacementRefusal, check_placement


class AdmitRefusal(str, Enum):
    BASIS_EXPIRY_MISSING = "basis_expiry_missing"
    CLIP_POLICY_ABSENT = "clip_policy_absent"
    RETENTION_IN_THE_PAST = "retention_in_the_past"


Refusal = AdmitRefusal | PlacementRefusal


@dataclass(frozen=True)
class ClipPolicy:
    """C5 retention is set by clip policy, not by a canon constant (F16 R1).

    There is no default: a site that has not stated how long clips live may not keep clips, which
    is why `DurableStore.clip_policy` is optional and its absence is a refusal rather than a
    fallback to some implementer's guess.
    """

    max_age_days: int
    purpose: str


@dataclass(frozen=True)
class RecordRef:
    record_id: str
    data_class: DataClass
    created_at: datetime
    retention_until: datetime
    basis_ref: str | None = None
    blob_path: str | None = None

    @property
    def domain(self) -> Domain:
        return DOMAIN_FOR_CLASS[self.data_class]


class DurableStore:
    """The index. Opening it twice over the same path is expected, not a mistake."""

    def __init__(
        self,
        path: Path,
        profile: Profile,
        clip_policy: ClipPolicy | None = None,
    ) -> None:
        self.profile = profile
        self.clip_policy = clip_policy
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS retained (
                record_id TEXT PRIMARY KEY,
                data_class TEXT NOT NULL,
                domain TEXT NOT NULL,
                created_at TEXT NOT NULL,
                retention_until TEXT NOT NULL,
                basis_ref TEXT,
                blob_path TEXT,
                pending_delete INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def admit(self, record: RecordRef) -> Refusal | None:
        placement = check_placement(record.data_class, record.domain, self.profile)
        if placement is not None:
            return placement
        if record.data_class is DataClass.C4_IDENTIFIED and record.basis_ref is None:
            # C4 dies with the basis that justified it; with no basis reference there is nothing to
            # expire against and the record would outlive its own justification.
            return AdmitRefusal.BASIS_EXPIRY_MISSING
        if record.data_class is DataClass.C5_MEDIA and self.clip_policy is None:
            return AdmitRefusal.CLIP_POLICY_ABSENT
        if record.retention_until <= record.created_at:
            return AdmitRefusal.RETENTION_IN_THE_PAST

        until = self._clamp(record)
        self._db.execute(
            "INSERT OR REPLACE INTO retained VALUES (?,?,?,?,?,?,?,0)",
            (
                record.record_id,
                record.data_class.value,
                record.domain.value,
                record.created_at.isoformat(),
                until.isoformat(),
                record.basis_ref,
                record.blob_path,
            ),
        )
        self._db.commit()
        return None

    def get(self, record_id: str) -> RecordRef | None:
        row = self._db.execute(
            "SELECT record_id, data_class, created_at, retention_until, basis_ref, blob_path "
            "FROM retained WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            return None
        return RecordRef(
            record_id=str(row[0]),
            data_class=DataClass(row[1]),
            created_at=datetime.fromisoformat(str(row[2])),
            retention_until=datetime.fromisoformat(str(row[3])),
            basis_ref=None if row[4] is None else str(row[4]),
            blob_path=None if row[5] is None else str(row[5]),
        )

    def count(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM retained").fetchone()[0])

    def _clamp(self, record: RecordRef) -> datetime:
        """Ceilings by class: C3 by profile, C5 by clip policy, C4 by the basis it carries."""
        if record.data_class is DataClass.C3_TRACE:
            return min(
                record.retention_until,
                record.created_at + timedelta(days=C3_RETENTION_DAYS[self.profile]),
            )
        if record.data_class is DataClass.C5_MEDIA and self.clip_policy is not None:
            return min(
                record.retention_until,
                record.created_at + timedelta(days=self.clip_policy.max_age_days),
            )
        return record.retention_until


@dataclass
class RetentionService:
    """The enforcer. It takes a path and an audit chain — never the writer's objects."""

    path: Path
    chain: AuditChain
    unlink: Callable[[str], None] | None = None
    receipts: list[str] = field(default_factory=list)

    def sweep(self, now: datetime) -> list[str]:
        db = sqlite3.connect(self.path)
        try:
            deleted = self._finish_pending(db)
            rows = db.execute(
                "SELECT record_id FROM retained WHERE pending_delete = 0 AND retention_until <= ?",
                (now.isoformat(),),
            ).fetchall()
            for row in rows:
                deleted.append(self._delete(db, str(row[0]), now))
        finally:
            db.close()
        return deleted

    def _finish_pending(self, db: sqlite3.Connection) -> list[str]:
        """A marked row already has its receipt; finishing it must not write a second."""
        rows = db.execute("SELECT record_id, blob_path FROM retained WHERE pending_delete = 1")
        finished: list[str] = []
        for row in rows.fetchall():
            record_id = str(row[0])
            self._remove_blob(None if row[1] is None else str(row[1]))
            db.execute("DELETE FROM retained WHERE record_id = ?", (record_id,))
            db.commit()
            finished.append(record_id)
        return finished

    def _delete(self, db: sqlite3.Connection, record_id: str, now: datetime) -> str:
        row = db.execute(
            "SELECT data_class, blob_path FROM retained WHERE record_id = ?", (record_id,)
        ).fetchone()
        db.execute("UPDATE retained SET pending_delete = 1 WHERE record_id = ?", (record_id,))
        db.commit()

        record = self.chain.append(
            "deletion_receipt",
            {"record_id": record_id, "class": str(row[0]), "reason": "retention_expired"},
            now.isoformat(),
        )
        self.receipts.append(record.hash)

        self._remove_blob(None if row[1] is None else str(row[1]))
        db.execute("DELETE FROM retained WHERE record_id = ?", (record_id,))
        db.commit()
        return record_id

    def _remove_blob(self, blob_path: str | None) -> None:
        if blob_path is not None and self.unlink is not None:
            self.unlink(blob_path)
