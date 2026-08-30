"""Independent retention enforcer (F16, C10).

Independent means what it says: the enforcer runs whether or not the application is up, so a
crashed analytics container cannot extend a retention period by being unavailable to delete.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from t1.canon import C3_RETENTION_DAYS, DataClass, Profile
from t1.control.audit_chain import AuditChain


@dataclass
class StoredRecord:
    record_id: str
    data_class: DataClass
    created_at: datetime
    retention_until: datetime


@dataclass
class RetentionEnforcer:
    profile: Profile
    chain: AuditChain
    store: dict[str, StoredRecord] = field(default_factory=dict)

    def admit(self, record: StoredRecord) -> None:
        """L1 never persists C3: the store refuses it rather than expiring it quickly."""
        if record.data_class is DataClass.C3_TRACE and C3_RETENTION_DAYS[self.profile] == 0:
            raise ValueError("c3_persistence_forbidden")
        ceiling = self._ceiling(record)
        if ceiling is not None and record.retention_until > ceiling:
            record.retention_until = ceiling
        self.store[record.record_id] = record

    def run(self, now: datetime) -> list[str]:
        expired = [r for r in self.store.values() if r.retention_until <= now]
        for record in expired:
            del self.store[record.record_id]
            self.chain.append(
                "deletion_receipt",
                {"record_id": record.record_id, "class": record.data_class.value},
                now.isoformat(),
            )
        return [r.record_id for r in expired]

    def _ceiling(self, record: StoredRecord) -> datetime | None:
        if record.data_class is DataClass.C3_TRACE:
            return record.created_at + timedelta(days=C3_RETENTION_DAYS[self.profile])
        return None
