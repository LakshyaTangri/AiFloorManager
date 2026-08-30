"""Consent / zone service (F10, C4, C5, C9).

Two halves with different profile scope: the prohibited-zone check runs everywhere, including L1,
because a mis-mapped camera is the cheapest way to create an incident. Recognition consent is
L2/L3 only, since L1 cannot run recognition at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from t1.canon import VALID_LAWFUL_BASIS


class ZoneRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Zone:
    zone_id: str
    prohibited: bool
    lawful_basis: str | None = None

    def validate(self) -> None:
        if self.prohibited:
            return
        if self.lawful_basis is None or self.lawful_basis not in VALID_LAWFUL_BASIS:
            raise ZoneRefused("zone_basis_missing")


@dataclass(frozen=True)
class ConsentRecord:
    subject_id: str
    basis: str
    granted_at: datetime
    withdrawn_at: datetime | None = None

    def live_at(self, when: datetime) -> bool:
        if self.withdrawn_at is not None and when >= self.withdrawn_at:
            return False
        return when >= self.granted_at


@dataclass
class ZoneService:
    zones: dict[str, Zone] = field(default_factory=dict)
    stream_zone: dict[str, str] = field(default_factory=dict)
    consents: dict[str, ConsentRecord] = field(default_factory=dict)
    refusals: list[tuple[str, str]] = field(default_factory=list)

    def register_zone(self, zone: Zone) -> None:
        zone.validate()
        self.zones[zone.zone_id] = zone

    def map_stream(self, stream_id: str, zone_id: str) -> None:
        zone = self.zones.get(zone_id)
        if zone is None:
            raise ZoneRefused("zone_unknown")
        if zone.prohibited:
            self.refusals.append((stream_id, "prohibited_zone"))
            raise ZoneRefused("prohibited_zone")
        self.stream_zone[stream_id] = zone_id

    def allows(self, stream_id: str) -> bool:
        zone_id = self.stream_zone.get(stream_id)
        if zone_id is None:
            return False
        return not self.zones[zone_id].prohibited

    def basis_for(self, stream_id: str) -> str | None:
        zone_id = self.stream_zone.get(stream_id)
        if zone_id is None:
            return None
        return self.zones[zone_id].lawful_basis

    def may_match(self, subject_id: str, when: datetime) -> bool:
        """Absence of a live record disables matching for that person. Absence is not consent."""
        record = self.consents.get(subject_id)
        return record is not None and record.live_at(when)

    def withdraw(self, subject_id: str, when: datetime) -> datetime:
        record = self.consents.get(subject_id)
        if record is None:
            raise ZoneRefused("subject_unknown")
        self.consents[subject_id] = ConsentRecord(
            subject_id=record.subject_id,
            basis=record.basis,
            granted_at=record.granted_at,
            withdrawn_at=when,
        )
        return when + timedelta(hours=24)  # deletion deadline (F10 R4)
