"""The bridge: the only component permitted to speak to T2 (SPEC §15, F12, F14).

Three properties are structural rather than configured:

    Outbound only. There is no bind, listen or accept anywhere in this module, and
    `assert_outbound_only` refuses a transport that offers one. "No inbound firewall rule, ever"
    is only true if the code cannot accept a connection even when told to.
    Everything goes through the egress filter first. `publish` cannot be called with an envelope
    that has not been judged, because judging it is the first thing it does.
    Backfill is a different endpoint from the live path. A device that spent seven days offline
    must not delay today's events while it catches up, so the backlog leaves over HTTPS ingest
    while MQTT keeps carrying live traffic.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol
from urllib.parse import urlparse

from t1.canon import TrustLevel
from t1.contracts import Envelope
from t1.control.egress_filter import EgressFilter, Verdict
from t1.control.spool import ClockStamp, Spool, SpooledRecord

MQTT_ENDPOINT = "mqtts://iot.pulsemanager.ai:443"
INGEST_ENDPOINT = "https://ingest.pulsemanager.ai:443"
ALLOWED_SCHEMES = ("mqtts", "https")
# TLS on 443 says nothing about *who* answers. The host allowlist is the part that stops a
# rewritten endpoint from pointing the whole fleet's telemetry at someone else's collector.
ALLOWED_HOSTS = ("iot.pulsemanager.ai", "ingest.pulsemanager.ai")
REQUIRED_PORT = 443
INBOUND_METHODS = ("bind", "listen", "accept", "serve_forever")

# F14 R3: backfill is rate-limited in both dimensions - records per batch and batches per minute -
# so a fleet reconnecting after a regional outage cannot turn into a thundering herd on ingest.
BACKFILL_BATCH = 100
BACKFILL_MIN_INTERVAL_S = 5.0


class BridgeRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Transport(Protocol):
    def send(self, endpoint: str, topic: str, body: bytes) -> None: ...


def assert_outbound_only(transport: object) -> None:
    for name in INBOUND_METHODS:
        if hasattr(transport, name):
            raise BridgeRefused("inbound_capability_present")


def assert_endpoint_allowed(endpoint: str, allowed_hosts: tuple[str, ...] = ALLOWED_HOSTS) -> None:
    parsed = urlparse(endpoint)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise BridgeRefused("scheme_forbidden")
    if parsed.port != REQUIRED_PORT:
        raise BridgeRefused("port_forbidden")
    if parsed.hostname not in allowed_hosts:
        raise BridgeRefused("host_not_allowed")


@dataclass(frozen=True)
class SendResult:
    envelope: Envelope
    verdict: Verdict
    endpoint: str | None


@dataclass
class Bridge:
    device_id: str
    trust_level: TrustLevel
    egress: EgressFilter
    transport: Transport
    mqtt_endpoint: str = MQTT_ENDPOINT
    ingest_endpoint: str = INGEST_ENDPOINT
    allowed_hosts: tuple[str, ...] = ALLOWED_HOSTS
    min_backfill_interval_s: float = BACKFILL_MIN_INTERVAL_S
    sent: list[tuple[str, Envelope]] = field(default_factory=list)
    last_backfill_at: datetime | None = None

    accepts_inbound = False

    def __post_init__(self) -> None:
        assert_outbound_only(self.transport)
        assert_endpoint_allowed(self.mqtt_endpoint, self.allowed_hosts)
        assert_endpoint_allowed(self.ingest_endpoint, self.allowed_hosts)

    def publish(self, env: Envelope, topic: str = "t1/telemetry") -> SendResult:
        return self._send(env, self.mqtt_endpoint, topic)

    def backfill(
        self,
        spool: Spool,
        stamp: ClockStamp,
        limit: int = BACKFILL_BATCH,
        topic: str = "t1/backfill",
        now: datetime | None = None,
    ) -> list[SendResult]:
        """Drain in sequence order, stamped rather than re-dated, acked only when accepted.

        Order is the reason this loop stops at the first transport failure. Skipping ahead would
        deliver seq 91 before seq 90 arrives on the retry, and T2 reconstructs the outage from the
        sequence. A record the filter *refuses* is a different case: no retry will ever change that
        verdict, so it is discarded under a named reason rather than blocking the queue forever.
        """
        at = now or datetime.now(timezone.utc)
        if self.last_backfill_at is not None:
            earliest = self.last_backfill_at + timedelta(seconds=self.min_backfill_interval_s)
            if at < earliest:
                raise BridgeRefused("backfill_rate_limited")
        self.last_backfill_at = at

        results: list[SendResult] = []
        acked: list[int] = []
        undeliverable: list[int] = []
        try:
            for record in spool.drain(limit):
                result = self._send(self.envelope_for(record, stamp), self.ingest_endpoint, topic)
                results.append(result)
                if result.verdict.accepted:
                    acked.append(record.seq)
                else:
                    undeliverable.append(record.seq)
        finally:
            spool.ack(acked)
            spool.discard(undeliverable, "backfill_refused")
        return results

    def envelope_for(self, record: SpooledRecord, stamp: ClockStamp) -> Envelope:
        return Envelope(
            device_id=self.device_id,
            boot_id=record.boot_id,
            seq=record.seq,
            # Original device_time, never rewritten - the offset rides alongside it (F14 R6).
            device_time=record.device_time.isoformat(),
            schema=record.schema,
            data_class=record.data_class,
            purpose=record.purpose,
            trust_level=self.trust_level,
            payload=dict(record.payload),
            lawful_basis=record.lawful_basis,
            basis_ref=record.basis_ref,
            retention_until=record.retention_until,
            metric=record.metric,
            k_value=record.k_value,
            policy_version=self._policy_version(),
            clock_offset_ms=stamp.clock_offset_ms,
            time_uncertain=stamp.time_uncertain,
            backfill=True,
        )

    def _send(self, env: Envelope, endpoint: str, topic: str) -> SendResult:
        verdict = self.egress.evaluate(env)
        if verdict.rejected:
            return SendResult(env, verdict, None)
        # The whole envelope goes on the wire: T2 needs the identity, sequence, class, basis and
        # backfill marker to judge the payload, and a bare payload is unattributable.
        body = json.dumps(asdict(env), separators=(",", ":"), sort_keys=True, default=str)
        self.transport.send(endpoint, topic, body.encode())
        self.sent.append((endpoint, env))
        return SendResult(env, verdict, endpoint)

    def _policy_version(self) -> str | None:
        bundle = self.egress.policy.active
        return None if bundle is None else str(bundle.version)
