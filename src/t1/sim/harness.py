"""Host-side simulation (`t1-sim`).

Runs the whole path a frame takes - synthetic stream, sealed pipeline, tracking, aggregation,
k-anonymity, egress filter, fake bridge - on an ordinary developer machine, with no camera, no
Yocto image and no hardware. It asserts on what emerges *and* on what does not, which is the only
way to test a privacy control.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from t1.canon import DataClass, Profile, TrustLevel
from t1.contracts import AgeBand, Envelope, Frame, SealedDetection
from t1.control.audit_chain import AuditChain
from t1.control.egress_filter import EgressFilter
from t1.control.kanon import Window, apply
from t1.control.policy import PolicyBundle, PolicyStore, sign
from t1.sealed.pipeline import SealedPipeline

DEV_KEY = b"dev-only-not-a-production-key"
MODEL_BUNDLE = "det-age-trunk-2026.08.1"
REDACTION_VERSION = "redact-2026.08.1"


def default_bundle(version: int = 3) -> PolicyBundle:
    return PolicyBundle(
        version=version,
        floors={"footfall": 3, "dwell_time": 20, "corporate_occupancy": 10},
        allowed_schemas={
            "rtl.aggregate.v1": DataClass.C1_AGGREGATE.value,
            "rtl.event.v1": DataClass.C2_EVENT.value,
            "rtl.health.v1": DataClass.C0_OPERATIONAL.value,
            "rtl.trace.v1": DataClass.C3_TRACE.value,
        },
        field_allowlist={
            "rtl.aggregate.v1": (
                "metric",
                "value",
                "window_start",
                "k_suppressed",
                "window_seconds",
                "coarsened",
            ),
            "rtl.event.v1": ("event_code", "zone_id", "severity"),
            "rtl.health.v1": ("cpu_pct", "mem_mb", "minor_suppression_rate", "clock_offset_ms"),
            "rtl.trace.v1": ("trace_id", "zone_path"),
        },
    )


@dataclass
class SimFrameSpec:
    stream_id: str
    ages: tuple[float, ...]
    motion: bool = True
    redaction_fails: bool = False


@dataclass
class SimReport:
    frames: int = 0
    detections: int = 0
    minors_suppressed: int = 0
    adults_tracked: int = 0
    frames_dropped: int = 0
    egress_accepted: int = 0
    egress_rejected: dict[str, int] = field(default_factory=dict)
    chain_ok: bool = False
    chain_records: int = 0

    @property
    def minor_suppression_rate(self) -> float:
        if self.detections == 0:
            return 0.0
        return self.minors_suppressed / self.detections


def _fake_trunk(spec: SimFrameSpec) -> list[SealedDetection]:
    detections = []
    for index, age in enumerate(spec.ages):
        detections.append(
            SealedDetection(
                stream_id=spec.stream_id,
                ts_ms=index,
                bbox=(index * 10, 0, 20, 40),
                confidence=0.9,
                age_band=AgeBand.UNDER_22 if age < 22 else AgeBand.ADULT,
                age_score=age,
            )
        )
    return detections


def _redact(frame: Frame, fails: bool) -> Frame | None:
    if fails:
        return None
    digest = hashlib.sha256(frame.pixels).digest()
    return Frame(stream_id=frame.stream_id, ts_ms=frame.ts_ms, pixels=digest, redacted=True)


@dataclass
class Simulation:
    workdir: Path
    profile: Profile = Profile.L1
    trust_level: TrustLevel = TrustLevel.SOFTWARE_BOUND
    policy_version: int = 3

    def run(self, specs: list[SimFrameSpec]) -> SimReport:
        chain = AuditChain(self.workdir / "audit" / "chain.jsonl")
        store = PolicyStore(key=DEV_KEY, floor_path=self.workdir / "audit" / "policy_floor")
        bundle = default_bundle(self.policy_version)
        store.load(bundle, sign(bundle, DEV_KEY))
        egress = EgressFilter(policy=store, chain=chain)

        report = SimReport()
        current: SimFrameSpec | None = None

        pipeline = SealedPipeline(
            trunk=lambda frame: _fake_trunk(current) if current else [],
            redactor=lambda frame: _redact(frame, current.redaction_fails if current else False),
            model_bundle=MODEL_BUNDLE,
            redaction_version=REDACTION_VERSION,
            motion=lambda frame: current.motion if current else True,
        )

        adults = 0
        for index, spec in enumerate(specs):
            current = spec
            frame = Frame(
                stream_id=spec.stream_id,
                ts_ms=index * 1000,
                pixels=bytes(random.Random(index).getrandbits(8) for _ in range(32)),
            )
            output = pipeline.process(frame)
            report.frames += 1
            if output is None:
                report.frames_dropped += 1
                continue
            adults += len(output.detections)

        report.detections = pipeline.counters.detections_total
        report.minors_suppressed = pipeline.counters.minor_suppressed_n
        report.adults_tracked = adults

        now = datetime.now(timezone.utc).isoformat()
        result = apply(Window("footfall", now, adults, adults), bundle.floor_for("footfall"))
        envelopes = [
            Envelope(
                device_id="sim-device",
                boot_id="sim-boot",
                seq=1,
                device_time=now,
                schema="rtl.aggregate.v1",
                data_class=DataClass.C1_AGGREGATE,
                purpose="operations",
                trust_level=self.trust_level,
                payload={
                    "metric": result.metric,
                    "value": result.value if result.value is not None else 0,
                    "window_start": result.window_start,
                    "k_suppressed": result.k_suppressed,
                },
                policy_version=str(bundle.version),
                age_gate_ver=MODEL_BUNDLE,
                metric="footfall",
                k_value=adults,
            ),
            Envelope(
                device_id="sim-device",
                boot_id="sim-boot",
                seq=2,
                device_time=now,
                schema="rtl.health.v1",
                data_class=DataClass.C0_OPERATIONAL,
                purpose="operations",
                trust_level=self.trust_level,
                payload={
                    "cpu_pct": 41,
                    "mem_mb": 3120,
                    "minor_suppression_rate": report.minor_suppression_rate,
                    "clock_offset_ms": 0,
                },
                policy_version=str(bundle.version),
            ),
        ]
        for env in envelopes:
            verdict = egress.evaluate(env)
            if verdict.accepted:
                report.egress_accepted += 1

        report.egress_rejected = egress.reject_rate()
        verification = chain.verify()
        report.chain_ok = verification.ok
        report.chain_records = verification.records
        return report
