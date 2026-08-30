"""`egress-fuzz` - hostile payload generator for the filter (LIFECYCLE 3.4).

A pass here is a *refusal*, correctly named and counted. Each case declares the reason it expects,
so a filter that rejects the right payload for the wrong reason fails too - that distinction
matters, because the reason string is what the fleet dashboard aggregates on.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from t1.canon import DataClass, TrustLevel
from t1.contracts import Envelope
from t1.control.audit_chain import AuditChain
from t1.control.egress_filter import EgressFilter
from t1.control.policy import PolicyStore, sign
from t1.sim.harness import DEV_KEY, default_bundle

NOW = datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Case:
    name: str
    envelope: Envelope
    expected_reason: str


def _env(
    schema: str = "rtl.event.v1",
    data_class: DataClass = DataClass.C2_EVENT,
    payload: dict[str, Any] | None = None,
    trust_level: TrustLevel = TrustLevel.SOFTWARE_BOUND,
    **overrides: Any,
) -> Envelope:
    base: dict[str, Any] = {
        "device_id": "fuzz",
        "boot_id": "fuzz-boot",
        "seq": 1,
        "device_time": NOW,
        "schema": schema,
        "data_class": data_class,
        "purpose": "operations",
        "trust_level": trust_level,
        "payload": payload if payload is not None else {"event_code": "queue_breach"},
        "lawful_basis": "notice.public_space",
        "retention_until": "2026-12-31T00:00:00Z",
        "policy_version": "3",
    }
    base.update(overrides)
    return Envelope(**base)


def hostile_cases() -> list[Case]:
    return [
        Case(
            "free_text_in_typed_field",
            _env(payload={"event_code": "a shopper in a red jacket loitered near aisle four"}),
            "free_text_forbidden",
        ),
        Case(
            "oversized_payload",
            _env(payload={"event_code": "x" * 70_000}),
            "free_text_forbidden",
        ),
        Case(
            "base64_media",
            _env(payload={"event_code": "clip", "zone_id": "data:image/png;base64,AAAA"}),
            "media_forbidden",
        ),
        Case(
            "raw_bytes_media",
            _env(payload={"event_code": "clip", "zone_id": "z1", "severity": b"\x89PNG"}),
            "media_forbidden",
        ),
        Case("missing_basis", _env(lawful_basis=None), "basis_missing"),
        Case("invalid_basis", _env(lawful_basis="because_we_want_to"), "basis_invalid"),
        Case("missing_retention", _env(retention_until=None), "retention_missing"),
        Case("forged_policy_version", _env(policy_version="99"), "policy_version_mismatch"),
        Case("unknown_schema", _env(schema="rtl.exfil.v1"), "schema_unknown"),
        Case(
            "class_mismatch",
            _env(schema="rtl.event.v1", data_class=DataClass.C1_AGGREGATE),
            "class_mismatch",
        ),
        Case(
            "undeclared_field",
            _env(payload={"event_code": "queue_breach", "face_crop_ref": "x1"}),
            "field_not_allowed",
        ),
        Case(
            "age_smuggled_into_payload",
            _env(
                schema="rtl.health.v1",
                data_class=DataClass.C0_OPERATIONAL,
                payload={"cpu_pct": 10, "mem_mb": 100, "age_band": "under_22"},
                lawful_basis=None,
                retention_until=None,
            ),
            "field_not_allowed",
        ),
        Case(
            "c3_on_software_bound",
            _env(
                schema="rtl.trace.v1",
                data_class=DataClass.C3_TRACE,
                payload={"trace_id": "t1", "zone_path": "a>b"},
            ),
            "trust_level_forbids_class",
        ),
        Case(
            "c3_on_module_attested_without_entitlement",
            _env(
                schema="rtl.trace.v1",
                data_class=DataClass.C3_TRACE,
                payload={"trace_id": "t1", "zone_path": "a>b"},
                trust_level=TrustLevel.MODULE_ATTESTED,
            ),
            "entitlement_missing",
        ),
        Case(
            "k_below_floor",
            _env(
                schema="rtl.aggregate.v1",
                data_class=DataClass.C1_AGGREGATE,
                payload={
                    "metric": "footfall",
                    "value": 2,
                    "window_start": NOW,
                    "k_suppressed": False,
                },
                metric="footfall",
                k_value=2,
                lawful_basis=None,
                retention_until=None,
            ),
            "k_below_floor",
        ),
        Case(
            "dwell_below_its_own_higher_floor",
            _env(
                schema="rtl.aggregate.v1",
                data_class=DataClass.C1_AGGREGATE,
                payload={
                    "metric": "dwell_time",
                    "value": 5,
                    "window_start": NOW,
                    "k_suppressed": False,
                },
                metric="dwell_time",
                k_value=11,
                lawful_basis=None,
                retention_until=None,
            ),
            "k_below_floor",
        ),
        Case("empty_purpose", _env(purpose=""), "purpose_missing"),
        Case(
            "prohibited_class",
            _env(schema="rtl.event.v1", data_class=DataClass.C6_PROHIBITED),
            "prohibited_class",
        ),
    ]


def run(verbose: bool = False) -> tuple[int, list[str]]:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        chain = AuditChain(root / "chain.jsonl")
        store = PolicyStore(key=DEV_KEY, floor_path=root / "policy_floor")
        bundle = default_bundle()
        store.load(bundle, sign(bundle, DEV_KEY))
        filt = EgressFilter(policy=store, chain=chain)

        failures: list[str] = []
        for case in hostile_cases():
            verdict = filt.evaluate(case.envelope)
            if verdict.accepted:
                failures.append(f"{case.name}: ACCEPTED (expected {case.expected_reason})")
            elif verdict.reason != case.expected_reason:
                failures.append(
                    f"{case.name}: rejected as {verdict.reason}, expected {case.expected_reason}"
                )
            elif verbose:
                print(f"  refused {case.name} -> {verdict.reason}")

        if filt.accepted_count:
            failures.append(f"{filt.accepted_count} hostile payload(s) reached the chain")
        return len(hostile_cases()), failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="egress-fuzz")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    total, failures = run(verbose=args.verbose)
    if args.json:
        print(json.dumps({"cases": total, "failures": failures, "ok": not failures}))
    else:
        print(f"egress-fuzz: {total} hostile cases, {len(failures)} failure(s)")
        for failure in failures:
            print(f"  {failure}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
