"""`sealed-probe` - structural assertions about the redaction boundary (D-006).

Four things, all of which must hold before a build is allowed out:

    1. no boundary-crossing type can carry age information
    2. the sealed process refuses to start with a network namespace or a writable path
    3. an egress attempt from sealed-side code raises rather than connecting
    4. a sealed-process crash stops the stream instead of falling back to an unsealed path
"""

from __future__ import annotations

import argparse
import json
import sys

from t1.contracts import AgeBand, Frame, SealedDetection
from t1.sealed.guard import (
    BoundaryViolation,
    SealedEgressError,
    SealedEnvironment,
    assert_boundary_clean,
    attempt_egress,
)
from t1.sealed.pipeline import SealedPipeline, SealedPipelineDown


def _boundary_clean() -> str | None:
    try:
        assert_boundary_clean()
    except BoundaryViolation as exc:
        return str(exc)
    return None


def _refuses_network() -> str | None:
    try:
        SealedEnvironment(network_namespace=True).assert_sealed()
    except SealedEgressError:
        return None
    return "sealed process started with a network namespace"


def _refuses_writable_path() -> str | None:
    try:
        SealedEnvironment(writable_persistent_paths=("/var/lib/pixels",)).assert_sealed()
    except SealedEgressError:
        return None
    return "sealed process started with a writable persistent path"


def _refuses_egress() -> str | None:
    try:
        attempt_egress("mqtt://bridge:8883")
    except SealedEgressError:
        return None
    return "sealed-side egress attempt was not refused"


def _crash_fails_closed() -> str | None:
    pipeline = SealedPipeline(
        trunk=lambda _frame: [SealedDetection("s1", 0, (0, 0, 1, 1), 0.9, AgeBand.ADULT, 40.0)],
        redactor=lambda frame: Frame(frame.stream_id, frame.ts_ms, b"x", redacted=True),
        model_bundle="probe",
        redaction_version="probe",
    )
    pipeline.crash()
    try:
        pipeline.process(Frame("s1", 0, b"pixels"))
    except SealedPipelineDown:
        return None
    return "a crashed sealed process kept producing output"


CHECKS = {
    "boundary_types_age_free": _boundary_clean,
    "refuses_network_namespace": _refuses_network,
    "refuses_writable_path": _refuses_writable_path,
    "refuses_egress_attempt": _refuses_egress,
    "crash_fails_closed": _crash_fails_closed,
}


def run() -> dict[str, str | None]:
    return {name: check() for name, check in CHECKS.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sealed-probe")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    results = run()
    failures = {name: reason for name, reason in results.items() if reason}
    if args.json:
        print(json.dumps({"checks": results, "ok": not failures}))
    else:
        for name, reason in results.items():
            print(f"  {'FAIL' if reason else 'pass'}  {name}{f'  {reason}' if reason else ''}")
        print(f"sealed-probe: {len(results) - len(failures)}/{len(results)} passed")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
