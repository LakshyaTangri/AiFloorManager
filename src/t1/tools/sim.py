"""`t1-sim` - run the full path on a developer machine (LIFECYCLE stage 2 rule 2).

Default scenario mixes adults, under-22s, a no-motion frame and a redaction failure, so a single
run exercises both the accept path and the three refusal paths that matter most.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from t1.sim.harness import SimFrameSpec, Simulation


def default_scenario() -> list[SimFrameSpec]:
    return [
        SimFrameSpec("cam-1", (34.0, 41.0)),
        SimFrameSpec("cam-1", (17.0, 29.0)),
        SimFrameSpec("cam-1", (19.0, 15.0)),
        SimFrameSpec("cam-1", (), motion=False),
        SimFrameSpec("cam-1", (45.0,), redaction_fails=True),
        SimFrameSpec("cam-1", (52.0, 61.0, 23.0)),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="t1-sim")
    parser.add_argument("--workdir", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    with TemporaryDirectory() as tmp:
        workdir = args.workdir or Path(tmp)
        report = Simulation(workdir=workdir).run(default_scenario())

    payload = {
        "frames": report.frames,
        "detections": report.detections,
        "minors_suppressed": report.minors_suppressed,
        "minor_suppression_rate": round(report.minor_suppression_rate, 4),
        "adults_tracked": report.adults_tracked,
        "frames_dropped": report.frames_dropped,
        "egress_accepted": report.egress_accepted,
        "egress_rejected": report.egress_rejected,
        "chain_ok": report.chain_ok,
        "chain_records": report.chain_records,
    }
    if args.json:
        print(json.dumps(payload))
    else:
        for key, value in payload.items():
            print(f"{key:<24}{value}")
    return 0 if report.chain_ok else 1


if __name__ == "__main__":
    sys.exit(main())
