"""`t1-bench` - hardware-in-the-loop runner (LIFECYCLE 3.3).

Deliberately a stub with a real interface. There is no reference rig attached to a development
machine, and the important behaviour is that its absence is reported as *unproven*, never as a
pass: every bench-only claim in the spec - steady-state RSS on 4 GB, decode throughput, boot
matrix, thermal soak, crypto-erase read-back, RTC-less clock behaviour - stays unproven until this
runs against real hardware.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass

RIG_ENV = "T1_BENCH_RIG"


@dataclass(frozen=True)
class BenchTest:
    name: str
    verifies: str
    blocks: str


BENCH_MATRIX: tuple[BenchTest, ...] = (
    BenchTest("boot_matrix", "Real UEFI variants, Secure Boot on/off, USB boot order", "F03"),
    BenchTest("thermal_soak", "8 h sustained load, throttle detection", "F20"),
    BenchTest("decode_capacity", "Streams actually sustained per profile", "F07"),
    BenchTest("memory_ceiling", "Steady-state RSS against the 3280 MB v3.1 ceiling", "D-001"),
    BenchTest("rollback", "Forced update failure to automatic slot rollback", "F15"),
    BenchTest("disk_pull", "Hot disconnect behaviour, chain integrity on reconnect", "F13"),
    BenchTest(
        "crypto_erase", "Forensic read-back after decommission; audit partition exported", "F16"
    ),
    BenchTest("clock_skew", "RTC-less boot, offline run, backfill offset correctness", "F14"),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="t1-bench")
    parser.add_argument("--list", action="store_true", help="show the bench matrix")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    rig = os.environ.get(RIG_ENV)
    matrix = [{"name": t.name, "verifies": t.verifies, "blocks": t.blocks} for t in BENCH_MATRIX]

    if args.list or rig is None:
        status = "unproven_no_rig" if rig is None else "listed"
        if args.json:
            print(json.dumps({"rig": rig, "status": status, "matrix": matrix}))
        else:
            print(f"t1-bench: no rig attached (set {RIG_ENV}). These remain UNPROVEN:\n")
            for test in BENCH_MATRIX:
                print(f"  {test.name:<18}{test.verifies}   [{test.blocks}]")
            print("\nNot a failure. Bench results cannot be simulated, so they are not claimed.")
        return 0

    print(f"t1-bench: rig {rig} attached, but no rig driver is implemented yet", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
