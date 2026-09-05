"""`t1-preflight` - host or site qualification at the counter (F01).

Prints the profile the FE acts on, and exits non-zero on refusal so the commissioning gate (F21)
can consume the exit status directly. The signing key is a development key here for the same reason
the policy bundle uses one: the verification shape is what is under test on the host.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from t1.canon import Profile
from t1.platform.probe import SiteObservation, probe_host
from t1.platform.qualification import Result, qualify_host, qualify_site

DEV_KEY = b"dev-preflight-key"


def _run_host(args: argparse.Namespace) -> tuple[dict[str, object], Result]:
    started = time.monotonic()
    observation = probe_host(
        Path(args.sysroot),
        t1_media_mb=args.t1_media_mb,
        internal_os_last_boot_days=args.internal_os_last_boot_days,
    )
    profile = qualify_host(observation, elapsed_s=time.monotonic() - started)
    payload = profile.to_dict()
    payload["signature"] = profile.sign(DEV_KEY)
    return payload, profile.result


def _run_site(args: argparse.Namespace) -> tuple[dict[str, object], Result]:
    started = time.monotonic()
    observation = SiteObservation(
        power_stable=args.power_stable,
        network_reachable=args.network_reachable,
        cameras_reachable=tuple(args.camera_reachable),
        cameras_unreachable=tuple(args.camera_unreachable),
        mounting_suitable=args.mounting_suitable,
    )
    profile = qualify_site(
        observation, profile=Profile(args.profile), elapsed_s=time.monotonic() - started
    )
    payload = profile.to_dict()
    payload["signature"] = profile.sign(DEV_KEY)
    return payload, profile.result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="t1-preflight")
    parser.add_argument("--profile", choices=[p.value for p in Profile], default=Profile.L1.value)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sysroot", default="/")
    parser.add_argument("--t1-media-mb", type=int, default=0)
    parser.add_argument("--internal-os-last-boot-days", type=float, default=None)
    parser.add_argument("--power-stable", action="store_true")
    parser.add_argument("--network-reachable", action="store_true")
    parser.add_argument("--mounting-suitable", action="store_true")
    parser.add_argument("--camera-reachable", action="append", default=[])
    parser.add_argument("--camera-unreachable", action="append", default=[])
    args = parser.parse_args(argv)

    is_l1 = args.profile == Profile.L1.value
    payload, result = _run_host(args) if is_l1 else _run_site(args)

    if args.json:
        print(json.dumps(payload))
    else:
        print(f"t1-preflight: {payload['profile']} {payload['result']}")
        remedies = payload["remedies"]
        assert isinstance(remedies, list)
        for remedy in remedies:
            mark = "FAIL" if remedy["hard"] else "note"
            print(f"  {mark}  {remedy['finding']}  {remedy['remedy']}")

    return 0 if result is Result.PASS else 1


if __name__ == "__main__":
    sys.exit(main())
