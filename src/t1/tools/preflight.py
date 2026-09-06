"""`t1-preflight` - host or site qualification at the counter (F01).

Prints the profile the FE acts on, and exits non-zero on refusal so the commissioning gate (F21)
can consume the exit status directly.

Signing is optional and never falls back to a key that ships with the source: a signature anyone
can compute is not evidence of anything, and a profile that claims to be signed when it is not is
worse than an unsigned one. Without `--key-file` the payload carries `"signature": null` and
commissioning can refuse it on that basis.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Protocol

from t1.canon import Profile
from t1.platform.probe import SiteObservation, SleepPolicy, probe_host
from t1.platform.qualification import Result, qualify_host, qualify_site

SLEEP_CHOICES = [policy.value for policy in SleepPolicy]


class SignedProfile(Protocol):
    @property
    def result(self) -> Result: ...

    def to_dict(self) -> dict[str, Any]: ...

    def sign(self, key: bytes) -> str: ...


def _run_host(args: argparse.Namespace) -> SignedProfile:
    started = time.monotonic()
    observation = probe_host(
        Path(args.sysroot),
        t1_media_mb=args.t1_media_mb,
        t1_media_link_mbps=args.t1_media_link_mbps,
        sleep_policy=SleepPolicy(args.sleep_policy) if args.sleep_policy else None,
        internal_os_last_boot_days=args.internal_os_last_boot_days,
    )
    return qualify_host(observation, elapsed_s=time.monotonic() - started)


def _run_site(args: argparse.Namespace) -> SignedProfile:
    started = time.monotonic()
    observation = SiteObservation(
        power_stable=args.power_stable,
        network_reachable=args.network_reachable,
        cameras_expected=tuple(args.camera),
        cameras_reachable=tuple(args.camera_reachable),
        mounting_suitable=args.mounting_suitable,
    )
    return qualify_site(
        observation, profile=Profile(args.profile), elapsed_s=time.monotonic() - started
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="t1-preflight")
    parser.add_argument("--profile", choices=[p.value for p in Profile], default=Profile.L1.value)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--key-file", help="profile signing key file; the profile is unsigned without one"
    )
    parser.add_argument("--sysroot", default="/")
    parser.add_argument(
        "--t1-media-mb",
        type=int,
        help="capacity of the T1 device in MB (L1); omitted means unmeasured, which is refused",
    )
    parser.add_argument(
        "--t1-media-link-mbps",
        type=float,
        default=None,
        help="negotiated link speed of the port the T1 device is attached to",
    )
    parser.add_argument(
        "--sleep-policy",
        choices=SLEEP_CHOICES,
        default=None,
        help="FE-observed BIOS sleep setting; without it a running system can only say unverified",
    )
    parser.add_argument("--internal-os-last-boot-days", type=float, default=None)
    parser.add_argument("--power-stable", action="store_true")
    parser.add_argument("--network-reachable", action="store_true")
    parser.add_argument("--mounting-suitable", action="store_true")
    parser.add_argument(
        "--camera",
        action="append",
        default=[],
        help="a stream the site survey expected (L2/L3); no cameras means the survey did not run",
    )
    parser.add_argument("--camera-reachable", action="append", default=[])
    args = parser.parse_args(argv)

    is_l1 = args.profile == Profile.L1.value
    if is_l1 and args.t1_media_mb is None:
        parser.error("--t1-media-mb is required for RTL-L1: the T1 device capacity is qualified")

    profile = _run_host(args) if is_l1 else _run_site(args)
    payload = profile.to_dict()
    payload["signature"] = profile.sign(Path(args.key_file).read_bytes()) if args.key_file else None

    if args.json:
        print(json.dumps(payload))
    else:
        print(f"t1-preflight: {payload['profile']} {payload['result']}")
        remedies = payload["remedies"]
        assert isinstance(remedies, list)
        for remedy in remedies:
            mark = "FAIL" if remedy["hard"] else "note"
            print(f"  {mark}  {remedy['finding']}  {remedy['remedy']}")

    return 0 if profile.result is Result.PASS else 1


if __name__ == "__main__":
    sys.exit(main())
