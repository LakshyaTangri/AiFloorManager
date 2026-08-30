"""`budget-report` - per-container RSS against declared ceiling (LIFECYCLE stage 2/5).

On a developer host this reports *declared* ceilings and whatever RSS the simulator produced. That
is a regression guard, not evidence: no datasheet number is published until `t1-bench` measures it
on the reference rig. The tool says so in its own output so that a screenshot of it cannot be
mistaken for a bench result.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BUDGETS = Path("ops/budgets.json")


@dataclass(frozen=True)
class Line:
    component: str
    ceiling_mb: int
    measured_mb: float | None

    @property
    def over(self) -> bool:
        return self.measured_mb is not None and self.measured_mb > self.ceiling_mb


def load(path: Path) -> tuple[str, int, int, list[Line]]:
    raw = json.loads(path.read_text())
    profile = str(raw["profile"])
    total_ceiling = int(raw["total_ceiling_mb"])
    usable = int(raw["assumed_usable_mb"])
    lines = [
        Line(str(c["component"]), int(c["ceiling_mb"]), c.get("measured_mb"))
        for c in raw["components"]
    ]
    return profile, total_ceiling, usable, lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="budget-report")
    parser.add_argument("--budgets", type=Path, default=DEFAULT_BUDGETS)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    profile, total_ceiling, usable, lines = load(args.budgets)
    declared = sum(line.ceiling_mb for line in lines)
    breaches = [line for line in lines if line.over]
    ok = declared <= total_ceiling and not breaches

    if args.json:
        print(
            json.dumps(
                {
                    "profile": profile,
                    "declared_mb": declared,
                    "total_ceiling_mb": total_ceiling,
                    "assumed_usable_mb": usable,
                    "headroom_mb": usable - declared,
                    "breaches": [line.component for line in breaches],
                    "ok": ok,
                    "evidence": "declared-only; bench required",
                }
            )
        )
        return 0 if ok else 1

    print(f"budget-report  profile={profile}")
    print(f"{'component':<52}{'ceiling':>9}{'measured':>10}")
    for line in lines:
        measured = "-" if line.measured_mb is None else f"{line.measured_mb:.0f}"
        flag = "  OVER" if line.over else ""
        print(f"{line.component:<52}{line.ceiling_mb:>9}{measured:>10}{flag}")
    print(f"{'declared total':<52}{declared:>9}")
    print(f"{'ceiling':<52}{total_ceiling:>9}")
    print(f"{'assumed usable':<52}{usable:>9}")
    print(f"{'headroom':<52}{usable - declared:>9}")
    print()
    print("declared ceilings only. Not a bench measurement; publish nothing from this output.")
    if not ok:
        print("FAIL: declared total exceeds the ceiling, or a component is over budget")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
