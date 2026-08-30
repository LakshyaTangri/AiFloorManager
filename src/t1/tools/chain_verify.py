"""`chain-verify` - audit chain verification (F13 R3).

The same code path runs in tests, in CI and behind the local UI's audit viewer. A DPO who exports a
range and verifies it off-box must get the identical answer the device gives.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from t1.control.audit_chain import AuditChain


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chain-verify")
    parser.add_argument("chain", type=Path, help="path to chain.jsonl")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--export-since", type=int, default=None, metavar="SEQ")
    args = parser.parse_args(argv)

    if not args.chain.exists():
        print(f"chain-verify: no chain at {args.chain}", file=sys.stderr)
        return 2

    chain = AuditChain(args.chain)
    result = chain.verify()

    if args.export_since is not None:
        for record in chain.export(args.export_since):
            print(record.to_json())
        return 0 if result.ok else 1

    if args.json:
        print(
            json.dumps(
                {
                    "ok": result.ok,
                    "records": result.records,
                    "broken_at": result.broken_at,
                    "reason": result.reason,
                }
            )
        )
    elif result.ok:
        print(f"chain-verify: OK, {result.records} records")
    else:
        print(f"chain-verify: FAIL at seq {result.broken_at} ({result.reason})")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
