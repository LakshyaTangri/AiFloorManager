"""Contract checks (F08 R5, F12 R1).

The published schemas and the runtime allowlist are two descriptions of the same thing, and they
drift silently unless something compares them. These tests are that something.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from t1.canon import DataClass
from t1.sim.harness import default_bundle

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts" / "t1-t2"
PAYLOAD_SCHEMAS = {
    "rtl.aggregate.v1": CONTRACTS / "aggregate.v1.schema.json",
    "rtl.event.v1": CONTRACTS / "event.v1.schema.json",
    "rtl.health.v1": CONTRACTS / "health.v1.schema.json",
}
AGE_TOKENS = ("age_band", "age_score", "age_estimate", "estimated_age", "age_years")


def _load(path: Path) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(path.read_text())
    return parsed


def _keys(node: object) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.append(str(key))
            found.extend(_keys(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_keys(item))
    return found


@pytest.mark.parametrize("path", sorted(CONTRACTS.glob("*.schema.json")), ids=lambda p: p.name)
def test_no_schema_declares_an_age_field(path: Path) -> None:
    keys = _keys(_load(path))
    assert not [k for k in keys if any(token in k for token in AGE_TOKENS)]


@pytest.mark.parametrize("path", sorted(CONTRACTS.glob("*.schema.json")), ids=lambda p: p.name)
def test_every_schema_is_closed(path: Path) -> None:
    """additionalProperties:false everywhere - an open schema is a hole in the field allowlist."""
    assert _load(path)["additionalProperties"] is False


def test_envelope_contract_permits_no_class_above_c2() -> None:
    allowed = set(_load(CONTRACTS / "envelope.schema.json")["properties"]["data_class"]["enum"])
    assert allowed == {
        DataClass.C0_OPERATIONAL.value,
        DataClass.C1_AGGREGATE.value,
        DataClass.C2_EVENT.value,
    }


@pytest.mark.parametrize(("schema_id", "path"), sorted(PAYLOAD_SCHEMAS.items()))
def test_allowlist_matches_the_published_schema(schema_id: str, path: Path) -> None:
    published = set(_load(path)["properties"])
    allowlisted = set(default_bundle().field_allowlist[schema_id])
    assert allowlisted == published


def test_every_allowlisted_schema_has_a_declared_class() -> None:
    bundle = default_bundle()
    assert set(bundle.field_allowlist) == set(bundle.allowed_schemas)
    for declared in bundle.allowed_schemas.values():
        DataClass(declared)
