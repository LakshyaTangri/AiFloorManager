"""egress-fuzz suite (LIFECYCLE 3.4). Every case must be refused, and refused by name."""

from __future__ import annotations

import pytest

from t1.control.egress_filter import EgressFilter
from t1.tools.egress_fuzz import Case, hostile_cases
from t1.tools.egress_fuzz import run as fuzz_run


@pytest.mark.parametrize("case", hostile_cases(), ids=lambda c: c.name)
def test_hostile_payload_is_refused_by_name(case: Case, egress: EgressFilter) -> None:
    verdict = egress.evaluate(case.envelope)
    assert verdict.rejected, f"{case.name} was accepted"
    assert verdict.reason == case.expected_reason


def test_no_hostile_payload_reaches_the_chain(egress: EgressFilter) -> None:
    for case in hostile_cases():
        egress.evaluate(case.envelope)
    assert egress.accepted_count == 0
    assert egress.chain.verify().records == 0


def test_cli_entrypoint_passes() -> None:
    total, failures = fuzz_run()
    assert total > 0
    assert failures == []
