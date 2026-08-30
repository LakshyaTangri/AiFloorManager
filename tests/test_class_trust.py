"""class-trust and capability-probe suites (F05, F12, C8, C12, D-008)."""

from __future__ import annotations

import pytest

from t1.canon import CLASSES_PERMITTED, PROFILE_TRUST, DataClass, Profile, TrustLevel
from t1.contracts import Envelope
from t1.control.capability import CapabilityGate, CapabilityVector, l1_vector
from t1.control.egress_filter import EgressFilter

from .conftest import NOW_ISO

KEY = b"capability-dev-key"


def _vector(
    profile: Profile = Profile.L1,
    trust_level: TrustLevel = TrustLevel.SOFTWARE_BOUND,
    adapter_cap: int = 3,
    stream_cap: int = 2,
) -> CapabilityVector:
    return CapabilityVector(
        profile=profile,
        trust_level=trust_level,
        adapter_cap=adapter_cap,
        stream_cap=stream_cap,
    )


def _gate(vector: CapabilityVector) -> CapabilityGate:
    return CapabilityGate(vector, KEY, vector.sign(KEY))


def test_profile_trust_ladder() -> None:
    assert PROFILE_TRUST[Profile.L1] is TrustLevel.SOFTWARE_BOUND
    assert PROFILE_TRUST[Profile.L2] is TrustLevel.MODULE_ATTESTED
    assert PROFILE_TRUST[Profile.L3] is TrustLevel.HARDWARE_ATTESTED


@pytest.mark.parametrize(
    "data_class", [DataClass.C3_TRACE, DataClass.C4_IDENTIFIED, DataClass.C5_MEDIA]
)
def test_software_bound_forbids_c3_c4_c5(data_class: DataClass) -> None:
    assert data_class not in CLASSES_PERMITTED[TrustLevel.SOFTWARE_BOUND]


def test_c6_is_permitted_nowhere() -> None:
    for permitted in CLASSES_PERMITTED.values():
        assert DataClass.C6_PROHIBITED not in permitted


def test_entitlement_cannot_override_trust_level(egress: EgressFilter) -> None:
    """An L1 device holding a C3 entitlement still refuses: trust is checked before entitlement."""
    env = Envelope(
        device_id="d",
        boot_id="b",
        seq=1,
        device_time=NOW_ISO,
        schema="rtl.trace.v1",
        data_class=DataClass.C3_TRACE,
        purpose="analytics",
        trust_level=TrustLevel.SOFTWARE_BOUND,
        payload={"trace_id": "t", "zone_path": "a"},
        lawful_basis="legitimate_use.security",
        retention_until="2026-12-31T00:00:00Z",
        policy_version="3",
        entitlements=("c3_traces",),
    )
    assert egress.evaluate(env).reason == "trust_level_forbids_class"


def test_unsigned_capability_vector_is_refused() -> None:
    with pytest.raises(ValueError):
        CapabilityGate(_vector(), KEY, "deadbeef")


def test_adapter_and_stream_caps() -> None:
    gate = _gate(_vector())
    assert gate.accepts({"adapters": ["a", "b", "c"], "streams": ["s1", "s2"]})
    rejections = gate.evaluate({"adapters": ["a", "b", "c", "d"], "streams": ["s1", "s2", "s3"]})
    assert {r.reason for r in rejections} == {"adapter_cap_exceeded", "stream_cap_exceeded"}


def test_every_rejection_is_reported_not_just_the_first() -> None:
    rejections = _gate(_vector()).evaluate(
        {"recognition": True, "p2p": True, "local_vlm": True, "c3_persistence": True}
    )
    assert {r.key for r in rejections} == {"recognition", "p2p", "local_vlm", "c3_persistence"}
    assert {r.reason for r in rejections} == {"trust_level_insufficient"}


def test_entitled_l2_capability_is_named_differently() -> None:
    gate = _gate(_vector(profile=Profile.L2, trust_level=TrustLevel.MODULE_ATTESTED))
    rejections = gate.evaluate({"recognition": True})
    assert [r.reason for r in rejections] == ["capability_not_entitled"]


@pytest.mark.parametrize(
    ("usable_ram_mb", "expected_cap"),
    [(4096, 3), (3481, 3), (3480, 2), (3338, 2), (3337, None), (2048, None)],
)
def test_l1_adapter_cap_is_a_measured_output(usable_ram_mb: int, expected_cap: int | None) -> None:
    vector = l1_vector(usable_ram_mb)
    if expected_cap is None:
        assert vector is None  # host_not_qualified
    else:
        assert vector is not None and vector.adapter_cap == expected_cap
