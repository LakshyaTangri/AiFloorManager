"""F06: passive by default, three adapters on L1, and no write-capable credential on a readable
disk."""

from __future__ import annotations

from t1.canon import TrustLevel
from t1.devices.discovery import (
    ACTIVE,
    ACTIVE_PROBES_PER_MINUTE,
    PASSIVE,
    REMEDY,
    Adapter,
    Credential,
    Fingerprint,
    Method,
    ProbePlan,
    Refusal,
    Vault,
    match,
    select_adapters,
)

READ_ONLY = Credential("cam1", "viewer", "s3cret", frozenset({"read", "stream"}))
PTZ = Credential("cam2", "operator", "s3cret", frozenset({"read", "ptz"}))


def test_passive_discovery_needs_no_permission_because_it_sends_nothing() -> None:
    plan = ProbePlan(opted_in=False)

    assert all(plan.permits(method, "10.0.0.5") is None for method in PASSIVE)


def test_active_probing_without_opt_in_is_refused() -> None:
    plan = ProbePlan(opted_in=False)

    assert all(
        plan.permits(method, "10.0.0.5") is Refusal.ACTIVE_PROBE_NOT_OPTED_IN for method in ACTIVE
    )


def test_the_do_not_probe_list_outranks_the_opt_in() -> None:
    plan = ProbePlan(opted_in=True, do_not_probe=frozenset({"10.0.0.9"}))

    assert plan.permits(Method.ONVIF_PROBE, "10.0.0.9") is Refusal.DO_NOT_PROBE
    assert plan.permits(Method.ONVIF_PROBE, "10.0.0.5") is None


def test_a_probe_sweep_cannot_outrun_its_rate_limit() -> None:
    plan = ProbePlan(opted_in=True, probes_last_minute=ACTIVE_PROBES_PER_MINUTE)

    assert plan.permits(Method.SNMP_SYSDESCR, "10.0.0.5") is Refusal.PROBE_RATE_EXCEEDED


def test_a_known_onvif_camera_is_proposed_with_confidence_the_engineer_confirms() -> None:
    proposal = match(Fingerprint("10.0.0.5", "_onvif._tcp", vendor="Axis", model="M3085"))

    assert proposal.driver is Adapter.ONVIF
    assert proposal.confidence >= 0.8
    assert not proposal.needs_manual_mapping


def test_an_unknown_vendor_still_matches_a_driver_but_more_weakly() -> None:
    proposal = match(Fingerprint("10.0.0.6", "_rtsp._tcp", vendor="Unbranded"))

    assert proposal.driver is Adapter.ONVIF
    assert proposal.confidence < 0.8


def test_an_unmatched_fingerprint_goes_to_t2_as_metadata_only() -> None:
    proposal = match(Fingerprint("10.0.0.7", "_weird._udp", vendor="Acme"))

    assert proposal.needs_manual_mapping
    metadata = proposal.to_t2_metadata()
    assert metadata["proposed_driver"] is None
    assert "address" not in metadata


def test_l1_takes_any_three_adapters_and_refuses_the_fourth_with_the_upgrade_path() -> None:
    three = (Adapter.ONVIF, Adapter.MQTT, Adapter.POS_WEBHOOK)

    assert select_adapters(three, trust_level=TrustLevel.SOFTWARE_BOUND) is None
    refusal = select_adapters((*three, Adapter.BACNET_IP), trust_level=TrustLevel.SOFTWARE_BOUND)
    assert refusal is Refusal.ADAPTER_CAP
    assert "L2" in REMEDY[Refusal.ADAPTER_CAP]


def test_an_attested_profile_is_not_held_to_the_l1_slot_count() -> None:
    four = (Adapter.ONVIF, Adapter.MQTT, Adapter.POS_WEBHOOK, Adapter.BACNET_IP)

    assert select_adapters(four, trust_level=TrustLevel.MODULE_ATTESTED) is None


def test_an_adapter_needing_attested_hardware_is_refused_on_l1() -> None:
    refusal = select_adapters((Adapter.NVR_RESTREAM,), trust_level=TrustLevel.SOFTWARE_BOUND)

    assert refusal is Refusal.ADAPTER_NOT_AVAILABLE_ON_PROFILE


def test_a_write_capable_account_is_refused_on_a_readable_disk() -> None:
    vault = Vault(TrustLevel.SOFTWARE_BOUND)

    assert vault.store(PTZ) is Refusal.RW_CREDENTIAL_FORBIDDEN_L1
    assert vault.use("cam2", "rtsp_open") is Refusal.CREDENTIAL_UNKNOWN
    assert "read-only" in REMEDY[Refusal.RW_CREDENTIAL_FORBIDDEN_L1]


def test_the_same_account_is_storable_where_the_vault_is_attested() -> None:
    assert Vault(TrustLevel.MODULE_ATTESTED).store(PTZ) is None


def test_every_credential_use_is_logged_without_the_secret() -> None:
    vault = Vault(TrustLevel.SOFTWARE_BOUND)
    vault.store(READ_ONLY)

    used = vault.use("cam1", "rtsp_open")

    assert isinstance(used, Credential)
    entries = vault.audit_entries()
    assert entries == ({"kind": "credential_use", "credential": "cam1", "purpose": "rtsp_open"},)
    assert READ_ONLY.secret not in repr(entries)


def test_t2_learns_that_credentials_exist_and_nothing_else() -> None:
    vault = Vault(TrustLevel.SOFTWARE_BOUND)
    vault.store(READ_ONLY)

    report = vault.t2_report()

    assert report == {"credential_names": ["cam1"]}
    assert READ_ONLY.secret not in repr(report)


def test_every_refusal_carries_a_remedy() -> None:
    assert set(REMEDY) == set(Refusal)
    assert all(REMEDY[refusal].strip() for refusal in Refusal)
