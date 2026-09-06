"""M06: the link is outbound, inspected TLS is refused, and an unreachable T2 is survivable."""

from __future__ import annotations

from t1.platform.reachability import (
    MQTT_ALPN,
    PINNED_ROOT,
    REMEDY,
    Endpoint,
    Finding,
    Observation,
    Posture,
    assess,
)


def _clear(endpoint: Endpoint) -> Observation:
    return Observation(
        endpoint,
        resolves=True,
        tcp_open=True,
        tls_root=PINNED_ROOT,
        negotiated_alpn=MQTT_ALPN if endpoint is Endpoint.MQTT else "h2",
        proxy_requires_auth=False,
    )


def _all_clear() -> dict[Endpoint, Observation]:
    return {endpoint: _clear(endpoint) for endpoint in Endpoint}


def test_a_clean_network_needs_no_firewall_sheet() -> None:
    result = assess(_all_clear())

    assert result.posture is Posture.ONLINE
    assert result.enrolment_possible
    assert result.firewall_sheet() == ()


def test_an_endpoint_nobody_probed_is_not_a_reachable_endpoint() -> None:
    observations = _all_clear()
    del observations[Endpoint.ARTIFACTS]

    result = assess(observations)

    assert result.findings[Endpoint.ARTIFACTS] == (Finding.UNVERIFIED,)
    assert result.posture is Posture.OFFLINE_LOCAL_ONLY


def test_a_blocked_uplink_leaves_counting_running() -> None:
    observations = _all_clear()
    observations[Endpoint.MQTT] = Observation(Endpoint.MQTT, resolves=True, tcp_open=False)

    result = assess(observations)

    assert result.posture is Posture.OFFLINE_LOCAL_ONLY
    assert not result.local_function_affected
    assert result.enrolment_possible


def test_enrolment_is_the_one_thing_that_cannot_wait_for_the_network() -> None:
    observations = _all_clear()
    observations[Endpoint.ENROL] = Observation(Endpoint.ENROL, resolves=False)

    result = assess(observations)

    assert result.findings[Endpoint.ENROL] == (Finding.DNS_UNRESOLVED,)
    assert not result.enrolment_possible


def test_an_inspecting_proxy_is_refused_rather_than_trusted() -> None:
    observations = _all_clear()
    observations[Endpoint.INGEST] = Observation(
        Endpoint.INGEST,
        resolves=True,
        tcp_open=True,
        tls_root="Customer Root CA",
        negotiated_alpn="h2",
        proxy_requires_auth=False,
    )

    result = assess(observations)

    assert Finding.TLS_INTERCEPTED in result.findings[Endpoint.INGEST]
    assert result.posture is Posture.REFUSED
    assert not result.enrolment_possible
    assert any("passthrough" in line for line in result.firewall_sheet())


def test_a_proxy_that_strips_alpn_breaks_mqtt_and_says_so() -> None:
    observations = _all_clear()
    observations[Endpoint.MQTT] = Observation(
        Endpoint.MQTT,
        resolves=True,
        tcp_open=True,
        tls_root=PINNED_ROOT,
        negotiated_alpn=None,
        proxy_requires_auth=False,
    )

    result = assess(observations)

    assert Finding.ALPN_STRIPPED in result.findings[Endpoint.MQTT]
    assert result.posture is Posture.REFUSED


def test_a_proxy_demanding_auth_names_the_missing_credentials() -> None:
    observations = _all_clear()
    observations[Endpoint.ARTIFACTS] = Observation(
        Endpoint.ARTIFACTS,
        resolves=True,
        tcp_open=True,
        tls_root=PINNED_ROOT,
        negotiated_alpn="h2",
        proxy_requires_auth=True,
    )

    result = assess(observations)

    assert Finding.PROXY_AUTH_MISSING in result.findings[Endpoint.ARTIFACTS]
    assert result.posture is Posture.OFFLINE_LOCAL_ONLY


def test_supplied_proxy_credentials_satisfy_a_proxy_that_demands_them() -> None:
    observations = _all_clear()
    observations[Endpoint.ARTIFACTS] = Observation(
        Endpoint.ARTIFACTS,
        resolves=True,
        tcp_open=True,
        tls_root=PINNED_ROOT,
        negotiated_alpn="h2",
        proxy_requires_auth=True,
        proxy_credentials_present=True,
    )

    assert assess(observations).posture is Posture.ONLINE


def test_an_offered_inbound_rule_is_a_finding_not_a_favour() -> None:
    result = assess(_all_clear(), inbound_rule_offered=True)

    assert result.posture is Posture.REFUSED
    assert result.firewall_sheet()[0].startswith(Finding.INBOUND_RULE_OFFERED.value)


def test_every_finding_carries_a_remedy() -> None:
    assert set(REMEDY) == set(Finding)
    assert all(REMEDY[finding].strip() for finding in Finding)
