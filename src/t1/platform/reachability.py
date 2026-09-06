"""Outbound reachability assessment for the T1-T2 link (M06, SPEC section 15).

Three rules shape this module.

The link is device-initiated and outbound only, so an offered inbound firewall rule is a finding
and not an accommodation. A TLS-inspecting proxy is likewise a finding: the remedy is a passthrough
allowlist, never a customer CA in the device trust store.

An unreachable T2 is not a local failure. Ingest, analytics and retention run offline, so
unreachable endpoints degrade the bridge alone; only enrolment genuinely requires the network.

An unmeasured check is a refusal, as in F01: `None` means nobody looked, and nobody-looked never
reads as pass.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final

MQTT_ALPN: Final[str] = "x-amzn-mqtt-ca"
PINNED_ROOT: Final[str] = "Tangri Service CA"


class Endpoint(str, Enum):
    MQTT = "iot.pulsemanager.ai"
    ARTIFACTS = "artifacts.pulsemanager.ai"
    INGEST = "ingest.pulsemanager.ai"
    ENROL = "enrol.pulsemanager.ai"
    PKI = "pki.pulsemanager.ai"


PURPOSE: Final[Mapping[Endpoint, str]] = MappingProxyType(
    {
        Endpoint.MQTT: "control, state, telemetry and events",
        Endpoint.ARTIFACTS: "signed artifact download",
        Endpoint.INGEST: "bulk aggregate and backfill",
        Endpoint.ENROL: "one-time enrolment",
        Endpoint.PKI: "CRL and OCSP",
    }
)

# Enrolment is the one exchange with no offline path: without it the device has no identity.
REQUIRED_FOR_ENROLMENT: Final[frozenset[Endpoint]] = frozenset({Endpoint.ENROL, Endpoint.PKI})


class Finding(str, Enum):
    UNVERIFIED = "unverified"
    DNS_UNRESOLVED = "dns_unresolved"
    TCP_BLOCKED = "tcp_blocked"
    TLS_INTERCEPTED = "tls_intercepted"
    ALPN_STRIPPED = "alpn_stripped"
    PROXY_AUTH_MISSING = "proxy_auth_missing"
    INBOUND_RULE_OFFERED = "inbound_rule_offered"


REMEDY: Final[Mapping[Finding, str]] = MappingProxyType(
    {
        Finding.UNVERIFIED: "run the reachability probe from the installed device on the "
        "customer network; an unmeasured endpoint is not a reachable one",
        Finding.DNS_UNRESOLVED: "allow DNS resolution of the Tangri hostnames, or supply the "
        "customer resolver that serves them",
        Finding.TCP_BLOCKED: "allow outbound TCP 443 to the named hostname; no inbound rule is "
        "needed",
        Finding.TLS_INTERCEPTED: "allowlist the Tangri hostnames for TLS passthrough on the "
        "inspecting proxy; the device will not trust a customer CA for these endpoints",
        Finding.ALPN_STRIPPED: f"permit ALPN {MQTT_ALPN} through the proxy, or allowlist the "
        "MQTT endpoint for passthrough",
        Finding.PROXY_AUTH_MISSING: "supply the HTTP proxy credentials to the device; the proxy "
        "demands authentication and none is configured",
        Finding.INBOUND_RULE_OFFERED: "withdraw the inbound rule; the device dials out and an "
        "inbound path only enlarges the customer's attack surface",
    }
)

# A route that exists but is being read or rewritten is worse than no route: the device would be
# trusting the wrong peer. These refuse rather than degrade.
REFUSING: Final[frozenset[Finding]] = frozenset(
    {Finding.TLS_INTERCEPTED, Finding.ALPN_STRIPPED, Finding.INBOUND_RULE_OFFERED}
)


@dataclass(frozen=True)
class Observation:
    """What the probe saw at one endpoint. `None` is 'not measured', never 'fine'."""

    endpoint: Endpoint
    resolves: bool | None = None
    tcp_open: bool | None = None
    tls_root: str | None = None
    negotiated_alpn: str | None = None
    proxy_requires_auth: bool | None = None
    proxy_credentials_present: bool = False

    def findings(self) -> tuple[Finding, ...]:
        if self.resolves is None:
            return (Finding.UNVERIFIED,)
        if not self.resolves:
            return (Finding.DNS_UNRESOLVED,)
        if self.tcp_open is None:
            return (Finding.UNVERIFIED,)
        if not self.tcp_open:
            return (Finding.TCP_BLOCKED,)
        if self.proxy_requires_auth is None:
            return (Finding.UNVERIFIED,)
        found: list[Finding] = []
        if self.proxy_requires_auth and not self.proxy_credentials_present:
            found.append(Finding.PROXY_AUTH_MISSING)
        if self.tls_root is None:
            found.append(Finding.UNVERIFIED)
        elif self.tls_root != PINNED_ROOT:
            found.append(Finding.TLS_INTERCEPTED)
        if self.endpoint is Endpoint.MQTT and self.negotiated_alpn != MQTT_ALPN:
            found.append(Finding.ALPN_STRIPPED)
        return tuple(found)


class Posture(str, Enum):
    ONLINE = "online"
    OFFLINE_LOCAL_ONLY = "offline_local_only"
    REFUSED = "refused"


@dataclass(frozen=True)
class Assessment:
    findings: Mapping[Endpoint, tuple[Finding, ...]]
    inbound_rule_offered: bool

    @property
    def posture(self) -> Posture:
        flat = {finding for group in self.findings.values() for finding in group}
        if self.inbound_rule_offered or flat & REFUSING:
            return Posture.REFUSED
        return Posture.ONLINE if not flat else Posture.OFFLINE_LOCAL_ONLY

    @property
    def enrolment_possible(self) -> bool:
        return self.posture is Posture.ONLINE or (
            self.posture is Posture.OFFLINE_LOCAL_ONLY
            and not any(self.findings[e] for e in REQUIRED_FOR_ENROLMENT)
        )

    @property
    def local_function_affected(self) -> bool:
        """SPEC section 3: no cloud failure degrades local function. Counting keeps running."""
        return False

    def firewall_sheet(self) -> tuple[str, ...]:
        """The IT ask handed over at commissioning: one line per unmet requirement."""
        lines: list[str] = []
        if self.inbound_rule_offered:
            lines.append(
                f"{Finding.INBOUND_RULE_OFFERED.value}: {REMEDY[Finding.INBOUND_RULE_OFFERED]}"
            )
        for endpoint in Endpoint:
            for finding in self.findings.get(endpoint, ()):
                lines.append(
                    f"{endpoint.value} ({PURPOSE[endpoint]}) — {finding.value}: {REMEDY[finding]}"
                )
        return tuple(lines)


def assess(
    observations: Mapping[Endpoint, Observation], *, inbound_rule_offered: bool = False
) -> Assessment:
    """Every endpoint is assessed; one the probe never visited counts as unverified."""
    findings = {
        endpoint: (
            observations[endpoint].findings() if endpoint in observations else (Finding.UNVERIFIED,)
        )
        for endpoint in Endpoint
    }
    return Assessment(
        findings=MappingProxyType(findings), inbound_rule_offered=inbound_rule_offered
    )
