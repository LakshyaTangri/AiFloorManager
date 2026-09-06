"""Adapter framework, discovery and the local credential vault (M05, F06).

Discovery is passive by default because a counting appliance has no business port-scanning a
customer network; active probing is opt-in, rate-limited and honours a do-not-probe list.

The vault is the other half of the promise made to the customer's IT: credentials are entered on
site, every use is auditable, nothing but non-secret metadata is ever offered to T2, and on L1 —
whose disk is readable if the device is stolen (D-004) — a write-capable device account is refused
outright rather than stored carefully.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Final

from t1.canon import TrustLevel


class Adapter(str, Enum):
    ONVIF = "onvif"
    MQTT = "mqtt"
    POS_WEBHOOK = "pos_webhook"
    BACNET_IP = "bacnet_ip"
    SNMP = "snmp"
    BLE = "ble"
    MODBUS_TCP = "modbus_tcp"
    NVR_RESTREAM = "nvr_restream"


# SPEC section 9: L2/L3 only, because the re-stream path assumes attested hardware upstream.
RESTRICTED_ADAPTERS: Final[frozenset[Adapter]] = frozenset({Adapter.NVR_RESTREAM})

L1_ADAPTER_SLOTS: Final[int] = 3


class Method(str, Enum):
    MDNS = "mdns"
    SSDP = "ssdp"
    ARP = "arp"
    DHCP_OBSERVE = "dhcp_observe"
    BACNET_WHO_IS = "bacnet_who_is"
    MQTT_TOPIC_SCAN = "mqtt_topic_scan"
    ONVIF_PROBE = "onvif_probe"
    MODBUS_UNIT_SWEEP = "modbus_unit_sweep"
    SNMP_SYSDESCR = "snmp_sysdescr"


PASSIVE: Final[frozenset[Method]] = frozenset(
    {
        Method.MDNS,
        Method.SSDP,
        Method.ARP,
        Method.DHCP_OBSERVE,
        Method.BACNET_WHO_IS,
        Method.MQTT_TOPIC_SCAN,
    }
)

ACTIVE: Final[frozenset[Method]] = frozenset(Method) - PASSIVE

# Rate limit for active probing. Slow enough that a probe sweep cannot be mistaken for an attack
# by the customer's own network monitoring, which is the real failure mode on site.
ACTIVE_PROBES_PER_MINUTE: Final[int] = 30


class Refusal(str, Enum):
    ACTIVE_PROBE_NOT_OPTED_IN = "active_probe_not_opted_in"
    DO_NOT_PROBE = "do_not_probe_listed"
    PROBE_RATE_EXCEEDED = "probe_rate_exceeded"
    ADAPTER_CAP = "adapter_cap"
    ADAPTER_NOT_AVAILABLE_ON_PROFILE = "adapter_not_available_on_profile"
    RW_CREDENTIAL_FORBIDDEN_L1 = "rw_credential_forbidden_l1"
    CREDENTIAL_UNKNOWN = "credential_unknown"


REMEDY: Final[Mapping[Refusal, str]] = MappingProxyType(
    {
        Refusal.ACTIVE_PROBE_NOT_OPTED_IN: "have the customer opt in to active probing before "
        "sweeping; passive discovery runs without permission because it sends nothing",
        Refusal.DO_NOT_PROBE: "leave the address alone; it is on the customer's do-not-probe list",
        Refusal.PROBE_RATE_EXCEEDED: f"probe no faster than {ACTIVE_PROBES_PER_MINUTE} targets "
        "per minute",
        Refusal.ADAPTER_CAP: f"L1 runs any {L1_ADAPTER_SLOTS} adapters; drop one or move the site "
        "to L2, which carries the memory for more",
        Refusal.ADAPTER_NOT_AVAILABLE_ON_PROFILE: "this adapter needs an attested profile (L2/L3)",
        Refusal.RW_CREDENTIAL_FORBIDDEN_L1: "create a read-only device account; the L1 disk is "
        "readable if the box is stolen, so a PTZ or config-write account cannot be stored",
        Refusal.CREDENTIAL_UNKNOWN: "store the credential before using it",
    }
)


@dataclass(frozen=True)
class ProbePlan:
    opted_in: bool
    do_not_probe: frozenset[str] = frozenset()
    probes_last_minute: int = 0

    def permits(self, method: Method, target: str) -> Refusal | None:
        if method in PASSIVE:
            return None
        if not self.opted_in:
            return Refusal.ACTIVE_PROBE_NOT_OPTED_IN
        if target in self.do_not_probe:
            return Refusal.DO_NOT_PROBE
        if self.probes_last_minute >= ACTIVE_PROBES_PER_MINUTE:
            return Refusal.PROBE_RATE_EXCEEDED
        return None


@dataclass(frozen=True)
class Fingerprint:
    """Non-secret observation of a device: what it announced, not what it holds."""

    address: str
    service: str
    vendor: str = ""
    model: str = ""


# Confidence is a match strength, not a probability: a service match alone is weak evidence, a
# service plus a known vendor is what the FE is asked to confirm.
SERVICE_DRIVER: Final[Mapping[str, Adapter]] = MappingProxyType(
    {
        "_onvif._tcp": Adapter.ONVIF,
        "_rtsp._tcp": Adapter.ONVIF,
        "mqtt": Adapter.MQTT,
        "bacnet": Adapter.BACNET_IP,
        "snmp": Adapter.SNMP,
    }
)

KNOWN_VENDORS: Final[Mapping[Adapter, frozenset[str]]] = MappingProxyType(
    {Adapter.ONVIF: frozenset({"axis", "hanwha", "hikvision", "dahua", "bosch"})}
)


@dataclass(frozen=True)
class Match:
    fingerprint: Fingerprint
    driver: Adapter | None
    confidence: float

    @property
    def needs_manual_mapping(self) -> bool:
        return self.driver is None

    def to_t2_metadata(self) -> dict[str, object]:
        """F06 R4: fingerprints grow the point-map library; they carry no credential material."""
        return {
            "service": self.fingerprint.service,
            "vendor": self.fingerprint.vendor,
            "model": self.fingerprint.model,
            "proposed_driver": self.driver.value if self.driver else None,
            "confidence": self.confidence,
        }


def match(fingerprint: Fingerprint) -> Match:
    driver = SERVICE_DRIVER.get(fingerprint.service)
    if driver is None:
        return Match(fingerprint, None, 0.0)
    vendor = fingerprint.vendor.lower()
    confidence = 0.6
    if vendor in KNOWN_VENDORS.get(driver, frozenset()):
        confidence = 0.9 if fingerprint.model else 0.8
    return Match(fingerprint, driver, confidence)


def select_adapters(
    chosen: tuple[Adapter, ...], *, trust_level: TrustLevel, slots: int = L1_ADAPTER_SLOTS
) -> Refusal | None:
    """F06 R5: the fourth adapter is refused with the upgrade path named, never clamped."""
    if trust_level is TrustLevel.SOFTWARE_BOUND:
        if any(adapter in RESTRICTED_ADAPTERS for adapter in chosen):
            return Refusal.ADAPTER_NOT_AVAILABLE_ON_PROFILE
        if len(set(chosen)) > slots:
            return Refusal.ADAPTER_CAP
    return None


@dataclass(frozen=True)
class Credential:
    """A device account. `secret` never leaves this process boundary and is never serialised."""

    name: str
    username: str
    secret: str
    capabilities: frozenset[str]

    @property
    def read_only(self) -> bool:
        return self.capabilities <= frozenset({"read", "stream"})


@dataclass
class Vault:
    """Local credential store. Not the sealed vault itself — the policy it must enforce."""

    trust_level: TrustLevel
    _stored: dict[str, Credential] = field(default_factory=dict)
    _uses: list[tuple[str, str]] = field(default_factory=list)

    def store(self, credential: Credential) -> Refusal | None:
        if self.trust_level is TrustLevel.SOFTWARE_BOUND and not credential.read_only:
            return Refusal.RW_CREDENTIAL_FORBIDDEN_L1
        self._stored[credential.name] = credential
        return None

    def use(self, name: str, purpose: str) -> Credential | Refusal:
        credential = self._stored.get(name)
        if credential is None:
            return Refusal.CREDENTIAL_UNKNOWN
        self._uses.append((name, purpose))
        return credential

    def audit_entries(self) -> tuple[dict[str, str], ...]:
        """F06 R6: every use is logged, with the credential named and the material absent."""
        return tuple(
            {"kind": "credential_use", "credential": name, "purpose": purpose}
            for name, purpose in self._uses
        )

    def t2_report(self) -> dict[str, list[str]]:
        """What T2 may learn: that credentials exist, and nothing about them."""
        return {"credential_names": sorted(self._stored)}
