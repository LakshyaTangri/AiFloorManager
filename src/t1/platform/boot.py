"""Boot chain, A/B slots and the pre-service ordering (M02, F03, C3/C7).

Three F03 requirements are behaviour rather than configuration, and they are what this module
makes executable and testable off the hardware:

    R3  three *consecutive* failed health checks roll back to the other slot. A boot counter that
        resets on success is the difference between "this release is bad" and "this site loses
        power at night".
    R4  the privacy control set is verified before any application container starts. A failed
        signature is not a refusal to boot: ingest continues and the bridge is disabled, because a
        store that stops counting is a support call while a store that leaks is a breach.
    R5  the audit volume is mounted append-only *before* any service starts, so that everything a
        service could later do is already inside the chain.

`step_boot` is the whole sequence as data: the order is asserted rather than implied by where the
calls happen to sit, and a stage that has not completed cannot be skipped past.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, replace
from enum import Enum
from typing import Final

from t1.platform.layout import DiskLayout, LayoutFinding, Volume, validate_layout

MAX_FAILED_HEALTH_CHECKS: Final[int] = 3
PRIVACY_SET_SIGNING_DOMAIN: Final[str] = "privacy-control-set"


class Slot(str, Enum):
    A = "rootfs_a"
    B = "rootfs_b"

    @property
    def other(self) -> Slot:
        return Slot.B if self is Slot.A else Slot.A


class Mode(str, Enum):
    """What the device is allowed to do once it is up."""

    NORMAL = "normal"
    INGEST_ONLY = "ingest_only"


class Stage(str, Enum):
    """SPEC §5's chain, in the order it must happen. `START_CONTAINERS` is last for R4's sake."""

    VERIFY_CHAIN = "verify_chain"
    UNLOCK_DATA = "unlock_data"
    MOUNT_AUDIT = "mount_audit"
    START_SERVICES = "start_services"
    VERIFY_PRIVACY_SET = "verify_privacy_set"
    START_CONTAINERS = "start_containers"


SEQUENCE: Final[tuple[Stage, ...]] = tuple(Stage)


class BootFinding(str, Enum):
    CHAIN_UNSIGNED = "chain_unsigned"
    LAYOUT_INVALID = "layout_invalid"
    AUDIT_NOT_MOUNTED = "audit_not_mounted"
    STAGE_OUT_OF_ORDER = "stage_out_of_order"
    PRIVACY_SET_UNVERIFIED = "privacy_set_unverified"
    HEALTH_CHECK_FAILED = "health_check_failed"
    ROLLED_BACK = "rolled_back"
    NO_HEALTHY_SLOT = "no_healthy_slot"


@dataclass(frozen=True)
class SlotState:
    version: str
    healthy: bool = True
    failed_health_checks: int = 0


@dataclass(frozen=True)
class BootState:
    active: Slot
    slots: dict[Slot, SlotState]
    mode: Mode = Mode.NORMAL
    completed: tuple[Stage, ...] = ()
    findings: tuple[BootFinding, ...] = ()

    @property
    def active_slot(self) -> SlotState:
        return self.slots[self.active]


class BootOrderError(RuntimeError):
    """Raised when a stage is attempted before its predecessor completed."""


def verify_privacy_set(digest: bytes, signature: str, key: bytes) -> bool:
    expected = hmac.new(key, PRIVACY_SET_SIGNING_DOMAIN.encode() + digest, hashlib.sha256)
    return hmac.compare_digest(expected.hexdigest(), signature)


def step_boot(
    state: BootState,
    stage: Stage,
    *,
    layout: DiskLayout | None = None,
    chain_signed: bool = True,
    privacy_set_ok: bool = True,
) -> BootState:
    """Advance one stage. Stages run in `SEQUENCE` order and nothing may be skipped."""
    expected = SEQUENCE[len(state.completed)] if len(state.completed) < len(SEQUENCE) else None
    if stage is not expected:
        raise BootOrderError(f"{stage.value} cannot run after {[s.value for s in state.completed]}")

    findings = list(state.findings)
    mode = state.mode

    if stage is Stage.VERIFY_CHAIN and not chain_signed:
        findings.append(BootFinding.CHAIN_UNSIGNED)
    if stage is Stage.MOUNT_AUDIT:
        problems = (
            validate_layout(layout) if layout is not None else (LayoutFinding.VOLUME_MISSING,)
        )
        if problems:
            findings.append(BootFinding.LAYOUT_INVALID)
        if layout is None or layout.partition(Volume.AUDIT) is None:
            findings.append(BootFinding.AUDIT_NOT_MOUNTED)
    if stage is Stage.START_SERVICES and Stage.MOUNT_AUDIT not in state.completed:
        findings.append(BootFinding.AUDIT_NOT_MOUNTED)
    if stage is Stage.VERIFY_PRIVACY_SET and not privacy_set_ok:
        findings.append(BootFinding.PRIVACY_SET_UNVERIFIED)
        mode = Mode.INGEST_ONLY
    if stage is Stage.START_CONTAINERS and mode is Mode.INGEST_ONLY:
        # R4: ingest keeps running, the bridge does not. Containers stay down.
        return replace(state, mode=mode, findings=tuple(findings))

    return replace(state, mode=mode, completed=(*state.completed, stage), findings=tuple(findings))


def report_health(state: BootState, *, healthy: bool) -> BootState:
    """R3. A success clears the counter; the third consecutive failure rolls back."""
    slot = state.slots[state.active]
    if healthy:
        slots = {**state.slots, state.active: replace(slot, healthy=True, failed_health_checks=0)}
        return replace(state, slots=slots)

    failed = slot.failed_health_checks + 1
    slots = {**state.slots, state.active: replace(slot, healthy=False, failed_health_checks=failed)}
    findings = (*state.findings, BootFinding.HEALTH_CHECK_FAILED)
    if failed < MAX_FAILED_HEALTH_CHECKS:
        return replace(state, slots=slots, findings=findings)

    target = state.active.other
    if slots[target].failed_health_checks >= MAX_FAILED_HEALTH_CHECKS:
        return replace(state, slots=slots, findings=(*findings, BootFinding.NO_HEALTHY_SLOT))
    return replace(
        state,
        active=target,
        slots=slots,
        completed=(),
        findings=(*findings, BootFinding.ROLLED_BACK),
    )


def rollback_report(state: BootState, rolled_back_from: Slot) -> dict[str, str]:
    """What OPS is told after an automatic rollback (F03 acceptance criterion 1)."""
    return {
        "event": BootFinding.ROLLED_BACK.value,
        "failing_slot": rolled_back_from.value,
        "failing_version": state.slots[rolled_back_from].version,
        "active_slot": state.active.value,
        "active_version": state.active_slot.version,
    }
