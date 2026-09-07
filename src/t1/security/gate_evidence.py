"""Evidence-backed commissioning items for identity and the kill switch (M15, F21).

`CommissioningGate.record_pass` takes an actor's word for it, which is right for items whose
evidence is physical - signage photographs, a sign-off. Identity and the kill switch are not like
that: the device can check both itself, so these helpers observe the real state and refuse the item
rather than let a Field Engineer tick it from the van.

The kill-switch item is an exercise, not an inspection: it kills a camera, confirms the stream is
actually refused, and releases it again under TA authorisation, so the recorded pass means the path
ran end to end on this box.
"""

from __future__ import annotations

from datetime import datetime

from t1.control.commissioning import REFUSAL, REMEDY, ActivationRefused, CommissioningGate, GateItem
from t1.security.identity import DeviceIdentity, IdentityState
from t1.security.kill_switch import KillScope, KillSwitch, Role


def record_identity(
    gate: CommissioningGate, identity: DeviceIdentity, actor: str, now: datetime
) -> None:
    if identity.state is not IdentityState.ENROLLED:
        raise ActivationRefused(
            REFUSAL[GateItem.IDENTITY], GateItem.IDENTITY, REMEDY[GateItem.IDENTITY]
        )
    gate.record_pass(GateItem.IDENTITY, now, actor)


def exercise_kill_switch(
    gate: CommissioningGate,
    switch: KillSwitch,
    camera_id: str,
    ta_actor: str,
    now: datetime,
) -> None:
    """Kill a camera, prove the stream stops, release it, and only then record the item."""
    item = GateItem.KILL_SWITCH
    if not switch.stream_allowed(camera_id):
        raise ActivationRefused(REFUSAL[item], item, "Release the existing kill before the test")

    switch.kill(KillScope.CAMERA, camera_id, ta_actor, "commissioning_exercise", now)
    if switch.stream_allowed(camera_id):
        raise ActivationRefused(REFUSAL[item], item, REMEDY[item])

    if switch.unkill(KillScope.CAMERA, camera_id, ta_actor, Role.TENANT_ADMIN, now) is not None:
        raise ActivationRefused(REFUSAL[item], item, "Release the test kill with TA authorisation")
    gate.record_pass(item, now, ta_actor)
