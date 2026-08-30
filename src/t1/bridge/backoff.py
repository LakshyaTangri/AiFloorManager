"""Reconnect backoff with per-device jitter (F14 R2).

The jitter is the point, not the backoff. A thousand devices that all wake from an AWS blip on the
same doubling schedule reconnect in the same second and finish the outage on T2's behalf. The
offset is derived from `device_id`, so it is stable across reboots (a device does not re-roll into
a worse slot every crash) and uncorrelated between devices.
"""

from __future__ import annotations

import hashlib

from t1.canon import BACKOFF_MAX_S, BACKOFF_MIN_S


def jitter_fraction(device_id: str) -> float:
    digest = hashlib.sha256(device_id.encode()).digest()
    return float(int.from_bytes(digest[:8], "big")) / float(1 << 64)


def window_seconds(attempt: int) -> float:
    if attempt < 0:
        raise ValueError("attempt_negative")
    return min(BACKOFF_MAX_S, BACKOFF_MIN_S * float(1 << min(attempt, 32)))


def next_delay(attempt: int, device_id: str) -> float:
    """Full jitter within the doubling window: uniform in [0, window], keyed to the device."""
    return window_seconds(attempt) * jitter_fraction(device_id)
