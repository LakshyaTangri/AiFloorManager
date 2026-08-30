"""Structural assertions about the sealed process (D-006, F07 R1a).

These are checks, not documentation: `assert_boundary_clean` runs in CI and in `sealed-probe`, and
`SealedEgressError` is what a socket attempt from inside the sealed process raises.
"""

from __future__ import annotations

import dataclasses
import typing
from collections.abc import Iterable

from t1.contracts import BOUNDARY_CROSSING, AgeBand

AGE_TYPE_NAMES = frozenset({"AgeBand"})
AGE_FIELD_TOKENS = ("age_band", "age_score", "age_estimate", "estimated_age", "age_years")


class SealedEgressError(RuntimeError):
    """Raised when sealed-side code attempts to leave the process."""


class BoundaryViolation(AssertionError):
    """Raised when a boundary-crossing type exposes age information."""


def _leaf_types(annotation: object) -> Iterable[object]:
    yield annotation
    for arg in typing.get_args(annotation):
        yield from _leaf_types(arg)


def _type_name(annotation: object) -> str:
    if isinstance(annotation, type):
        return annotation.__name__
    return str(annotation)


def assert_boundary_clean(types: Iterable[type] = BOUNDARY_CROSSING) -> None:
    """Refuse any age-typed or age-named field reachable from a boundary-crossing type.

    `age_gate_passed` is permitted by name because it is a verdict, not a measurement; a bool
    cannot carry a band. Everything else in AGE_FIELD_TOKENS fails the build.
    """
    for cls in types:
        if not dataclasses.is_dataclass(cls):
            raise BoundaryViolation(f"{cls.__name__} is not a dataclass; cannot be checked")
        hints = typing.get_type_hints(cls)
        for name, annotation in hints.items():
            for token in AGE_FIELD_TOKENS:
                if token in name:
                    raise BoundaryViolation(
                        f"{cls.__name__}.{name} carries age information across the boundary"
                    )
            for leaf in _leaf_types(annotation):
                if leaf is AgeBand or _type_name(leaf) in AGE_TYPE_NAMES:
                    raise BoundaryViolation(
                        f"{cls.__name__}.{name} is typed {_type_name(leaf)}, "
                        "which is sealed-side only"
                    )


@dataclasses.dataclass(frozen=True)
class SealedEnvironment:
    """What the supervisor must give the sealed process before it will start."""

    network_namespace: bool = False
    writable_persistent_paths: tuple[str, ...] = ()
    core_dumps_enabled: bool = False
    swap_enabled: bool = False

    def violations(self) -> list[str]:
        problems = []
        if self.network_namespace:
            problems.append("sealed_process_has_network")
        if self.writable_persistent_paths:
            problems.append("sealed_process_has_writable_path")
        if self.core_dumps_enabled:
            problems.append("sealed_process_core_dumps_enabled")
        if self.swap_enabled:
            problems.append("sealed_process_swap_enabled")
        return problems

    def assert_sealed(self) -> None:
        problems = self.violations()
        if problems:
            raise SealedEgressError(",".join(problems))


def attempt_egress(_target: str) -> None:
    """The only network entry point sealed-side code has. It always refuses."""
    raise SealedEgressError("sealed_process_egress_forbidden")
