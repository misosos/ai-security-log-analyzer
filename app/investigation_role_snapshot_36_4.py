"""Private source-role provenance snapshots for checklist construction."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from types import MappingProxyType
from typing import Mapping

from app.models.schemas import NormalizedEvent


_ROLE_BY_EVENT_SOURCE = MappingProxyType({
    "application": "application",
    "ssh": "ssh",
    "access_log": "access",
})
_ALLOWED_ROLES = frozenset({"application", "ssh", "access"})


@dataclass(frozen=True, slots=True, repr=False)
class BoundCaseSourceRole:
    """A role result bound to the exact case and analysis objects that produced it."""

    source_role: str
    _case: object = field(repr=False, compare=False)
    _analysis: object = field(repr=False, compare=False)
    _projection: object = field(repr=False, compare=False)

    def is_current(self, case: object, analysis: object, projection: object) -> bool:
        return (case is self._case and analysis is self._analysis
                and projection is self._projection)

    def __repr__(self) -> str:
        return "BoundCaseSourceRole(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AnalysisSourceRoleSnapshot:
    """Immutable source-role observations scoped to one analysis result."""

    _analysis: object = field(repr=False, compare=False)
    _roles_by_subject: Mapping[str, frozenset[str]] = field(repr=False, compare=False)

    @classmethod
    def from_events(cls, analysis: object, events: object) -> "AnalysisSourceRoleSnapshot":
        roles: dict[str, set[str]] = {}
        try:
            if type(analysis) is not dict or type(events) not in (tuple, list):
                return cls(analysis, MappingProxyType({}))
            for event in events:
                if type(event) is not NormalizedEvent:
                    return cls(analysis, MappingProxyType({}))
                source_ip = event.src_ip
                if type(source_ip) is not str:
                    continue
                try:
                    subject = ip_address(source_ip).compressed
                except ValueError:
                    continue
                role = _ROLE_BY_EVENT_SOURCE.get(event.source)
                roles.setdefault(subject, set()).add(role if role in _ALLOWED_ROLES else "unknown")
            frozen = MappingProxyType({key: frozenset(value) for key, value in roles.items()})
            return cls(analysis, frozen)
        except Exception:
            # Provenance failure is deliberately fail-closed and does not affect analysis.
            return cls(analysis, MappingProxyType({}))

    def bind_projection(self, projection: object, analysis: object) -> tuple[BoundCaseSourceRole, ...]:
        cases = getattr(projection, "cases", None)
        if type(cases) is not tuple:
            return ()
        bound = []
        for case in cases:
            role = "unknown"
            try:
                if analysis is self._analysis and type(analysis) is dict:
                    subject_ip = case.row.subject_ip
                    if type(subject_ip) is str:
                        subject = ip_address(subject_ip).compressed
                        recorded = self._roles_by_subject.get(subject, frozenset())
                        if len(recorded) == 1:
                            candidate = next(iter(recorded))
                            if candidate in _ALLOWED_ROLES:
                                role = candidate
            except Exception:
                role = "unknown"
            bound.append(BoundCaseSourceRole(role, case, analysis, projection))
        return tuple(bound)

    def __repr__(self) -> str:
        return "AnalysisSourceRoleSnapshot(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AnalysisWithSourceRoleSnapshot:
    """Analysis output plus private immutable metadata captured from its parsed events."""

    analysis: dict = field(repr=False, compare=False)
    source_roles: AnalysisSourceRoleSnapshot = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "AnalysisWithSourceRoleSnapshot(<redacted>)"
