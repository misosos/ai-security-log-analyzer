"""Pure preflight checks for Phase 33.3D; this module never accesses a VM."""

from __future__ import annotations

from dataclasses import dataclass
import re


MINIMUM_FREE_BYTES = 3 * 1024**3
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ArtifactPin:
    artifact_id: str
    revision: str
    size_bytes: int
    sha256: str


def artifact_manifest_complete(
    required: tuple[ArtifactPin, ...], supplied: tuple[ArtifactPin, ...]
) -> bool:
    """Require exact artifact identities, byte sizes and SHA-256 pins."""
    if type(required) is not tuple or type(supplied) is not tuple or not required:
        return False
    if any(type(item) is not ArtifactPin for item in (*required, *supplied)):
        return False
    for item in (*required, *supplied):
        if (
            type(item.artifact_id) is not str
            or not item.artifact_id
            or type(item.revision) is not str
            or not item.revision
            or type(item.size_bytes) is not int
            or item.size_bytes <= 0
            or type(item.sha256) is not str
            or _SHA256.fullmatch(item.sha256) is None
        ):
            return False
    if len({item.artifact_id for item in required}) != len(required):
        return False
    if len({item.artifact_id for item in supplied}) != len(supplied):
        return False
    if set(supplied) != set(required):
        return False
    return True


def disk_floor_safe(free_bytes: int, peak_additional_bytes: int) -> bool:
    """Keep at least 3 GiB free after the estimated peak; no filesystem reads."""
    return (
        type(free_bytes) is int
        and type(peak_additional_bytes) is int
        and free_bytes >= 0
        and peak_additional_bytes >= 0
        and free_bytes - peak_additional_bytes >= MINIMUM_FREE_BYTES
    )


def preflight_verdict(
    *, isolation_verified: bool, artifact_plan_complete: bool, disk_safe: bool
) -> str:
    """Return a stop verdict; readiness still requires a separate human review."""
    gates = (isolation_verified, artifact_plan_complete, disk_safe)
    if any(type(value) is not bool for value in gates):
        return "ISOLATION_BLOCKED"
    if not isolation_verified:
        return "ISOLATION_BLOCKED"
    if not artifact_plan_complete:
        return "SUPPLY_CHAIN_BLOCKED"
    if not disk_safe:
        return "RESOURCE_NO_GO"
    return "PREFLIGHT_COMPLETE_REQUIRES_REVIEW"
