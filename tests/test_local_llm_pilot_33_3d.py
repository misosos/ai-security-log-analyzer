from tests.local_llm_pilot_33_3d import (
    ArtifactPin,
    artifact_manifest_complete,
    disk_floor_safe,
    preflight_verdict,
)


def _pin(name: str, sha: str) -> ArtifactPin:
    return ArtifactPin(name, "fixed-revision", 12, sha * 64)


def test_artifact_manifest_requires_exact_closed_set_and_sha256():
    required = (_pin("model", "a"), _pin("runtime", "b"))
    assert artifact_manifest_complete(required, required)
    assert not artifact_manifest_complete(required, required[:1])
    assert not artifact_manifest_complete(required, (*required, _pin("extra", "c")))
    assert not artifact_manifest_complete(required, (required[0], _pin("runtime", "z")))
    assert not artifact_manifest_complete(required, (_pin("model", "a"), ArtifactPin("runtime", "fixed-revision", 12, "bad")))
    assert not artifact_manifest_complete(required, (_pin("model", "a"), ArtifactPin([], "fixed-revision", 12, "b" * 64)))
    assert not artifact_manifest_complete((required[0], required[0]), required)


def test_disk_guard_preserves_three_gibibyte_free_floor():
    floor = 3 * 1024**3
    assert disk_floor_safe(floor + 1, 1)
    assert not disk_floor_safe(floor, 1)
    assert not disk_floor_safe(-1, 0)
    assert not disk_floor_safe(True, 0)


def test_preflight_fails_closed_in_order_and_never_claims_execution_readiness():
    assert preflight_verdict(
        isolation_verified=False, artifact_plan_complete=False, disk_safe=False
    ) == "ISOLATION_BLOCKED"
    assert preflight_verdict(
        isolation_verified=True, artifact_plan_complete=False, disk_safe=True
    ) == "SUPPLY_CHAIN_BLOCKED"
    assert preflight_verdict(
        isolation_verified=True, artifact_plan_complete=True, disk_safe=False
    ) == "RESOURCE_NO_GO"
    assert preflight_verdict(
        isolation_verified=True, artifact_plan_complete=True, disk_safe=True
    ) == "PREFLIGHT_COMPLETE_REQUIRES_REVIEW"
    assert preflight_verdict(
        isolation_verified=1, artifact_plan_complete=True, disk_safe=True
    ) == "ISOLATION_BLOCKED"
