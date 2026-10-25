from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from local_llm_disk_peak_33_3e import (
    BUILD_MANIFEST,
    MODEL_MANIFEST,
    WHEEL_MANIFEST,
    ClosureError,
    calculate_peak,
    load_and_validate_manifests,
    load_manifest,
    validate_model_manifest,
    validate_wheel_manifest,
)


def test_pinned_model_and_arm64_wheel_manifests_validate_without_artifact_files():
    model, wheels, build = load_and_validate_manifests()
    assert model["revision"] == "c1899de289a04d12100db370d81485cdf75e47ca"
    assert wheels["python"] == "3.12"
    assert len(wheels["packages"]) == 28
    assert wheels["wheel_bodies_downloaded"] is True
    assert wheels["transient_resolver_downloads"][0]["name"] == "setuptools"
    assert next(row for row in wheels["packages"] if row["name"] == "setuptools")["candidate_wheel_body_downloaded"] is True
    assert build["runtime"]["commit"] == "620d2225cc436ab0b001e3200e590e3b286ef9ab"


def test_model_manifest_rejects_tampered_digest():
    model, _, _ = load_and_validate_manifests()
    changed = copy.deepcopy(model)
    changed["files"][0]["sha256"] = "0" * 64
    changed["files"][0]["bytes"] += 1
    # A syntactically valid candidate digest is accepted as metadata; digest tampering
    # is caught by the repository's pinned expectation check below.
    with pytest.raises(ClosureError, match="ARTIFACT_MANIFEST_PIN_MISMATCH"):
        validate_model_manifest(changed)


def test_model_manifest_rejects_missing_and_duplicate_files():
    model, _, _ = load_and_validate_manifests()
    missing = copy.deepcopy(model)
    missing["files"].pop()
    with pytest.raises(ClosureError, match="ARTIFACT_MANIFEST_FILE_SET_MISMATCH"):
        validate_model_manifest(missing)
    duplicate = copy.deepcopy(model)
    duplicate["files"].append(copy.deepcopy(duplicate["files"][0]))
    with pytest.raises(ClosureError, match="ARTIFACT_MANIFEST_DUPLICATE_OR_MALFORMED"):
        validate_model_manifest(duplicate)


def test_wheel_manifest_rejects_duplicate_and_platform_mismatch():
    _, wheels, _ = load_and_validate_manifests()
    duplicate = copy.deepcopy(wheels)
    duplicate["packages"].append(copy.deepcopy(duplicate["packages"][0]))
    with pytest.raises(ClosureError, match="WHEEL_MANIFEST_DUPLICATE_OR_MALFORMED"):
        validate_wheel_manifest(duplicate)
    wrong_platform = copy.deepcopy(wheels)
    wrong_platform["platform"] = "Ubuntu x86_64"
    with pytest.raises(ClosureError, match="WHEEL_PLATFORM_MISMATCH"):
        validate_wheel_manifest(wrong_platform)
    tampered = copy.deepcopy(wheels)
    tampered["packages"][0]["sha256"] = "0" * 64
    with pytest.raises(ClosureError, match="WHEEL_MANIFEST_PIN_MISMATCH"):
        validate_wheel_manifest(tampered)


def test_missing_manifest_file_fails_closed(tmp_path: Path):
    missing = tmp_path / "missing.json"
    with pytest.raises(ClosureError, match="ARTIFACT_MANIFEST_INVALID"):
        load_manifest(missing)


def test_peak_estimate_includes_simultaneous_conversion_and_preserved_free_space():
    model, wheels, build = load_and_validate_manifests()
    caps = {
        "conversion_staging": 1_503_300_328,
        "installed_converter_environment": 536_870_912,
        "source_extract": 536_870_912,
        "runtime_build_directory": 536_870_912,
        "fixtures_and_bounded_outputs": 67_108_864,
    }
    result = calculate_peak(
        model,
        wheels,
        build,
        free_bytes=round(8.1 * 1024**3),
        reserve_bytes=3 * 1024**3,
        planning_caps=caps,
    )
    assert result["components_bytes"]["model_source_and_tokenizer"] == 1_519_209_243
    assert result["components_bytes"]["wheelhouse"] == 197_071_951
    assert result["safe_fit_proven"] is False
    assert result["verdict"] == "RESOURCE_NO_GO"
    assert result["over_budget_bytes"] > 0


def test_build_manifest_missing_archive_digest_is_rejected():
    model, wheels, build = load_and_validate_manifests()
    changed = copy.deepcopy(build)
    changed["runtime"]["archive_sha256"] = ""
    with pytest.raises(ClosureError, match="BUILD_MANIFEST_DIGEST_INVALID"):
        calculate_peak(
            model,
            wheels,
            changed,
            free_bytes=8 * 1024**3,
            reserve_bytes=3 * 1024**3,
            planning_caps={
                "conversion_staging": 1,
                "installed_converter_environment": 1,
                "source_extract": 1,
                "runtime_build_directory": 1,
                "fixtures_and_bounded_outputs": 1,
            },
        )
