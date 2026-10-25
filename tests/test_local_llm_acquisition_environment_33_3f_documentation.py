from __future__ import annotations

import json
from pathlib import Path

from local_llm_storage_33_3f import calculate_storage_peak, validate_wheel_license_manifest


ROOT = Path(__file__).resolve().parents[1]


def test_33_3f_record_truthfully_keeps_physical_disk_and_vm_build_pending():
    doc = (ROOT / "docs/local_llm_acquisition_environment_33_3f.md").read_text(encoding="utf-8")
    for phrase in (
        "Final disposition: `STORAGE_SETUP_BLOCKED`",
        "ad226412e2440fceb7cc458b1976f40780c32d62",
        "40148946929",
        "9,256,782,529",
        "12,218,053,951 bytes",
        "744,996,145-byte",
        "before and after",
        "No format approval was requested or received",
        "exact installed/candidate apt versions",
        "No disk was formatted or mounted",
    ):
        assert phrase in doc
    for private_marker in (
        "/" + "Users" + "/",
        "/" + "home" + "/",
        "10" + ".0.",
        "192" + ".168.",
    ):
        assert private_marker not in doc


def test_33_3f_machine_manifests_close_wheel_licenses_and_show_pending_acceptance():
    licenses = json.loads(
        (ROOT / "docs/artifacts/local_llm_wheel_licenses_33_3f.json").read_text(encoding="utf-8")
    )
    storage = json.loads(
        (ROOT / "docs/artifacts/local_llm_storage_plan_33_3f.json").read_text(encoding="utf-8")
    )
    build = json.loads(
        (ROOT / "docs/artifacts/local_llm_build_closure_33_3f.json").read_text(encoding="utf-8")
    )
    assert validate_wheel_license_manifest(licenses) == 28
    assert licenses["archive_audit"]["total_compressed_bytes"] == 197_071_951
    assert licenses["archive_audit"]["total_unpacked_bytes"] == 744_996_145
    assert storage["physical_disk_acceptance"]["status"] == "PENDING_USER_INVENTORY"
    assert storage["physical_disk_acceptance"]["format_performed"] is False
    assert storage["format_authorization"] == "NOT_REQUESTED"
    assert build["status"] == "STATIC_REFERENCE_ONLY_VM_CLOSURE_PENDING"
    assert build["build_and_conversion_performed"] is False


def test_33_3f_capacity_calculation_is_repeatable_and_reserves_space():
    first = calculate_storage_peak(capacity_gib=20)
    second = calculate_storage_peak(capacity_gib=20)
    assert first == second
    assert first["planning_peak_bytes"] == 9_256_782_529
    assert first["free_after_planning_peak_bytes"] >= 5 * 1024**3
    assert first["filesystem_safety_overhead_percent"] >= 15
    assert first["verdict"] == "PLAN_FITS_BUT_DEVICE_NOT_ACCEPTED"


def test_33_3f_roadmaps_reference_the_followup_and_preserve_no_model_execution():
    for relative in ("README.md", "docs/index.md", "docs/local_llm_artifact_closure_33_3e.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "local_llm_acquisition_environment_33_3f.md" in text
    doc = (ROOT / "docs/local_llm_acquisition_environment_33_3f.md").read_text(encoding="utf-8")
    assert "no model conversion or inference occurred" in doc
    assert "no model, runtime source archive, package" in doc
