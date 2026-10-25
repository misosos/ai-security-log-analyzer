from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from local_llm_storage_33_3f import (
    StoragePlanError,
    calculate_storage_peak,
    select_added_disk,
    validate_wheel_license_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
WHEELS = ROOT / "docs/artifacts/local_llm_wheel_licenses_33_3f.json"


def test_storage_calculator_reserves_at_least_five_gib_and_uses_20_gib_disk():
    plan = calculate_storage_peak(capacity_gib=20)
    assert plan["minimum_free_reserve_bytes"] >= 5 * 1024**3
    assert plan["filesystem_safety_overhead_percent"] >= 15
    assert plan["planning_peak_bytes"] < plan["capacity_bytes"]
    assert plan["free_after_planning_peak_bytes"] >= plan["minimum_free_reserve_bytes"]


def test_storage_calculator_rejects_capacity_that_cannot_preserve_reserve():
    with pytest.raises(StoragePlanError, match="RESOURCE_NO_GO"):
        calculate_storage_peak(capacity_gib=10)


def test_added_disk_selection_requires_new_empty_unmounted_non_root_device():
    before = [
        {"path": "/dev/rootdisk", "size": 40 * 1024**3, "type": "disk", "fstype": "", "mountpoints": []},
    ]
    after = before + [
        {"path": "/dev/newdisk", "size": 20 * 1024**3, "type": "disk", "fstype": "", "mountpoints": []},
    ]
    candidate = select_added_disk(before, after, root_disk_path="/dev/rootdisk")
    assert candidate == {"status": "CANDIDATE_EMPTY_20_GIB_DISK"}

    with pytest.raises(StoragePlanError, match="STORAGE_SETUP_BLOCKED"):
        select_added_disk([], before, root_disk_path="/dev/rootdisk")

    formatted = before + [
        {"path": "/dev/formatted", "size": 20 * 1024**3, "type": "disk", "fstype": "ext4", "mountpoints": []},
    ]
    with pytest.raises(StoragePlanError, match="STORAGE_SETUP_BLOCKED"):
        select_added_disk(before, formatted, root_disk_path="/dev/rootdisk")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda rows: rows.pop(),
        lambda rows: rows.append(copy.deepcopy(rows[0])),
        lambda rows: rows[0].update(sha256="0" * 64),
        lambda rows: rows[0]["license_files"][0].update(sha256="0" * 64),
        lambda rows: rows[0].update(license_expression="NOT_VERIFIED"),
        lambda rows: rows[0].update(platform_tag="win_amd64"),
    ],
)
def test_wheel_license_closure_rejects_incomplete_or_tampered_rows(mutate):
    manifest = json.loads(WHEELS.read_text(encoding="utf-8"))
    mutate(manifest["packages"])
    with pytest.raises(StoragePlanError):
        validate_wheel_license_manifest(manifest)


def test_wheel_license_manifest_covers_all_pinned_candidates():
    manifest = json.loads(WHEELS.read_text(encoding="utf-8"))
    assert validate_wheel_license_manifest(manifest) == 28
    assert manifest["sdist_fallback"] is False
    assert len(manifest["setuptools_78_1_0_vendored_license_files"]) == 17
    setuptools = next(row for row in manifest["packages"] if row["name"] == "setuptools")
    assert setuptools["install_hook_files"] == ["distutils-precedence.pth"]
    assert setuptools["install_hooks_reviewed"] is True


def test_acceptance_record_and_plan_have_no_device_or_personal_identity():
    plan = json.loads((ROOT / "docs/artifacts/local_llm_storage_plan_33_3f.json").read_text())
    assert plan["physical_disk_acceptance"]["status"] == "PENDING_USER_INVENTORY"
    assert plan["format_authorization"] == "NOT_REQUESTED"
    serialized = json.dumps(plan)
    for secret in ("/dev/", "/home/", "/Users/", "10.0.", "192.168.", "SERIAL"):
        assert secret not in serialized
