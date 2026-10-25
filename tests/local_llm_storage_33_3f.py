from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODEL_MANIFEST = ROOT / "docs/artifacts/local_llm_model_manifest_33_3e.json"
WHEEL_MANIFEST = ROOT / "docs/artifacts/local_llm_wheel_closure_33_3e.json"
BUILD_MANIFEST = ROOT / "docs/artifacts/local_llm_build_closure_33_3e.json"
LICENSE_MANIFEST = ROOT / "docs/artifacts/local_llm_wheel_licenses_33_3f.json"
STORAGE_MANIFEST = ROOT / "docs/artifacts/local_llm_storage_plan_33_3f.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIB = 1024**3
PINNED_LICENSE_MANIFEST_SHA256 = "32c3ff74d6b52648f16b222179987b1144f31ac23cfd295dc3bd2ece323dee69"


class StoragePlanError(ValueError):
    """Fixed, privacy-safe storage or supply-chain contract error."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StoragePlanError("MANIFEST_INVALID") from exc
    if not isinstance(value, dict):
        raise StoragePlanError("MANIFEST_INVALID")
    return value


def validate_wheel_license_manifest(manifest: dict[str, Any]) -> int:
    if manifest.get("schema") != "phase33_3f_wheel_license_closure_v1":
        raise StoragePlanError("WHEEL_LICENSE_MANIFEST_INVALID")
    if manifest.get("python") != "3.12" or manifest.get("platform") != "manylinux_2_28_aarch64":
        raise StoragePlanError("WHEEL_PLATFORM_MISMATCH")
    rows = manifest.get("packages")
    if not isinstance(rows, list) or len(rows) != 28:
        raise StoragePlanError("WHEEL_SET_INCOMPLETE")
    baseline = _read_json(WHEEL_MANIFEST)
    expected = {row["name"]: row for row in baseline["packages"]}
    names = [row.get("name") for row in rows if isinstance(row, dict)]
    if len(names) != len(rows) or len(names) != len(set(names)) or set(names) != set(expected):
        raise StoragePlanError("WHEEL_DUPLICATE_OR_SET_MISMATCH")
    for row in rows:
        old = expected[row["name"]]
        if any(row.get(key) != old.get(old_key) for key, old_key in (
            ("version", "version"),
            ("filename", "filename"),
            ("bytes", "size"),
            ("sha256", "sha256"),
        )):
            raise StoragePlanError("WHEEL_HASH_OR_IDENTITY_MISMATCH")
        expected_tag = "-".join(old["filename"][:-4].split("-")[-3:])
        if row.get("platform_tag") != expected_tag:
            raise StoragePlanError("WHEEL_PLATFORM_MISMATCH")
        expression = row.get("license_expression")
        if not isinstance(expression, str) or not expression.strip() or "NOT_VERIFIED" in expression:
            raise StoragePlanError("WHEEL_LICENSE_UNRESOLVED")
        files = row.get("license_files")
        if not isinstance(files, list) or not files:
            raise StoragePlanError("WHEEL_LICENSE_FILE_MISSING")
        for license_file in files:
            if (
                not isinstance(license_file, dict)
                or not isinstance(license_file.get("path"), str)
                or type(license_file.get("bytes")) is not int
                or license_file["bytes"] < 0
                or not SHA256_RE.fullmatch(str(license_file.get("sha256", "")))
            ):
                raise StoragePlanError("WHEEL_LICENSE_FILE_INVALID")
        if row.get("sdist_fallback") is not False:
            raise StoragePlanError("WHEEL_SDIST_NOT_ALLOWED")
        if row.get("install_hooks_reviewed") is not True:
            raise StoragePlanError("WHEEL_INSTALL_HOOK_UNVERIFIED")
        if (
            not isinstance(row.get("source_index"), str)
            or not row["source_index"].startswith("https://")
            or type(row.get("native_file_count")) is not int
            or row["native_file_count"] < 0
            or not isinstance(row.get("required_by"), list)
            or not isinstance(row.get("install_hook_files"), list)
        ):
            raise StoragePlanError("WHEEL_CONTENT_AUDIT_INCOMPLETE")
    if manifest.get("sdist_fallback") is not False:
        raise StoragePlanError("WHEEL_SDIST_NOT_ALLOWED")
    canonical = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != PINNED_LICENSE_MANIFEST_SHA256:
        raise StoragePlanError("WHEEL_LICENSE_MANIFEST_PIN_MISMATCH")
    return len(rows)


def calculate_storage_peak(*, capacity_gib: int = 20) -> dict[str, Any]:
    if type(capacity_gib) is not int or capacity_gib < 1:
        raise StoragePlanError("RESOURCE_NO_GO")
    model = _read_json(MODEL_MANIFEST)
    wheels = _read_json(WHEEL_MANIFEST)
    build = _read_json(BUILD_MANIFEST)
    licenses = _read_json(LICENSE_MANIFEST)
    validate_wheel_license_manifest(licenses)
    if len(model.get("files", [])) != 10 or wheels.get("total_wheel_bytes") != 197_071_951:
        raise StoragePlanError("ARTIFACT_SET_MISMATCH")
    if build.get("runtime", {}).get("archive_sha256") != (
        "1d4a987d9bd048f6e93107e838026438df70fbde237fc0c69c63d600512b4bd9"
    ):
        raise StoragePlanError("RUNTIME_SOURCE_DIGEST_INVALID")
    components = {
        "model_allowlist_bytes": sum(row["bytes"] for row in model["files"]),
        "wheelhouse_bytes": wheels["total_wheel_bytes"],
        "installed_python_environment_bytes": licenses["archive_audit"][
            "expanded_wheel_payload_bytes_cap"
        ],
        "apt_package_archive_cache_cap_bytes": 1024 * 1024**2,
        "llama_cpp_source_archive_bytes": build["runtime"]["archive_bytes"],
        "llama_cpp_extracted_source_cap_bytes": 512 * 1024**2,
        "llama_cpp_build_directory_cap_bytes": 512 * 1024**2,
        "converter_staging_cap_bytes": next(
            row["bytes"] for row in model["files"] if row["path"] == "model.safetensors"
        ),
        "f16_gguf_payload_floor_bytes": 1_503_264_768,
        "fixtures_private_outputs_cap_bytes": 64 * 1024**2,
    }
    subtotal = sum(components.values())
    overhead = (subtotal * 15 + 99) // 100
    peak = subtotal + overhead
    capacity = capacity_gib * GIB
    reserve = max(5 * GIB, (capacity * 15 + 99) // 100)
    free_after_peak = capacity - peak
    if peak + reserve > capacity:
        raise StoragePlanError("RESOURCE_NO_GO")
    return {
        "capacity_bytes": capacity,
        "components_bytes": components,
        "subtotal_bytes": subtotal,
        "filesystem_safety_overhead_percent": 15,
        "overhead_bytes": overhead,
        "planning_peak_bytes": peak,
        "minimum_free_reserve_bytes": reserve,
        "free_after_planning_peak_bytes": free_after_peak,
        "root_filesystem_minimum_free_bytes": 3 * GIB,
        "planning_caps_are_measured_bounds": False,
        "physical_disk_acceptance_required": True,
        "verdict": "PLAN_FITS_BUT_DEVICE_NOT_ACCEPTED",
    }


def select_added_disk_from_inventory(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    *,
    root_disk_path: str,
) -> dict[str, str]:
    return select_added_disk(before, after, root_disk_path=root_disk_path)


def select_added_disk(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    *,
    root_disk_path: str,
) -> dict[str, str]:
    """Return only a safe status; never persist or return a device identifier."""
    before_paths = {row.get("path") for row in before if isinstance(row, dict)}
    after_rows = [row for row in after if isinstance(row, dict) and row.get("path") not in before_paths]
    if len(after_rows) != 1:
        raise StoragePlanError("STORAGE_SETUP_BLOCKED")
    row = after_rows[0]
    mounts = row.get("mountpoints")
    empty_mounts = mounts is None or mounts == [] or mounts == [None]
    if (
        not isinstance(row.get("path"), str)
        or row["path"] == root_disk_path
        or row.get("type") != "disk"
        or type(row.get("size")) is not int
        or not 19 * GIB <= row["size"] <= 21 * GIB
        or row.get("fstype") not in (None, "")
        or not empty_mounts
    ):
        raise StoragePlanError("STORAGE_SETUP_BLOCKED")
    return {"status": "CANDIDATE_EMPTY_20_GIB_DISK"}


def load_acceptance_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    return _read_json(STORAGE_MANIFEST), _read_json(LICENSE_MANIFEST)


def main() -> None:
    print(json.dumps(calculate_storage_peak(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
