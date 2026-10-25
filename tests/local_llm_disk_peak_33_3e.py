"""Metadata-only artifact closure checks and conservative disk scenario."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODEL_MANIFEST = ROOT / "docs/artifacts/local_llm_model_manifest_33_3e.json"
WHEEL_MANIFEST = ROOT / "docs/artifacts/local_llm_wheel_closure_33_3e.json"
BUILD_MANIFEST = ROOT / "docs/artifacts/local_llm_build_closure_33_3e.json"
EXPECTED_MODEL_FILES = {
    ".gitattributes",
    "LICENSE",
    "README.md",
    "config.json",
    "generation_config.json",
    "merges.txt",
    "model.safetensors",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.json",
}
PINNED_MODEL_FILE_DIGESTS = {
    ".gitattributes": (1570, "34448b82c17d60fec9b65b1f093c115ddbaadc04beb1b0140b6bfed2e012a930"),
    "LICENSE": (11343, "832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e"),
    "README.md": (13965, "1ab64a26fcb3b461423b89a433a8c858f1bf8d4086f979cbb3ff878d47cf20e9"),
    "config.json": (726, "660db3b73d788119c04535e48cf9be5f55bc3100841a718637ae695b442f27dd"),
    "generation_config.json": (239, "2325da0f15bb848e018c5ae071b7943332e9f871d6b60e2ed22ca97d4cb993d2"),
    "merges.txt": (1671853, "8831e4f1a044471340f7c0a83d7bd71306a5b867e95fd870f74d0c5308a904d5"),
    "model.safetensors": (1503300328, "f47f71177f32bcd101b7573ec9171e6a57f4f4d31148d38e382306f42996874b"),
    "tokenizer.json": (11422654, "aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4"),
    "tokenizer_config.json": (9732, "d5d09f07b48c3086c508b30d1c9114bd1189145b74e982a265350c923acd8101"),
    "vocab.json": (2776833, "ca10d7e9fb3ed18575dd1e277a2579c16d108e32f27439684afa0e10b1440910"),
}
PINNED_WHEEL_MANIFEST_SHA256 = "4dfa0e20de782ebe9300f932da6982ba9d8c434041e95d2a897ac3e6d6b979df"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ClosureError(ValueError):
    """Fixed, non-sensitive manifest validation error."""


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ClosureError("ARTIFACT_MANIFEST_INVALID") from exc
    if not isinstance(value, dict):
        raise ClosureError("ARTIFACT_MANIFEST_INVALID")
    return value


def validate_model_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema") != "phase33_3e_model_artifacts_v1":
        raise ClosureError("ARTIFACT_MANIFEST_INVALID")
    rows = manifest.get("files")
    if not isinstance(rows, list):
        raise ClosureError("ARTIFACT_MANIFEST_INVALID")
    paths = [row.get("path") for row in rows if isinstance(row, dict)]
    if len(paths) != len(rows) or len(paths) != len(set(paths)):
        raise ClosureError("ARTIFACT_MANIFEST_DUPLICATE_OR_MALFORMED")
    if set(paths) != EXPECTED_MODEL_FILES:
        raise ClosureError("ARTIFACT_MANIFEST_FILE_SET_MISMATCH")
    for row in rows:
        if (
            type(row.get("bytes")) is not int
            or row["bytes"] <= 0
            or not isinstance(row.get("sha256"), str)
            or not SHA256_RE.fullmatch(row["sha256"])
            or row.get("actual_bytes_revalidation_required_before_acquisition") is not True
        ):
            raise ClosureError("ARTIFACT_MANIFEST_INVALID")
        if (row["bytes"], row["sha256"]) != PINNED_MODEL_FILE_DIGESTS[row["path"]]:
            raise ClosureError("ARTIFACT_MANIFEST_PIN_MISMATCH")


def validate_wheel_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema") != "phase33_3e_wheel_closure_v1":
        raise ClosureError("WHEEL_MANIFEST_INVALID")
    if manifest.get("python") != "3.12" or manifest.get("platform") != (
        "Ubuntu 24.04 ARM64 target aarch64-manylinux_2_28"
    ):
        raise ClosureError("WHEEL_PLATFORM_MISMATCH")
    if manifest.get("only_binary") is not True or manifest.get("sdist_used") is not False:
        raise ClosureError("WHEEL_SOURCE_BUILD_NOT_ALLOWED")
    rows = manifest.get("packages")
    if not isinstance(rows, list) or not rows:
        raise ClosureError("WHEEL_MANIFEST_INVALID")
    names = [row.get("name") for row in rows if isinstance(row, dict)]
    if len(names) != len(rows) or len(names) != len(set(names)):
        raise ClosureError("WHEEL_MANIFEST_DUPLICATE_OR_MALFORMED")
    for row in rows:
        if (
            type(row.get("size")) is not int
            or row["size"] <= 0
            or not SHA256_RE.fullmatch(str(row.get("sha256", "")))
            or not isinstance(row.get("filename"), str)
        ):
            raise ClosureError("WHEEL_MANIFEST_INVALID")
    if sum(row["size"] for row in rows) != manifest.get("total_wheel_bytes"):
        raise ClosureError("WHEEL_TOTAL_MISMATCH")
    canonical = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != PINNED_WHEEL_MANIFEST_SHA256:
        raise ClosureError("WHEEL_MANIFEST_PIN_MISMATCH")


def calculate_peak(
    model: dict[str, Any],
    wheels: dict[str, Any],
    build: dict[str, Any],
    *,
    free_bytes: int,
    reserve_bytes: int,
    planning_caps: dict[str, int],
    overhead_percent: int = 15,
) -> dict[str, Any]:
    validate_model_manifest(model)
    validate_wheel_manifest(wheels)
    if build.get("schema") != "phase33_3e_build_closure_v1":
        raise ClosureError("BUILD_MANIFEST_INVALID")
    runtime = build.get("runtime")
    if (
        not isinstance(runtime, dict)
        or type(runtime.get("archive_bytes")) is not int
        or runtime["archive_bytes"] <= 0
        or not SHA256_RE.fullmatch(str(runtime.get("archive_sha256", "")))
    ):
        raise ClosureError("BUILD_MANIFEST_DIGEST_INVALID")
    required_caps = {
        "conversion_staging",
        "installed_converter_environment",
        "source_extract",
        "runtime_build_directory",
        "fixtures_and_bounded_outputs",
    }
    if set(planning_caps) != required_caps or any(
        type(value) is not int or value <= 0 for value in planning_caps.values()
    ):
        raise ClosureError("DISK_CAPS_INCOMPLETE")
    artifacts = sum(row["bytes"] for row in model["files"])
    gguf_floor = 1_503_264_768  # 751,632,384 parameters × 2 bytes; excludes GGUF headers/padding.
    components = {
        "model_source_and_tokenizer": artifacts,
        "unquantized_gguf_payload_floor": gguf_floor,
        "wheelhouse": wheels["total_wheel_bytes"],
        "runtime_source_archive": build["runtime"]["archive_bytes"],
        **planning_caps,
    }
    subtotal = sum(components.values())
    overhead = (subtotal * overhead_percent + 99) // 100
    estimated_peak = subtotal + overhead
    usable_bytes = max(0, free_bytes - reserve_bytes)
    return {
        "components_bytes": components,
        "subtotal_bytes": subtotal,
        "filesystem_and_safety_overhead_percent": overhead_percent,
        "overhead_bytes": overhead,
        "estimated_peak_bytes": estimated_peak,
        "usable_bytes_after_reserve": usable_bytes,
        "over_budget_bytes": max(0, estimated_peak - usable_bytes),
        "all_component_caps_verified": False,
        "safe_fit_proven": False,
        "verdict": "RESOURCE_NO_GO" if estimated_peak > usable_bytes else "NOT_PROVEN",
    }


def load_and_validate_manifests() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    model, wheels, build = map(_load, (MODEL_MANIFEST, WHEEL_MANIFEST, BUILD_MANIFEST))
    validate_model_manifest(model)
    validate_wheel_manifest(wheels)
    return model, wheels, build


def load_manifest(path: Path) -> dict[str, Any]:
    return _load(path)


def manifest_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Calculate the Phase 33.3E disk planning scenario")
    parser.add_argument("--free-gib", type=float, default=8.1)
    parser.add_argument("--reserve-gib", type=float, default=3.0)
    args = parser.parse_args()
    model, wheels, build = load_and_validate_manifests()
    planning_caps = {
        "conversion_staging": 1_503_300_328,
        "installed_converter_environment": 512 * 1024**2,
        "source_extract": 512 * 1024**2,
        "runtime_build_directory": 512 * 1024**2,
        "fixtures_and_bounded_outputs": 64 * 1024**2,
    }
    result = calculate_peak(
        model,
        wheels,
        build,
        free_bytes=round(args.free_gib * 1024**3),
        reserve_bytes=round(args.reserve_gib * 1024**3),
        planning_caps=planning_caps,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
