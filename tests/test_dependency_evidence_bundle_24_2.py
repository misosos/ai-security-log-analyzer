"""Synthetic and current-lock contracts for the development evidence bundle."""

from pathlib import Path
import json
import stat
import subprocess

import pytest

from scripts.dependency_evidence_bundle_24_2 import (
    BundleError,
    create_bundle,
    inspect_lock,
    inspect_requirements,
    validate_bundle,
)
from scripts import dependency_evidence_bundle_24_2 as bundle


ROOT = Path(__file__).resolve().parents[1]


def test_current_bundle_is_private_and_scoped(tmp_path: Path) -> None:
    output = tmp_path / "evidence"
    result = create_bundle(ROOT, output)
    assert result.runtime_count == 37
    assert result.development_count == 57
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert {p.name for p in output.iterdir()} == {
        "manifest.json", "runtime-requirements.txt", "development-requirements.txt",
        "runtime.cdx.json", "development.cdx.json", "checksums.sha256",
    }
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in output.iterdir())
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["schema_version"] == 1
    assert manifest["runtime_package_count"] == 37
    assert manifest["development_package_count"] == 57
    assert "hypothesis==" not in (output / "runtime-requirements.txt").read_text()
    assert "schemathesis==" not in (output / "runtime-requirements.txt").read_text()
    assert "hypothesis==" in (output / "development-requirements.txt").read_text()
    assert "schemathesis==" in (output / "development-requirements.txt").read_text()


def test_repeat_manifest_is_byte_identical_but_raw_cdx_is_not_promised(tmp_path: Path) -> None:
    create_bundle(ROOT, tmp_path / "one")
    create_bundle(ROOT, tmp_path / "two")
    for name in ("manifest.json", "runtime-requirements.txt", "development-requirements.txt"):
        assert (tmp_path / "one" / name).read_bytes() == (tmp_path / "two" / name).read_bytes()


def test_utc_kst_evidence_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "UTC")
    create_bundle(ROOT, tmp_path / "utc")
    monkeypatch.setenv("TZ", "Asia/Seoul")
    create_bundle(ROOT, tmp_path / "kst")
    for name in ("manifest.json", "runtime-requirements.txt", "development-requirements.txt"):
        assert (tmp_path / "utc" / name).read_bytes() == (tmp_path / "kst" / name).read_bytes()


def test_validation_rejects_mutated_evidence(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    create_bundle(ROOT, output)
    assert validate_bundle(ROOT, output).runtime_count == 37
    with (output / "runtime-requirements.txt").open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(BundleError, match="BUNDLE_VALIDATION_FAILED"):
        validate_bundle(ROOT, output)


def test_validation_rejects_public_permission(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    create_bundle(ROOT, output)
    (output / "manifest.json").chmod(0o644)
    with pytest.raises(BundleError, match="BUNDLE_VALIDATION_FAILED"):
        validate_bundle(ROOT, output)


def test_lock_and_requirement_rejection() -> None:
    lock = inspect_lock((ROOT / "uv.lock").read_bytes(), (ROOT / "pyproject.toml").read_bytes())
    with pytest.raises(BundleError, match="EXPORT_HASH_MISMATCH"):
        inspect_requirements("annotated-doc==0.0.5 \\\n    --hash=sha256:" + "0" * 64 + "\n", lock)
    with pytest.raises(BundleError, match="BUNDLE_INCOMPLETE"):
        inspect_requirements("annotated-doc==0.0.5\n", lock)
    with pytest.raises(BundleError, match="EXPORT_CONTAINS_CREDENTIAL"):
        inspect_requirements("--index-url https://secret@pypi.example/simple\n", lock)


def test_no_clobber_and_symlink(tmp_path: Path) -> None:
    output = tmp_path / "evidence"
    output.mkdir()
    with pytest.raises(BundleError, match="BUNDLE_WRITE_FAILED"):
        create_bundle(ROOT, output)
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(BundleError, match="BUNDLE_WRITE_FAILED"):
        create_bundle(ROOT, linked_parent / "bundle")
    output.rmdir()
    output.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(BundleError, match="BUNDLE_WRITE_FAILED"):
        create_bundle(ROOT, output)


def test_private_error_and_output(tmp_path: Path) -> None:
    canary = "PRIVATE_ACCOUNT_24_2"
    bad = tmp_path / canary
    with pytest.raises(BundleError) as caught:
        create_bundle(bad, tmp_path / "output")
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)
    assert not (tmp_path / "output").exists()


def test_unsupported_source_and_malformed_lock() -> None:
    project = (ROOT / "pyproject.toml").read_bytes()
    raw = (ROOT / "uv.lock").read_bytes()
    with pytest.raises(BundleError, match="LOCKFILE_INVALID"):
        inspect_lock(b"not toml", project)
    with pytest.raises(BundleError, match="LOCKFILE_UNSUPPORTED"):
        inspect_lock(raw.replace(b'registry = "https://pypi.org/simple"', b'url = "file:///private/canary"', 1), project)
    with pytest.raises(BundleError, match="LOCKFILE_UNSUPPORTED"):
        inspect_lock(raw.replace(b"https://files.pythonhosted.org/packages/", b"https://files.pythonhosted.org/packages/?token=synthetic/", 1), project)


def test_partial_write_failure_cleans_only_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sibling = tmp_path / "sibling"
    sibling.write_text("preserve")
    original = bundle._write_private
    calls = 0

    def fail_second(directory: Path, name: str, data: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise BundleError("BUNDLE_WRITE_FAILED")
        original(directory, name, data)

    monkeypatch.setattr(bundle, "_write_private", fail_second)
    with pytest.raises(BundleError, match="BUNDLE_WRITE_FAILED"):
        create_bundle(ROOT, tmp_path / "output")
    assert not (tmp_path / "output").exists()
    assert sibling.read_text() == "preserve"


def test_export_failure_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bundle, "_run_export", lambda *args, **kwargs: (_ for _ in ()).throw(BundleError("EXPORT_FAILED")))
    with pytest.raises(BundleError, match="EXPORT_FAILED"):
        create_bundle(ROOT, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_cli_prints_only_safe_summary() -> None:
    run = subprocess.run(
        ["uv", "run", "python", "-m", "scripts.dependency_evidence_bundle_24_2"],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=False,
    )
    assert run.returncode == 0
    assert run.stdout.startswith("BUNDLE_VALIDATED runtime=37 development=57 lock_sha256_prefix=")
    assert str(ROOT) not in run.stdout + run.stderr
    assert "PRIVATE_ACCOUNT_24_2" not in run.stdout + run.stderr
