"""Build a host-specific, allowlisted PyInstaller onedir prototype."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
PYINSTALLER_VERSION = "6.22.3"
APPLICATION_VERSION = tomllib.loads(
    (ROOT / "pyproject.toml").read_text(encoding="utf-8")
)["project"]["version"]
RUNTIME_ASSET_ALLOWLIST = (
    "frontend/index.html",
    "frontend/style.css",
    "frontend/app.js",
    "frontend/input-quality-ui-36-12b.js",
    "frontend/review-queue-ui-36-13a.js",
    "frontend/investigation-review-state-36-14d.js",
    "frontend/linux-audit.js",
    "frontend/live-monitoring.js",
    "frontend/multi-source-live.js",
    "data/account_metadata.json",
    "app/knowledge_corpus_33_1/corpus.json",
    "app/knowledge_corpus_33_1/manifest.json",
    "sample_logs/brute_force.log",
    "sample_logs/ssh_auth.log",
    "sample_logs/web_shell.log",
)
OUTPUT_RELATIVE = Path("dist") / "ai-security-log-analyzer"
OUTPUT_MARKER = ".ai-security-log-analyzer-owned"


def validate_output_directory(repo_root: Path, output: Path) -> Path:
    root = repo_root.resolve(strict=True)
    expected = root / OUTPUT_RELATIVE
    candidate = output if output.is_absolute() else root / output
    if candidate != expected:
        raise ValueError("Unsafe output directory.")
    dist = root / "dist"
    if dist.exists() or dist.is_symlink():
        if dist.is_symlink() or not dist.is_dir() or dist.resolve(strict=True) != dist:
            raise ValueError("Unsafe output directory.")
    if candidate.is_symlink():
        raise ValueError("Unsafe output directory.")
    if candidate.exists() and (not candidate.is_dir() or candidate.resolve(strict=True) != candidate):
        raise ValueError("Unsafe output directory.")
    return candidate


def validate_work_directory(repo_root: Path, workpath: Path) -> Path:
    root = repo_root.resolve(strict=True)
    expected = root / "build" / "pyinstaller-onedir-36-15b"
    candidate = workpath if workpath.is_absolute() else root / workpath
    if candidate != expected:
        raise ValueError("Unsafe build working directory.")
    build_root = root / "build"
    if build_root.is_symlink() or (build_root.exists() and not build_root.is_dir()):
        raise ValueError("Unsafe build working directory.")
    if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()):
        raise ValueError("Unsafe build working directory.")
    if candidate.exists() and candidate.resolve(strict=True) != candidate:
        raise ValueError("Unsafe build working directory.")
    return candidate


def clean_owned_output(repo_root: Path, output: Path) -> None:
    target = validate_output_directory(repo_root, output)
    marker = target.parent / OUTPUT_MARKER
    if not target.exists():
        return
    if marker.is_symlink() or not marker.is_file():
        raise ValueError("Output ownership could not be verified.")
    try:
        if marker.read_text(encoding="ascii") != "ai-security-log-analyzer onedir prototype\n":
            raise ValueError("Output ownership could not be verified.")
    except OSError:
        raise ValueError("Output ownership could not be verified.") from None
    shutil.rmtree(target)


def build_manifest(
    bundle_root: Path,
    *,
    platform_name: str,
    architecture: str,
    python_version: str,
    pyinstaller_version: str,
) -> dict:
    root = bundle_root.resolve(strict=True)
    files = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("Bundle inventory path is invalid.")
        if path.is_dir() and not path.is_symlink():
            continue
        if path.is_symlink():
            target = Path(path.readlink())
            resolved = path.resolve(strict=False)
            if target.is_absolute() or (resolved != root and root not in resolved.parents):
                raise ValueError("Bundle contains an escaping symbolic link.")
            if not path.exists():
                raise ValueError("Bundle contains a dangling symbolic link.")
            content = target.as_posix().encode("utf-8")
            file_type = "symbolic_link"
            size = len(content)
            file_hash = hashlib.sha256(content).hexdigest()
        elif path.is_file():
            suffix = path.suffix.lower().lstrip(".")
            file_type = suffix or "extensionless"
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            file_hash = digest.hexdigest()
        else:
            raise ValueError("Bundle inventory contains an unsupported file type.")
        files.append({
            "path": relative,
            "file_type": file_type,
            "size_bytes": size,
            "sha256": file_hash,
        })
    return {
        "schema_version": 1,
        "application_version": APPLICATION_VERSION,
        "platform": platform_name,
        "architecture": architecture,
        "python_version": python_version,
        "pyinstaller_version": pyinstaller_version,
        "files": files,
    }


def _asset_pairs() -> list[tuple[str, str]]:
    pairs = []
    for relative in RUNTIME_ASSET_ALLOWLIST:
        source = ROOT / relative
        if not source.is_file() or source.is_symlink():
            raise ValueError("An allowlisted runtime asset is unavailable.")
        pairs.append((str(source), str(Path(relative).parent)))
    return pairs


def _metadata() -> tuple[str, str, str]:
    version = PYINSTALLER_VERSION
    try:
        import PyInstaller
    except ImportError:
        raise ValueError("The isolated build environment does not contain PyInstaller.") from None
    return version, platform.system().lower(), platform.machine().lower()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the local onedir prototype.")
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--manifest-only", action="store_true")
    args = parser.parse_args(argv)
    output = validate_output_directory(ROOT, OUTPUT_RELATIVE)
    if sys.version_info[:2] != (3, 12):
        print("STANDALONE_BUILD_BLOCKED: expected Python 3.12.", file=sys.stderr)
        return 2
    version, platform_name, architecture = _metadata()
    if version != PYINSTALLER_VERSION:
        print("STANDALONE_BUILD_BLOCKED: PyInstaller version mismatch.", file=sys.stderr)
        return 2
    if args.manifest_only:
        if not output.is_dir():
            print("STANDALONE_BUILD_BLOCKED: bundle is unavailable.", file=sys.stderr)
            return 2
    else:
        if args.clean:
            try:
                clean_owned_output(ROOT, output)
            except ValueError as error:
                print(f"STANDALONE_BUILD_BLOCKED: {error}", file=sys.stderr)
                return 2
        if output.exists():
            print("STANDALONE_BUILD_BLOCKED: use --clean for an owned build.", file=sys.stderr)
            return 2
        try:
            _asset_pairs()
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            workpath = validate_work_directory(ROOT, ROOT / "build" / "pyinstaller-onedir-36-15b")
            workpath.mkdir(mode=0o700, parents=True, exist_ok=True)
        except (OSError, ValueError):
            print("STANDALONE_BUILD_BLOCKED: an output or runtime asset path is unsafe.", file=sys.stderr)
            return 2
        try:
            output.parent.joinpath(OUTPUT_MARKER).write_text(
                "ai-security-log-analyzer onedir prototype\n", encoding="ascii"
            )
        except OSError:
            print("STANDALONE_BUILD_BLOCKED: output marker could not be created.", file=sys.stderr)
            return 2
        command = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--distpath",
            str(output.parent),
            "--workpath",
            str(workpath),
            str(ROOT / "packaging" / "ai-security-log-analyzer.spec"),
        ]
        result = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
        (workpath / "pyinstaller-output.log").write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        if result.returncode != 0 or not output.is_dir():
            print("STANDALONE_BUILD_FAILED: PyInstaller did not create the onedir bundle.", file=sys.stderr)
            return 1
    try:
        manifest = build_manifest(
            output,
            platform_name=platform_name,
            architecture=architecture,
            python_version=platform.python_version(),
            pyinstaller_version=version,
        )
        manifest_path = output.parent / "ai-security-log-analyzer.manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, KeyError):
        print("STANDALONE_MANIFEST_FAILED: bundle inventory could not be verified.", file=sys.stderr)
        return 1
    print(f"STANDALONE_BUILD_OK: {len(manifest['files'])} files inventoried.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
