"""Development-only, private evidence for the current locked Python dependencies.

The raw CycloneDX files are unmodified uv exports. Their serial/timestamp make
their *byte* checksums variable; the manifest records a stable graph digest and
``checksums.sha256`` separately records actual file bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any
from urllib.parse import urlsplit

from scripts.supply_chain_pilot_24_1 import inspect_sbom


MAX_INPUT = 8 * 1024 * 1024
FILES = (
    "runtime-requirements.txt", "development-requirements.txt",
    "runtime.cdx.json", "development.cdx.json", "manifest.json",
)
HASH_LINE = re.compile(r"^    --hash=sha256:([0-9a-f]{64})(?: \\)?$")
REQUIREMENT = re.compile(r"^([A-Za-z0-9_.-]+)==([^;\s]+)(?: ; .+)? \\$")
PRIVATE = re.compile(r"/Users/|/home/|/private/var/|/var/folders/|file://|\.env\b|checkpoint|monitor.config", re.I)


class BundleError(Exception):
    """Fixed, privacy-safe failure code; the internal cause is not rendered."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class LockEvidence:
    project: str
    version: str
    python: str
    packages: dict[tuple[str, str], frozenset[str]]


@dataclass(frozen=True)
class BundleResult:
    runtime_count: int
    development_count: int
    lock_sha256: str
    runtime_graph_sha256: str
    development_graph_sha256: str


def _json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _safe_url(url: object) -> bool:
    if not isinstance(url, str):
        return False
    parsed = urlsplit(url)
    return parsed.scheme == "https" and parsed.hostname in {"pypi.org", "files.pythonhosted.org"} and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment


def inspect_lock(raw: bytes, project_raw: bytes) -> LockEvidence:
    """Validate only the uv.lock v1/revision 3 registry shape used here."""
    try:
        if len(raw) > MAX_INPUT or len(project_raw) > MAX_INPUT:
            raise ValueError
        lock = tomllib.loads(raw.decode("utf-8"))
        project = tomllib.loads(project_raw.decode("utf-8"))["project"]
        if type(lock.get("version")) is not int or lock["version"] != 1 or lock.get("revision") != 3:
            raise BundleError("LOCKFILE_UNSUPPORTED")
        root_name, root_version = project["name"], project["version"]
        if not isinstance(root_name, str) or not isinstance(root_version, str) or not isinstance(lock.get("requires-python"), str):
            raise ValueError
        if root_name != "ai-security-log-analyzer" or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", root_version) or not re.fullmatch(r">=[0-9]+\.[0-9]+", lock["requires-python"]):
            raise BundleError("LOCKFILE_UNSUPPORTED")
        packages: dict[tuple[str, str], frozenset[str]] = {}
        roots = 0
        for item in lock["package"]:
            name, version, source = item["name"], item["version"], item["source"]
            if not isinstance(name, str) or not isinstance(version, str) or not isinstance(source, dict):
                raise ValueError
            if source == {"virtual": "."} and (name, version) == (root_name, root_version):
                roots += 1
                continue
            if set(source) != {"registry"} or source["registry"] != "https://pypi.org/simple":
                raise BundleError("LOCKFILE_UNSUPPORTED")
            hashes: set[str] = set()
            artifacts = ([item["sdist"]] if "sdist" in item else []) + item.get("wheels", [])
            if not artifacts or not isinstance(artifacts, list):
                raise ValueError
            for artifact in artifacts:
                digest = artifact["hash"]
                if not _safe_url(artifact["url"]) or not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                    raise BundleError("LOCKFILE_UNSUPPORTED")
                hashes.add(digest[7:])
            key = (name.lower().replace("_", "-"), version)
            if key in packages:
                raise BundleError("LOCKFILE_UNSUPPORTED")
            packages[key] = frozenset(hashes)
        if roots != 1 or not packages:
            raise ValueError
        return LockEvidence(root_name, root_version, lock["requires-python"], packages)
    except BundleError:
        raise
    except (ValueError, KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError):
        raise BundleError("LOCKFILE_INVALID") from None


def inspect_requirements(text: str, lock: LockEvidence) -> dict[tuple[str, str], frozenset[str]]:
    """Verify uv's exact pinned/hash export, not resolve dependencies anew."""
    if len(text.encode("utf-8")) > MAX_INPUT or PRIVATE.search(text) or re.search(r"://[^/\s]+@", text):
        raise BundleError("EXPORT_CONTAINS_CREDENTIAL")
    result: dict[tuple[str, str], frozenset[str]] = {}
    current: tuple[str, str] | None = None
    hashes: set[str] = set()

    def finish() -> None:
        nonlocal current, hashes
        if current is None:
            return
        if not hashes:
            raise BundleError("BUNDLE_INCOMPLETE")
        if current in result:
            raise BundleError("BUNDLE_INCOMPLETE")
        if current not in lock.packages or frozenset(hashes) != lock.packages[current]:
            raise BundleError("EXPORT_HASH_MISMATCH")
        result[current] = frozenset(hashes)
        current, hashes = None, set()

    for line in text.splitlines():
        if match := REQUIREMENT.fullmatch(line):
            finish()
            current = (match[1].lower().replace("_", "-"), match[2])
        elif match := HASH_LINE.fullmatch(line):
            if current is None:
                raise BundleError("BUNDLE_INCOMPLETE")
            hashes.add(match[1])
        elif line.strip():
            raise BundleError("BUNDLE_INCOMPLETE")
    finish()
    if not result:
        raise BundleError("BUNDLE_INCOMPLETE")
    return result


def _run_export(project: Path, *, development: bool, format_name: str) -> bytes:
    executable = shutil.which("uv")
    if executable is None:
        raise BundleError("EXPORT_FAILED")
    args = [executable, "export", "--locked", "--offline", "--quiet", "--no-config", "--no-emit-project"]
    if not development:
        args.append("--no-dev")
    if format_name == "requirements.txt":
        args += ["--no-header", "--no-annotate"]
    else:
        args += ["--preview-features", "sbom-export"]
    args += ["--format", format_name]
    env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}
    env["UV_NO_PROGRESS"] = "1"
    try:
        with tempfile.TemporaryDirectory(prefix="uv-export-cache-24-2-") as cache:
            env["UV_CACHE_DIR"] = cache
            run = subprocess.run(args, cwd=project, env=env, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise BundleError("EXPORT_FAILED") from None
    if run.returncode or len(run.stdout) > MAX_INPUT or len(run.stderr) > 4096:
        raise BundleError("EXPORT_FAILED")
    return run.stdout


def _write_private(directory: Path, name: str, data: bytes) -> None:
    if len(data) > MAX_INPUT:
        raise BundleError("BUNDLE_INCOMPLETE")
    temporary = directory / (name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            written = os.fstat(stream.fileno())
        os.rename(temporary, directory / name)
    except Exception:
        raise BundleError("BUNDLE_WRITE_FAILED") from None
    published = (directory / name).lstat()
    if not stat.S_ISREG(published.st_mode) or (published.st_dev, published.st_ino) != (written.st_dev, written.st_ino) or stat.S_IMODE(published.st_mode) != 0o600:
        raise BundleError("BUNDLE_VALIDATION_FAILED")


def validate_bundle(project: Path, directory: Path) -> BundleResult:
    """Re-open and validate a completed private bundle against the current lock."""
    try:
        directory = Path(directory)
        mode = directory.lstat().st_mode
        if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) != 0o700 or directory.stat().st_uid != os.getuid():
            raise BundleError("BUNDLE_VALIDATION_FAILED")
        if {item.name for item in directory.iterdir()} != set(FILES) | {"checksums.sha256"}:
            raise BundleError("BUNDLE_VALIDATION_FAILED")
        files: dict[str, bytes] = {}
        for name in (*FILES, "checksums.sha256"):
            path = directory / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_size > MAX_INPUT:
                raise BundleError("BUNDLE_VALIDATION_FAILED")
            files[name] = path.read_bytes()
        checksums = "".join(f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n" for name in FILES).encode()
        if files["checksums.sha256"] != checksums:
            raise BundleError("BUNDLE_VALIDATION_FAILED")
        lock_raw = (Path(project) / "uv.lock").read_bytes()
        lock = inspect_lock(lock_raw, (Path(project) / "pyproject.toml").read_bytes())
        manifest = json.loads(files["manifest.json"])
        if set(manifest) != {
            "schema_version", "generation_policy_version", "project", "uv_version",
            "uv_lock_sha256", "runtime_package_count", "development_package_count",
            "files", "validation",
        } or manifest["schema_version"] != 1 or manifest["generation_policy_version"] != 1:
            raise BundleError("BUNDLE_VALIDATION_FAILED")
        if manifest["uv_version"] != _uv_version() or manifest["uv_lock_sha256"] != hashlib.sha256(lock_raw).hexdigest() or manifest["project"] != {
            "name": lock.project, "version": lock.version, "requires_python": lock.python,
        } or manifest["validation"] != "LOCK_AND_EXPORT_MATCH":
            raise BundleError("BUNDLE_VALIDATION_FAILED")
        if set(manifest["files"]) != set(FILES) - {"manifest.json"}:
            raise BundleError("BUNDLE_VALIDATION_FAILED")
        graphs: dict[str, str] = {}
        for scope in ("runtime", "development"):
            req_name, cdx_name = f"{scope}-requirements.txt", f"{scope}.cdx.json"
            packages = inspect_requirements(files[req_name].decode("utf-8"), lock)
            document = json.loads(files[cdx_name])
            graph = inspect_sbom(document)
            graph_keys = {(item["name"].lower().replace("_", "-"), item["version"]) for item in document["components"]}
            if graph_keys != set(packages) or manifest[f"{scope}_package_count"] != len(packages):
                raise BundleError("BUNDLE_VALIDATION_FAILED")
            if manifest["files"][req_name] != {"sha256": hashlib.sha256(files[req_name]).hexdigest(), "digest_kind": "file_bytes"}:
                raise BundleError("BUNDLE_VALIDATION_FAILED")
            if manifest["files"][cdx_name] != {"sha256": graph.canonical_sha256, "digest_kind": "canonical_graph"}:
                raise BundleError("BUNDLE_VALIDATION_FAILED")
            graphs[scope] = graph.canonical_sha256
        return BundleResult(
            manifest["runtime_package_count"], manifest["development_package_count"],
            manifest["uv_lock_sha256"], graphs["runtime"], graphs["development"],
        )
    except BundleError:
        raise
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        raise BundleError("BUNDLE_VALIDATION_FAILED") from None


def create_bundle(project: Path, output: Path) -> BundleResult:
    """Create a private one-use directory; caller owns its later disposal.

    ``output`` must not exist and its parent must be a trusted private directory.
    The CLI always supplies a fresh temporary parent and removes it on return.
    """
    created = False
    complete = False
    output_identity: tuple[int, int] | None = None
    try:
        project = Path(project)
        output = Path(output)
        if output.exists() or output.is_symlink() or not output.is_absolute():
            raise BundleError("BUNDLE_WRITE_FAILED")
        parent = output.parent
        pst = parent.lstat()
        if not stat.S_ISDIR(pst.st_mode) or pst.st_uid != os.getuid() or stat.S_IMODE(pst.st_mode) != 0o700:
            raise BundleError("BUNDLE_WRITE_FAILED")
        ancestor = parent
        while ancestor != ancestor.parent:
            if stat.S_ISLNK(ancestor.lstat().st_mode):
                raise BundleError("BUNDLE_WRITE_FAILED")
            ancestor = ancestor.parent
        lock_raw = (project / "uv.lock").read_bytes()
        project_raw = (project / "pyproject.toml").read_bytes()
        lock = inspect_lock(lock_raw, project_raw)
        exported: dict[str, bytes] = {}
        evidence: dict[str, dict[str, Any]] = {}
        counts: dict[str, int] = {}
        graphs: dict[str, str] = {}
        for scope, development in (("runtime", False), ("development", True)):
            req_name, cdx_name = f"{scope}-requirements.txt", f"{scope}.cdx.json"
            req = _run_export(project, development=development, format_name="requirements.txt")
            packages = inspect_requirements(req.decode("utf-8"), lock)
            cdx = _run_export(project, development=development, format_name="cyclonedx1.5")
            try:
                document = json.loads(cdx)
                graph = inspect_sbom(document)
                component_keys = {(item["name"].lower().replace("_", "-"), item["version"]) for item in document["components"]}
            except (ValueError, KeyError, TypeError, UnicodeError):
                raise BundleError("CYCLONEDX_INVALID") from None
            if component_keys != set(packages) or graph.component_count != len(packages):
                raise BundleError("BUNDLE_INCOMPLETE")
            exported[req_name], exported[cdx_name] = req, cdx
            evidence[req_name] = {"sha256": hashlib.sha256(req).hexdigest(), "digest_kind": "file_bytes"}
            evidence[cdx_name] = {"sha256": graph.canonical_sha256, "digest_kind": "canonical_graph"}
            counts[scope], graphs[scope] = len(packages), graph.canonical_sha256
        if not set(inspect_requirements(exported["runtime-requirements.txt"].decode(), lock)).issubset(
            inspect_requirements(exported["development-requirements.txt"].decode(), lock)
        ) or len(lock.packages) != counts["development"]:
            raise BundleError("DEVELOPMENT_SCOPE_MISMATCH")
        names = {key[0] for key in inspect_requirements(exported["runtime-requirements.txt"].decode(), lock)}
        if {"hypothesis", "schemathesis"} & names:
            raise BundleError("RUNTIME_SCOPE_MISMATCH")
        dev_names = {key[0] for key in inspect_requirements(exported["development-requirements.txt"].decode(), lock)}
        if not {"hypothesis", "schemathesis"}.issubset(dev_names):
            raise BundleError("DEVELOPMENT_SCOPE_MISMATCH")
        manifest = {
            "schema_version": 1, "generation_policy_version": 1,
            "project": {"name": lock.project, "version": lock.version, "requires_python": lock.python},
            "uv_version": _uv_version(), "uv_lock_sha256": hashlib.sha256(lock_raw).hexdigest(),
            "runtime_package_count": counts["runtime"], "development_package_count": counts["development"],
            "files": evidence, "validation": "LOCK_AND_EXPORT_MATCH",
        }
        exported["manifest.json"] = _json(manifest)
        checksums = "".join(f"{hashlib.sha256(exported[name]).hexdigest()}  {name}\n" for name in FILES).encode()
        output.mkdir(mode=0o700)
        created = True
        created_stat = output.lstat()
        output_identity = (created_stat.st_dev, created_stat.st_ino)
        for name in FILES:
            _write_private(output, name, exported[name])
        _write_private(output, "checksums.sha256", checksums)
        published_directory = output.lstat()
        if not stat.S_ISDIR(published_directory.st_mode) or (published_directory.st_dev, published_directory.st_ino) != output_identity or stat.S_IMODE(published_directory.st_mode) != 0o700:
            raise BundleError("BUNDLE_VALIDATION_FAILED")
        validate_bundle(project, output)
        complete = True
        return BundleResult(counts["runtime"], counts["development"], manifest["uv_lock_sha256"], graphs["runtime"], graphs["development"])
    except BundleError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError):
        raise BundleError("BUNDLE_WRITE_FAILED") from None
    finally:
        try:
            current = output.lstat()
            same_output = stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == output_identity
        except OSError:
            same_output = False
        if created and not complete and same_output:
            # Remove only known files; never recursively delete unknown siblings.
            for name in (*FILES, "checksums.sha256", *(item + ".tmp" for item in FILES), "checksums.sha256.tmp"):
                candidate = output / name
                try:
                    if candidate.is_file() and not candidate.is_symlink():
                        candidate.unlink()
                except OSError:
                    pass
            try:
                output.rmdir()
            except OSError:
                pass


def _uv_version() -> str:
    executable = shutil.which("uv")
    if executable is None:
        raise BundleError("EXPORT_FAILED")
    try:
        result = subprocess.run([executable, "--version"], capture_output=True, timeout=5, check=True)
        match = re.fullmatch(rb"uv ([0-9]+\.[0-9]+\.[0-9]+).*\n", result.stdout)
        if match is None:
            raise ValueError
        return match[1].decode()
    except (OSError, subprocess.SubprocessError, ValueError):
        raise BundleError("EXPORT_FAILED") from None


def main() -> int:
    """Ephemeral validation only: never prints private bundle content or paths."""
    previous_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="dependency-evidence-24-2-") as temporary:
            result = create_bundle(Path(__file__).resolve().parents[1], Path(temporary).resolve() / "bundle")
            print(f"BUNDLE_VALIDATED runtime={result.runtime_count} development={result.development_count} lock_sha256_prefix={result.lock_sha256[:12]}")
        return 0
    except BundleError as error:
        print(error.code, file=sys.stderr)
        return 1
    except Exception:
        print("BUNDLE_VALIDATION_FAILED", file=sys.stderr)
        return 1
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
