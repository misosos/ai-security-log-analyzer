from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "packaging" / "ai-security-log-analyzer.spec"
ENTRYPOINT = ROOT / "scripts" / "standalone_entrypoint.py"
BUILDER = ROOT / "scripts" / "build_standalone.py"


def _builder_module():
    spec = importlib.util.spec_from_file_location("standalone_builder", BUILDER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_prototype_uses_onedir_and_does_not_enable_onefile():
    assert SPEC.is_file()
    source = SPEC.read_text(encoding="utf-8")
    assert "COLLECT(" in source
    assert "onefile" not in source.lower()
    assert "EXE(" in source


def test_runtime_data_is_an_explicit_allowlist_with_no_repository_glob():
    builder = _builder_module()
    expected = {
        "frontend/index.html",
        "frontend/style.css",
        "frontend/app.js",
        "data/account_metadata.json",
        "app/knowledge_corpus_33_1/corpus.json",
        "app/knowledge_corpus_33_1/manifest.json",
        "sample_logs/brute_force.log",
        "sample_logs/ssh_auth.log",
        "sample_logs/web_shell.log",
        "frontend/input-quality-ui-36-12b.js",
        "frontend/review-queue-ui-36-13a.js",
        "frontend/investigation-review-state-36-14d.js",
        "frontend/linux-audit.js",
        "frontend/live-monitoring.js",
        "frontend/multi-source-live.js",
    }
    assert set(builder.RUNTIME_ASSET_ALLOWLIST) == expected
    assert all("*" not in item for item in builder.RUNTIME_ASSET_ALLOWLIST)
    assert all((ROOT / item).is_file() and not (ROOT / item).is_symlink() for item in builder.RUNTIME_ASSET_ALLOWLIST)
    assert not any(item.startswith(("tests/", "docs/")) for item in builder.RUNTIME_ASSET_ALLOWLIST)
    assert {item for item in builder.RUNTIME_ASSET_ALLOWLIST if item.startswith("sample_logs/")} == {
        "sample_logs/brute_force.log",
        "sample_logs/ssh_auth.log",
        "sample_logs/web_shell.log",
    }


def test_entrypoint_reuses_local_web_and_has_no_host_override():
    assert ENTRYPOINT.is_file()
    source = ENTRYPOINT.read_text(encoding="utf-8")
    assert source.index("multiprocessing.freeze_support()") < source.index("from app.local_web import main")
    assert "raise SystemExit(main())" in source
    launcher = (ROOT / "app" / "local_web.py").read_text(encoding="utf-8")
    assert 'HOST = "127.0.0.1"' in launcher
    assert "reload=False, workers=1" in launcher
    assert "proxy_headers=False" in launcher
    assert "host=HOST" in launcher


def test_spec_datas_match_the_builder_allowlist():
    import ast

    builder = _builder_module()
    source = SPEC.read_text(encoding="utf-8")
    module = ast.parse(source)
    assignment = next(node for node in module.body if isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == "ASSETS" for target in node.targets
    ))
    listed = tuple(ast.literal_eval(item) for item in assignment.value.elts)
    assert listed == builder.RUNTIME_ASSET_ALLOWLIST
    assert "--host" not in source
    assert "127.0.0.1" not in source  # bind contract remains owned by app.local_web


def test_manifest_contains_only_relative_inventory_and_is_deterministic(tmp_path):
    builder = _builder_module()
    (tmp_path / "z.txt").write_text("z", encoding="utf-8")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    first = builder.build_manifest(tmp_path, platform_name="test", architecture="arm64", python_version="3.12", pyinstaller_version="6.22.3")
    second = builder.build_manifest(tmp_path, platform_name="test", architecture="arm64", python_version="3.12", pyinstaller_version="6.22.3")
    assert first == second
    assert [entry["path"] for entry in first["files"]] == ["a.txt", "z.txt"]
    assert all(not Path(entry["path"]).is_absolute() and ".." not in Path(entry["path"]).parts for entry in first["files"])
    assert {"schema_version", "application_version", "platform", "architecture", "python_version", "pyinstaller_version", "files"} == set(first)
    assert all(set(entry) == {"path", "file_type", "size_bytes", "sha256"} for entry in first["files"])
    assert not re.search(r"/Users/|/private/var/|/tmp/", json.dumps(first))


def test_manifest_accepts_only_internal_relative_symlinks(tmp_path):
    builder = _builder_module()
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "target.bin").write_bytes(b"synthetic")
    (root / "inside-link").symlink_to("target.bin")
    manifest = builder.build_manifest(root, platform_name="test", architecture="test", python_version="3.12", pyinstaller_version="6.22.3")
    link = next(item for item in manifest["files"] if item["path"] == "inside-link")
    assert link["file_type"] == "symbolic_link"
    (tmp_path / "outside").write_text("blocked", encoding="utf-8")
    (root / "outside-link").symlink_to("../../outside")
    with pytest.raises(ValueError):
        builder.build_manifest(root, platform_name="test", architecture="test", python_version="3.12", pyinstaller_version="6.22.3")


def test_destructive_clean_refuses_symlinks_and_paths_outside_exact_dist_target(tmp_path):
    builder = _builder_module()
    repo = tmp_path / "repo"
    dist = repo / "dist"
    dist.mkdir(parents=True)
    expected = dist / "ai-security-log-analyzer"
    assert builder.validate_output_directory(repo, expected) == expected
    with pytest.raises(ValueError):
        builder.validate_output_directory(repo, repo / "dist" / "other")
    with pytest.raises(ValueError):
        builder.validate_output_directory(repo, repo / "outside")
    target = dist / "link"
    target.symlink_to(repo, target_is_directory=True)
    with pytest.raises(ValueError):
        builder.validate_output_directory(repo, target)
    work = repo / "build" / "pyinstaller-onedir-36-15b"
    assert builder.validate_work_directory(repo, work) == work
    with pytest.raises(ValueError):
        builder.validate_work_directory(repo, repo / "outside")
