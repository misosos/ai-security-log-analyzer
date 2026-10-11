import json
import os
from pathlib import Path

import pytest

from app.live_monitoring import LiveMonitorConfig, LiveMonitorError, load_live_monitor_config
from app.live_monitoring.config import CONFIG_MAX_BYTES


def _write_config(tmp_path: Path, *, source: dict | None = None, text: str | None = None) -> Path:
    path = tmp_path / "monitor.json"
    if text is None:
        text = json.dumps({
            "schema_version": "1", "source": source or {
                "role": "application", "path": str((tmp_path / "source.log").resolve()),
            }, "start_policy": "FROM_END",
        })
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path.resolve()


@pytest.mark.parametrize("role", ("application", "ssh", "access"))
def test_valid_closed_config_for_each_role(tmp_path, role):
    source_path = (tmp_path / "source.log").resolve()
    config = load_live_monitor_config(_write_config(
        tmp_path, source={"role": role, "path": str(source_path)},
    ))
    assert config == LiveMonitorConfig(role=role, path=source_path)
    assert str(source_path) not in repr(config)
    assert config.start_policy == "FROM_END"


@pytest.mark.parametrize("value", (
    '{}',
    '{"schema_version":"1","source":{},"start_policy":"FROM_END","other":1}',
    '{"schema_version":"1","source":{"role":"application"},"start_policy":"FROM_END"}',
    '{"schema_version":"1","source":{"role":"application","path":"/tmp/x","extra":1},"start_policy":"FROM_END"}',
    '[]',
    '{"schema_version":"1","schema_version":"1","source":{},"start_policy":"FROM_END"}',
    '{"schema_version":"1","source":{},"start_policy":"FROM_END","n":NaN}',
    '{"schema_version":"1","source":{},"start_policy":"FROM_END","n":Infinity}',
))
def test_closed_json_rejects_unknown_missing_duplicate_and_nonstandard(tmp_path, value):
    with pytest.raises(LiveMonitorError) as raised:
        load_live_monitor_config(_write_config(tmp_path, text=value))
    assert raised.value.code in {"INVALID_CONFIG", "DUPLICATE_JSON_KEY"}


@pytest.mark.parametrize(("key", "value", "code"), (
    ("schema_version", 1, "UNSUPPORTED_SCHEMA"),
    ("schema_version", True, "UNSUPPORTED_SCHEMA"),
    ("schema_version", "2", "UNSUPPORTED_SCHEMA"),
    ("start_policy", "FROM_START", "UNSUPPORTED_START_POLICY"),
    ("start_policy", False, "UNSUPPORTED_START_POLICY"),
))
def test_schema_and_policy_fail_closed(tmp_path, key, value, code):
    raw = {
        "schema_version": "1", "source": {
            "role": "application", "path": str((tmp_path / "source.log").resolve()),
        }, "start_policy": "FROM_END",
    }
    raw[key] = value
    with pytest.raises(LiveMonitorError) as raised:
        load_live_monitor_config(_write_config(tmp_path, text=json.dumps(raw)))
    assert raised.value.code == code


@pytest.mark.parametrize(("role", "code"), (
    ("linux_audit", "UNSUPPORTED_ROLE"), ("APPLICATION_AUTH", "UNSUPPORTED_ROLE"),
    (True, "UNSUPPORTED_ROLE"), ("", "UNSUPPORTED_ROLE"),
))
def test_role_is_an_exact_allowlist(tmp_path, role, code):
    with pytest.raises(LiveMonitorError) as raised:
        load_live_monitor_config(_write_config(
            tmp_path, source={"role": role, "path": str((tmp_path / "x").resolve())},
        ))
    assert raised.value.code == code


@pytest.mark.parametrize("path", ("", "relative.log", "/tmp/../x", "/tmp//x", "/"))
def test_path_must_be_clean_absolute(tmp_path, path):
    with pytest.raises(LiveMonitorError) as raised:
        load_live_monitor_config(_write_config(
            tmp_path, source={"role": "application", "path": path},
        ))
    assert raised.value.code == "NON_ABSOLUTE_PATH"


def test_config_size_exact_boundary_and_one_over(tmp_path):
    path = _write_config(tmp_path)
    base = path.read_bytes()
    path.write_bytes(base + b" " * (CONFIG_MAX_BYTES - len(base)))
    assert load_live_monitor_config(path).role == "application"
    path.write_bytes(base + b" " * (CONFIG_MAX_BYTES + 1 - len(base)))
    with pytest.raises(LiveMonitorError) as raised:
        load_live_monitor_config(path)
    assert raised.value.code == "CONFIG_TOO_LARGE"


def test_invalid_utf8_and_config_symlink_rejected(tmp_path):
    path = _write_config(tmp_path)
    path.write_bytes(b"\xff")
    with pytest.raises(LiveMonitorError) as raised:
        load_live_monitor_config(path)
    assert raised.value.code == "INVALID_UTF8"
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    with pytest.raises(LiveMonitorError) as raised:
        load_live_monitor_config(alias)
    assert raised.value.code == "SYMLINK_REJECTED"


def test_config_regular_owner_only_and_missing(tmp_path):
    path = _write_config(tmp_path)
    path.chmod(0o644)
    with pytest.raises(LiveMonitorError) as raised:
        load_live_monitor_config(path)
    assert raised.value.code == "PERMISSION_DENIED"
    with pytest.raises(LiveMonitorError) as raised:
        load_live_monitor_config(tmp_path / "missing.json")
    assert raised.value.code == "CONFIG_UNAVAILABLE"
    with pytest.raises(LiveMonitorError):
        load_live_monitor_config(tmp_path.resolve())


def test_unsafe_platform_is_fail_closed(tmp_path, monkeypatch):
    path = _write_config(tmp_path)
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with pytest.raises(LiveMonitorError) as raised:
        load_live_monitor_config(path)
    assert raised.value.code == "UNSAFE_PLATFORM"


def test_parent_symlink_is_rejected_for_config_and_source(tmp_path):
    real_directory = (tmp_path / "real").resolve()
    real_directory.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real_directory, target_is_directory=True)
    config = _write_config(real_directory)
    with pytest.raises(LiveMonitorError) as raised:
        load_live_monitor_config(alias / config.name)
    assert raised.value.code == "SYMLINK_REJECTED"


def test_final_symlink_swap_between_stat_and_open_is_rejected(tmp_path, monkeypatch):
    import app.live_monitoring.config as module

    source = (tmp_path / "source.log").resolve()
    source.write_bytes(b"safe\n")
    original_stat = os.stat
    swapped = False

    def swap_after_stat(name, *args, **kwargs):
        nonlocal swapped
        result = original_stat(name, *args, **kwargs)
        if name == source.name and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            backup = tmp_path / "backup.log"
            os.replace(source, backup)
            source.symlink_to(backup)
        return result

    monkeypatch.setattr(module.os, "stat", swap_after_stat)
    with pytest.raises(LiveMonitorError) as raised:
        module._open_regular(source)
    assert swapped is True
    assert raised.value.code == "SYMLINK_REJECTED"
