"""Phase 20.1 default-profile management contracts."""

from pathlib import Path
import json
import os
import socket
from types import SimpleNamespace

import pytest

from app import monitor_setup
from app.live_monitoring.config import LiveMonitorConfigV2, LiveMonitorError, resolve_default_monitor_config_path
from app.live_monitoring.default_config import open_default_config
from app.live_monitoring.default_config import DefaultConfigGuard
from app.monitor_setup import MonitorSetupError, delete_default_config, show_default_config


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "source-canary.log"
    source.write_text("2026-01-02 03:04:05 INFO login_failed user=secret_user ip=192.0.2.9\n")
    config = tmp_path / "private" / "monitoring.json"
    monitor_setup.create_monitor_config(source, config)
    return source, config


def test_default_resolver_is_injected_and_cwd_independent(tmp_path: Path) -> None:
    home = tmp_path / "user home"
    assert resolve_default_monitor_config_path(platform="darwin", home=home) == (
        home / "Library/Application Support/ai-security-log-analyzer/monitoring.json"
    )
    assert resolve_default_monitor_config_path(platform="linux", home=home, xdg_config_home="") == (
        home / ".config/ai-security-log-analyzer/monitoring.json"
    )
    assert resolve_default_monitor_config_path(platform="linux", home=home,
                                                xdg_config_home=str(tmp_path / "space 配置")) == (
        tmp_path / "space 配置/ai-security-log-analyzer/monitoring.json"
    )
    with pytest.raises(LiveMonitorError):
        resolve_default_monitor_config_path(platform="win32", home=home)
    with pytest.raises(LiveMonitorError):
        resolve_default_monitor_config_path(platform="linux", home=home, xdg_config_home="relative")
    literal = resolve_default_monitor_config_path(platform="linux", home=home,
                                                  xdg_config_home=str(tmp_path / "$LITERAL"))
    assert "$LITERAL" in str(literal)  # no shell/environment expansion


def test_show_and_delete_default_config_are_explicit_and_path_free(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    sibling = config.parent / "keep.txt"
    sibling.write_text("keep")
    summary = show_default_config(config)
    assert summary.source_role == "application" and summary.source_available and summary.runnable
    assert summary.permission_ok and summary.start_position == "FROM_END"
    assert str(source) not in repr(summary) and str(config) not in repr(summary)
    assert delete_default_config(config, ask=lambda _: "yes").status == "DELETED"
    assert not config.exists() and source.exists() and config.parent.exists() and sibling.read_text() == "keep"


@pytest.mark.parametrize("role,label", (
    ("application", "애플리케이션 로그인 로그"),
    ("ssh", "SSH 인증 로그"),
))
def test_delete_approval_names_only_user_facing_targets(
    tmp_path: Path, role: str, label: str,
) -> None:
    source = tmp_path / "synthetic.log"
    line = (
        "2026-01-02 03:04:05 INFO login_failed user=secret_user ip=192.0.2.9\n"
        if role == "application" else
        "2026-01-02 03:04:05 sshd: Failed password for secret_user from 192.0.2.9\n"
    )
    source.write_text(line, encoding="utf-8")
    config = tmp_path / "private" / "monitoring.json"
    monitor_setup.create_monitor_config(source, config, role=role)
    output: list[str] = []
    prompts: list[str] = []

    def cancel(prompt: str) -> str:
        prompts.append(prompt)
        return "no"

    result = delete_default_config(config, ask=cancel, emit=output.append)
    public = "\n".join([*output, *prompts])
    if result.status != "CANCELLED" or not config.exists():
        pytest.fail("DELETE_CANCEL_CONTRACT_FAILED", pytrace=False)
    if any(phrase not in public for phrase in (
        f"{label}용 기본 설정", "연결된 복구 자료", "원본 로그 파일은 삭제하지 않습니다",
    )):
        pytest.fail("DELETE_TARGETS_NOT_CLEAR", pytrace=False)
    if any(internal in public for internal in (
        "schema", "application", "FROM_END", "원본 로그와 결과",
    )):
        pytest.fail("DELETE_INTERNAL_OR_AMBIGUOUS_TERM_VISIBLE", pytrace=False)
    if any(private in public for private in (
        str(source), str(config), "secret_user", "192.0.2.9", line.strip(),
    )):
        pytest.fail("DELETE_PRIVATE_VALUE_EXPOSED", pytrace=False)


def test_show_and_delete_cli_use_only_default_resolver(tmp_path: Path, monkeypatch, capsys) -> None:
    source, config = _fixture(tmp_path)
    monkeypatch.setattr(monitor_setup, "resolve_default_monitor_config_path", lambda: config)
    assert monitor_setup.main(["--show"]) == 0
    shown = capsys.readouterr()
    assert "애플리케이션 로그인 로그" in shown.out and "새 줄부터 시작" in shown.out
    for private in (str(source), str(config), "secret_user", "192.0.2.9", "source-canary"):
        assert private not in shown.out + shown.err
    assert monitor_setup.main(["--delete"], ask=lambda _: "NO") == 0
    assert config.exists() and capsys.readouterr().err == ""
    assert monitor_setup.main(["--delete"], ask=lambda _: " yes ") == 0
    deleted = capsys.readouterr()
    assert not config.exists() and str(source) not in deleted.out + deleted.err
    assert monitor_setup.main(["--show"]) == 3
    assert "app.monitor_setup" in capsys.readouterr().err


def test_delete_eof_cancels_without_unlink(tmp_path: Path, monkeypatch, capsys) -> None:
    _, config = _fixture(tmp_path)
    monkeypatch.setattr(monitor_setup, "resolve_default_monitor_config_path", lambda: config)
    assert monitor_setup.main(["--delete"], ask=lambda _: (_ for _ in ()).throw(EOFError)) == 0
    assert config.exists() and capsys.readouterr().err == ""


@pytest.mark.parametrize("args", (["--show", "--delete"], ["--show", "--output", "/tmp/config"],
                                  ["--delete", "--output", "/tmp/config"], ["--unknown"]))
def test_management_cli_modes_conflict(args: list[str], capsys) -> None:
    assert monitor_setup.main(args) == 2
    assert "SETUP_INVALID_INPUT" in capsys.readouterr().err


@pytest.mark.parametrize("mutation,code", [
    ("mode", "DEFAULT_CONFIG_PERMISSION"), ("symlink", "DEFAULT_CONFIG_SYMLINK"),
    ("directory", "DEFAULT_CONFIG_TYPE"), ("fifo", "DEFAULT_CONFIG_TYPE"),
    ("malformed", "DEFAULT_CONFIG_MALFORMED"), ("schema", "DEFAULT_CONFIG_SCHEMA"),
    ("unknown", "DEFAULT_CONFIG_MALFORMED"), ("large", "DEFAULT_CONFIG_TOO_LARGE"),
    ("parent", "DEFAULT_CONFIG_UNSAFE_PARENT"),
])
def test_unsafe_config_is_never_shown_or_deleted(tmp_path: Path, mutation: str, code: str) -> None:
    source, config = _fixture(tmp_path)
    if mutation == "mode":
        config.chmod(0o644)
    elif mutation == "symlink":
        config.unlink()
        config.symlink_to(source)
    elif mutation == "directory":
        config.unlink()
        config.mkdir()
    elif mutation == "fifo":
        config.unlink()
        os.mkfifo(config)
    elif mutation == "malformed":
        config.write_text("{bad", encoding="utf-8")
    elif mutation == "schema":
        document = LiveMonitorConfigV2(source).as_document()
        document["schema_version"] = "1"
        config.write_text(json.dumps(document), encoding="utf-8")
    elif mutation == "unknown":
        document = LiveMonitorConfigV2(source).as_document()
        document["secret"] = "private"
        config.write_text(json.dumps(document), encoding="utf-8")
    elif mutation == "large":
        config.write_bytes(b"x" * 4097)
    elif mutation == "parent":
        config.parent.chmod(0o755)
    for operation in (show_default_config, lambda path: delete_default_config(path, ask=lambda _: "yes")):
        with pytest.raises(MonitorSetupError) as caught:
            operation(config)
        assert caught.value.code == code
        assert str(config) not in str(caught.value) + repr(caught.value)
    assert config.exists() and source.exists()


def test_symlink_parent_and_missing_are_fixed_failures(tmp_path: Path) -> None:
    _, config = _fixture(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(config.parent, target_is_directory=True)
    with pytest.raises(MonitorSetupError) as caught:
        show_default_config(alias / config.name)
    assert caught.value.code == "DEFAULT_CONFIG_UNSAFE_PARENT"
    with pytest.raises(MonitorSetupError) as caught:
        delete_default_config(tmp_path / "missing" / "monitoring.json", ask=lambda _: "yes")
    assert caught.value.code == "DEFAULT_CONFIG_MISSING"


def test_other_owner_is_rejected_without_opening_file(tmp_path: Path, monkeypatch) -> None:
    from app.live_monitoring import default_config
    _, config = _fixture(tmp_path)
    real_stat = os.stat
    def foreign_named(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if path == config.name and kwargs.get("dir_fd") is not None:
            return SimpleNamespace(**{key: getattr(result, key) for key in (
                "st_dev", "st_ino", "st_mode", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")},
                                   st_gid=result.st_gid)
        return result
    # A foreign owner is validated independently of group/other mode.
    def foreign_owner(path, *args, **kwargs):
        result = foreign_named(path, *args, **kwargs)
        if path == config.name and kwargs.get("dir_fd") is not None:
            result.st_uid += 1
        return result
    monkeypatch.setattr(default_config.os, "stat", foreign_owner)
    with pytest.raises(LiveMonitorError) as caught:
        open_default_config(config)
    assert caught.value.code == "DEFAULT_CONFIG_PERMISSION"


def test_source_unavailable_is_safe_show_not_auto_repair(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    source.unlink()
    summary = show_default_config(config)
    assert not summary.source_available and not summary.runnable and config.exists()


def test_source_symlink_replacement_is_not_reported_runnable(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    replacement = source.parent / "replacement.log"
    replacement.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(replacement)
    assert not show_default_config(config).runnable


def test_replacement_during_show_and_approval_fails_closed(tmp_path: Path) -> None:
    _, config = _fixture(tmp_path)
    with open_default_config(config) as guard:
        replacement = config.parent / "replacement"
        replacement.write_bytes(config.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, config)
        with pytest.raises(LiveMonitorError) as caught:
            guard.check()
        assert caught.value.code == "DEFAULT_CONFIG_CHANGED"
    _, config = _fixture(tmp_path / "second")
    def replace_during_approval(_prompt: str) -> str:
        replacement = config.parent / "replacement"
        replacement.write_bytes(config.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, config)
        return "yes"
    with pytest.raises(MonitorSetupError) as caught:
        delete_default_config(config, ask=replace_during_approval, emit=lambda _: None)
    assert caught.value.code == "DEFAULT_CONFIG_CHANGED" and config.exists()


def test_two_deletes_cannot_both_succeed(tmp_path: Path) -> None:
    _, config = _fixture(tmp_path)
    def competitor(_prompt: str) -> str:
        assert delete_default_config(config, ask=lambda _: "yes", emit=lambda _: None).status == "DELETED"
        return "yes"
    with pytest.raises(MonitorSetupError):
        delete_default_config(config, ask=competitor, emit=lambda _: None)
    assert not config.exists()


def test_setup_cannot_overwrite_while_delete_confirmation_waits(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    def competing_setup(_prompt: str) -> str:
        with pytest.raises(MonitorSetupError) as caught:
            monitor_setup.create_monitor_config(source, config)
        assert caught.value.code == "SETUP_OUTPUT_EXISTS"
        return "no"
    assert delete_default_config(config, ask=competing_setup, emit=lambda _: None).status == "CANCELLED"
    assert config.exists()


def test_delete_unlink_failure_keeps_file(tmp_path: Path, monkeypatch) -> None:
    _, config = _fixture(tmp_path)
    real_unlink = os.unlink
    def fail_unlink(path, *, dir_fd=None):
        if path == config.name and dir_fd is not None:
            raise OSError("private exception")
        return real_unlink(path, dir_fd=dir_fd)
    monkeypatch.setattr(os, "unlink", fail_unlink)
    with pytest.raises(MonitorSetupError) as caught:
        delete_default_config(config, ask=lambda _: "yes", emit=lambda _: None)
    assert caught.value.code == "DEFAULT_CONFIG_DELETE_FAILED" and config.exists()
    assert "private exception" not in str(caught.value)


def test_replacement_immediately_before_unlink_is_rejected(tmp_path: Path, monkeypatch) -> None:
    _, config = _fixture(tmp_path)
    original = DefaultConfigGuard.unlink
    def replace_then_unlink(guard: DefaultConfigGuard) -> None:
        replacement = config.parent / "replacement"
        replacement.write_bytes(config.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, config)
        original(guard)
    monkeypatch.setattr(DefaultConfigGuard, "unlink", replace_then_unlink)
    with pytest.raises(MonitorSetupError) as caught:
        delete_default_config(config, ask=lambda _: "yes", emit=lambda _: None)
    assert caught.value.code == "DEFAULT_CONFIG_CHANGED" and config.exists()


def test_post_delete_fsync_failure_is_not_reported_as_success(tmp_path: Path, monkeypatch) -> None:
    _, config = _fixture(tmp_path)
    monkeypatch.setattr(os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("private")))
    with pytest.raises(MonitorSetupError) as caught:
        delete_default_config(config, ask=lambda _: "yes", emit=lambda _: None)
    assert caught.value.code == "DEFAULT_CONFIG_POST_DELETE_FAILED"
    assert "private" not in str(caught.value) and not config.exists()


def test_show_detects_replacement_during_source_check(tmp_path: Path, monkeypatch) -> None:
    _, config = _fixture(tmp_path)
    original = monitor_setup.source_available
    def replace_during_source_check(document):
        replacement = config.parent / "replacement"
        replacement.write_bytes(config.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, config)
        return original(document)
    monkeypatch.setattr(monitor_setup, "source_available", replace_during_source_check)
    with pytest.raises(MonitorSetupError) as caught:
        show_default_config(config)
    assert caught.value.code == "DEFAULT_CONFIG_CHANGED"


def test_management_does_not_enter_analysis_or_network(tmp_path: Path, monkeypatch) -> None:
    from app.analyzer import pipeline, html_report
    from app.live_monitoring import runner
    import subprocess
    import webbrowser

    def forbidden(*_args, **_kwargs):
        raise AssertionError("management crossed an unrelated boundary")

    for name in ("detect_attacks", "correlate_attacks", "assess_risk"):
        monkeypatch.setattr(pipeline, name, forbidden)
    monkeypatch.setattr(html_report, "render_investigation_report_html", forbidden)
    monkeypatch.setattr(runner.LiveMonitoringRunner, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(webbrowser, "open", forbidden)
    _, config = _fixture(tmp_path)
    assert show_default_config(config).runnable
    assert delete_default_config(config, ask=lambda _: "yes", emit=lambda _: None).status == "DELETED"
