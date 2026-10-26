"""User-facing loopback collector management contracts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from app import tcp_syslog_management as management


APPROVAL = management.SAVE_APPROVAL
DELETE_APPROVAL = management.DELETE_APPROVAL
REVEAL_APPROVAL = management.REVEAL_APPROVAL


def _free_high_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    if port >= management.MIN_PORT:
        return port
    for candidate in range(management.MIN_PORT, management.MAX_PORT + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", candidate))
            return candidate
        except OSError:
            continue
    raise RuntimeError("no test port available")


def _sandbox(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "synthetic-home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    return home


def _setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, role: str = "1") -> Path:
    _sandbox(monkeypatch, tmp_path)
    answers = iter((role, "1", str(_free_high_port()), APPROVAL))
    assert management.setup_tcp_syslog(ask=lambda _prompt: next(answers), emit=lambda _line: None) == "CREATED"
    return management.tcp_config_path()


def test_setup_requires_exact_approval_and_saves_private_closed_config(monkeypatch, tmp_path):
    _sandbox(monkeypatch, tmp_path)
    output = []
    port = _free_high_port()
    answers = iter(("1", "1", str(port), APPROVAL))
    assert management.setup_tcp_syslog(ask=lambda _prompt: next(answers), emit=output.append) == "CREATED"
    path = management.tcp_config_path()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    document = json.loads(path.read_text())
    assert set(document) == {"schema_version", "source_role", "bind_family", "port", "runtime_profile"}
    assert document["schema_version"] == "tcp-syslog-user-config/v1"
    assert document["source_role"] == "application"
    assert document["port"] == port
    assert str(path) not in "\n".join(output)
    assert str(port) not in "\n".join(output)
    assert "TLS" in "\n".join(output)


def test_setup_explains_full_safety_boundary_before_first_choice(monkeypatch, tmp_path):
    _sandbox(monkeypatch, tmp_path)
    output = []
    answers = iter(("1", "1", str(_free_high_port()), "취소"))

    def ask(prompt):
        if prompt.startswith("로그 종류"):
            first_screen = "\n".join(output)
            for required in (
                "같은 컴퓨터", "인증되지 않습니다", "TLS·mTLS", "합성 pilot",
                "중단 중 메시지는 복구되지 않습니다", "중복", "무유실",
                "제한된 메모리", "공개 화면·오류·상태", "외부 AI",
            ):
                assert required in first_screen
        return next(answers)

    assert management.setup_tcp_syslog(ask=ask, emit=output.append) == "CANCELLED"


@pytest.mark.parametrize("approval", ["", "y", "아니오"])
def test_setup_cancel_or_wrong_approval_creates_no_config(monkeypatch, tmp_path, approval):
    _sandbox(monkeypatch, tmp_path)
    answers = iter(("1", "1", str(_free_high_port()), approval))
    result = management.setup_tcp_syslog(ask=lambda _prompt: next(answers), emit=lambda _line: None)
    assert result == "CANCELLED"
    assert not management.tcp_config_path().exists()


@pytest.mark.parametrize("exception", [EOFError, KeyboardInterrupt])
def test_setup_eof_or_interrupt_during_approval_creates_no_config(monkeypatch, tmp_path, exception):
    _sandbox(monkeypatch, tmp_path)
    answers = iter(("1", "1", str(_free_high_port())))
    def ask(prompt):
        if prompt.startswith("승인"):
            raise exception
        return next(answers)
    assert management.setup_tcp_syslog(ask=ask, emit=lambda _line: None) == "CANCELLED"
    assert not management.tcp_config_path().exists()


@pytest.mark.parametrize("port", ["0", "1023", "65536", "-2", "1.2", "５５００１", " 55001"])
def test_setup_rejects_invalid_high_port_without_saving(monkeypatch, tmp_path, port):
    _sandbox(monkeypatch, tmp_path)
    answers = iter(("1", "1", port))
    with pytest.raises(management.TcpManagementError):
        management.setup_tcp_syslog(ask=lambda _prompt: next(answers), emit=lambda _line: None)
    assert not management.tcp_config_path().exists()


def test_show_hides_address_port_path_and_internal_values(monkeypatch, tmp_path):
    path = _setup(monkeypatch, tmp_path)
    output = []
    management.show_tcp_syslog(emit=output.append)
    rendered = "\n".join(output)
    assert "application" not in rendered.lower()
    assert "55001" not in rendered
    assert str(path) not in rendered
    assert "127.0.0.1" not in rendered and "::1" not in rendered
    assert "loopback 전용" in rendered
    assert "길이가 포함된 TCP 메시지" in rendered
    assert "검토 필요" not in rendered


def test_duplicate_key_unknown_field_and_corrupt_config_show_review_not_absence(monkeypatch, tmp_path):
    path = _setup(monkeypatch, tmp_path)
    raw = path.read_text()
    path.write_text(raw[:-2] + ',"unknown":"private"}\n')
    output = []
    assert management.show_tcp_syslog(emit=output.append) == "REVIEW"
    assert "검토 필요" in "\n".join(output)
    path.write_text('{"schema_version":"x","schema_version":"y"}')
    assert management.show_tcp_syslog(emit=lambda _line: None) == "REVIEW"


def test_reveal_requires_active_runtime_and_exact_local_approval(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    output = []
    assert management.reveal_tcp_endpoint(ask=lambda _prompt: REVEAL_APPROVAL,
                                           emit=output.append) == "NOT_RUNNING"
    assert not any("55001" in line for line in output)


def test_delete_exact_approval_only_removes_tcp_config(monkeypatch, tmp_path):
    path = _setup(monkeypatch, tmp_path)
    file_config = path.parent / "monitoring.json"
    checkpoint = path.parent / "checkpoint-source-000001.json"
    file_config.write_text("file-config")
    checkpoint.write_text("checkpoint")
    assert management.delete_tcp_syslog(ask=lambda _prompt: "아니오", emit=lambda _line: None) == "CANCELLED"
    assert path.exists()
    assert management.delete_tcp_syslog(ask=lambda _prompt: DELETE_APPROVAL,
                                        emit=lambda _line: None) == "DELETED"
    assert not path.exists()
    assert file_config.read_text() == "file-config" and checkpoint.read_text() == "checkpoint"


def test_management_and_file_monitor_share_mutual_exclusion_lock(monkeypatch, tmp_path, capsys):
    path = _setup(monkeypatch, tmp_path)
    lock = management.acquire_collector_lock(path)
    try:
        with pytest.raises(management.TcpManagementError) as raised:
            management._management_locks(path)
        assert raised.value.code == "COLLECTOR_BUSY"
        with pytest.raises(management.TcpManagementError) as blocked_delete:
            management.delete_tcp_syslog(ask=lambda _prompt: DELETE_APPROVAL,
                                         emit=lambda _line: None, path=path)
        assert blocked_delete.value.code == "COLLECTOR_BUSY"
        assert path.exists()
        from app import local_web
        result = local_web.run_local_web(
            monitor_config=path.parent / "file-config.json",
            default_config_resolver=lambda: path,
            listener_factory=lambda *_args: pytest.fail("file and TCP collectors must not run together"),
        )
        assert result == 4
        assert "다른 로그 수집이 실행 중입니다" in capsys.readouterr().err
    finally:
        lock.close()


def test_setup_never_overwrites_existing_config_and_busy_port_is_sanitized(monkeypatch, tmp_path):
    path = _setup(monkeypatch, tmp_path)
    original = path.read_bytes()
    with pytest.raises(management.TcpManagementError) as raised:
        management._save_config(management.TcpUserConfig(
            management.SCHEMA_VERSION, "ssh", "ipv4", 55002, management.RUNTIME_PROFILE), path)
    assert raised.value.code == "CONFIG_EXISTS"
    assert path.read_bytes() == original
    other = tmp_path / "other"
    other.mkdir()
    _sandbox(monkeypatch, other)
    busy_port = _free_high_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
        occupied.bind(("127.0.0.1", busy_port))
        answers = iter(("1", "1", str(busy_port)))
        with pytest.raises(management.TcpManagementError) as busy:
            management.setup_tcp_syslog(ask=lambda _prompt: next(answers), emit=lambda _line: None)
    assert busy.value.code == "PORT_UNAVAILABLE"
    assert str(busy_port) not in str(busy.value)


@pytest.mark.parametrize("failure", ["serialize", "open", "write", "file_fsync", "publish", "directory_fsync"])
def test_config_save_faults_fail_closed_without_leaking_exception(monkeypatch, tmp_path, failure):
    home = _sandbox(monkeypatch, tmp_path)
    path = management.tcp_config_path()
    config = management.TcpUserConfig(management.SCHEMA_VERSION, "application", "ipv4",
                                      55004, management.RUNTIME_PROFILE)
    canary = "PRIVATE_CONFIG_FAULT_CANARY"
    if failure == "serialize":
        monkeypatch.setattr(management.json, "dumps", lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError(canary)))
    elif failure == "open":
        original_open = management.os.open
        def fail_temp(name, *args, **kwargs):
            if isinstance(name, str) and name.startswith(".tcp-config-"):
                raise OSError(canary)
            return original_open(name, *args, **kwargs)
        monkeypatch.setattr(management.os, "open", fail_temp)
    elif failure == "write":
        monkeypatch.setattr(management.os, "write", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(canary)))
    elif failure in {"file_fsync", "directory_fsync"}:
        original_fsync = management.os.fsync
        calls = {"count": 0}
        def fail_fsync(fd):
            calls["count"] += 1
            if failure == "file_fsync" or calls["count"] == 2:
                raise OSError(canary)
            return original_fsync(fd)
        monkeypatch.setattr(management.os, "fsync", fail_fsync)
    elif failure == "publish":
        monkeypatch.setattr(management.os, "link", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(canary)))
    with pytest.raises(management.TcpManagementError) as raised:
        management._save_config(config, path)
    assert canary not in str(raised.value) and canary not in repr(raised.value)
    assert not path.exists()
    if path.parent.exists():
        assert not list(path.parent.glob(".tcp-config-*"))


def test_tcp_config_symlink_parent_and_target_are_reviewed_not_followed(monkeypatch, tmp_path):
    home = _sandbox(monkeypatch, tmp_path)
    expected_parent = management.tcp_config_path().parent
    expected_parent.parent.mkdir(parents=True, mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    expected_parent.symlink_to(outside, target_is_directory=True)
    assert management.show_tcp_syslog(emit=lambda _line: None) == "REVIEW"
    assert not (outside / "tcp-syslog.json").exists()


def test_tcp_management_cli_contract_is_separate_from_file_setup():
    result = subprocess.run([sys.executable, "-m", "app.monitor_setup", "--help"],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0
    for flag in ("--setup-tcp-syslog", "--show-tcp-syslog", "--run-tcp-syslog",
                 "--delete-tcp-syslog", "--reveal-tcp-syslog-endpoint"):
        assert flag in result.stdout


def test_public_cli_sources_no_raw_endpoint_or_exception(monkeypatch, tmp_path):
    path = _setup(monkeypatch, tmp_path)
    output = []
    status = management.show_tcp_syslog(emit=output.append)
    assert status == "CONFIGURED"
    assert str(path) not in repr(management.load_tcp_config())


def test_ci_has_separate_linux_management_smoke_after_reliability_step():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    reliability = workflow.index("- name: Verify bounded TCP Syslog reliability on Linux")
    management_step = workflow.index("- name: Verify TCP Syslog management pilot on Linux")
    restricted = workflow.index("- name: Verify restricted analyst report on Linux")
    assert reliability < management_step < restricted
    segment = workflow[management_step:restricted]
    assert "python tests/smoke_tcp_syslog_management_34_4.py" in segment
    assert "upload-artifact" not in segment


def test_management_document_closes_pilot_and_privacy_boundaries():
    root = Path(__file__).resolve().parents[1]
    document = (root / "docs/loopback_tcp_syslog_management_34_4.md").read_text(encoding="utf-8")
    for phrase in (
        "--setup-tcp-syslog", "--show-tcp-syslog", "--run-tcp-syslog", "--delete-tcp-syslog",
        "49152–65535", "0700", "0600", "no-clobber", "loopback", "인증되지",
        "TLS·mTLS", "중단 중", "중복", "무유실", "endpoint", "NOT_TESTED", "NO_GO",
        "공개 API", "checkpoint", "사용자 이해도",
    ):
        assert phrase in document
