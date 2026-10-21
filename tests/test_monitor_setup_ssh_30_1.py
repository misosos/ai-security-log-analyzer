"""SSH setup wizard contracts using only synthetic, temporary files."""

from pathlib import Path

import pytest

from app import monitor_setup
from app.live_monitoring.config import load_live_monitor_config, load_live_monitor_setup_config
from app.monitor_setup import MonitorSetupError, run_setup


SSH_LINES = (
    "2026-01-02 03:04:01 sshd: Failed password for synthetic from 192.0.2.1\n"
    "2026-01-02 03:04:02 sshd: Accepted password for synthetic from 192.0.2.1 port 22 ssh2\n"
    "2026-01-02 03:04:03 sshd: synthetic other event\n"
    "\n"
)


def _wizard(source: Path, output: Path, role: str = "2"):
    answers = iter(("yes", role, str(source), "yes"))
    lines: list[str] = []
    result = run_setup(output=output, ask=lambda _: next(answers), emit=lines.append)
    return result, "\n".join(lines)


def test_ssh_choice_dry_run_and_private_v2_round_trip(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "synthetic.log"
    source.write_text(SSH_LINES, encoding="utf-8")
    output = tmp_path / "private" / "monitoring.json"
    calls = []
    parser = monitor_setup.parse_live_records

    def count_parser(role, records):
        calls.append((role, len(records)))
        return parser(role, records)

    monkeypatch.setattr(monitor_setup, "parse_live_records", count_parser)
    result, text = _wizard(source, output)
    assert result.status == "CREATED" and result.source_role == "ssh"
    assert (result.dry_run.auth_failure_count, result.dry_run.auth_success_count,
            result.dry_run.other_ssh_event_count) == (1, 1, 1)
    assert result.dry_run.ignored_count == 1
    assert calls == [("ssh", 4), ("ssh", 4)]  # preview and post-approval recheck
    assert load_live_monitor_config(output).role == "ssh"
    config = load_live_monitor_setup_config(output)
    assert config.source_role == "ssh" and config.display_alias == "SSH 로그 1"
    assert config.start_position == "FROM_END" and config.checkpoint_policy == "BOUNDED_REPLAY_V1"
    assert output.parent.stat().st_mode & 0o777 == 0o700
    assert output.stat().st_mode & 0o777 == 0o600
    assert "설정 생성 완료" in text
    assert str(source) not in text and str(output) not in text


@pytest.mark.parametrize("choice", ("", "1,2", "3", "access", "linux-audit"))
def test_role_must_be_one_explicit_closed_choice(tmp_path: Path, choice: str) -> None:
    answers = iter(("yes", choice))
    with pytest.raises(MonitorSetupError) as caught:
        run_setup(output=tmp_path / "monitor.json", ask=lambda _: next(answers), emit=lambda _: None)
    assert caught.value.code == "SETUP_UNSUPPORTED_ROLE"
    assert not (tmp_path / "monitor.json").exists()


def test_ssh_existing_config_no_clobber_and_private_output(tmp_path: Path) -> None:
    source = tmp_path / "synthetic.log"
    source.write_text(SSH_LINES, encoding="utf-8")
    output = tmp_path / "private" / "monitoring.json"
    output.parent.mkdir(mode=0o700)
    output.write_bytes(b"original")
    with pytest.raises(MonitorSetupError) as caught:
        _wizard(source, output)
    assert caught.value.code == "SETUP_OUTPUT_EXISTS"
    assert output.read_bytes() == b"original"
    assert "--show" in caught.value.recovery_action
    assert "--delete" in caught.value.recovery_action
    assert "--reset-checkpoint" in caught.value.recovery_action


def test_ssh_canaries_do_not_enter_output_or_repr(tmp_path: Path) -> None:
    source = tmp_path / "synthetic.log"
    source.write_text(SSH_LINES.replace("synthetic", "private_account_marker")
                      .replace("192.0.2.1", "198.51.100.77")
                      + "2026-01-02 03:04:04 sshd: private_hostname_marker\n", encoding="utf-8")
    output = tmp_path / "private" / "monitoring.json"
    try:
        result, text = _wizard(source, output)
    except Exception:
        raise AssertionError("SSH_PRIVATE_PROJECTION_FAILED") from None
    surface = text + repr(result) + repr(result.dry_run)
    if any(marker in surface for marker in (
        "private_account_marker", "198.51.100.77", "private_hostname_marker",
        str(source), str(output))):
        pytest.fail("SSH_PRIVATE_PROJECTION_FAILED", pytrace=False)


def test_ssh_error_output_is_fixed_and_private(tmp_path: Path, capsys) -> None:
    source = tmp_path / "synthetic.log"
    source.write_bytes(b"private_account_marker private_hostname_marker 198.51.100.77\xff\n")
    answers = iter(("yes", "2", str(source)))
    result = monitor_setup.main(["--output", str(tmp_path / "private" / "monitoring.json")],
                                ask=lambda _: next(answers), emit=lambda _: None)
    output = capsys.readouterr()
    surface = output.out + output.err
    assert result == 3
    if any(marker in surface for marker in (
        "private_account_marker", "private_hostname_marker", "198.51.100.77",
        str(source))):
        pytest.fail("SSH_PRIVATE_ERROR_EXPOSED", pytrace=False)


def test_existing_application_choice_still_works(tmp_path: Path) -> None:
    source = tmp_path / "application.log"
    source.write_text("2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.1\n",
                      encoding="utf-8")
    result, _ = _wizard(source, tmp_path / "private" / "monitoring.json", "application")
    assert result.source_role == "application"


def test_ssh_bounded_lines_crlf_partial_and_unknown(tmp_path: Path) -> None:
    source = tmp_path / "synthetic.log"
    line = SSH_LINES.splitlines()[0]
    source.write_bytes(((line + "\r\n") * 20 + "trailing partial").encode())
    summary, _ = monitor_setup._preview_source(source, "ssh")
    assert summary.inspected_bytes <= 4096
    assert summary.inspected_lines == 16
    assert summary.auth_failure_count == 16
    assert summary.sample_limited
    source.write_bytes((SSH_LINES + "partial").encode())
    summary, _ = monitor_setup._preview_source(source, "ssh")
    assert summary.partial_line and summary.inspected_lines == 4
    assert summary.auth_failure_count == 1 and summary.auth_success_count == 1


def test_ssh_exact_line_and_byte_caps(tmp_path: Path) -> None:
    source = tmp_path / "synthetic.log"
    prefix = SSH_LINES.splitlines()[0]
    exact_line = prefix + " " * (2048 - len(prefix.encode()))
    source.write_bytes(exact_line.encode() + b"\n")
    summary, _ = monitor_setup._preview_source(source, "ssh")
    assert summary.inspected_lines == 1 and summary.auth_failure_count == 1
    payload = (prefix + " " * (129 - len(prefix.encode())) + "\n").encode()
    source.write_bytes(payload * 16 + b"x" * (4096 - len(payload) * 16) + b"z")
    summary, _ = monitor_setup._preview_source(source, "ssh")
    assert summary.inspected_bytes == 4096 and summary.inspected_lines == 16
    assert summary.sample_limited


def test_ssh_mixed_valid_blank_and_malformed_counts(tmp_path: Path) -> None:
    source = tmp_path / "synthetic.log"
    source.write_text(SSH_LINES + "not a timestamped ssh record\n", encoding="utf-8")
    summary, _ = monitor_setup._preview_source(source, "ssh")
    assert summary.inspected_lines == 5
    assert summary.parsed_count == 3
    assert summary.ignored_count == 1
    assert summary.rejected_count == 1


@pytest.mark.parametrize("payload,code", (
    (b"\xff\n", "SETUP_INVALID_UTF8"),
    (b"partial\xff", "SETUP_INVALID_UTF8"),
    (b"a" * 2049 + b"\n", "SETUP_LINE_TOO_LONG"),
    (b"a\x00b\n", "SETUP_BINARY_INPUT"),
))
def test_ssh_bad_input_has_fixed_error(tmp_path: Path, payload: bytes, code: str) -> None:
    source = tmp_path / "synthetic.log"
    source.write_bytes(payload)
    with pytest.raises(MonitorSetupError) as caught:
        monitor_setup._preview_source(source, "ssh")
    assert caught.value.code == code
    assert str(source) not in str(caught.value) + repr(caught.value)


def test_ssh_symlink_and_writable_parent_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "synthetic.log"
    source.write_text(SSH_LINES, encoding="utf-8")
    alias = tmp_path / "alias.log"
    alias.symlink_to(source)
    with pytest.raises(MonitorSetupError) as caught:
        monitor_setup._preview_source(alias, "ssh")
    assert caught.value.code == "SETUP_SYMLINK_REJECTED"
    parent = tmp_path / "writable"
    parent.mkdir(mode=0o700)
    nested = parent / "synthetic.log"
    nested.write_text(SSH_LINES, encoding="utf-8")
    parent.chmod(0o777)
    try:
        with pytest.raises(MonitorSetupError) as caught:
            monitor_setup._preview_source(nested, "ssh")
        assert caught.value.code == "SETUP_UNSAFE_SOURCE_PARENT"
    finally:
        parent.chmod(0o700)


def test_ssh_writable_source_and_other_owner_are_rejected(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "synthetic.log"
    source.write_text(SSH_LINES, encoding="utf-8")
    source.chmod(0o666)
    try:
        with pytest.raises(MonitorSetupError) as caught:
            monitor_setup._preview_source(source, "ssh")
        assert caught.value.code == "SETUP_PERMISSION_DENIED"
    finally:
        source.chmod(0o600)
    monkeypatch.setattr(monitor_setup.os, "geteuid", lambda: -1)
    with pytest.raises(MonitorSetupError) as caught:
        monitor_setup._preview_source(source, "ssh")
    assert caught.value.code == "SETUP_PERMISSION_DENIED"


def test_ssh_cancel_and_eof_do_not_write(tmp_path: Path) -> None:
    source = tmp_path / "synthetic.log"
    source.write_text(SSH_LINES, encoding="utf-8")
    output = tmp_path / "private" / "monitoring.json"
    answers = iter(("yes", "2", str(source), "no"))
    result = run_setup(output=output, ask=lambda _: next(answers), emit=lambda _: None)
    assert result.status == "CANCELLED" and not output.exists()
    answers = iter(("yes", "2"))

    def eof_after_role(_prompt: str) -> str:
        try:
            return next(answers)
        except StopIteration:
            raise EOFError from None

    assert monitor_setup.main(["--output", str(output)],
                              ask=eof_after_role, emit=lambda _: None) == 0
    assert not output.exists()


def test_ssh_source_replacement_after_preview_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "synthetic.log"
    source.write_text(SSH_LINES, encoding="utf-8")
    output = tmp_path / "private" / "monitoring.json"
    responses = iter(("yes", "2", str(source)))

    def answer(_prompt: str) -> str:
        try:
            return next(responses)
        except StopIteration:
            replacement = tmp_path / "replacement.log"
            replacement.write_text(SSH_LINES, encoding="utf-8")
            replacement.replace(source)
            return "yes"

    with pytest.raises(MonitorSetupError) as caught:
        run_setup(output=output, ask=answer, emit=lambda _: None)
    assert caught.value.code == "SETUP_SOURCE_CHANGED"
    assert not output.exists()


def test_ssh_dry_run_does_not_invoke_analysis(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "synthetic.log"
    source.write_text(SSH_LINES, encoding="utf-8")
    from app.detector import brute_force
    from app.analyzer import risk

    def forbidden(*_args, **_kwargs):
        raise AssertionError("analysis was invoked")

    monkeypatch.setattr(brute_force, "detect_brute_force", forbidden)
    monkeypatch.setattr(risk, "evaluate_likelihood", forbidden)
    summary, _ = monitor_setup._preview_source(source, "ssh")
    assert summary.auth_failure_count == 1
