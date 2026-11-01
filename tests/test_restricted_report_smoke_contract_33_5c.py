"""Characterize the restricted-report smoke inputs and safe diagnostics."""

from pathlib import Path

import pytest
from app.parser.ssh_auth import parse_ssh_auth_log
from tests import smoke_restricted_report_33_5c as smoke


ROOT = Path(__file__).resolve().parents[1]


def test_ssh_smoke_fixture_uses_supported_message_tail():
    from tests.smoke_restricted_report_33_5c import SSH_SMOKE_LINE

    event = parse_ssh_auth_log(SSH_SMOKE_LINE, "UTC")

    assert event.event_type == "login_failed"
    assert event.user == "account-canary-5c"
    assert event.src_ip == "2001:db8::55"
    assert event.authentication is not None


def test_unseparated_canary_suffix_is_not_treated_as_authentication():
    old_smoke_line = (
        "2026-09-14 11:00:01 sshd Failed password for account-canary-5c "
        "from 2001:db8::55 port 22 ssh2 host-canary-5c raw-line-canary-5c "
        "credential-canary-5c rationale-canary-5c exception-canary-5c"
    )

    event = parse_ssh_auth_log(old_smoke_line, "UTC")

    assert event.event_type is None
    assert event.user is None
    assert event.src_ip is None
    assert event.authentication is None


def test_smoke_failure_diagnostic_is_fixed_and_staged():
    smoke = (ROOT / "tests/smoke_restricted_report_33_5c.py").read_text(encoding="utf-8")

    assert "RESTRICTED_REPORT_LINUX_SMOKE_FAIL stage=" in smoke
    assert "category=" in smoke
    assert "RESTRICTED_REPORT_LINUX_SMOKE_PASS roles=" in smoke


def test_non_linux_guard_reports_only_fixed_stage_and_category(monkeypatch, capsys):
    monkeypatch.setattr(smoke.sys, "platform", "darwin")

    with pytest.raises(SystemExit) as failure:
        smoke.main()

    assert failure.value.code == 1
    assert capsys.readouterr().out.strip() == (
        "RESTRICTED_REPORT_LINUX_SMOKE_FAIL stage=linux_platform category=platform"
    )
