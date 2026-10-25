"""Synthetic-only contract tests for the restricted analyst report CLI."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest


APPROVAL = "제한된 내부 보고서 생성을 승인합니다"


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _child_env(private: Path, timezone_name: str = "UTC") -> dict[str, str]:
    home = private / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    home.chmod(0o700)
    return {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TZ": timezone_name,
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _run(tmp_path: Path, role: str, log_line: str, approval: str = APPROVAL):
    private = _private_dir(tmp_path / "private")
    source = private / "synthetic-input.log"
    source.write_text(log_line + "\n", encoding="utf-8")
    source.chmod(0o600)
    output = private / "restricted.json"
    command = [
        sys.executable, "-m", "app.restricted_report",
        "--source-role", role,
        "--input", str(source),
        "--output", str(output),
    ]
    result = subprocess.run(
        command,
        input=approval + "\n" if approval is not None else "",
        text=True,
        capture_output=True,
        check=False,
        env=_child_env(private),
    )
    return result, output, private


def test_restricted_export_requires_exact_interactive_approval(tmp_path):
    result, output, private = _run(
        tmp_path, "application",
        "2026-09-11 10:00:01 INFO login_failed user=pilot-account-7 ip=192.0.2.77 hostname=pilot-host-9 file=/private/pilot/secret.log credential=token-canary exception=internal-canary raw-canary",
        "아니오",
    )
    assert result.returncode != 0
    assert not output.exists()
    assert list(private.glob("*.tmp")) == []
    assert "pilot-account-7" not in result.stdout + result.stderr
    assert "192.0.2.77" not in result.stdout + result.stderr
    assert not (private / ".restricted-report-audit.jsonl").exists()


def test_restricted_export_is_private_closed_json_and_never_overwrites(tmp_path):
    result, output, private = _run(
        tmp_path, "application",
        "2026-09-11 10:00:01 INFO login_failed user=pilot-account-7 ip=192.0.2.77 hostname=pilot-host-9 file=/private/pilot/secret.log credential=token-canary exception=internal-canary raw-canary",
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert set(report) == {
        "schema_version", "report_id", "generated_at", "source_role",
        "classification", "encryption_status", "limitations", "subjects",
        "observations", "relations", "risks", "cases", "audit_summary",
    }
    assert report["source_role"] == "application"
    serialized = output.read_text(encoding="utf-8")
    assert "pilot-account-7" in serialized
    assert "192.0.2.77" in serialized
    for canary in ("synthetic-input.log", "/private/pilot/secret.log", "pilot-host-9", "token-canary", "internal-canary", "raw-canary"):
        assert canary not in serialized
    assert str(private) not in serialized
    assert output.stat().st_mode & 0o777 == 0o600
    audit = private / ".restricted-report-audit.jsonl"
    assert audit.stat().st_mode & 0o777 == 0o600
    audit_text = audit.read_text(encoding="utf-8")
    for canary in ("pilot-account-7", "192.0.2.77", "pilot-host-9", "/private/pilot/secret.log", "token-canary", "internal-canary", "raw-canary", str(private)):
        assert canary not in audit_text
    assert str(private) not in result.stdout + result.stderr
    before = output.read_bytes()
    audit_before = audit.read_bytes()
    retry = subprocess.run(
        result.args,
        input=APPROVAL + "\n",
        text=True,
        capture_output=True,
        check=False,
        env=_child_env(private),
    )
    assert retry.returncode != 0
    assert output.read_bytes() == before
    assert audit.read_bytes() == audit_before


def test_restricted_export_accepts_only_explicit_synthetic_source_roles(tmp_path):
    samples = {
        "application": "2026-09-11 10:00:01 INFO login_failed user=app-user ip=192.0.2.8",
        "ssh": "2026-09-14 11:00:01 sshd Failed password for ssh-user from 2001:db8::8 port 22 ssh2",
        "access": '192.0.2.9 - - [14/Sep/2026:12:00:01 +0900] "GET /index.php HTTP/1.1" 200 1024 "-" "pilot-agent"',
    }
    for role, line in samples.items():
        case_dir = _private_dir(tmp_path / role)
        source = case_dir / "input.log"
        source.write_text(line + "\n", encoding="utf-8")
        source.chmod(0o600)
        output = case_dir / "out.json"
        result = subprocess.run(
            [sys.executable, "-m", "app.restricted_report", "--source-role", role,
             "--input", str(source), "--output", str(output)],
            input=APPROVAL + "\n", text=True, capture_output=True,
            check=False, env=_child_env(case_dir, "Asia/Seoul"),
        )
        assert result.returncode == 0, role
        report = json.loads(output.read_text(encoding="utf-8"))
        assert report["source_role"] == role
        assert report["generated_at"].endswith(("Z", "+00:00", "+09:00"))
        identifiers = [identifier for subject in report["subjects"] for identifier in subject["identifiers"]]
        if role == "ssh":
            assert {"kind": "account", "value": "ssh-user"} in identifiers
            assert {"kind": "ipv6", "value": "2001:db8::8"} in identifiers
        elif role == "application":
            assert {"kind": "account", "value": "app-user"} in identifiers
            assert {"kind": "ipv4", "value": "192.0.2.8"} in identifiers
        else:
            assert {"kind": "ipv4", "value": "192.0.2.9"} in identifiers


def test_input_symlink_is_rejected_without_sensitive_error(tmp_path):
    private = _private_dir(tmp_path / "private")
    real = private / "real.log"
    real.write_text("2026-09-11 10:00:01 INFO login_failed user=private-user ip=192.0.2.4\n")
    real.chmod(0o600)
    link = private / "linked.log"
    link.symlink_to(real)
    output = private / "out.json"
    result = subprocess.run(
        [sys.executable, "-m", "app.restricted_report", "--source-role", "application",
         "--input", str(link), "--output", str(output)],
        input=APPROVAL + "\n", text=True, capture_output=True,
        check=False, env=_child_env(private),
    )
    assert result.returncode != 0
    assert not output.exists()
    assert "private-user" not in result.stdout + result.stderr
    assert str(link) not in result.stdout + result.stderr


def test_input_hardlink_and_non_private_permissions_are_rejected(tmp_path):
    private = _private_dir(tmp_path / "private")
    source = private / "source.log"
    source.write_text("2026-09-11 10:00:01 INFO login_failed user=hardlink-user ip=192.0.2.6\n")
    source.chmod(0o600)
    linked = private / "linked.log"
    os.link(source, linked)
    out = private / "out.json"
    command = [sys.executable, "-m", "app.restricted_report", "--source-role", "application", "--input", str(source), "--output", str(out)]
    result = subprocess.run(command, input=APPROVAL + "\n", text=True, capture_output=True, check=False, env=_child_env(private))
    assert result.returncode != 0
    assert not out.exists()
    linked.unlink()
    source.chmod(0o644)
    result = subprocess.run(command, input=APPROVAL + "\n", text=True, capture_output=True, check=False, env=_child_env(private))
    assert result.returncode != 0
    assert not out.exists()
    assert "hardlink-user" not in result.stderr


def test_output_no_clobber_and_parent_must_be_private(tmp_path):
    private = _private_dir(tmp_path / "private")
    source = private / "input.log"
    source.write_text("2026-09-11 10:00:01 INFO login_failed user=pilot ip=192.0.2.1\n")
    source.chmod(0o600)
    output = private / "existing.json"
    output.write_text("keep")
    output.chmod(0o600)
    result = subprocess.run(
        [sys.executable, "-m", "app.restricted_report", "--source-role", "application", "--input", str(source), "--output", str(output)],
        input=APPROVAL + "\n", text=True, capture_output=True, check=False,
        env=_child_env(private),
    )
    assert result.returncode != 0
    assert output.read_text() == "keep"
    unsafe = _private_dir(tmp_path / "unsafe")
    unsafe.chmod(0o755)
    result = subprocess.run(
        [sys.executable, "-m", "app.restricted_report", "--source-role", "application", "--input", str(source), "--output", str(unsafe / "out.json")],
        input=APPROVAL + "\n", text=True, capture_output=True, check=False,
        env=_child_env(unsafe),
    )
    assert result.returncode != 0
    assert not (unsafe / "out.json").exists()


def test_oversized_line_fails_whole_export_and_audit_has_closed_fields(tmp_path):
    private = _private_dir(tmp_path / "private")
    source = private / "oversized.log"
    source.write_text("x" * 16385 + "\n", encoding="utf-8")
    source.chmod(0o600)
    output = private / "out.json"
    result = subprocess.run(
        [sys.executable, "-m", "app.restricted_report", "--source-role", "application", "--input", str(source), "--output", str(output)],
        input=APPROVAL + "\n", text=True, capture_output=True, check=False,
        env=_child_env(private),
    )
    assert result.returncode != 0
    assert not output.exists()
    audit = json.loads((private / ".restricted-report-audit.jsonl").read_text().splitlines()[-1])
    assert set(audit) == {
        "status", "occurred_at", "schema_version", "source_role", "report_id",
        "identifier_counts", "case_count", "relation_count", "observation_count",
    }
    assert audit["status"] == "failure"


def test_eof_and_sigint_cancel_without_publishing_report(tmp_path):
    private = _private_dir(tmp_path / "private")
    source = private / "input.log"
    source.write_text("2026-09-11 10:00:01 INFO login_failed user=cancel-user ip=192.0.2.2\n")
    source.chmod(0o600)
    output = private / "out.json"
    command = [sys.executable, "-m", "app.restricted_report", "--source-role", "application", "--input", str(source), "--output", str(output)]
    eof = subprocess.run(command, input="", text=True, capture_output=True, check=False, env=_child_env(private))
    assert eof.returncode != 0
    assert not output.exists()
    assert not (private / ".restricted-report-audit.jsonl").exists()
    assert "cancel-user" not in eof.stdout + eof.stderr

    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=_child_env(private))
    time.sleep(0.15)
    process.send_signal(signal.SIGINT)
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode != 0
    assert not output.exists()
    assert not (private / ".restricted-report-audit.jsonl").exists()
    assert "cancel-user" not in stdout + stderr
    assert not list(private.glob(".restricted-*.tmp"))


def test_output_symlink_and_hardlink_targets_are_not_replaced(tmp_path):
    private = _private_dir(tmp_path / "private")
    source = private / "input.log"
    source.write_text("2026-09-11 10:00:01 INFO login_failed user=output-user ip=192.0.2.3\n")
    source.chmod(0o600)
    preserved = private / "preserved"
    preserved.write_text("unchanged")
    preserved.chmod(0o600)
    for target in (private / "symlink.json", private / "hardlink.json"):
        if target.name.startswith("symlink"):
            target.symlink_to(preserved)
        else:
            os.link(preserved, target)
        result = subprocess.run(
            [sys.executable, "-m", "app.restricted_report", "--source-role", "application", "--input", str(source), "--output", str(target)],
            input=APPROVAL + "\n", text=True, capture_output=True, check=False,
            env=_child_env(private),
        )
        assert result.returncode != 0
        assert preserved.read_text() == "unchanged"
        target.unlink()


def test_publish_fault_records_safe_failure_and_leaves_no_report(tmp_path, monkeypatch):
    from app import restricted_report

    private = _private_dir(tmp_path / "private")
    source = private / "input.log"
    source.write_text("2026-09-11 10:00:01 INFO login_failed user=fault-user ip=192.0.2.10\n")
    source.chmod(0o600)
    output = private / "fault.json"

    def fail_publish(*_args, **_kwargs):
        raise restricted_report.RestrictedReportError()

    monkeypatch.setattr(restricted_report, "_atomic_publish", fail_publish)
    with pytest.raises(restricted_report.RestrictedReportError):
        restricted_report.export_report(
            "application", str(source), str(output), approval_reader=lambda: APPROVAL,
        )
    assert not output.exists()
    audit = [json.loads(line) for line in (private / ".restricted-report-audit.jsonl").read_text().splitlines()]
    assert audit[-1]["status"] == "failure"
    assert "fault-user" not in json.dumps(audit)


def test_markup_shaped_identifier_is_only_json_data_and_not_a_public_change(tmp_path):
    result, output, _private = _run(
        tmp_path, "application",
        "2026-09-11 10:00:01 INFO login_failed user=<script>alert(1)</script> ip=192.0.2.12",
    )
    assert result.returncode == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    account = next(identifier["value"] for subject in report["subjects"] for identifier in subject["identifiers"] if identifier["kind"] == "account")
    assert account == "<script>alert(1)</script>"


def test_case_relation_and_risk_confidence_use_existing_pipeline(tmp_path):
    lines = [
        "2026-09-11 10:00:01 INFO login_failed user=case-user ip=192.0.2.21",
        "2026-09-11 10:00:10 INFO login_failed user=case-user ip=192.0.2.21",
        "2026-09-11 10:00:20 INFO login_failed user=case-user ip=192.0.2.21",
        "2026-09-11 10:00:40 INFO user_login user=case-user ip=192.0.2.21",
    ]
    result, output, _private = _run(tmp_path, "application", "\n".join(lines))
    assert result.returncode == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["cases"]
    assert report["cases"][0]["supporting_relation_count"] >= 1
    assert report["cases"][0]["start_time"].endswith("Z")
    subject = next(item for item in report["subjects"] if item["subject_id"] == report["cases"][0]["subject_id"])
    assert {"kind": "account", "value": "case-user"} in subject["identifiers"]
    assert {"kind": "ipv4", "value": "192.0.2.21"} in subject["identifiers"]
    assert report["risks"]
    assert set(report["risks"][0]) == {
        "level", "subject_count", "confidence_high", "confidence_medium", "confidence_low",
    }


def test_line_byte_boundary_and_closed_report_reject_duplicate_and_extra_fields():
    from app import restricted_report

    base = "2026-09-11 10:00:01 INFO login_failed user=boundary ip=192.0.2.22"
    exact = base + " " + "x" * (restricted_report.MAX_LINE_BYTES - len(base.encode()) - 1)
    assert len(exact.encode()) == restricted_report.MAX_LINE_BYTES
    assert len(restricted_report._parse_lines((exact + "\n").encode(), "application")) == 1
    with pytest.raises(restricted_report.RestrictedReportError):
        restricted_report._parse_lines((exact + "x\n").encode(), "application")
    with pytest.raises(restricted_report.RestrictedReportError):
        json.loads('{"x":1,"x":2}', object_pairs_hook=restricted_report._reject_duplicate_pairs)
    sample = "2026-09-11 10:00:01 INFO login_failed user=boundary ip=192.0.2.22\n"
    report = restricted_report._build_report("application", restricted_report._parse_lines(sample.encode(), "application"))
    restricted_report._validate_report(report)
    report["unexpected"] = "value"
    with pytest.raises(restricted_report.RestrictedReportError):
        restricted_report._validate_report(report)


def test_file_fsync_fault_rolls_back_and_records_failure(tmp_path, monkeypatch):
    from app import restricted_report

    private = _private_dir(tmp_path / "private")
    source = private / "input.log"
    source.write_text("2026-09-11 10:00:01 INFO login_failed user=fsync-user ip=192.0.2.23\n")
    source.chmod(0o600)
    output = private / "out.json"
    real_fsync = restricted_report.os.fsync
    calls = 0

    def fail_once(fd):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("fsync-canary-private")
        return real_fsync(fd)

    monkeypatch.setattr(restricted_report.os, "fsync", fail_once)
    with pytest.raises(restricted_report.RestrictedReportError):
        restricted_report.export_report("application", str(source), str(output), approval_reader=lambda: APPROVAL)
    assert not output.exists()
    assert not list(private.glob(".restricted-*.tmp"))
    audit = [json.loads(line) for line in (private / ".restricted-report-audit.jsonl").read_text().splitlines()]
    assert audit[-1]["status"] == "failure"
    assert "fsync-canary-private" not in json.dumps(audit)


def test_content_digest_is_stable_across_repeat_and_utc_kst(tmp_path):
    private = _private_dir(tmp_path / "private")
    source = private / "input.log"
    source.write_text("2026-09-11 10:00:01 INFO login_failed user=time-user ip=192.0.2.24\n")
    source.chmod(0o600)
    results = []
    reports = []
    for name, zone in (("utc.json", "UTC"), ("kst.json", "Asia/Seoul"), ("repeat.json", "UTC")):
        result = subprocess.run(
            [sys.executable, "-m", "app.restricted_report", "--source-role", "application", "--input", str(source), "--output", str(private / name)],
            input=APPROVAL + "\n", text=True, capture_output=True, check=False,
            env=_child_env(private, zone),
        )
        assert result.returncode == 0
        results.append(result.stdout)
        reports.append(json.loads((private / name).read_text(encoding="utf-8")))
    digests = [line.rsplit("SHA-256 ", 1)[1].strip() for line in results]
    assert digests[0] == digests[1] == digests[2]
    assert reports[0]["audit_summary"]["time_start"] == reports[1]["audit_summary"]["time_start"]
    assert reports[0]["generated_at"].endswith("+00:00")
    assert reports[1]["generated_at"].endswith("+09:00")
    assert len({report["report_id"] for report in reports}) == 3


def test_line_byte_boundary_and_closed_report_reject_duplicate_and_extra_fields(monkeypatch):
    from app import restricted_report

    base = "2026-09-11 10:00:01 INFO login_failed user=boundary ip=192.0.2.22"
    exact = base + " " + "x" * (restricted_report.MAX_LINE_BYTES - len(base.encode()) - 1)
    assert len(exact.encode()) == restricted_report.MAX_LINE_BYTES
    assert len(restricted_report._parse_lines((exact + "\n").encode(), "application")) == 1
    with pytest.raises(restricted_report.RestrictedReportError):
        restricted_report._parse_lines((exact + "x\n").encode(), "application")
    with pytest.raises(restricted_report.RestrictedReportError):
        json.loads('{"x":1,"x":2}', object_pairs_hook=restricted_report._reject_duplicate_pairs)
    sample = "2026-09-11 10:00:01 INFO login_failed user=boundary ip=192.0.2.22\n"
    report = restricted_report._build_report("application", restricted_report._parse_lines(sample.encode(), "application"))
    restricted_report._validate_report(report)
    report["unexpected"] = "value"
    with pytest.raises(restricted_report.RestrictedReportError):
        restricted_report._validate_report(report)


def test_file_fsync_fault_rolls_back_and_records_failure(tmp_path, monkeypatch):
    from app import restricted_report

    private = _private_dir(tmp_path / "private")
    source = private / "input.log"
    source.write_text("2026-09-11 10:00:01 INFO login_failed user=fsync-user ip=192.0.2.23\n")
    source.chmod(0o600)
    output = private / "out.json"
    real_fsync = restricted_report.os.fsync
    calls = 0

    def fail_once(fd):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("fsync-canary-private")
        return real_fsync(fd)

    monkeypatch.setattr(restricted_report.os, "fsync", fail_once)
    with pytest.raises(restricted_report.RestrictedReportError):
        restricted_report.export_report("application", str(source), str(output), approval_reader=lambda: APPROVAL)
    assert not output.exists()
    assert not list(private.glob(".restricted-*.tmp"))
    audit = [json.loads(line) for line in (private / ".restricted-report-audit.jsonl").read_text().splitlines()]
    assert audit[-1]["status"] == "failure"
    assert "fsync-canary-private" not in json.dumps(audit)


def test_concurrent_exports_to_same_target_publish_at_most_one_report(tmp_path):
    private = _private_dir(tmp_path / "private")
    source = private / "input.log"
    source.write_text("2026-09-11 10:00:01 INFO login_failed user=race-user ip=192.0.2.13\n")
    source.chmod(0o600)
    output = private / "race.json"
    command = [sys.executable, "-m", "app.restricted_report", "--source-role", "application", "--input", str(source), "--output", str(output)]
    first = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=_child_env(private))
    second = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=_child_env(private))
    first.stdin.write(APPROVAL + "\n")
    first.stdin.close()
    first.stdin = None
    second.stdin.write(APPROVAL + "\n")
    second.stdin.close()
    second.stdin = None
    first_out = first.communicate(timeout=10)
    second_out = second.communicate(timeout=10)
    statuses = [first.returncode, second.returncode]
    assert statuses.count(0) == 1
    assert output.exists()
    assert json.loads(output.read_text(encoding="utf-8"))["source_role"] == "application"
    audit = [json.loads(line) for line in (private / ".restricted-report-audit.jsonl").read_text().splitlines()]
    assert len(audit) in {1, 2}
    assert sum(item["status"] == "success" for item in audit) == 1
    assert all(item["status"] in {"success", "failure"} for item in audit)
    assert "race-user" not in "".join(first_out + second_out)
