"""Linux-only subprocess smoke with synthetic files and fixed safe output."""

import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


APPROVAL = "제한된 내부 보고서 생성을 승인합니다"
AUDIT = ".restricted-report-audit.jsonl"
SCHEMA = "restricted-investigation-report/v1"
_FORBIDDEN = (
    "host-canary-5c", "raw-line-canary-5c", "credential-canary-5c",
    "rationale-canary-5c", "exception-canary-5c", "path-canary-5c",
)


class _SmokeFailure(Exception):
    pass


def _require(condition):
    if not condition:
        raise _SmokeFailure()


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def _filesystem_type(path):
    target = str(path.resolve())
    best = None
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        mount = fields[4].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
        if target == mount or target.startswith(mount.rstrip("/") + "/"):
            if best is None or len(mount) > len(best[0]):
                best = (mount, fields[fields.index("-") + 1])
    _require(best is not None)
    return best[1]


def _environment(root):
    home = root / "isolated-home"
    home.mkdir(mode=0o700)
    home.chmod(0o700)
    return {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TZ": "UTC",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _run(command, env, answer=APPROVAL):
    result = subprocess.run(
        command, input=None if answer is None else answer + "\n",
        text=True, capture_output=True, check=False, env=env, timeout=10,
        preexec_fn=lambda: os.umask(0),
    )
    _require(result.returncode == 0)
    return result


def _no_private_output(result, root, source, output):
    visible = result.stdout + result.stderr
    _check_no_private_output(visible, root, source, output)


def _check_no_private_output(visible, root, source, output):
    canaries = (*_FORBIDDEN, "account-canary-5c", "192.0.2.55", "2001:db8::55")
    _require(str(root) not in visible and str(source) not in visible and str(output) not in visible)
    _require(source.name not in visible and output.name not in visible)
    _require(all(value not in visible for value in canaries))


def _role_case(root, role, line, expected):
    case_dir = root / f"case-{role}"
    case_dir.mkdir(mode=0o700)
    case_dir.chmod(0o700)
    source = case_dir / "input-filename-canary-5c.log"
    source.write_text(line + "\n", encoding="utf-8")
    source.chmod(0o600)
    output = case_dir / "output-filename-canary-5c.json"
    env = _environment(case_dir)
    command = [sys.executable, "-m", "app.restricted_report", "--source-role", role,
               "--input", str(source), "--output", str(output)]

    # Cancellation and EOF create neither a report nor an audit record.
    cancelled = subprocess.run(command, input="취소\n", text=True, capture_output=True,
                               check=False, env=env, timeout=10)
    _require(cancelled.returncode != 0 and not output.exists() and not (case_dir / AUDIT).exists())
    _check_no_private_output(cancelled.stdout + cancelled.stderr, root, source, output)
    eof = subprocess.run(command, input="", text=True, capture_output=True,
                         check=False, env=env, timeout=10)
    _require(eof.returncode != 0 and not output.exists() and not (case_dir / AUDIT).exists())
    _check_no_private_output(eof.stdout + eof.stderr, root, source, output)

    for requested_signal in (signal.SIGINT, signal.SIGTERM):
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=env)
        time.sleep(0.15)
        process.send_signal(requested_signal)
        stdout, stderr = process.communicate(timeout=10)
        _require(process.returncode != 0 and not output.exists())
        _check_no_private_output(stdout + stderr, root, source, output)
        _require(not (case_dir / AUDIT).exists())
        _require(not list(case_dir.glob(".restricted-*.tmp")))

    result = _run(command, env)
    audit_path = case_dir / AUDIT
    _require(_mode(case_dir) == 0o700 and _mode(output) == 0o600 and _mode(audit_path) == 0o600)
    report_raw = output.read_bytes()
    report = json.loads(report_raw)
    _require(set(report) == {
        "schema_version", "report_id", "generated_at", "source_role", "classification",
        "encryption_status", "limitations", "subjects", "observations", "relations",
        "risks", "cases", "audit_summary",
    })
    _require(report["schema_version"] == SCHEMA and report["source_role"] == role)
    identifiers = [value for subject in report["subjects"] for value in subject["identifiers"]]
    for kind, value in expected:
        _require({"kind": kind, "value": value} in identifiers)
    serialized = report_raw.decode("utf-8")
    for value in (*_FORBIDDEN, "host-canary-5c", str(root), str(source), source.name,
                  str(output), output.name):
        _require(value not in serialized)

    audit_raw = audit_path.read_bytes()
    audit = [json.loads(row) for row in audit_raw.splitlines()]
    _require(len(audit) == 1 and audit[0]["status"] == "success")
    _require(audit[0]["report_id"] == report["report_id"])
    _require(set(audit[0]) == {
        "status", "occurred_at", "schema_version", "source_role", "report_id",
        "identifier_counts", "case_count", "relation_count", "observation_count",
    })
    for value in (*_FORBIDDEN, "account-canary-5c", "192.0.2.55", "2001:db8::55",
                  str(root), str(source), source.name, output.name):
        _require(value not in audit_raw.decode("utf-8"))
    _no_private_output(result, root, source, output)
    for marker in ("schema restricted-investigation-report/v1", " bytes, SHA-256 "):
        _require(marker in result.stdout)

    # Existing destination is rejected before approval and does not mutate audit.
    audit_before = audit_path.read_bytes()
    report_before = output.read_bytes()
    retry = subprocess.run(command, input=APPROVAL + "\n", text=True, capture_output=True,
                           check=False, env=env, timeout=10)
    _require(retry.returncode != 0 and output.read_bytes() == report_before)
    _require(audit_path.read_bytes() == audit_before)
    _require(all(value not in retry.stdout + retry.stderr for value in (*_FORBIDDEN, str(root), str(output))))

    second_output = case_dir / "second.json"
    second = _run([*command[:-1], str(second_output)], env)
    second_report = json.loads(second_output.read_text(encoding="utf-8"))
    audit_after = [json.loads(row) for row in audit_path.read_bytes().splitlines()]
    _require(second_report["report_id"] != report["report_id"] and len(audit_after) == 2)
    _require(audit_after[-1]["report_id"] == second_report["report_id"])
    _no_private_output(second, root, source, second_output)
    _require(not list(case_dir.glob(".restricted-*.tmp")))
    return len(audit_after)


def main():
    _require(sys.platform == "linux")
    temp_base = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    root = Path(tempfile.mkdtemp(prefix="restricted-report-33-5c-", dir=temp_base))
    root.chmod(0o700)
    fs_type = _filesystem_type(root)
    _require(fs_type in {"ext4", "xfs", "btrfs", "tmpfs", "overlay"})
    baseline_fds = len(os.listdir("/proc/self/fd"))
    try:
        roles = {
            "application": (
                "2026-09-11 10:00:01 INFO login_failed user=account-canary-5c ip=192.0.2.55 hostname=host-canary-5c file=path-canary-5c raw-line-canary-5c credential=credential-canary-5c rationale-canary-5c exception-canary-5c",
                [("account", "account-canary-5c"), ("ipv4", "192.0.2.55")],
            ),
            "ssh": (
                "2026-09-14 11:00:01 sshd Failed password for account-canary-5c from 2001:db8::55 port 22 ssh2 host-canary-5c raw-line-canary-5c credential-canary-5c rationale-canary-5c exception-canary-5c",
                [("account", "account-canary-5c"), ("ipv6", "2001:db8::55")],
            ),
            "access": (
                '192.0.2.55 - - [14/Sep/2026:12:00:01 +0000] "GET /path-canary-5c HTTP/1.1" 200 1024 "-" "raw-line-canary-5c credential-canary-5c rationale-canary-5c exception-canary-5c host-canary-5c"',
                [("ipv4", "192.0.2.55")],
            ),
        }
        audit_rows = 0
        for role, (line, expected) in roles.items():
            audit_rows += _role_case(root, role, line, expected)
        _require(len(os.listdir("/proc/self/fd")) == baseline_fds)
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        print("RESTRICTED_REPORT_LINUX_SMOKE_FAIL")
        raise SystemExit(1) from None
    try:
        shutil.rmtree(root)
        _require(not root.exists())
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        print("RESTRICTED_REPORT_LINUX_SMOKE_FAIL")
        raise SystemExit(1) from None
    print(f"RESTRICTED_REPORT_LINUX_SMOKE_PASS roles={len(roles)} audit_rows={audit_rows} fs={fs_type}")


if __name__ == "__main__":
    main()
