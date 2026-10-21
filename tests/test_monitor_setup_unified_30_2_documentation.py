"""Current setup management guidance keeps both roles and failure limits visible."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_unified_management_contract_and_entry_points() -> None:
    audit = (ROOT / "docs/monitor_setup_unified_audit_30_2.md").read_text(encoding="utf-8")
    setup = (ROOT / "docs/monitor_setup_20.md").read_text(encoding="utf-8")
    ssh = (ROOT / "docs/monitor_setup_ssh_30_1.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for phrase in (
        "애플리케이션 로그인 로그", "SSH 인증 로그", "--show", "--monitor",
        "--reset-checkpoint", "--delete", "원본 로그", "과거 SSE", "revision 0",
        "0700", "0600", "no-clobber", "256 event", "256 KiB", "257번째",
        "fail-closed", "sample-only", "symlink", "advisory lock", "secure erase",
        "rotation/copytruncate", "crash recovery", "exactly-once", "무유실",
        "CONDITIONAL GO", "NOT_TESTED",
    ):
        assert phrase in audit
    for document in (setup, ssh, index):
        assert "monitor_setup_unified_audit_30_2.md" in document
    for phrase in ("--show", "--delete", "--reset-checkpoint", "원본 로그", "정상 종료"):
        assert phrase in readme
    assert "Verify Linux unified application and SSH setup management" in ci
    assert "tests/smoke_unified_monitor_management_30_2.py" in ci
    assert "upload-artifact" not in ci
