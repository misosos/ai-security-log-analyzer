"""Keep the REA static-path decision separate from permission to execute it."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs/rea_static_path_audit_22_1a.md"


def test_static_audit_records_pinned_artifacts_and_native_reachability() -> None:
    report = REPORT.read_text(encoding="utf-8")
    for fact in (
        "rea-agents-6.5.0",
        "3b79af28e80785afce9f5998d8f03289402a1847",
        "sha512-C6BG7LyrAdR74mSjertM6PrxJkcNZ2bfQNOJornPo9erDEp2tyPRVYPnV5Yodr+1RqewCQla68WulXlVnveD+A==",
        "scripts/rea.mjs",
        "analyze-javascript-application",
        "@lydell/node-pty",
        "frida",
        "rea-windows-x64.node",
        "dynamic import",
        "--ignore-scripts --omit=optional",
    ):
        assert fact in report


def test_static_audit_does_not_turn_uncertain_imports_into_execution_approval() -> None:
    report = REPORT.read_text(encoding="utf-8")
    assert "**NO-GO**" in report
    assert "REA CLI는 실행하지 않았다" in report
    assert "dependency를 설치하지 않았다" in report
    assert "production dependency" in report and "변경하지 않았다" in report
    assert "Phase 22.1" in report and "공급망" in report
