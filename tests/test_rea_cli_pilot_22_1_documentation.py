"""The REA pilot records a supply-chain stop, not a completed analysis."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs/rea_cli_pilot_22_1.md"


def test_report_records_exact_stop_gate_and_no_analysis_claim() -> None:
    report = REPORT.read_text(encoding="utf-8")
    assert "PILOT_BLOCKED_SUPPLY_CHAIN" in report
    assert "package/native/windows/build/rea-windows-x64.node" in report
    assert "873,593-byte" in report
    assert "`NOT_TESTED`" in report
    assert "REA CLI help" in report and "수행하지 않았다" in report
    assert "Dependency를 설치하거나" in report
    assert "`--omit=optional`의 호환성을 추측" in report


def test_report_preserves_pinning_isolation_privacy_and_cleanup_boundary() -> None:
    report = REPORT.read_text(encoding="utf-8")
    for fact in (
        "rea-agents-6.5.0",
        "3b79af28e80785afce9f5998d8f03289402a1847",
        "sha512-C6BG7LyrAdR74mSjertM6PrxJkcNZ2bfQNOJornPo9erDEp2tyPRVYPnV5Yodr+1RqewCQla68WulXlVnveD+A==",
        "--network none", "--read-only", "--cap-drop ALL",
        "no-new-privileges", "Docker socket", "Codex MCP·skill·config",
        "volume은 제거", "secure erase", "raw output", "uv.lock",
    ):
        assert fact in report
    assert "사용자 홈" in report and "저장소 전체" in report
    assert "서명 자체를 독립 검증한 것은 아니므로" in report
