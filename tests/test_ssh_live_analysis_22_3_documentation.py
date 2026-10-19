"""Current SSH live support must not be confused with the historical v0.2 gate."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "docs/ssh_live_analysis_integration_22_3.md"


def test_ssh_integration_record_states_exact_scope_and_transaction() -> None:
    text = RECORD.read_text(encoding="utf-8")
    for fact in (
        "application", "SSH", "access", "batch-prefix parity",
        "observation_changes", "analysis_changes", "queue ack",
        "DEGRADED", "FAILED", "256 PARSED", "16 KiB",
        "FROM_END", "SSH checkpoint", "Spray case", "file-access",
        "account", "IP", "path", "rationale", "exactly-once",
    ):
        assert fact in text


def test_current_entry_points_do_not_claim_ssh_is_detection_only() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    design = (ROOT / "docs/live_log_monitoring_design.md").read_text(encoding="utf-8")
    assert "application·SSH 파일 하나" in readme
    assert "access live는 detection-only" in readme
    assert "ssh_live_analysis_integration_22_3.md" in design
    assert "SSH/access detection-only 수동 v1 설정" not in readme
