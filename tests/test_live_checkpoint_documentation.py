"""Phase 21 public scope and failure semantics remain explicit."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_checkpoint_contract_documents_real_scope() -> None:
    design = (ROOT / "docs/live_checkpoint_21.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for term in ("BOUNDED_REPLAY_V1", "FROM_END", "--monitor-config", "rotation",
                 "exactly-once", "application"):
        assert term.lower() in design.lower()
    for term in ("FROM_END", "rotation", "exactly-once", "application", "checkpoint"):
        assert term.lower() in readme.lower()
    for term in ("ack", "publication", "256", "private", "중복", "fail closed"):
        assert term.lower() in design.lower()
    assert "원본 로그" in design and "재전송하지" in design


def test_setup_and_monitoring_docs_link_current_scope() -> None:
    for name in ("monitor_setup_20.md", "live_log_monitoring_design.md",
                 "local_collector_v030_design.md"):
        assert "live_checkpoint_21.md" in (ROOT / "docs" / name).read_text(encoding="utf-8")
