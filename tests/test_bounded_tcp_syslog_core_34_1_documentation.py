from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "docs/bounded_tcp_syslog_core_34_1.md"


def test_phase_34_1_record_closes_core_contract_and_scope():
    text = RECORD.read_text(encoding="utf-8")
    for phrase in (
        "CONDITIONAL_GO", "NOT_IMPLEMENTED", "RFC 6587", "octet-counting",
        "max_prefix_digits", "max_frame_bytes", "max_connection_buffer_bytes",
        "max_queue_events", "max_queue_bytes", "INVALID_UTF8", "INCOMPLETE_FRAME",
        "STARTING", "READY", "DEGRADED", "FAILED", "STOPPED",
        "detection", "checkpoint", "NOT_TESTED", "slowloris", "listener",
        "memory의 secure erase",
    ):
        assert phrase in text
    assert "socket을 열지 않았다" in text


def test_phase_34_design_and_readme_keep_listener_unimplemented():
    design = (ROOT / "docs/automatic_log_collection_design_34_0.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "Phase 34.1 순수 core 구현" in design
    assert "아직 지원하지 않습니다" in readme
    assert "bounded_tcp_syslog_core_34_1.md" in index
