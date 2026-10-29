from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "investigation_workspace_tasks_evidence_36_6e.md"


def test_phase_36_6e_document_records_contract_and_safe_request_flow() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "05c5bc73b1ae81d6e8b943f18ed5f1e715434f87",
        "40823601898",
        "investigation-workspace-ui/v1",
        "investigation-workspace-timeline-ui/v1",
        "19개 필드",
        "investigation-checklist/v2",
        "not_requested",
        "loading",
        "available",
        "refused",
        "unavailable",
        "stale",
        "분석 한계",
        "직접 증거가 아닙니다",
        "300ms",
        "external_requests=0",
        "160 KiB",
        "320px",
        "200%",
        "36.6F",
        "36.6G",
        "NO_GO",
    ):
        assert required in text


def test_phase_36_6e_keeps_unverified_scope_and_no_go_states() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "Safari·실제 모바일: `NOT_TESTED`" in text
    assert "실제 사용자 자료·조직 운영·자동 대응: `NO_GO`" in text
    assert "모델 기반 AI: `NOT_TESTED`" in text
    assert "Vector/VM: `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`" in text
    assert "Linux 전용 TCP Syslog·JSONL·restricted report acceptance는 새 변경 SHA의 CI가 아직 없으므로" in text
