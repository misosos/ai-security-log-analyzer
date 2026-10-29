from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "investigation_workspace_timeline_relation_36_6d.md"


def test_phase_36_6d_document_records_gate_adapter_and_timeline_semantics() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "3a081c9a135535b93ed206fe13dd65efba77ddc9",
        "40818811785",
        "investigation-workspace-ui/v1",
        "19개 필드",
        "investigation-workspace-timeline-ui/v1",
        "immutable",
        "sequence",
        "동일 시각 tie-break",
        "시간 정보 없음",
        "분석상 연결 · 인과관계 미확정",
        "원문 fact",
        "WORKSPACE_TIMELINE_INVALID",
        "WORKSPACE_TIMELINE_VIEW_OR_CLOSED_ADAPTER_MISSING",
        "false !== true",
        "POST 0",
        "320",
        "200%",
        "44×44",
        "36.6E",
        "NO_GO",
    ):
        assert required in text


def test_phase_36_6d_doc_preserves_unverified_status_and_no_production_claim() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "Safari·실제 모바일·VoiceOver 검증이 아니다" in text
    assert "모델 기반 AI `NOT_TESTED`" in text
    assert "실제 사용자 자료·조직 운영·자동 대응 `NO_GO`" in text
    assert "Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`" in text
