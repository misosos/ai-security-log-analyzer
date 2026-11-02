from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs/investigation_review_workflow_state_design_36_14a.md"


def test_review_workflow_design_closes_state_and_analysis_boundaries():
    text = DOCUMENT.read_text()

    required = (
        "unreviewed",
        "in_review",
        "reviewed",
        "deferred",
        "분석 결과와 workflow 상태",
        "자동 상태 변경 금지",
        "메모는 `DEFERRED`",
        "case_ref",
        "analysis_ref",
        "schema_version",
        "stale",
        "다른 분석의 상태를 현재 분석에 결합하지 않는다",
    )
    for phrase in required:
        assert phrase in text


def test_review_workflow_design_compares_storage_and_selects_a_bounded_option():
    text = DOCUMENT.read_text()

    for option in ("메모리 전용", "sessionStorage", "localStorage", "JSON sidecar", "SQLite"):
        assert option in text
    for criterion in (
        "새로고침",
        "브라우저 종료",
        "다중 탭",
        "민감정보 노출면",
        "원자적 쓰기",
        "파일 권한",
        "stale analysis 격리",
        "dependency",
    ):
        assert criterion in text
    assert "최종 권고" in text


def test_review_workflow_design_has_closed_dto_privacy_transitions_and_rollback_phases():
    text = DOCUMENT.read_text()

    for phrase in (
        "원문 로그",
        "account",
        "IP",
        "hostname",
        "checkpoint",
        "last-write-wins",
        "revision",
        "CSRF",
        "unknown case_ref",
        "상태 변경은 사용자 조작으로만",
        "36.14B",
        "36.14C",
        "36.14D",
        "36.14E",
        "36.14F",
        "rollback",
        "NO_GO",
        "Research Basis",
        "Sources",
    ):
        assert phrase in text
    assert "CREATE TABLE" in text
    assert "GET /api/v1" in text
    assert "PUT /api/v1" in text


def test_review_workflow_design_is_indexed_and_readme_links_without_exceeding_size_contract():
    text = DOCUMENT.read_text()
    index = (ROOT / "docs/index.md").read_text()
    readme = (ROOT / "README.md").read_text()

    assert "investigation_review_workflow_state_design_36_14a.md" in index
    assert "investigation_review_workflow_state_design_36_14a.md" in readme
    assert len(readme.encode("utf-8")) <= 17_000


def test_design_phase_does_not_claim_production_implementation_or_operational_approval():
    text = DOCUMENT.read_text()

    assert "production 코드·API·frontend는 변경하지 않았다" in text
    assert "실제 사용자 자료: `NO_GO`" in text
    assert "조직 운영: `NO_GO`" in text
    assert "자동 대응: `NO_GO`" in text
    assert "모델 기반 AI: `NOT_TESTED`" in text
    assert "PHASE_36_14A_REVIEW_WORKFLOW_STATE_DESIGN_LOCAL_CONDITIONAL_GO" in text
