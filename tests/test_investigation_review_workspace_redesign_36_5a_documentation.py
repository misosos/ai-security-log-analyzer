from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "investigation_review_workspace_redesign_36_5a.md"


def test_phase_36_5a_record_covers_workspace_contract_and_limits():
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "결과 목록과 독립 상세 화면", "#/investigations/{opaque_case_ref}",
        "분석상 연결", "인과관계", "확인할 작업", "progressive disclosure",
        "개인정보", "분석 불변", "axe", "Safari",
        "USER_HOME_ISOLATION_BLOCKED", "실제 사용자 자료", "모델 기반 AI",
        "Vector/VM", "운영 SLA가 아닙니다", "npm ci --ignore-scripts",
    ):
        assert required in text


def test_workspace_redesign_is_not_full_production_acceptance():
    text = DOC.read_text(encoding="utf-8")
    assert "CONDITIONAL_GO" in text
    assert "새 SHA의 Ubuntu CI와 새 UI 사용자 검수 전에는 최종 GO가 아닙니다" in text
    assert "실제 자료·조직 운영·자동 대응은 NO_GO" in text
