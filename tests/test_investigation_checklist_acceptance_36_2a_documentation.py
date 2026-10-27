from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_36_2a_acceptance_record_preserves_human_and_automatic_results():
    record = (ROOT / "docs/investigation_checklist_acceptance_36_2a.md").read_text()
    for required in (
        "3343b5c443f1b920bc2b359a072083ba7ab01515",
        "40489300620",
        "1/8: PASS",
        "5/8: PASS",
        "6/8: FAIL",
        "6/8 재검수: PASS",
        "7/8: PASS",
        "8/8: PASS",
        "3,038 passed",
        "USER_COMPREHENSION_CONDITIONAL_GO",
        "NOT_TESTED",
        "NO_GO",
    ):
        assert required in record
    assert "자동 평가 결과는 사용자 응답을 대신하지 않습니다" in record
    assert "실제 조직 로그 사용은 승인되지 않았습니다" in record
