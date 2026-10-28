from pathlib import Path


DOC = Path(__file__).resolve().parents[1] / "docs/investigation_workspace_mobile_acceptance_36_5d.md"


def test_mobile_acceptance_preserves_initial_not_tested_and_final_pass() -> None:
    text = DOC.read_text(encoding="utf-8")

    assert "Phase 36.5C 결과" in text
    assert "모바일 `NOT_TESTED`" in text
    assert "6/6 최종 응답은 모두 `PASS`" in text
    assert "PROTOTYPE_USER_ACCEPTED" in text
    assert "200% equivalent" in text and "넘침이 관찰됨" in text
    assert "19px" in text
    assert "실제 모바일 기기: `NOT_TESTED`" in text
    assert "Safari: `NOT_TESTED`" in text
    assert "production 이식: 미승인 / 미구현" in text
    assert "실제 사용자 자료·조직 운영·자동 대응: `NO_GO`" in text
    assert "## 완료 후 사용자 확인" in text
    assert "완료 보고 뒤 사용자가 `PASS`라고 응답했다" in text
