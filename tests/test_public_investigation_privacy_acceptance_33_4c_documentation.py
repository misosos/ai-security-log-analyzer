from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_33_4c_acceptance_separates_ci_automation_and_safari_results():
    report = (ROOT / "docs/public_investigation_privacy_acceptance_33_4c.md").read_text()
    privacy = (ROOT / "docs/public_analysis_privacy.md").read_text()
    readme = (ROOT / "README.md").read_text()
    index = (ROOT / "docs/index.md").read_text()

    for marker in (
        "2fc96a896f155874cc14953a0b003303af2d2d3a", "40163159684",
        "2665 passed", "warning 2개", "14개 상태", "외부 요청 0건",
        "schema 1", "subject_alias", "응답 간 비교",
        "Trusted 내부 분석", "STORAGE_SETUP_BLOCKED", "NO_GO",
        "| 1 |", "| 4 |", "NOT_TESTED", "CONDITIONAL_GO",
        "실제 분석 결과로도 보고서를 생성할 수 있으며",
        "제한된 조사 보고서",
        "320 CSS px", "VoiceOver", "Safari Web Inspector",
        "발견한 stale 도움말 결함", "수정 전 production UI", "key 순서",
        "실제 citation 응답",
    ):
        assert marker in report
    assert "영구 저장 또는 상관 키로 사용하면 안 된다" in privacy
    assert "응답 간 상관 키나 영구 ID로 사용하지 마십시오" in readme
    assert "public_investigation_privacy_acceptance_33_4c.md" in index
