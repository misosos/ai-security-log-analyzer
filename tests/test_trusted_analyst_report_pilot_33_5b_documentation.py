from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pilot_record_documents_bounded_synthetic_cli_contract():
    path = ROOT / "docs/trusted_analyst_report_pilot_33_5b.md"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    for term in (
        "CONDITIONAL_GO", "합성 입력 전용", "--source-role", "--input", "--output",
        "제한된 내부 보고서 생성을 승인합니다", "0600", "0700", "O_NOFOLLOW",
        "no-clobber", "자동 암호화되지", "실제 자료 export:", "NO_GO",
        "llama", "embedding", "Gemini", "NOT_TESTED", "operational_sla",
    ):
        assert term in text


def test_cli_contract_has_no_public_api_ui_or_dependency_integration():
    source = (ROOT / "app/restricted_report.py").read_text(encoding="utf-8")
    assert "--source-role" in source
    assert "--input" in source
    assert "--output" in source
    assert "O_EXCL" in source
    assert "O_NOFOLLOW" in source
    assert "requests." not in source
    assert "urllib.request" not in source


def test_readme_and_index_call_out_synthetic_pilot_and_no_operational_approval():
    for path in (ROOT / "README.md", ROOT / "docs/index.md"):
        text = path.read_text(encoding="utf-8")
        assert "trusted_analyst_report_pilot_33_5b.md" in text
        assert "합성" in text


def test_phase_33_5a_design_is_updated_from_proposal_to_pilot_evidence():
    text = (ROOT / "docs/trusted_analyst_report_design_33_5a.md").read_text(encoding="utf-8")
    assert "Phase 33.5B 구현 결과" in text
    assert "실제 사용자 자료 export는 승인되지 않았다" in text
