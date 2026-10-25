from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_trusted_report_design_closes_cli_data_and_filesystem_contract():
    design = ROOT / "docs/trusted_analyst_report_design_33_5a.md"
    assert design.exists()
    text = design.read_text(encoding="utf-8")
    for required in (
        "CONDITIONAL_GO",
        "CLI 전용, 닫힌 JSON",
        "schema_version",
        "subject_alias",
        "account",
        "hostname",
        "report/run ID",
        "원본 로그 줄",
        "0600",
        "0700",
        "O_EXCL",
        "O_NOFOLLOW",
        "fsync",
        "hard link",
        "동일 UID",
        "정확한 승인 문구",
        "감사 기록",
        "암호화되지 않은 민감 로컬 파일",
        "Time Machine",
        "SIGTERM",
        "disk full",
        "HTML",
        "Phase 33.5B",
        "800-209",
    ):
        assert required in text


def test_readme_and_index_distinguish_public_and_restricted_report():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "trusted_analyst_report_design_33_5a.md" in readme
    assert "trusted_analyst_report_design_33_5a.md" in index
    assert "제한된 내부 조사 보고서" in readme
    assert "trusted_analyst_report_pilot_33_5b.md" in readme
    assert "trusted_analyst_report_pilot_33_5b.md" in index


def test_phase_33_4c_scope_go_does_not_claim_full_accessibility_acceptance():
    acceptance = (ROOT / "docs/public_investigation_privacy_acceptance_33_4c.md").read_text(
        encoding="utf-8"
    )
    assert "Phase 33.4 공개 projection·별칭·lexical guidance 범위: **GO**" in acceptance
    assert "200% 확대" in acceptance
    assert "전체 페이지 VoiceOver" in acceptance
    assert "Web Inspector" in acceptance
    assert "NOT_TESTED" in acceptance
