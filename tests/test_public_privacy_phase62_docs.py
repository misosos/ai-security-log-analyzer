from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_public_privacy_migration_notice_is_linked_and_bounded():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    privacy = (ROOT / "docs/public_analysis_privacy.md").read_text(encoding="utf-8")
    web = (ROOT / "docs/web_application_design.md").read_text(encoding="utf-8")
    html = (ROOT / "docs/html_investigation_report_design.md").read_text(encoding="utf-8")
    evaluation = (ROOT / "docs/detection_evaluation.md").read_text(encoding="utf-8")

    assert "docs/public_analysis_privacy.md" in readme
    assert "deprecated" in readme
    assert "nested-value breaking change" in privacy
    assert "Deprecation: true" in privacy
    assert "POST /api/v1/investigations" in privacy
    assert "trusted internal result" in privacy
    assert "memory dump" in privacy and "debugger" in privacy
    assert "secure erasure" in privacy
    assert "public internet" in privacy
    assert "public_analysis_privacy.md" in web
    assert "원래 HTTP path" in html and "full query" in html
    assert "public_analysis_privacy.md" in evaluation
