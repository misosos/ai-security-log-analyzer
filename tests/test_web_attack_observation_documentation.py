"""Stable release/documentation claims for Phase 8 web observations."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_design_names_observable_types_project_thresholds_and_official_basis():
    text = _read("docs/web_attack_observation_design.md")
    for marker in (
        "SQL Injection-like", "XSS-like", "Sensitive Resource Probing-like",
        "Web Scanning-like", "SQLI_BOOLEAN_EXPRESSION", "XSS_SCRIPT_ELEMENT",
        "SENSITIVE_ENV_FILE", "WEB_SCAN_DISTINCT_TARGETS", "6/6/3/60",
        "OWASP", "MITRE", "실제 운영환경 탐지율", "WAF", "독립 관찰",
    ):
        assert marker in text
    assert "https://wstg.owasp.org/" in text
    assert "https://attack.mitre.org/" in text
    assert "원래 path/query" in text


def test_release_and_product_docs_distinguish_phase8_from_historical_baseline():
    release = _read("docs/releases/v0.1.0.md")
    evaluation = _read("docs/detection_evaluation.md")
    checklist = _read("docs/release_checklist.md")
    web = _read("docs/web_application_design.md")
    for text in (release, evaluation):
        assert "79/79" in text
        assert "70/70" in text
        assert "실제 운영환경" in text
    assert "43/43" in evaluation  # historical Phase 6.1 baseline remains visible
    assert "독립 관찰 4" in web
    assert "clean checkout" in checklist
    assert "[ ] Phase 8 기능 커밋 이후" in checklist
    assert "원래 path/query" in _read("docs/public_analysis_privacy.md")
    assert "SQL Injection-like" in _read("README.md")
    assert "79개" in _read("CHANGELOG.md")
