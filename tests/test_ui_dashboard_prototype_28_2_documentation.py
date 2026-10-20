"""Documentation keeps source attribution and prototype/production boundaries explicit."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_design_record_tracks_all_sources_and_decision() -> None:
    doc = (ROOT / "docs" / "ui_dashboard_prototype_28_2.md").read_text()
    for term in (
        "Pico CSS", "2.1.1", "MIT", "sha512-kIDugA7Ps4U+2BHxiNHmvgPIQDWPDU4IeU6TNRdvXQM1uZX+FibqDQT2xUOnnO2yq/LUHcwnGlu1hvf4KfXnMg==",
        "PatternFly", "Carbon", "Apache-2.0", "GOV.UK", "Open Government Licence",
        "Lucide", "archived", "직접 복사", "참고", "Safari", "VoiceOver", "WCAG",
        "320", "640", "1024", "1440", "200%", "source checkout",
    ):
        assert term in doc
    assert "production" in doc and "CSP" in doc
    assert "security_dashboard_calm.html" in doc
    assert "security_dashboard_dense.html" in doc


def test_readme_remains_short_and_links_from_map() -> None:
    readme = (ROOT / "README.md").read_text()
    index = (ROOT / "docs" / "index.md").read_text()
    assert len(readme.splitlines()) <= 120
    assert "ui_dashboard_prototype_28_2.md" in index
    assert "Phase 28.2" not in readme
