from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / "docs/ui_workspace_navigation_28_4.md").read_text(encoding="utf-8")
INDEX = (ROOT / "docs/index.md").read_text(encoding="utf-8")


def test_workspace_design_and_manual_boundary_are_documented():
    for required in ("PatternFly", "Primer", "Carbon", "GOV.UK", "라이선스", "EventSource",
                     "aria-current", "320/640/767/768/1024/1200/1440/1600/2000", "개인정보", "CSP", "NOT_TESTED",
                     "Safari", "VoiceOver", "scroll", "focus"):
        assert required in DOC
    assert "ui_workspace_navigation_28_4.md" in INDEX
    assert "WCAG 2.2 AA 준수" in DOC
