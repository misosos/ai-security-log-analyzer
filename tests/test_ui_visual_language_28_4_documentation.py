from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / "docs/ui_visual_language_28_4.md").read_text(encoding="utf-8")


def test_visual_language_records_supply_chain_and_semantic_limits():
    for phrase in ("lucide-static@1.59.0", "sha512-MuHZYaXbHgzN2QO6", "ISC", "MIT",
                   "PatternFly", "Carbon", "HIGH/MEDIUM/LOW", "Apache ECharts", "Chart.js",
                   "NOT_TESTED", "Safari", "VoiceOver", "WCAG 2.2 AA", "CSP", "IP"):
        assert phrase in DOC
    assert (ROOT / "docs/licenses/lucide-static-1.59.0-LICENSE").is_file()
    assert "ui_visual_language_28_4.md" in (ROOT / "docs/index.md").read_text(encoding="utf-8")
