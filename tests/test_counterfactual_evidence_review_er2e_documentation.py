from pathlib import Path
import re


ROOT = Path(__file__).parents[1]


def test_security_acceptance_report_has_required_sections():
    report = (ROOT / "docs/counterfactual_evidence_review_security_acceptance_er2e.md").read_text(encoding="utf-8")
    required = (
        "Start SHA / Exact CI", "Feature Flag OFF/ON", "HTTP Admission", "Browser Validator",
        "Snapshot Integrity", "Comparison Semantics", "Snapshot Lifecycle",
        "Synthetic/Production Isolation", "Privacy/XSS", "Keyboard/Focus", "Accessibility",
        "Responsive", "Chromium", "WebKit", "Safari Manual Status", "Mobile Manual Status",
        "Screen Reader Manual Status", "TDD RED/GREEN", "Defect and Repair Log", "Full Regression",
        "User Acceptance Checklist", "Rollback", "Remaining Security Limitations", "Human Review Gate",
        "Final Decision",
    )
    normalized = re.sub(r"^## \d+\. ", "## ", report, flags=re.MULTILINE)
    assert all(f"## {heading}" in normalized for heading in required)


def test_user_acceptance_template_defaults_to_not_tested_and_is_indexed():
    checklist = (ROOT / "docs/counterfactual_evidence_review_user_acceptance_er2e.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "Desktop Safari" in checklist and "좁은 화면" in checklist and "Keyboard" in checklist
    assert "Security UX" in checklist
    assert "| NOT_TESTED |" in checklist
    assert "counterfactual_evidence_review_user_acceptance_er2e.md" in index
