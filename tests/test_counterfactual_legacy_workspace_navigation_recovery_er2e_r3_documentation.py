from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC_PATH = "docs/counterfactual_legacy_workspace_navigation_recovery_er2e_r3.md"


def test_er2e_r3_records_modernized_navigation_contract_and_preserved_security_checks():
    document = (ROOT / DOC_PATH).read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    browser_test = (ROOT / "tests/ui_workspace_navigation_28_4.mjs").read_text(encoding="utf-8")

    for contract in (
        "Legacy Test Failure Reproduction",
        "Obsolete Selector Inventory",
        "Investigation Detail Migration",
        "Guidance Contract",
        "Timeline Contract",
        "Radio Group Regression",
        "Security Assertions Preservation",
        "Browser Console Results",
        "User Acceptance Status",
        "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "ER_2E_USER_ACCEPTANCE_PENDING",
        "ER_2E_R3_LEGACY_BROWSER_REGRESSION_LOCAL_CONDITIONAL_GO",
        "3881 passed, 2 warnings",
    ):
        assert contract in document

    assert DOC_PATH.removeprefix("docs/") in index
    assert "#/investigations/${expectedCaseRef}" in browser_test
    assert "review-detail-link" in browser_test
    assert "guidanceRequests === 0" in browser_test
    assert "guidance-citation script" in browser_test
    assert "workspace-timeline-relation-36-6d" in browser_test
    assert "review-queue-sort-36-13a" not in browser_test
    assert "review-queue-risk-36-13a" not in browser_test
    assert "review-queue-role-36-13a" not in browser_test
    assert "review-queue-priority-36-13a" not in browser_test
    assert "review-queue-state-36-14d" not in browser_test
    assert ":scope > summary" not in browser_test
    assert ".timeline-disclosure" not in browser_test
    assert "!(disabled404 && value.text().startsWith('Failed to load resource'))" not in browser_test
