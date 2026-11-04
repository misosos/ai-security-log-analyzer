from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "counterfactual_analyst_report_er2a.md"


def test_er2a_report_documentation_records_contract_and_limitations():
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "## Executive Summary",
        "## Start SHA and CI",
        "## Existing Replay Architecture",
        "## Report Projection Contract",
        "## Corpus Summary",
        "## Scenario Review Table",
        "## Comparison State Interpretation",
        "## Incomparable and Undetermined Handling",
        "## Security and Privacy",
        "## Determinism",
        "## Test Results",
        "## Human Review Status",
        "## ER-2B Entry Requirements",
        "## Limitations",
        "## Final Decision",
        "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "MANUAL_APPROVAL_REQUIRED",
        "ER_1D_IMPLEMENTATION_HOLD",
        "PRESERVED 4",
        "LOST 6",
        "GAINED 2",
        "UNCHANGED_ABSENT 1",
        "INCOMPARABLE 3",
        "UNDETERMINED 0",
        "3 / 4 / 3 / 1 / 3 / 0",
        "Expected Label",
        "Blind Packet",
    ):
        assert required in text
