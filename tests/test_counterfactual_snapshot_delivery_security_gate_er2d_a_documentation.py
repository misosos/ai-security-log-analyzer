from pathlib import Path

DOC = Path("docs/counterfactual_snapshot_delivery_security_gate_er2d_a.md")


def test_required_sections_and_delivery_contract():
    text = DOC.read_text(encoding="utf-8")
    for section in (
        "Executive Summary", "Start SHA / Exact CI", "Existing ER-2C Snapshot Architecture",
        "Current FastAPI/Web Security Boundary", "Delivery Options", "Trust Boundary",
        "Replay/Decoder Cost", "Feature Flag Contract", "Browser Validation Contract",
        "Snapshot Lifecycle", "Synthetic/Production Isolation", "Threat Model",
        "Security Test Matrix", "Recommended Architecture", "Rollback",
        "ER-2D-B/C and ER-2E Roadmap", "Human Review Gate", "Limitations", "Test Results", "Final Decision",
    ):
        assert section in text
    for term in (
        "Option A", "Option B", "Option C", "EVIDENCE_REVIEW_VIEWER_ENABLED",
        "Structural Validity", "Semantic Consistency", "Snapshot Integrity", "Trusted Source Binding",
        "NOT_LOADED", "LOADING", "VERIFIED", "INVALID", "STALE", "UNAVAILABLE", "UNSUPPORTED_VERSION",
        "DNS Rebinding", "Host", "Origin", "no-store", "O_NOFOLLOW", "128 KiB", "160 KiB",
        "crypto.subtle.digest", "duplicate", "prototype pollution", "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "MANUAL_APPROVAL_REQUIRED", "ER_1D_IMPLEMENTATION_HOLD", "NO_GO",
        "합성 평가 전용 · 실제 보안 사건 아님", "ER_2D_A_SNAPSHOT_DELIVERY_DESIGN_LOCAL_CONDITIONAL_GO",
    ):
        assert term in text


def test_document_is_indexed_and_no_false_approval():
    text = DOC.read_text(encoding="utf-8")
    assert DOC.name in Path("docs/index.md").read_text(encoding="utf-8")
    assert "구현하지 않았다" in text
    assert "별도 승인" in text
    assert "서명이 아니다" in text
