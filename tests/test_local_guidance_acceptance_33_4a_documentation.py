from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_acceptance_record_preserves_exact_ci_and_privacy_no_go():
    report = (ROOT / "docs/local_investigation_guidance_acceptance_33_4a.md").read_text()
    phase = (ROOT / "docs/local_investigation_guidance_33_4.md").read_text()
    index = (ROOT / "docs/index.md").read_text()
    readme = (ROOT / "README.md").read_text()
    for marker in (
        "Final disposition: `NO_GO`", "098e652f41963ad18dc2d1ffa623c7ed772a52d8",
        "40159254345", "2,661 passed, 2 existing deprecation warnings",
        "external_requests=0", "0 artifacts", "cases[].subject",
        "cases[].timeline[].subject", "report_export.html", "NOT_TESTED",
        "STORAGE_SETUP_BLOCKED", "NO_GO",
    ):
        assert marker in report
    assert "Phase 33.4A acceptance disposition: `NO_GO`" in phase
    assert "local_investigation_guidance_acceptance_33_4a.md" in index
    assert "synthetic IP canary 노출" in readme
    assert "account-private-canary" not in report + phase + index + readme
    assert "192.0.2.77" not in report + phase + index + readme
    assert "/tmp/phase-33-4a" not in report + phase + index + readme
