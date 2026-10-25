from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ubuntu_workflow_runs_a_dedicated_restricted_report_smoke():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    smoke = ROOT / "tests/smoke_restricted_report_33_5c.py"

    assert "Verify restricted analyst report on Linux" in workflow
    assert "tests/smoke_restricted_report_33_5c.py" in workflow
    assert "Measure bounded synthetic report export on Linux" in workflow
    assert "tests/benchmark_restricted_report_33_5b.py" in workflow
    assert "upload-artifact" not in workflow
    assert smoke.is_file()


def test_linux_smoke_uses_synthetic_inputs_and_has_a_safe_fixed_summary():
    smoke = (ROOT / "tests/smoke_restricted_report_33_5c.py").read_text(encoding="utf-8")

    assert "synthetic" in smoke.lower()
    assert "RESTRICTED_REPORT_LINUX_SMOKE_PASS" in smoke
    assert "restricted-investigation-report/v1" in smoke
    assert "Popen" in smoke or "subprocess.run" in smoke
    assert "upload-artifact" not in smoke


def test_linux_acceptance_record_separates_gate_ci_from_post_change_linux_evidence():
    acceptance = (ROOT / "docs/trusted_analyst_report_linux_acceptance_33_5c.md").read_text(encoding="utf-8")

    assert "e5340f9916eb977ae1ef46ad51c5adf63192ba1d" in acceptance
    assert "40174710982" in acceptance
    assert "NOT_TESTED" in acceptance
    assert "실제 사용자 자료" in acceptance and "NO_GO" in acceptance
    assert "자동 암호화되지 않습니다" in acceptance
