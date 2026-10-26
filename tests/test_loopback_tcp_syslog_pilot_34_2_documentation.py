from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_34_2_record_closes_required_safety_contracts():
    text = (ROOT / "docs/loopback_tcp_syslog_pilot_34_2.md").read_text(encoding="utf-8")
    for phrase in (
        "RFC 6587", "loopback", "application", "SSH", "framing", "backpressure",
        "인증", "개인정보", "장애", "AI", "migration", "NOT_TESTED",
        "duplicate", "downtime", "조건부", "NO_GO",
    ):
        assert phrase.casefold() in text.casefold()


def test_ubuntu_ci_runs_the_separate_process_smoke_without_artifact_upload():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "Verify bounded loopback TCP Syslog pilot on Linux" in workflow
    assert "python tests/smoke_tcp_syslog_34_2.py" in workflow
    smoke = (ROOT / "tests/smoke_tcp_syslog_34_2.py").read_text(encoding="utf-8")
    assert "TCP_SYSLOG_SMOKE_COMPLETE" in smoke
    assert "upload-artifact" not in workflow


def test_phase_34_design_and_readme_keep_runtime_and_remote_collection_unimplemented():
    design = (ROOT / "docs/automatic_log_collection_design_34_0.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Phase 34.2" in design
    assert "NOT_IMPLEMENTED" in design
    assert "자동 수집은 합성 입력의 loopback TCP Syslog pilot 범위만" in readme
    assert "원격·실제 사용자 로그 수집은 지원하지 않습니다" in readme
