from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_34_3_record_separates_remote_ci_from_local_repetition_evidence():
    text = (ROOT / "docs/loopback_tcp_syslog_acceptance_34_3.md").read_text(encoding="utf-8")
    for phrase in (
        "b3bec0833dde77f672ccebad42633b90efed3ed6",
        "40274877704",
        "2814 passed, 2 warnings",
        "TCP_SYSLOG_SMOKE_COMPLETE roles=2 subprocesses=4 synthetic=1",
        "140/140",
        "UNEXPLAINED_NON_REPRODUCED",
        "NO_GO",
        "NOT_TESTED",
        "운영 SLA가 아닙니다",
    ):
        assert phrase in text


def test_phase_34_2_errno_ci_history_is_correctly_attributed():
    text = (ROOT / "docs/loopback_tcp_syslog_pilot_34_2.md").read_text(encoding="utf-8")
    assert "40272852172" in text
    assert "40274877704" in text
    assert "errno.EADDRINUSE" in text
    assert "40178663076" not in text


def test_phase_34_3_harness_is_bounded_and_has_no_network_or_user_data_adapter():
    source = (ROOT / "tests/accept_loopback_tcp_syslog_34_3.py").read_text(encoding="utf-8")
    for phrase in (
        '"sigint": 10', '"sigterm": 20', '"normal": 10',
        '"startup": 10', '"processing": 10', '"malformed": 10',
        "range(30 if bounded else 100)", "count = 256", "TCP_SYSLOG_CYCLE_COMPLETE",
        "TCP_SYSLOG_CYCLE_COMPLETE", "TEMP_CLEANUP_FAILURES",
    ):
        assert phrase in source
    for forbidden in ("httpx", "requests.", "https://", "file_monitor", "checkpoint"):
        assert forbidden not in source


def test_docs_navigation_explains_synthetic_scope_and_keeps_real_collection_no_go():
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "loopback_tcp_syslog_acceptance_34_3.md" in index
    assert "원격·실제 사용자 로그 수집은 지원하지 않습니다" in readme


def test_phase_34_3a_linux_reliability_step_and_bounded_harness_contract():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    harness = (ROOT / "tests/accept_loopback_tcp_syslog_34_3.py").read_text(encoding="utf-8")
    record_path = ROOT / "docs/loopback_tcp_syslog_linux_reliability_34_3a.md"
    regression_step = workflow.index("- name: Run complete regression")
    reliability_step = workflow.index("- name: Verify bounded TCP Syslog reliability on Linux")
    node_step = workflow.index("- name: Install pinned Node for development-only accessibility checks")
    assert regression_step < reliability_step < node_step
    assert "Verify bounded TCP Syslog reliability on Linux" in workflow
    assert "tests/accept_loopback_tcp_syslog_34_3.py --linux-bounded" in workflow
    assert "timeout-minutes: 5" in workflow
    assert "TCP_SYSLOG_LINUX_RELIABILITY_PASS roles=2 runs=80 synthetic=1 leaks=0" in harness
    assert '"readiness": 10' in harness
    assert '"sigint": 5' in harness and '"sigterm": 5' in harness
    assert '"normal": 5' in harness and '"startup": 5' in harness
    assert '"processing": 5' in harness and '"malformed": 5' in harness
    assert "range(30 if bounded else 100)" in harness
    assert "unsupported_platform" in harness
    assert record_path.exists()
