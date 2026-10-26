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
        "range(100)", "count = 256", "TCP_SYSLOG_CYCLE_COMPLETE",
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
