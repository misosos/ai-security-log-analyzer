from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_34_5_record_separates_ci_and_user_acceptance():
    record = (ROOT / "docs/loopback_tcp_syslog_management_acceptance_34_5.md").read_text(
        encoding="utf-8"
    )
    for phrase in (
        "961e279c19ae848d405724cc09d71bfba5cfbb38",
        "40308485200",
        "2861 passed, 기존 warning 2개",
        "TCP_SYSLOG_SMOKE_COMPLETE roles=2 subprocesses=4 synthetic=1",
        "TCP_SYSLOG_LINUX_RELIABILITY_PASS roles=2 runs=80 synthetic=1 leaks=0",
        "TCP_SYSLOG_MANAGEMENT_SMOKE_PASS roles=2 synthetic=1 leaks=0",
        "states=14 external_requests=0",
        "CI artifact: **0**",
        "사용자는 명령을 직접 조작하지 않았다",
        "최초 `FAIL`",
        "최종 응답",
        "UNEXPLAINED_NON_REPRODUCED",
        "실제 사용자 자료와 조직 운영: `NO_GO`",
    ):
        assert phrase in record
    for item in range(1, 11):
        assert f"| {item}." in record


def test_phase_34_4_and_readme_point_to_phase_34_5_acceptance():
    management = (ROOT / "docs/loopback_tcp_syslog_management_34_4.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "loopback_tcp_syslog_management_acceptance_34_5.md" in management
    assert "loopback_tcp_syslog_management_acceptance_34_5.md" in readme
    assert "loopback_tcp_syslog_management_acceptance_34_5.md" in index
    assert "실제 사용자 자료·조직 운영·원격 수집은 계속 `NO_GO`" in management
