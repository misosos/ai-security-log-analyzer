from datetime import datetime

from app.analyzer.report import print_global_correlation


def test_report_prints_distributed_authentication_observations(capsys):
    limitation = (
        "이 이벤트 관계만으로 계정 침해, 공격자 로그인 또는 앞선 "
        "실패와 성공 사이의 인과관계를 확인할 수 없음"
    )
    result = {
        "multi_ip_authentication": [],
        "distributed_authentication_to_success": [
            {
                "user": "admin",
                "failure_source_ips": [
                    "10.0.0.1",
                    "10.0.0.2",
                    "10.0.0.3",
                ],
                "failure_count": 3,
                "failure_start_timestamp": datetime(
                    2026, 9, 16, 10, 0, 1
                ),
                "failure_end_timestamp": datetime(
                    2026, 9, 16, 10, 0, 5
                ),
                "success_timestamp": datetime(
                    2026, 9, 16, 10, 0, 20
                ),
                "success_source_ip": "10.0.0.4",
                "success_from_failure_source": False,
                "time_delta_seconds": 15.0,
                "rationale": [limitation],
            }
        ],
    }

    print_global_correlation(result)

    output = capsys.readouterr().out

    assert "User: admin" in output
    assert "10.0.0.1, 10.0.0.2, 10.0.0.3" in output
    assert "Failure count: 3" in output
    assert "Success source IP: 10.0.0.4" in output
    assert "Success from failure source: False" in output
    assert "Last failure → success: 15.0 seconds" in output
    assert limitation in output


def test_report_ignores_unpresented_session_lifecycle_collection(capsys):
    print_global_correlation({
        "multi_ip_authentication": [],
        "distributed_authentication_to_success": [],
        "linux_audit_session_lifecycle": [
            {
                "is_correlated": True,
                "type": "linux_audit_session_lifecycle",
            }
        ],
    })

    assert capsys.readouterr().out == ""
