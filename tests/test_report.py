from datetime import datetime

from app.analyzer.report import (
    print_analysis_result,
    print_global_correlation,
)


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


def lifecycle_result(**overrides):
    result = {
        "is_correlated": True,
        "type": "linux_audit_session_lifecycle",
        "source_instance": "hidden-source-instance",
        "node": "hidden-node.example",
        "audit_session_id": 51,
        "user": "alice",
        "start_event_id": "hidden-start-event",
        "end_event_id": "hidden-end-event",
        "start_timestamp": datetime(2026, 9, 18, 1, 0),
        "end_timestamp": datetime(2026, 9, 18, 1, 2),
        "observed_session_lifecycle_interval_seconds": 120.0,
        "matched_fields": ["audit_user_id"],
        "missing_fields": ["terminal"],
        "context_differences": ["operation"],
    }
    result.update(overrides)
    return result


def test_report_prints_bounded_session_lifecycle_observation(capsys):
    print_global_correlation({
        "multi_ip_authentication": [],
        "distributed_authentication_to_success": [],
        "linux_audit_session_lifecycle": [lifecycle_result()],
    })

    output = capsys.readouterr().out

    assert "Telemetry Relations" in output
    assert "Linux Audit 세션 시작/종료 연관" in output
    assert "계정: alice" in output
    assert "Linux Audit 세션 ID: 51" in output
    assert "시작 이벤트 관찰: 2026-09-18 01:00:00" in output
    assert "종료 이벤트 관찰: 2026-09-18 01:02:00" in output
    assert "시작/종료 이벤트 간 관찰 간격: 120.0초" in output
    assert "물리적 세션 동일성" in output
    assert "사용자·공격자 활동" in output
    assert "침해" in output
    assert "인과관계" in output


def test_report_hides_session_lifecycle_provenance_and_unsafe_terms(capsys):
    print_global_correlation({
        "linux_audit_session_lifecycle": [lifecycle_result()],
    })

    output = capsys.readouterr().out

    for hidden in [
        "source_instance",
        "hidden-source-instance",
        "node",
        "hidden-node.example",
        "start_event_id",
        "hidden-start-event",
        "end_event_id",
        "hidden-end-event",
        "matched_fields",
        "missing_fields",
        "context_differences",
    ]:
        assert hidden not in output

    for misleading in [
        "세션 지속 시간",
        "공격자 체류 시간",
        "침해 세션",
        "확인된 세션",
    ]:
        assert misleading not in output


def test_report_prints_limitation_once_and_preserves_relation_order(capsys):
    print_global_correlation({
        "linux_audit_session_lifecycle": [
            lifecycle_result(user="first-user", audit_session_id=52),
            lifecycle_result(user="second-user", audit_session_id=51),
        ],
    })

    output = capsys.readouterr().out

    assert output.index("계정: first-user") < output.index(
        "계정: second-user"
    )
    assert output.count("source-scoped context의 일치") == 1


def test_report_omits_empty_or_false_session_lifecycle_section(capsys):
    print_global_correlation({
        "linux_audit_session_lifecycle": [],
    })
    print_global_correlation({
        "linux_audit_session_lifecycle": [
            lifecycle_result(is_correlated=False),
        ],
    })

    output = capsys.readouterr().out

    assert "Telemetry Relations" not in output
    assert "Linux Audit 세션 시작/종료 연관" not in output


def test_report_accepts_missing_global_and_lifecycle_keys(capsys):
    print_analysis_result({"results": {}})
    print_global_correlation({})
    print_global_correlation({
        "multi_ip_authentication": [],
        "distributed_authentication_to_success": [],
    })

    assert capsys.readouterr().out == ""
