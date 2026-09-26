from datetime import datetime

import pytest

from app.analyzer.report import (
    print_analysis_result,
    print_global_correlation,
)
from app.detector.shared_memory_execution import (
    SharedMemoryExecutionReviewSummary,
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


def login_start_result(**overrides):
    result = {
        "is_correlated": True,
        "type": "linux_audit_login_start_co_observation",
        "source_instance": "hidden-login-source",
        "node": "hidden-login-node.example",
        "audit_session_id": 71,
        "user": "training-account",
        "login_event_id": "hidden-login-event",
        "start_event_id": "hidden-session-start-event",
        "login_timestamp": datetime(2026, 9, 18, 1, 0, 2),
        "start_timestamp": datetime(2026, 9, 18, 1, 0, 1),
        "matched_fields": ["audit_user_id"],
        "missing_fields": ["terminal"],
        "context_differences": ["operation"],
        "rationale": ["hidden-engine-rationale"],
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


def test_report_prints_bounded_login_start_co_observation(capsys):
    print_global_correlation({
        "linux_audit_login_start_co_observation": [
            login_start_result(),
        ],
    })

    output = capsys.readouterr().out

    assert "Telemetry Relations" in output
    assert (
        "Linux Audit 로그인·세션 시작 이벤트 공동 관찰"
        in output
    )
    assert "계정: training-account" in output
    assert "Linux Audit 세션 ID: 71" in output
    assert (
        "USER_LOGIN 이벤트 관찰 시각: 2026-09-18 01:00:02"
        in output
    )
    assert (
        "USER_START 이벤트 관찰 시각: 2026-09-18 01:00:01"
        in output
    )
    assert "USER_LOGIN 및 USER_START 이벤트가 각각 관찰" in output
    assert "표시 순서는 이벤트 순서나 전이를 의미하지 않으며" in output
    assert "물리적 세션" in output
    assert "PAM transaction" in output
    assert "SSH connection" in output
    assert "사용자·공격자 활동" in output
    assert "침해 또는 인과관계" in output


def test_report_hides_login_start_provenance_and_interval(capsys):
    print_global_correlation({
        "linux_audit_login_start_co_observation": [
            login_start_result(),
        ],
    })

    output = capsys.readouterr().out

    for hidden in [
        "source_instance",
        "hidden-login-source",
        "node",
        "hidden-login-node.example",
        "login_event_id",
        "hidden-login-event",
        "start_event_id",
        "hidden-session-start-event",
        "matched_fields",
        "missing_fields",
        "context_differences",
        "hidden-engine-rationale",
    ]:
        assert hidden not in output

    for forbidden in [
        "→",
        "로그인 후",
        "세션 생성",
        "same session",
        "관찰 간격",
        "경과 시간",
        "duration",
        "latency",
        "observed_login_to_start_interval_seconds",
    ]:
        assert forbidden not in output


def test_report_preserves_login_start_engine_order_and_note_once(capsys):
    print_global_correlation({
        "linux_audit_login_start_co_observation": [
            login_start_result(user="first-account"),
            login_start_result(user="second-account"),
        ],
    })

    output = capsys.readouterr().out

    assert output.index("계정: first-account") < output.index(
        "계정: second-account"
    )
    assert output.count(
        "Linux Audit 로그인·세션 시작 이벤트 공동 관찰"
    ) == 2
    assert output.count(
        "USER_LOGIN 및 USER_START 이벤트가 각각 관찰"
    ) == 1


def test_report_omits_empty_false_or_missing_login_start_collection(
    capsys,
):
    print_global_correlation({
        "linux_audit_login_start_co_observation": [],
    })
    print_global_correlation({
        "linux_audit_login_start_co_observation": [
            login_start_result(is_correlated=False),
        ],
    })
    print_global_correlation({})

    output = capsys.readouterr().out

    assert "Telemetry Relations" not in output
    assert (
        "Linux Audit 로그인·세션 시작 이벤트 공동 관찰"
        not in output
    )


def test_report_renders_lifecycle_and_login_start_as_independent_groups(
    capsys,
):
    print_global_correlation({
        "linux_audit_session_lifecycle": [lifecycle_result()],
        "linux_audit_login_start_co_observation": [
            login_start_result(),
        ],
    })

    output = capsys.readouterr().out

    lifecycle_label = "Linux Audit 세션 시작/종료 연관"
    login_start_label = (
        "Linux Audit 로그인·세션 시작 이벤트 공동 관찰"
    )

    assert output.count("===== Telemetry Relations =====") == 1
    assert output.index(lifecycle_label) < output.index(login_start_label)
    assert output.count("source-scoped context의 일치") == 1
    assert output.count(
        "USER_LOGIN 및 USER_START 이벤트가 각각 관찰"
    ) == 1
    assert "시작/종료 이벤트 간 관찰 간격: 120.0초" in output
    assert "로그인·세션 시작 이벤트 공동 관찰 →" not in output


def process_execution_aggregate(observation_count=7):
    return {
        "observation_count": observation_count,
        "outcome_counts": {
            "success": 4,
            "failure": 2,
            "unknown": 1,
        },
        "argv_completeness_counts": {
            "complete": 5,
            "incomplete": 2,
        },
        "path_completeness_counts": {
            "complete": 3,
            "incomplete": 4,
        },
    }


def test_report_prints_bounded_process_execution_aggregate(capsys):
    print_analysis_result(
        {"results": {}},
        process_execution_aggregate=(
            process_execution_aggregate()
        ),
    )

    output = capsys.readouterr().out

    assert "===== Process Execution Telemetry =====" in output
    assert "Linux Audit 프로세스 실행 관찰 집계" in output
    assert "관찰 수: 7" in output
    assert "success: 4" in output
    assert "failure: 2" in output
    assert "unknown: 1" in output
    assert output.count("complete: 5") == 1
    assert output.count("incomplete: 2") == 1
    assert output.count("complete: 3") == 1
    assert output.count("incomplete: 4") == 1
    assert "프로그램 목적 달성 또는 공격 성공을 의미하지 않습니다" in output
    assert "정확성, 신뢰도 또는 안전성을 의미하지 않습니다" in output
    assert "{'observation_count':" not in output
    assert '\"observation_count\"' not in output


def test_report_omits_empty_process_execution_aggregate(capsys):
    print_analysis_result({"results": {}})
    print_analysis_result(
        {"results": {}},
        process_execution_aggregate=(
            process_execution_aggregate(observation_count=0)
        ),
    )

    output = capsys.readouterr().out

    assert "Process Execution Telemetry" not in output
    assert "Linux Audit 프로세스 실행 관찰 집계" not in output
    assert "실행 없음" not in output


def test_process_execution_aggregate_output_shape_is_fixed(capsys):
    first = process_execution_aggregate(observation_count=1)
    second = process_execution_aggregate(observation_count=20)

    print_analysis_result(
        {"results": {}},
        process_execution_aggregate=first,
    )
    first_output = capsys.readouterr().out
    print_analysis_result(
        {"results": {}},
        process_execution_aggregate=second,
    )
    second_output = capsys.readouterr().out

    assert first_output.replace("관찰 수: 1", "관찰 수: N") == (
        second_output.replace("관찰 수: 20", "관찰 수: N")
    )


def review_summary(count):
    return SharedMemoryExecutionReviewSummary(
        shared_memory_privileged_execution_observation_count=count,
    )


def test_report_prints_only_bounded_review_count_and_disclaimer(capsys):
    print_analysis_result(
        {"results": {}},
        process_execution_aggregate=process_execution_aggregate(),
        process_detection_summary=review_summary(6),
    )

    output = capsys.readouterr().out

    assert "shared-memory privileged execution" in output
    assert "review" not in output
    assert ": 6" in output
    assert "unique process" in output
    assert "malware" in output
    assert "confirmed attack" in output
    assert "compromise" in output
    assert "/dev/shm/" not in output
    assert "/run/shm/" not in output
    assert "effective_user_id" not in output
    assert "source_instance" not in output
    assert "event_id" not in output
    assert "raw_records" not in output
    assert "malware count: 6" not in output
    assert "confirmed attack count: 6" not in output


def test_report_omits_zero_review_count_and_preserves_aggregate(capsys):
    print_analysis_result(
        {"results": {}},
        process_execution_aggregate=process_execution_aggregate(),
        process_detection_summary=review_summary(0),
    )

    output = capsys.readouterr().out

    assert "===== Process Execution Telemetry =====" in output
    assert "shared-memory privileged execution" not in output
    assert "unique process" not in output
    assert "no attack" not in output
    assert "safe" not in output


@pytest.mark.parametrize(
    "summary",
    [
        object(),
        review_summary(False),
        review_summary(-1),
    ],
)
def test_report_rejects_invalid_review_summary_contract(summary):
    with pytest.raises((TypeError, ValueError)):
        print_analysis_result(
            {"results": {}},
            process_execution_aggregate=process_execution_aggregate(),
            process_detection_summary=summary,
        )


@pytest.mark.parametrize(
    "aggregate",
    [
        None,
        process_execution_aggregate(observation_count=0),
    ],
)
def test_report_rejects_positive_review_count_without_telemetry(aggregate):
    with pytest.raises(ValueError):
        print_analysis_result(
            {"results": {}},
            process_execution_aggregate=aggregate,
            process_detection_summary=review_summary(1),
        )
