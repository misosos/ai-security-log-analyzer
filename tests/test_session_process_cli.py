import json
from pathlib import Path

import pytest

import app.main as main_module
from app.analyzer.llm import serialize_value
from app.analyzer.report import print_analysis_result
from app.api import build_analysis_response
from app.correlation.session_process import SessionProcessReviewSummary
from app.detector.shared_memory_execution import (
    SharedMemoryExecutionReviewSummary,
)


SESSION_LINKED_FIXTURE = Path(
    "sample_logs/"
    "linux_audit_session_shared_memory_review_contract_synthetic.log"
)
SESSION_FIXTURE = Path(
    "sample_logs/"
    "linux_audit_session_process_co_observation_contract_synthetic.log"
)
PROCESS_FIXTURE = Path(
    "sample_logs/"
    "linux_audit_shared_memory_execution_contract_synthetic.log"
)
CANARY = "SYNTHETIC_SESSION_PROCESS_SECRET_DO_NOT_EXPOSE"


def session_summary(
    sessions=1,
    processes=3,
    success=2,
    failure=1,
    unknown=0,
    shared=1,
    shared_sessions=1,
):
    return SessionProcessReviewSummary(
        session_co_observation_count=sessions,
        process_observation_count=processes,
        process_outcome_success_count=success,
        process_outcome_failure_count=failure,
        process_outcome_unknown_count=unknown,
        shared_memory_privileged_execution_observation_count=shared,
        sessions_with_shared_memory_privileged_execution_count=(
            shared_sessions
        ),
    )


def process_summary(count=2):
    return SharedMemoryExecutionReviewSummary(
        shared_memory_privileged_execution_observation_count=count,
    )


def process_aggregate(count=3):
    return {
        "observation_count": count,
        "outcome_counts": {
            "success": 2,
            "failure": 1,
            "unknown": 0,
        },
        "argv_completeness_counts": {
            "complete": count,
            "incomplete": 0,
        },
        "path_completeness_counts": {
            "complete": 0,
            "incomplete": count,
        },
    }


def test_report_prints_only_bounded_session_summary_and_disclaimers(capsys):
    print_analysis_result(
        {"results": {}},
        process_execution_aggregate=process_aggregate(),
        process_detection_summary=process_summary(),
        session_process_review_summary=session_summary(),
    )
    output = capsys.readouterr().out

    assert "===== Session–Process Co-Observation =====" in output
    assert "공동 관찰 세션 수: 1" in output
    assert "세션 구간 내 프로세스 관찰 수: 3" in output
    assert "success: 2" in output
    assert "failure: 1" in output
    assert "unknown: 0" in output
    assert "shared-memory privileged execution 관찰 수: 1" in output
    assert "해당 관찰이 포함된 세션 수: 1" in output
    assert "동일 Linux Audit scope" in output
    assert "직접 실행이나 인과관계를 증명하지 않습니다" in output
    assert "프로그램 목적 달성이나 공격 성공을 의미하지 않습니다" in output
    assert "malware, confirmed attack, compromise 또는 incident" in output
    for prohibited in (
        "source_instance",
        "audit_session_id",
        "audit_user_id",
        "event_id",
        "/dev/shm/",
        "raw_records",
    ):
        assert prohibited not in output


def test_report_none_and_zero_summary_preserve_existing_output(capsys):
    analysis = {"results": {}}
    print_analysis_result(analysis)
    baseline = capsys.readouterr().out
    print_analysis_result(
        analysis,
        session_process_review_summary=session_summary(
            sessions=0,
            processes=0,
            success=0,
            failure=0,
            shared=0,
            shared_sessions=0,
        ),
    )
    with_zero = capsys.readouterr().out

    assert baseline == with_zero
    assert "Session–Process" not in with_zero
    assert "관찰 없음" not in with_zero
    assert "공격 없음" not in with_zero


@pytest.mark.parametrize(
    "summary",
    [
        object(),
        session_summary(sessions=False),
        session_summary(processes=-1),
        session_summary(success=1),
        session_summary(shared=4),
        session_summary(shared_sessions=2),
        session_summary(
            sessions=0,
            processes=1,
            success=1,
            failure=0,
            shared=0,
            shared_sessions=0,
        ),
        session_summary(
            sessions=1,
            processes=0,
            success=0,
            failure=0,
            shared=0,
            shared_sessions=0,
        ),
        session_summary(shared=0, shared_sessions=1),
    ],
)
def test_report_rejects_invalid_session_summary_contract(summary):
    with pytest.raises(ValueError):
        print_analysis_result(
            {"results": {}},
            process_detection_summary=process_summary(5),
            session_process_review_summary=summary,
        )


def test_report_rejects_session_linked_count_above_overall_count():
    with pytest.raises(ValueError):
        print_analysis_result(
            {"results": {}},
            process_detection_summary=process_summary(0),
            session_process_review_summary=session_summary(),
        )


def test_main_uses_single_logs_and_shared_observation_objects(monkeypatch):
    logs = []
    analysis = {"results": {}, "global_correlation": {}}
    aggregate = {"observation_count": 3}
    observations = (object(), object())
    relations = (object(),)
    detection_summary = process_summary(2)
    review_summary = session_summary()
    calls = []

    monkeypatch.setattr(
        main_module,
        "load_normalized_logs",
        lambda sources: calls.append(("load", sources)) or logs,
    )
    monkeypatch.setattr(
        main_module,
        "_analyze_normalized_logs",
        lambda value: calls.append(("analyze", value)) or analysis,
    )
    monkeypatch.setattr(
        main_module,
        "aggregate_process_execution_observations",
        lambda value: calls.append(("aggregate", value)) or aggregate,
    )
    monkeypatch.setattr(
        main_module,
        "collect_shared_memory_execution_observations",
        lambda value: calls.append(("shared_collect", value))
        or observations,
    )
    monkeypatch.setattr(
        main_module,
        "summarize_shared_memory_execution_observations",
        lambda value: calls.append(("shared_summary", value))
        or detection_summary,
    )
    monkeypatch.setattr(
        main_module,
        "collect_session_process_co_observations",
        lambda value: calls.append(("session_collect", value))
        or relations,
    )
    monkeypatch.setattr(
        main_module,
        "summarize_session_process_co_observations",
        lambda first, second: calls.append(
            ("session_summary", first, second)
        ) or review_summary,
    )

    def fake_print(received, **kwargs):
        calls.append(("print", received, kwargs))

    monkeypatch.setattr(main_module, "print_analysis_result", fake_print)

    main_module.main()

    assert calls == [
        ("load", main_module.LOG_SOURCES),
        ("analyze", logs),
        ("aggregate", logs),
        ("shared_collect", logs),
        ("shared_summary", observations),
        ("session_collect", logs),
        ("session_summary", relations, observations),
        (
            "print",
            analysis,
            {
                "process_execution_aggregate": aggregate,
                "process_detection_summary": detection_summary,
                "session_process_review_summary": review_summary,
            },
        ),
    ]


@pytest.mark.parametrize("stage", ["collector", "summary", "report"])
def test_main_bounds_session_contract_failures(stage, monkeypatch, capsys):
    secret = "PRIVATE_SESSION_CONTRACT_DETAIL"
    monkeypatch.setattr(main_module, "load_normalized_logs", lambda _: [])
    monkeypatch.setattr(
        main_module,
        "_analyze_normalized_logs",
        lambda _: {"results": {}, "global_correlation": {}},
    )
    monkeypatch.setattr(
        main_module,
        "aggregate_process_execution_observations",
        lambda _: {"observation_count": 0},
    )
    monkeypatch.setattr(
        main_module,
        "collect_shared_memory_execution_observations",
        lambda _: (),
    )
    monkeypatch.setattr(
        main_module,
        "summarize_shared_memory_execution_observations",
        lambda _: process_summary(0),
    )

    if stage == "collector":
        def fail_collector(_):
            raise ValueError(secret)

        monkeypatch.setattr(
            main_module,
            "collect_session_process_co_observations",
            fail_collector,
        )
    else:
        monkeypatch.setattr(
            main_module,
            "collect_session_process_co_observations",
            lambda _: (),
        )
        if stage == "summary":
            def fail_summary(*_):
                raise TypeError(secret)

            monkeypatch.setattr(
                main_module,
                "summarize_session_process_co_observations",
                fail_summary,
            )
        else:
            monkeypatch.setattr(
                main_module,
                "summarize_session_process_co_observations",
                lambda *_: session_summary(),
            )

            def fail_report(*_, **__):
                raise ValueError(secret)

            monkeypatch.setattr(
                main_module,
                "print_analysis_result",
                fail_report,
            )

    with pytest.raises(SystemExit) as raised:
        main_module.main()

    captured = capsys.readouterr()
    assert raised.value.code == 1
    assert captured.out == ""
    assert captured.err == (
        "Session-process review summary could not be created: "
        "internal contract validation failed.\n"
    )
    assert secret not in captured.err
    assert "Traceback" not in captured.err


def run_cli(path, capsys):
    main_module.main(["--linux-audit", str(path)])
    return capsys.readouterr()


def test_actual_fixture_cli_acceptance_and_privacy(capsys):
    captured = run_cli(SESSION_LINKED_FIXTURE, capsys)
    output = captured.out

    assert captured.err == ""
    assert "shared-memory privileged execution 검토 관찰 수: 2" in output
    assert "공동 관찰 세션 수: 1" in output
    assert "세션 구간 내 프로세스 관찰 수: 3" in output
    assert "success: 2" in output
    assert "failure: 1" in output
    assert "unknown: 0" in output
    assert "shared-memory privileged execution 관찰 수: 1" in output
    assert "해당 관찰이 포함된 세션 수: 1" in output
    for private in (
        CANARY,
        "/dev/shm/session-review-probe",
        "session-shared-memory-review",
        "1793000001.000:4002",
        "audit_session_id",
        "raw=",
        "Traceback",
    ):
        assert private not in captured.out
        assert private not in captured.err


def test_default_and_existing_fixture_cli_section_policies(capsys):
    main_module.main([])
    default_output = capsys.readouterr().out
    assert "Session–Process Co-Observation" not in default_output

    process_output = run_cli(PROCESS_FIXTURE, capsys).out
    assert "shared-memory privileged execution 검토 관찰 수: 6" in process_output
    assert "Session–Process Co-Observation" not in process_output

    session_output = run_cli(SESSION_FIXTURE, capsys).out
    assert "공동 관찰 세션 수: 2" in session_output
    assert "세션 구간 내 프로세스 관찰 수: 5" in session_output
    assert "shared-memory privileged execution 관찰 수: 0" in session_output
    assert "해당 관찰이 포함된 세션 수: 0" in session_output


def test_multiple_inputs_preserve_source_scope_and_external_contracts(capsys):
    main_module.main([
        "--linux-audit",
        str(SESSION_LINKED_FIXTURE),
        "--linux-audit",
        str(SESSION_FIXTURE),
    ])
    output = capsys.readouterr().out

    assert "공동 관찰 세션 수: 3" in output
    assert "세션 구간 내 프로세스 관찰 수: 8" in output
    assert "shared-memory privileged execution 검토 관찰 수: 2" in output
    assert "shared-memory privileged execution 관찰 수: 1" in output

    analysis = main_module.analyze([])
    api = build_analysis_response(analysis, total_sources=0).model_dump()
    llm = serialize_value(analysis)
    serialized = json.dumps({"api": api, "llm": llm}, sort_keys=True)

    assert set(analysis) == {"results", "global_correlation"}
    assert "session_process_review_summary" not in serialized
    assert CANARY not in serialized
