from copy import deepcopy
from datetime import datetime, timezone
import json

import app.main as main_module
from app.analyzer.llm import serialize_value
from app.analyzer.process_execution import (
    aggregate_process_execution_observations,
)
from app.analyzer.report import print_analysis_result
from app.api import build_analysis_response
from app.models.schemas import (
    LinuxAuditContext,
    LinuxAuditPathContext,
    NormalizedEvent,
    ProcessExecutionContext,
)


CANARY = "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE"


def canary_event():
    path = LinuxAuditPathContext(
        item=0,
        name=f"/private/{CANARY}",
        nametype="NORMAL",
        inode=101,
        device="fd:01",
        mode="0100600",
        owner_user_id=1000,
        owner_group_id=1000,
    )
    context = ProcessExecutionContext(
        outcome="success",
        architecture_raw="c000003e",
        syscall_raw="59",
        architecture_name=None,
        syscall_name=None,
        exit_code=0,
        process_id=2001,
        parent_process_id=2000,
        real_user_id=1000,
        effective_user_id=1000,
        saved_user_id=1000,
        filesystem_user_id=1000,
        real_group_id=1000,
        effective_group_id=1000,
        saved_group_id=1000,
        filesystem_group_id=1000,
        command_name=CANARY,
        executable=f"/opt/{CANARY}",
        terminal="pts0",
        audit_rule_key=CANARY,
        argument_count=2,
        argv=("example", CANARY),
        argv_complete=True,
        incomplete_argument_indexes=(),
        working_directory=f"/work/{CANARY}",
        paths=(path,),
        paths_complete=True,
        proctitle_raw=CANARY,
        proctitle_arguments=("example", CANARY),
        raw_records=(f"raw={CANARY}",),
    )
    return NormalizedEvent(
        timestamp=datetime(2026, 9, 25, tzinfo=timezone.utc),
        event_type="process_execution_attempt",
        source="linux_audit",
        user=None,
        src_ip=None,
        dst_ip=None,
        application=None,
        protocol=None,
        user_agent=None,
        raw=f"raw={CANARY}",
        linux_audit=LinuxAuditContext(
            event_id="1790900000.001:1301",
            record_types=("SYSCALL", "EXECVE"),
            executable=f"/opt/{CANARY}",
            source_instance=CANARY,
            node=CANARY,
        ),
        process_execution=context,
    )


def test_main_loads_once_and_passes_separate_cli_aggregate(monkeypatch):
    logs = [object()]
    analysis = {
        "results": {},
        "global_correlation": {},
    }
    aggregate = {"observation_count": 1}
    calls = []

    def fake_load(sources):
        calls.append(("load", sources))
        return logs

    def fake_analyze(received_logs):
        calls.append(("analyze", received_logs))
        return analysis

    def fake_aggregate(received_logs):
        calls.append(("aggregate", received_logs))
        return aggregate

    def fake_print(received_analysis, *, process_execution_aggregate=None):
        calls.append((
            "print",
            received_analysis,
            process_execution_aggregate,
        ))

    monkeypatch.setattr(main_module, "load_normalized_logs", fake_load)
    monkeypatch.setattr(main_module, "_analyze_normalized_logs", fake_analyze)
    monkeypatch.setattr(
        main_module,
        "aggregate_process_execution_observations",
        fake_aggregate,
    )
    monkeypatch.setattr(main_module, "print_analysis_result", fake_print)

    main_module.main()

    assert calls == [
        ("load", main_module.LOG_SOURCES),
        ("analyze", logs),
        ("aggregate", logs),
        ("print", analysis, aggregate),
    ]


def test_analyze_keeps_existing_public_contract(monkeypatch):
    logs = [object()]
    analysis = {
        "results": {"fixture-ip": {}},
        "global_correlation": {"fixture": []},
    }

    monkeypatch.setattr(
        main_module,
        "load_normalized_logs",
        lambda sources: logs,
    )
    monkeypatch.setattr(
        main_module,
        "_analyze_normalized_logs",
        lambda received_logs: analysis
        if received_logs is logs
        else None,
    )

    result = main_module.analyze([{"source": "fixture"}])

    assert result is analysis
    assert set(result) == {"results", "global_correlation"}
    assert "process_execution_aggregate" not in result
    assert "logs" not in result


def test_canary_stays_internal_across_cli_api_and_llm(capsys):
    event = canary_event()
    original = deepcopy(event)
    aggregate = aggregate_process_execution_observations([event])
    analysis = main_module._analyze_normalized_logs([event])

    assert CANARY in repr(event.process_execution)
    assert CANARY in repr(event.linux_audit)

    print_analysis_result(
        analysis,
        process_execution_aggregate=aggregate,
    )
    cli_output = capsys.readouterr().out

    response = build_analysis_response(analysis, total_sources=1)
    api_output = response.model_dump()
    llm_output = serialize_value(analysis)

    assert CANARY not in repr(aggregate)
    assert CANARY not in cli_output
    assert CANARY not in json.dumps(api_output, sort_keys=True)
    assert CANARY not in json.dumps(llm_output, sort_keys=True)
    assert "process_execution_aggregate" not in api_output
    assert "process_execution_aggregate" not in llm_output
    assert "example" not in cli_output
    assert "/private/" not in cli_output
    assert "PROCTITLE" not in cli_output
    assert "raw_records" not in cli_output
    assert event == original
