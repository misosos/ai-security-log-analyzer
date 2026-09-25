from copy import deepcopy
from datetime import timezone
import json
from pathlib import Path

import pytest

from app.analyzer.llm import build_llm_input, serialize_value
from app.analyzer.pipeline import (
    assess_risk,
    correlate_attacks,
    detect_attacks,
    load_normalized_logs,
)
from app.analyzer.report import print_analysis_result
from app.api import build_analysis_response
from app.main import analyze


FIXTURE_DIR = Path("sample_logs")
PROCESS_FIXTURE = (
    FIXTURE_DIR / "linux_audit_exec_success_rhel_source_derived.log"
)
CANARY = "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE"
GLOBAL_KEYS = {
    "multi_ip_authentication",
    "distributed_authentication_to_success",
    "linux_audit_session_lifecycle",
    "linux_audit_login_start_co_observation",
}
BASE_SOURCES = (
    {"source": "application", "path": "sample_logs/brute_force.log"},
    {"source": "ssh", "path": "sample_logs/ssh_auth.log"},
    {"source": "access", "path": "sample_logs/web_shell.log"},
)


def linux_audit_source(path, source_instance="phase-3t-source"):
    return {
        "source": "linux_audit",
        "path": path,
        "source_instance": source_instance,
    }


def serialized_text(value):
    return json.dumps(
        serialize_value(value),
        ensure_ascii=False,
        sort_keys=True,
    )


def response_without_id(analysis, total_sources):
    response = build_analysis_response(analysis, total_sources=total_sources)
    return response.model_dump(exclude={"analysis_id"})


def write_canary_fixture(tmp_path):
    proctitle = (
        f"/usr/bin/example\0{CANARY}\0../../etc/passwd"
    ).encode("utf-8").hex()
    path = tmp_path / "process-canary.log"
    path.write_text(
        "\n".join((
            "node=phase-3t-canary type=EXECVE "
            "msg=audit(1790800000.001:1101): "
            f'argc=3 a0="/usr/bin/example" a1="{CANARY}" '
            'a2="../../etc/passwd"',
            "node=phase-3t-canary type=PATH "
            "msg=audit(1790800000.001:1101): "
            'item=0 name="/etc/shadow" inode=1201 dev=fd:01 '
            "mode=0100640 ouid=0 ogid=0 nametype=NORMAL",
            "node=phase-3t-canary type=PROCTITLE "
            "msg=audit(1790800000.001:1101): "
            f"proctitle={proctitle}",
            "node=phase-3t-canary type=SYSCALL "
            "msg=audit(1790800000.001:1101): "
            "arch=c000003e syscall=59 success=yes exit=0 items=1 "
            "ppid=7100 pid=7101 auid=0 uid=0 gid=0 euid=0 "
            "suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 "
            "ses=91 comm=\"example\" exe=\"/usr/bin/example\" "
            "key=\"phase-3t-canary\"",
        )),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    ("fixture", "expected_count", "outcomes", "completeness"),
    [
        (
            "linux_audit_exec_success_rhel_source_derived.log",
            1,
            ("success",),
            (True,),
        ),
        (
            "linux_audit_exec_failure_structurally_derived.log",
            1,
            ("failure",),
            (True,),
        ),
        (
            "linux_audit_exec_optional_records_missing.log",
            1,
            ("success",),
            (True,),
        ),
        (
            "linux_audit_exec_incomplete_arguments_synthetic.log",
            2,
            ("success", "success"),
            (False, False),
        ),
    ],
)
def test_real_files_reach_bounded_normalized_process_events(
    fixture,
    expected_count,
    outcomes,
    completeness,
):
    logs = load_normalized_logs([
        linux_audit_source(FIXTURE_DIR / fixture)
    ])

    assert len(logs) == expected_count
    assert tuple(event.process_execution.outcome for event in logs) == outcomes
    assert tuple(
        event.process_execution.argv_complete for event in logs
    ) == completeness
    assert all(event.event_type == "process_execution_attempt" for event in logs)
    assert all(event.source == "linux_audit" for event in logs)
    assert all(event.timestamp.tzinfo == timezone.utc for event in logs)
    assert all(event.src_ip is None for event in logs)
    assert all(event.authentication is None for event in logs)
    assert all(event.process_execution is not None for event in logs)
    assert all(event.linux_audit is not None for event in logs)
    assert all(
        event.linux_audit.source_instance == "phase-3t-source"
        for event in logs
    )


def test_core_ambiguity_is_omitted_without_stopping_other_groups():
    logs = load_normalized_logs([
        linux_audit_source(
            FIXTURE_DIR
            / "linux_audit_exec_required_records_ambiguous_synthetic.log"
        ),
        linux_audit_source(PROCESS_FIXTURE, "phase-3t-valid"),
    ])

    assert len(logs) == 1
    assert logs[0].linux_audit.source_instance == "phase-3t-valid"
    assert logs[0].linux_audit.event_id == "1790400000.001:801"


def test_same_event_id_remains_isolated_by_node_and_source_instance():
    interleaved = (
        FIXTURE_DIR / "linux_audit_exec_interleaved_scope_isolation.log"
    )
    first = load_normalized_logs([
        linux_audit_source(interleaved, "feed-a")
    ])
    second = load_normalized_logs([
        linux_audit_source(interleaved, "feed-b")
    ])

    assert len(first) == len(second) == 3
    assert {
        (event.linux_audit.source_instance,
         event.linux_audit.node,
         event.linux_audit.event_id)
        for event in (*first, *second)
    } == {
        ("feed-a", "fixture-node-a", "1790400005.006:806"),
        ("feed-a", "fixture-node-b", "1790400005.006:806"),
        ("feed-a", "fixture-node-a", "1790400006.007:807"),
        ("feed-b", "fixture-node-a", "1790400005.006:806"),
        ("feed-b", "fixture-node-b", "1790400005.006:806"),
        ("feed-b", "fixture-node-a", "1790400006.007:807"),
    }


def test_process_only_events_do_not_create_detection_correlation_or_risk():
    logs = load_normalized_logs([
        linux_audit_source(PROCESS_FIXTURE)
    ])

    detections = detect_attacks(logs)
    correlated = correlate_attacks(logs, detections)
    assessed = assess_risk(deepcopy(correlated))

    assert detections == {}
    assert correlated["results"] == {}
    assert set(correlated["global_correlation"]) == GLOBAL_KEYS
    assert all(
        value == []
        for value in correlated["global_correlation"].values()
    )
    assert assessed == correlated


def test_analyze_process_only_is_deterministic_and_keeps_internal_data_out():
    sources = [linux_audit_source(PROCESS_FIXTURE)]

    first = analyze(sources)
    second = analyze(sources)

    assert first == second
    assert first["results"] == {}
    assert set(first["global_correlation"]) == GLOBAL_KEYS
    assert all(value == [] for value in first["global_correlation"].values())
    assert "process_execution" not in first


def test_mixed_process_input_does_not_change_existing_analysis_or_consumers(
    capsys,
):
    baseline_sources = list(BASE_SOURCES)
    mixed_sources = [
        *baseline_sources,
        linux_audit_source(PROCESS_FIXTURE),
    ]

    baseline = analyze(baseline_sources)
    mixed = analyze(mixed_sources)

    assert mixed == baseline
    assert response_without_id(mixed, 4)["results"] == (
        response_without_id(baseline, 3)["results"]
    )
    assert response_without_id(mixed, 4)["global_correlation"] == (
        response_without_id(baseline, 3)["global_correlation"]
    )

    print_analysis_result(baseline)
    baseline_cli = capsys.readouterr().out
    print_analysis_result(mixed)
    mixed_cli = capsys.readouterr().out
    assert mixed_cli == baseline_cli

    assert serialize_value(mixed) == serialize_value(baseline)
    for ip in baseline["results"]:
        assert build_llm_input(ip, mixed["results"][ip]) == (
            build_llm_input(ip, baseline["results"][ip])
        )


def test_process_input_does_not_change_existing_linux_audit_relations():
    lifecycle_source = linux_audit_source(
        FIXTURE_DIR
        / "linux_audit_util_linux_login_pam_source_derived.log",
        "phase-3t-lifecycle",
    )

    baseline = analyze([lifecycle_source])
    mixed = analyze([
        lifecycle_source,
        linux_audit_source(PROCESS_FIXTURE, "phase-3t-process"),
    ])

    assert mixed == baseline
    assert len(
        mixed["global_correlation"][
            "linux_audit_session_lifecycle"
        ]
    ) == 1
    assert len(
        mixed["global_correlation"][
            "linux_audit_login_start_co_observation"
        ]
    ) == 1


def test_synthetic_canary_stays_internal_at_all_external_boundaries(
    tmp_path,
    capsys,
):
    path = write_canary_fixture(tmp_path)
    sources = [linux_audit_source(path, "phase-3t-canary-source")]
    logs = load_normalized_logs(sources)

    assert len(logs) == 1
    context = logs[0].process_execution
    assert context is not None
    assert CANARY in context.argv
    assert CANARY in context.proctitle_arguments
    assert any(CANARY in raw for raw in context.raw_records)
    assert context.real_user_id == 0
    assert context.paths[0].name == "/etc/shadow"

    analysis = analyze(sources)
    assert analysis["results"] == {}
    assert all(value == [] for value in analysis["global_correlation"].values())

    response = build_analysis_response(analysis, total_sources=1)
    response_data = response.model_dump()
    assert response_data["results"] == []
    assert "process_execution" not in response_data

    print_analysis_result(analysis)
    cli_output = capsys.readouterr().out
    assert cli_output == ""

    overall_llm_input = serialize_value(analysis)
    assert set(overall_llm_input) == {"results", "global_correlation"}
    assert CANARY not in serialized_text(response_data)
    assert CANARY not in cli_output
    assert CANARY not in serialized_text(overall_llm_input)
    assert "argv" not in serialized_text(overall_llm_input)
    assert "proctitle_arguments" not in serialized_text(overall_llm_input)
    assert "raw_records" not in serialized_text(overall_llm_input)


def test_failure_containment_skips_unsafe_groups_and_keeps_valid_events(
    tmp_path,
):
    path = tmp_path / "failure-containment.log"
    syscall = (
        "arch=c000003e syscall=59 success=yes exit=0 items=0 "
        "ppid=7200 pid=7201 auid=1000 uid=1000 ses=92 "
        'exe="/usr/bin/example"'
    )
    lines = [
        "not a Linux Audit record",
        "node=containment type=EXECVE msg=audit(1790800001.001:1201): "
        'argc=1 a0="valid"',
        "node=containment type=SYSCALL msg=audit(1790800001.001:1201): "
        + syscall,
        "node=containment type=EXECVE msg=audit(1790800002.001:1202): "
        "argc=1 a0=FF",
        "node=containment type=SYSCALL msg=audit(1790800002.001:1202): "
        + syscall.replace("pid=7201", "pid=7202"),
        "node=containment type=EXECVE msg=audit(1790800003.001:1203): "
        'argc=1 a0="execve-only"',
        "node=containment type=SYSCALL msg=audit(1790800004.001:1204): "
        + syscall.replace("pid=7201", "pid=7204"),
        "node=containment type=EXECVE msg=audit(1790800005.001:1205): "
        'argc=1 a0="multiple-syscall"',
        "node=containment type=SYSCALL msg=audit(1790800005.001:1205): "
        + syscall.replace("pid=7201", "pid=7205"),
        "node=containment type=SYSCALL msg=audit(1790800005.001:1205): "
        + syscall.replace("pid=7201", "pid=7206"),
        "node=containment type=EXECVE msg=audit(1790800006.001:1206): "
        'argc=1 argc=2 a0="conflict"',
        "node=containment type=SYSCALL msg=audit(1790800006.001:1206): "
        + syscall.replace("pid=7201", "pid=7206"),
        "node=containment type=EXECVE msg=audit(1790800007.001:1207): "
        'argc=999999999 a0="oversized"',
        "node=containment type=SYSCALL msg=audit(1790800007.001:1207): "
        + syscall.replace("pid=7201", "pid=7207"),
    ]
    path.write_text("\n".join(lines), encoding="utf-8")

    logs = load_normalized_logs([
        linux_audit_source(path, "phase-3t-containment")
    ])

    assert [event.linux_audit.event_id for event in logs] == [
        "1790800001.001:1201",
        "1790800002.001:1202",
    ]
    assert logs[0].process_execution.argv == ("valid",)
    assert logs[0].process_execution.argv_complete is True
    assert logs[1].process_execution.argv == (None,)
    assert logs[1].process_execution.argv_complete is False

    analysis = analyze([
        linux_audit_source(path, "phase-3t-containment")
    ])
    assert analysis["results"] == {}
    assert all(value == [] for value in analysis["global_correlation"].values())
