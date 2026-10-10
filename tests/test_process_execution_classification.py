"""Fixed process-execution review labels; no attack or transfer-success verdict."""

from dataclasses import asdict, replace
from datetime import timedelta, timezone
from pathlib import Path
import json
import subprocess
import sys

import pytest

from app.analyzer.pipeline import load_normalized_logs
from app.analyzer.process_execution_classification import (
    CATEGORY_IDS, ProcessExecutionClassificationError,
    classify_process_execution_observations,
)
from app.analyzer.process_execution import aggregate_process_execution_observations
from app.analyzer.report import print_analysis_result


FIXTURE = Path(__file__).resolve().parents[1] / "sample_logs" / "linux_audit_exec_success_rhel_source_derived.log"


def _base():
    return next(event for event in load_normalized_logs([{"source": "linux_audit", "path": str(FIXTURE)}])
                if event.event_type == "process_execution_attempt")


def _event(exe, *, comm=None, argv0=None, outcome="success", serial=1, seconds=0,
           argv_complete=True, paths_complete=True):
    base = _base()
    context = replace(base.process_execution, executable=exe, command_name=comm,
                      argv=(argv0,) if argv0 is not None else (),
                      outcome=outcome, argv_complete=argv_complete,
                      paths_complete=paths_complete)
    audit = replace(base.linux_audit, event_id=f"1790400000.001:{serial}")
    return replace(base, timestamp=base.timestamp + timedelta(seconds=seconds),
                   process_execution=context, linux_audit=audit)


@pytest.mark.parametrize(("exe", "comm", "category"), [
    ("/bin/bash", "bash", CATEGORY_IDS[0]),
    ("/bin/sh", "sh", CATEGORY_IDS[0]),
    ("/usr/bin/curl", "curl", CATEGORY_IDS[1]),
    ("/usr/bin/wget", "wget", CATEGORY_IDS[1]),
    ("/usr/bin/chmod", "chmod", CATEGORY_IDS[2]),
    ("/usr/bin/chown", "chown", CATEGORY_IDS[2]),
    ("/tmp/tool", "tool", CATEGORY_IDS[3]),
    ("/var/tmp/tool", "tool", CATEGORY_IDS[3]),
    ("/dev/shm/tool", "tool", CATEGORY_IDS[3]),
])
def test_exact_categories(exe, comm, category):
    result = classify_process_execution_observations((_event(exe, comm=comm),))
    assert tuple(item.category_id for item in result.observations) == (category,)
    assert result.summary.classified_execution_count == 1
    assert result.observations[0].confidence == "HIGH"
    assert result.observations[0].review_priority == ("MEDIUM" if category == CATEGORY_IDS[3] else "LOW")
    assert exe not in repr(result)


@pytest.mark.parametrize("exe", [
    "/bin/bashful", "/usr/bin/curl-wrapper", "/usr/bin/mysh",
    "/tmpfile/tool", "/var/tmp-backup/tool", "relative/bash",
    "/tmp/../bin/bash", "/tmp//bash", "/tmp/ba\x00sh",
])
def test_nonmatch_or_malformed_identity_is_unclassified(exe):
    result = classify_process_execution_observations((_event(exe),))
    assert not result.observations
    assert result.unclassified_count == 1


def test_fallback_conflict_and_cwd_only_temp():
    fallback = classify_process_execution_observations((_event(None, comm="bash"),))
    assert fallback.observations[0].confidence == "MEDIUM"
    assert fallback.observations[0].category_id == CATEGORY_IDS[0]
    assert any("comm" in text for text in fallback.observations[0].limitations)
    argv_fallback = classify_process_execution_observations((_event(None, argv0="curl"),))
    assert argv_fallback.observations[0].confidence == "LOW"
    assert any("argv[0]" in text for text in argv_fallback.observations[0].limitations)
    assert classify_process_execution_observations((_event("/bin/bash", comm="curl"),)).unclassified_count == 1
    base = _event("/usr/bin/tool", comm="tool")
    cwd_only = replace(base, process_execution=replace(base.process_execution,
                                                      working_directory="/tmp"))
    assert classify_process_execution_observations((cwd_only,)).unclassified_count == 1


def test_multi_category_outcomes_duplicates_and_input_order():
    first = _event("/tmp/curl", comm="curl", outcome="failure", serial=11)
    second = _event("/bin/bash", comm="bash", outcome="unknown", serial=12, seconds=1,
                    argv_complete=False)
    outputs = [classify_process_execution_observations(items) for items in (
        (first, second, first), (second, first, first),
    )]
    assert outputs[0] == outputs[1]
    result = outputs[0]
    assert result.summary.eligible_execution_count == 2
    assert result.summary.classified_execution_count == 2
    assert result.summary.category_observation_count == 3
    assert result.summary.outcome_counts.failure == result.summary.outcome_counts.unknown == 1
    assert result.incomplete_context_count == 1
    assert [item.category_id for item in result.observations] == [CATEGORY_IDS[1], CATEGORY_IDS[3], CATEGORY_IDS[0]]
    assert all(item.outcome in {"SUCCESS", "FAILURE", "UNKNOWN"} for item in result.observations)


def test_malformed_input_fails_with_fixed_code():
    event = _event("/bin/bash", comm="bash")
    cases = [([event], "invalid_input"),
             ((replace(event, timestamp=event.timestamp.replace(tzinfo=None)),), "invalid_timestamp"),
             ((replace(event, process_execution=replace(event.process_execution, outcome="other")),), "invalid_outcome"),
             ((replace(event, linux_audit=replace(event.linux_audit, event_id="PRIVATE-CANARY")),), "invalid_event"),
             ((event, replace(event, process_execution=replace(event.process_execution, executable="/bin/curl"))), "conflicting_event_identity")]
    for input_value, code in cases:
        with pytest.raises(ProcessExecutionClassificationError) as raised:
            classify_process_execution_observations(input_value)
        assert raised.value.code == code
        assert "PRIVATE-CANARY" not in str(raised.value)


def test_private_context_is_not_retained_or_printed():
    marker = "SYNTHETIC-CANARY-PRIVATE-CONTEXT"
    event = _event("/tmp/curl", comm="curl")
    event = replace(event, raw=marker,
                    process_execution=replace(event.process_execution,
                                              argv=("curl", marker),
                                              working_directory=marker,
                                              proctitle_raw=marker,
                                              raw_records=(marker,)))
    result = classify_process_execution_observations((event,))
    assert marker not in repr(result)
    assert marker not in str(result)
    assert marker not in json.dumps(asdict(result), ensure_ascii=False, default=str)
    assert all(item.observed_at_utc.tzinfo is timezone.utc for item in result.observations)


def test_file_and_record_order_do_not_change_public_assembly():
    root = FIXTURE.parent / "evaluation"
    bash = root / "linux_shell_bash.log"
    curl = root / "linux_network_curl.log"
    inputs = (
        {"source": "linux_audit", "path": str(bash), "source_instance": "synthetic-a"},
        {"source": "linux_audit", "path": str(curl), "source_instance": "synthetic-b"},
    )
    outputs = []
    for configs in (inputs, tuple(reversed(inputs))):
        logs = load_normalized_logs(list(configs))
        process_events = tuple(event for event in logs
                               if event.event_type == "process_execution_attempt")
        outputs.append(classify_process_execution_observations(process_events))
    assert outputs[0] == outputs[1]
    assert outputs[0].observations[0].observed_at_utc.microsecond == 1


def test_audit_record_permutation_and_duplicate_required_record_are_bounded(tmp_path):
    lines = (FIXTURE.parent / "evaluation" / "linux_shell_bash.log").read_text(encoding="utf-8").splitlines()
    outputs = []
    for name, ordered in (("forward", lines), ("reverse", list(reversed(lines)))):
        path = tmp_path / f"{name}.log"
        path.write_text("\n".join(ordered) + "\n", encoding="utf-8")
        logs = load_normalized_logs([{"source": "linux_audit", "path": str(path)}])
        outputs.append(classify_process_execution_observations(tuple(
            event for event in logs if event.event_type == "process_execution_attempt"
        )))
    assert outputs[0] == outputs[1]
    duplicate = tmp_path / "duplicate.log"
    duplicate.write_text("\n".join((lines[0], lines[0], lines[1])) + "\n", encoding="utf-8")
    logs = load_normalized_logs([{"source": "linux_audit", "path": str(duplicate)}])
    assert not any(event.event_type == "process_execution_attempt" for event in logs)


def test_unknown_public_category_fails_closed(capsys):
    assembly = classify_process_execution_observations((_event("/bin/bash", comm="bash"),))
    forged = replace(assembly, observations=(replace(assembly.observations[0],
                                                   category_id="PRIVATE-CANARY"),))
    with pytest.raises(ValueError, match="invalid_process_execution_classification"):
        print_analysis_result({"results": {}, "global_correlation": {}},
                              process_execution_classification=forged)
    assert "PRIVATE-CANARY" not in capsys.readouterr().out


def test_cli_section_is_count_only_and_empty_state_is_not_safety_claim(capsys):
    marker = "SYNTHETIC-ARGV-PRIVATE-CANARY"
    event = _event("/tmp/curl", comm="curl")
    event = replace(event, process_execution=replace(event.process_execution,
                                                      argv=("curl", marker)))
    assembly = classify_process_execution_observations((event,))
    print_analysis_result({"results": {}, "global_correlation": {}},
                          process_execution_aggregate=aggregate_process_execution_observations((event,)),
                          process_execution_classification=assembly)
    output = capsys.readouterr().out
    assert "Linux 프로세스 실행 조사 후보" in output
    assert "네트워크 전송 도구 실행 관찰: 1건" in output
    assert "임시 디렉터리 실행 관찰: 1건" in output
    assert "검토 우선순위: MEDIUM" in output
    assert marker not in output and "/tmp/curl" not in output
    empty = classify_process_execution_observations(())
    print_analysis_result({"results": {}, "global_correlation": {}},
                          process_execution_classification=empty)
    empty_output = capsys.readouterr().out
    assert "정해진 Linux 프로세스 실행 조사 후보가 없습니다." in empty_output
    assert "안전하거나 정상임을 의미하지 않으며" in empty_output


def test_real_cli_and_public_projection_exclude_distinct_audit_canaries():
    fixture = FIXTURE.parent / "evaluation" / "linux_network_curl.log"
    completed = subprocess.run([sys.executable, "-m", "app.main", "--linux-audit", str(fixture)],
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0 and not completed.stderr
    assert "Linux 프로세스 실행 조사 후보" in completed.stdout
    assert "SYNTHETIC_ARG_CANARY" not in completed.stdout
    markers = (
        "SYNTHETIC_ACCOUNT_CANARY", "SYNTHETIC_EXE_CANARY",
        "SYNTHETIC_ARG_CANARY", "SYNTHETIC_URL_CANARY",
        "SYNTHETIC_CWD_CANARY", "SYNTHETIC_PATH_CANARY",
        "SYNTHETIC_PROCTITLE_CANARY", "SYNTHETIC_NODE_CANARY",
        "987654321", "876543210", "SYNTHETIC_TOKEN_CANARY",
        "SYNTHETIC_FILENAME_CANARY",
    )
    event = _event("/tmp/SYNTHETIC_EXE_CANARY", comm="SYNTHETIC_EXE_CANARY")
    event = replace(event, user=markers[0], raw=markers[2],
                    linux_audit=replace(event.linux_audit, node=markers[7],
                                        event_id="1790400000.001:987654321",
                                        audit_session_id=876543210),
                    process_execution=replace(event.process_execution,
                                              argv=("/tmp/SYNTHETIC_EXE_CANARY", markers[2], markers[3]),
                                              working_directory=markers[4],
                                              proctitle_raw=markers[6],
                                              proctitle_arguments=(markers[10], markers[11]),
                                              process_id=987654321,
                                              paths=(replace(event.process_execution.paths[0], name=markers[5]),),
                                              raw_records=(markers[5],)))
    public = classify_process_execution_observations((event,))
    exposed = repr(public) + str(public) + json.dumps(asdict(public), default=str)
    assert public.observations[0].category_id == CATEGORY_IDS[3]
    assert all(marker not in exposed for marker in markers)
