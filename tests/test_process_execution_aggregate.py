from copy import deepcopy
from datetime import datetime, timezone
import json

from app.analyzer.llm import serialize_value
from app.analyzer.process_execution import (
    aggregate_process_execution_observations,
)
from app.models.schemas import (
    LinuxAuditContext,
    LinuxAuditPathContext,
    NormalizedEvent,
    ProcessExecutionContext,
)


CANARY = "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE"
TOP_LEVEL_KEYS = {
    "observation_count",
    "outcome_counts",
    "argv_completeness_counts",
    "path_completeness_counts",
}


def process_context(
    *,
    outcome="success",
    argv_complete=True,
    paths_complete=True,
    sensitive_value=CANARY,
):
    path = LinuxAuditPathContext(
        item=0,
        name=f"/sensitive/{sensitive_value}",
        nametype="NORMAL",
        inode=101,
        device="fd:01",
        mode="0100600",
        owner_user_id=1000,
        owner_group_id=1000,
    )
    return ProcessExecutionContext(
        outcome=outcome,
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
        command_name=sensitive_value,
        executable=f"/opt/{sensitive_value}",
        terminal="pts0",
        audit_rule_key=sensitive_value,
        argument_count=2,
        argv=("example", sensitive_value),
        argv_complete=argv_complete,
        incomplete_argument_indexes=(),
        working_directory=f"/work/{sensitive_value}",
        paths=(path,),
        paths_complete=paths_complete,
        proctitle_raw=sensitive_value,
        proctitle_arguments=("example", sensitive_value),
        raw_records=(f"raw={sensitive_value}",),
    )


def normalized_event(
    *,
    context=None,
    event_type="process_execution_attempt",
    source="linux_audit",
    sensitive_value=CANARY,
):
    return NormalizedEvent(
        timestamp=datetime(2026, 9, 25, tzinfo=timezone.utc),
        event_type=event_type,
        source=source,
        user=None,
        src_ip=None,
        dst_ip=None,
        application=None,
        protocol=None,
        user_agent=None,
        raw=f"raw={sensitive_value}",
        linux_audit=LinuxAuditContext(
            event_id="1790900000.001:1301",
            record_types=("SYSCALL", "EXECVE"),
            executable=f"/opt/{sensitive_value}",
            source_instance=sensitive_value,
            node=sensitive_value,
        ),
        process_execution=context,
    )


def test_empty_input_has_complete_fixed_zero_shape():
    assert aggregate_process_execution_observations([]) == {
        "observation_count": 0,
        "outcome_counts": {
            "success": 0,
            "failure": 0,
            "unknown": 0,
        },
        "argv_completeness_counts": {
            "complete": 0,
            "incomplete": 0,
        },
        "path_completeness_counts": {
            "complete": 0,
            "incomplete": 0,
        },
    }


def test_counts_bounded_outcomes_and_strict_completeness():
    events = [
        normalized_event(context=process_context()),
        normalized_event(context=process_context(
            outcome="failure",
            argv_complete=False,
            paths_complete=False,
        )),
        normalized_event(context=process_context(
            outcome="unknown",
            argv_complete=None,
            paths_complete=1,
        )),
        normalized_event(context=process_context(
            outcome="unexpected",
            argv_complete="yes",
            paths_complete=[],
        )),
    ]

    result = aggregate_process_execution_observations(events)

    assert result == {
        "observation_count": 4,
        "outcome_counts": {
            "success": 1,
            "failure": 1,
            "unknown": 2,
        },
        "argv_completeness_counts": {
            "complete": 1,
            "incomplete": 3,
        },
        "path_completeness_counts": {
            "complete": 1,
            "incomplete": 3,
        },
    }
    assert result["observation_count"] == sum(
        result["outcome_counts"].values()
    )
    assert result["observation_count"] == sum(
        result["argv_completeness_counts"].values()
    )
    assert result["observation_count"] == sum(
        result["path_completeness_counts"].values()
    )


def test_filters_nonqualifying_events_without_security_inference():
    included = normalized_event(context=process_context())
    excluded = [
        normalized_event(
            context=process_context(),
            event_type="session_start",
        ),
        normalized_event(
            context=process_context(),
            source="application",
        ),
        normalized_event(context=None),
        normalized_event(
            context=None,
            event_type="authentication_attempt",
        ),
        normalized_event(
            context=None,
            event_type="http_request",
            source="access",
        ),
    ]

    assert aggregate_process_execution_observations(
        [included, *excluded]
    )["observation_count"] == 1


def test_order_generator_and_repeated_calls_are_deterministic():
    events = [
        normalized_event(context=process_context(outcome="success")),
        normalized_event(context=process_context(
            outcome="failure",
            argv_complete=False,
        )),
        normalized_event(context=process_context(
            outcome="unknown",
            paths_complete=False,
        )),
    ]

    expected = aggregate_process_execution_observations(events)

    assert aggregate_process_execution_observations(reversed(events)) == expected
    assert aggregate_process_execution_observations(
        event for event in events
    ) == expected
    assert aggregate_process_execution_observations(events) == expected


def test_privacy_allowlist_and_canary_independence_preserve_evidence():
    event = normalized_event(context=process_context())
    original = deepcopy(event)

    result = aggregate_process_execution_observations([event])
    serialized = json.dumps(serialize_value(result), sort_keys=True)

    assert set(result) == TOP_LEVEL_KEYS
    assert set(result["outcome_counts"]) == {
        "success",
        "failure",
        "unknown",
    }
    assert set(result["argv_completeness_counts"]) == {
        "complete",
        "incomplete",
    }
    assert set(result["path_completeness_counts"]) == {
        "complete",
        "incomplete",
    }
    assert CANARY in repr(event.process_execution)
    assert CANARY in repr(event.linux_audit)
    assert CANARY not in repr(result)
    assert CANARY not in serialized
    assert event == original

    other = normalized_event(
        context=process_context(sensitive_value="OTHER_PRIVATE_VALUE"),
        sensitive_value="OTHER_PRIVATE_VALUE",
    )
    assert aggregate_process_execution_observations([other]) == result


def test_output_shape_does_not_grow_with_event_cardinality():
    one = aggregate_process_execution_observations([
        normalized_event(context=process_context())
    ])
    many = aggregate_process_execution_observations(
        normalized_event(context=process_context())
        for _ in range(500)
    )

    assert set(many) == set(one) == TOP_LEVEL_KEYS
    assert {
        key: set(value)
        for key, value in many.items()
        if isinstance(value, dict)
    } == {
        key: set(value)
        for key, value in one.items()
        if isinstance(value, dict)
    }
    assert many["observation_count"] == 500
