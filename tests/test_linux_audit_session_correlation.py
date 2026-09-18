from datetime import datetime, timedelta, timezone

import pytest

from app.correlation.linux_audit_session import (
    correlate_linux_audit_session_lifecycle,
)
from app.models.schemas import (
    AuthenticationContext,
    LinuxAuditContext,
    NormalizedEvent,
)


BASE_TIME = datetime(2026, 9, 18, 1, 0, tzinfo=timezone.utc)


def make_session_event(
    event_type,
    *,
    seconds=0,
    source="linux_audit",
    source_instance="feed-a",
    node="host-a",
    audit_session_id=41,
    user="training-user",
    outcome="success",
    audit_user_id=1000,
    executable="/usr/sbin/sshd",
    terminal="ssh",
    src_ip="198.51.100.10",
    process_user_id=0,
    operation=None,
    event_id=None,
):
    if operation is None:
        operation = (
            "PAM:session_open"
            if event_type == "session_start"
            else "PAM:session_close"
        )

    if event_id is None:
        event_id = f"1790200000.{seconds:03d}:{700 + seconds}"

    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        event_type=event_type,
        source=source,
        user=user,
        src_ip=src_ip,
        dst_ip=None,
        application=None,
        protocol=None,
        user_agent=None,
        raw=f"type={event_type} test",
        authentication=AuthenticationContext(outcome=outcome),
        linux_audit=LinuxAuditContext(
            event_id=event_id,
            record_types=(event_type,),
            operation=operation,
            executable=executable,
            process_user_id=process_user_id,
            audit_user_id=audit_user_id,
            audit_session_id=audit_session_id,
            terminal=terminal,
            source_instance=source_instance,
            node=node,
        ),
    )


def correlate_pair(start=None, end=None):
    return correlate_linux_audit_session_lifecycle([
        start or make_session_event("session_start"),
        end or make_session_event("session_end", seconds=10),
    ])


def test_correlates_one_exact_successful_start_and_end():
    result = correlate_pair()[0]

    assert result["is_correlated"] is True
    assert result["type"] == "linux_audit_session_lifecycle"
    assert result["source"] == "linux_audit"
    assert result["source_instance"] == "feed-a"
    assert result["node"] == "host-a"
    assert result["audit_session_id"] == 41
    assert result["user"] == "training-user"
    assert result["start_event_id"] == "1790200000.000:700"
    assert result["end_event_id"] == "1790200000.010:710"
    assert result["start_timestamp"] == BASE_TIME
    assert result["end_timestamp"] == BASE_TIME + timedelta(seconds=10)
    assert result[
        "observed_session_lifecycle_interval_seconds"
    ] == 10.0
    assert result["matched_fields"] == [
        "source",
        "source_instance",
        "node",
        "audit_session_id",
        "user",
        "audit_user_id",
        "executable",
        "terminal",
        "src_ip",
        "process_user_id",
    ]
    assert result["missing_fields"] == []
    assert result["context_differences"] == ["operation"]
    assert all(
        forbidden not in " ".join(result["rationale"]).lower()
        for forbidden in ["attacker session", "compromise duration"]
    )


def test_auth_login_and_account_stages_are_not_prerequisites():
    assert len(correlate_pair()) == 1


def test_missing_optional_context_is_recorded_without_blocking_relation():
    start = make_session_event(
        "session_start",
        audit_user_id=None,
        executable=None,
        terminal=None,
        src_ip=None,
        process_user_id=None,
        operation=None,
    )
    end = make_session_event(
        "session_end",
        seconds=10,
        audit_user_id=None,
        executable=None,
        terminal=None,
        src_ip=None,
        process_user_id=None,
        operation=None,
    )
    start.linux_audit.operation = None
    end.linux_audit.operation = None

    result = correlate_pair(start, end)[0]

    assert result["missing_fields"] == [
        "audit_user_id",
        "executable",
        "terminal",
        "src_ip",
        "process_user_id",
        "operation",
    ]
    assert result["context_differences"] == []


def test_non_blocking_context_differences_are_recorded():
    start = make_session_event("session_start")
    end = make_session_event(
        "session_end",
        seconds=10,
        executable="/usr/bin/login",
        terminal="tty3",
        src_ip="198.51.100.11",
        process_user_id=1000,
        operation="application:session_close",
    )

    result = correlate_pair(start, end)[0]

    assert result["context_differences"] == [
        "executable",
        "terminal",
        "src_ip",
        "process_user_id",
        "operation",
    ]
    assert "audit_user_id" in result["matched_fields"]


def test_audit_user_id_match_and_missing_policies():
    matched = correlate_pair()[0]
    one_missing = correlate_pair(
        end=make_session_event(
            "session_end",
            seconds=10,
            audit_user_id=None,
        )
    )[0]
    both_missing = correlate_pair(
        start=make_session_event(
            "session_start",
            audit_user_id=None,
        ),
        end=make_session_event(
            "session_end",
            seconds=10,
            audit_user_id=None,
        ),
    )[0]

    assert "audit_user_id" in matched["matched_fields"]
    assert "audit_user_id" in one_missing["missing_fields"]
    assert "audit_user_id" in both_missing["missing_fields"]


def test_different_known_audit_user_ids_are_a_hard_conflict():
    end = make_session_event(
        "session_end",
        seconds=10,
        audit_user_id=1001,
    )

    assert correlate_pair(end=end) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_instance", None),
        ("node", None),
        ("audit_session_id", None),
        ("user", None),
    ],
)
def test_missing_required_identity_excludes_endpoint(field, value):
    start = make_session_event("session_start", **{field: value})

    assert correlate_pair(start=start) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_instance", "feed-b"),
        ("node", "host-b"),
        ("audit_session_id", 42),
        ("user", "other-user"),
    ],
)
def test_different_required_identity_does_not_correlate(field, value):
    end = make_session_event(
        "session_end",
        seconds=10,
        **{field: value},
    )

    assert correlate_pair(end=end) == []


@pytest.mark.parametrize(
    ("endpoint", "outcome"),
    [
        ("start", "failure"),
        ("start", "unknown"),
        ("end", "failure"),
        ("end", "unknown"),
    ],
)
def test_non_success_endpoint_is_not_eligible(endpoint, outcome):
    start = make_session_event("session_start")
    end = make_session_event("session_end", seconds=10)

    if endpoint == "start":
        start.authentication.outcome = outcome
    else:
        end.authentication.outcome = outcome

    assert correlate_pair(start, end) == []


def test_non_linux_audit_and_cross_source_events_are_excluded():
    start = make_session_event("session_start", source="ssh")

    assert correlate_pair(start=start) == []


@pytest.mark.parametrize("end_seconds", [0, -1])
def test_end_must_be_strictly_after_start(end_seconds):
    end = make_session_event("session_end", seconds=end_seconds)

    assert correlate_pair(end=end) == []


@pytest.mark.parametrize(
    ("start_count", "end_count"),
    [(2, 1), (1, 2), (2, 2)],
)
def test_ambiguous_cardinality_does_not_correlate(
    start_count,
    end_count,
):
    starts = [
        make_session_event(
            "session_start",
            seconds=index,
            event_id=f"start:{index}",
        )
        for index in range(start_count)
    ]
    ends = [
        make_session_event(
            "session_end",
            seconds=10 + index,
            event_id=f"end:{index}",
        )
        for index in range(end_count)
    ]

    assert correlate_linux_audit_session_lifecycle(
        starts + ends
    ) == []


def test_duplicate_looking_start_is_not_deduplicated():
    start = make_session_event("session_start")
    end = make_session_event("session_end", seconds=10)

    assert correlate_linux_audit_session_lifecycle([
        start,
        start,
        end,
    ]) == []


def test_incomplete_lifecycle_has_no_false_placeholder():
    start = make_session_event("session_start")
    end = make_session_event("session_end", seconds=10)

    assert correlate_linux_audit_session_lifecycle([start]) == []
    assert correlate_linux_audit_session_lifecycle([end]) == []


def test_same_account_and_ip_do_not_override_different_session_id():
    end = make_session_event(
        "session_end",
        seconds=10,
        audit_session_id=99,
    )

    assert correlate_pair(end=end) == []


def test_results_are_deterministic_for_reversed_and_interleaved_input():
    first_pair = [
        make_session_event("session_start"),
        make_session_event("session_end", seconds=10),
    ]
    second_pair = [
        make_session_event(
            "session_start",
            seconds=20,
            audit_session_id=42,
            user="training-user-b",
            event_id="start-b",
        ),
        make_session_event(
            "session_end",
            seconds=30,
            audit_session_id=42,
            user="training-user-b",
            event_id="end-b",
        ),
    ]
    original = first_pair + second_pair
    interleaved = [
        second_pair[1],
        first_pair[0],
        second_pair[0],
        first_pair[1],
    ]

    expected = correlate_linux_audit_session_lifecycle(original)

    assert correlate_linux_audit_session_lifecycle(
        list(reversed(original))
    ) == expected
    assert correlate_linux_audit_session_lifecycle(
        interleaved
    ) == expected
    assert [result["audit_session_id"] for result in expected] == [
        41,
        42,
    ]
