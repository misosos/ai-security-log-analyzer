from datetime import datetime, timedelta, timezone

import pytest

from app.correlation.linux_audit_login_session import (
    correlate_linux_audit_login_start_co_observation,
)
from app.models.schemas import (
    AuthenticationContext,
    LinuxAuditContext,
    NormalizedEvent,
)


BASE_TIME = datetime(2026, 9, 18, 1, 0, tzinfo=timezone.utc)
DEFAULT_OPERATION = object()


def make_event(
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
    hostname="remote-a",
    process_user_id=0,
    operation=DEFAULT_OPERATION,
    event_id=None,
):
    if operation is DEFAULT_OPERATION:
        operation = (
            "login"
            if event_type == "login_establishment"
            else "PAM:session_open"
        )

    if event_id is None:
        event_id = f"1790400000.{seconds:03d}:{800 + seconds}"

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
            hostname=hostname,
            source_instance=source_instance,
            node=node,
        ),
    )


def correlate_pair(login=None, start=None):
    return correlate_linux_audit_login_start_co_observation([
        login or make_event("login_establishment"),
        start or make_event("session_start", seconds=10),
    ])


def test_correlates_one_exact_successful_login_and_start():
    result = correlate_pair()[0]

    assert result == {
        "is_correlated": True,
        "type": "linux_audit_login_start_co_observation",
        "source": "linux_audit",
        "source_instance": "feed-a",
        "node": "host-a",
        "audit_session_id": 41,
        "user": "training-user",
        "login_event_id": "1790400000.000:800",
        "start_event_id": "1790400000.010:810",
        "login_timestamp": BASE_TIME,
        "start_timestamp": BASE_TIME + timedelta(seconds=10),
        "matched_fields": [
            "source",
            "source_instance",
            "node",
            "audit_session_id",
            "user",
            "audit_user_id",
            "executable",
            "terminal",
            "src_ip",
            "hostname",
            "process_user_id",
        ],
        "missing_fields": [],
        "context_differences": ["operation"],
        "rationale": result["rationale"],
    }
    assert "observed_login_to_start_interval_seconds" not in result
    assert "interval" not in result


@pytest.mark.parametrize(
    ("login_seconds", "start_seconds"),
    [(0, 10), (10, 0), (0, 0)],
)
def test_timestamp_order_and_equality_do_not_affect_eligibility(
    login_seconds,
    start_seconds,
):
    result = correlate_pair(
        make_event("login_establishment", seconds=login_seconds),
        make_event("session_start", seconds=start_seconds),
    )

    assert len(result) == 1


def test_distinct_event_ids_are_provenance_not_match_requirements():
    result = correlate_pair(
        make_event("login_establishment", event_id="login:1"),
        make_event("session_start", event_id="start:2"),
    )[0]

    assert result["login_event_id"] == "login:1"
    assert result["start_event_id"] == "start:2"


def test_missing_optional_context_is_recorded_without_blocking_relation():
    values = {
        "audit_user_id": None,
        "executable": None,
        "terminal": None,
        "src_ip": None,
        "hostname": None,
        "process_user_id": None,
        "operation": None,
    }
    result = correlate_pair(
        make_event("login_establishment", **values),
        make_event("session_start", seconds=10, **values),
    )[0]

    assert result["missing_fields"] == [
        "audit_user_id",
        "executable",
        "terminal",
        "src_ip",
        "hostname",
        "process_user_id",
        "operation",
    ]
    assert result["context_differences"] == []


def test_optional_context_differences_are_non_blocking():
    result = correlate_pair(
        start=make_event(
            "session_start",
            seconds=10,
            executable="/bin/login",
            terminal="tty2",
            src_ip="198.51.100.11",
            hostname="remote-b",
            process_user_id=1000,
            operation="PAM:session_open",
        )
    )[0]

    assert result["context_differences"] == [
        "executable",
        "terminal",
        "src_ip",
        "hostname",
        "process_user_id",
        "operation",
    ]


def test_audit_user_id_match_and_missing_policies():
    matched = correlate_pair()[0]
    one_missing = correlate_pair(
        start=make_event(
            "session_start",
            seconds=10,
            audit_user_id=None,
        )
    )[0]
    both_missing = correlate_pair(
        login=make_event(
            "login_establishment",
            audit_user_id=None,
        ),
        start=make_event(
            "session_start",
            seconds=10,
            audit_user_id=None,
        ),
    )[0]

    assert "audit_user_id" in matched["matched_fields"]
    assert "audit_user_id" in one_missing["missing_fields"]
    assert "audit_user_id" in both_missing["missing_fields"]


def test_different_known_audit_user_ids_are_a_hard_conflict():
    start = make_event(
        "session_start",
        seconds=10,
        audit_user_id=1001,
    )

    assert correlate_pair(start=start) == []


@pytest.mark.parametrize(
    "field",
    ["source_instance", "node", "audit_session_id", "user"],
)
def test_missing_required_identity_excludes_endpoint(field):
    login = make_event("login_establishment", **{field: None})

    assert correlate_pair(login=login) == []


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
    start = make_event(
        "session_start",
        seconds=10,
        **{field: value},
    )

    assert correlate_pair(start=start) == []


@pytest.mark.parametrize(
    ("endpoint", "outcome"),
    [
        ("login", "failure"),
        ("login", "unknown"),
        ("start", "failure"),
        ("start", "unknown"),
    ],
)
def test_non_success_endpoint_is_not_eligible(endpoint, outcome):
    login = make_event("login_establishment")
    start = make_event("session_start", seconds=10)

    if endpoint == "login":
        login.authentication.outcome = outcome
    else:
        start.authentication.outcome = outcome

    assert correlate_pair(login, start) == []


def test_non_linux_audit_and_cross_source_events_are_excluded():
    login = make_event("login_establishment", source="ssh")

    assert correlate_pair(login=login) == []


@pytest.mark.parametrize(
    ("login_count", "start_count"),
    [(2, 1), (1, 2), (2, 2)],
)
def test_ambiguous_cardinality_does_not_correlate(
    login_count,
    start_count,
):
    logins = [
        make_event(
            "login_establishment",
            seconds=index,
            event_id=f"login:{index}",
        )
        for index in range(login_count)
    ]
    starts = [
        make_event(
            "session_start",
            seconds=10 + index,
            event_id=f"start:{index}",
        )
        for index in range(start_count)
    ]

    assert correlate_linux_audit_login_start_co_observation(
        logins + starts
    ) == []


def test_audit_user_id_does_not_resolve_ambiguous_cardinality():
    logs = [
        make_event("login_establishment", audit_user_id=1000),
        make_event(
            "login_establishment",
            seconds=1,
            audit_user_id=2000,
        ),
        make_event("session_start", seconds=10, audit_user_id=1000),
    ]

    assert correlate_linux_audit_login_start_co_observation(logs) == []


def test_duplicate_looking_endpoint_is_not_deduplicated():
    login = make_event("login_establishment")
    start = make_event("session_start", seconds=10)

    assert correlate_linux_audit_login_start_co_observation([
        login,
        login,
        start,
    ]) == []


def test_incomplete_co_observation_has_no_false_placeholder():
    login = make_event("login_establishment")
    start = make_event("session_start", seconds=10)

    assert correlate_linux_audit_login_start_co_observation([login]) == []
    assert correlate_linux_audit_login_start_co_observation([start]) == []


def test_results_are_deterministic_for_reversed_and_interleaved_input():
    first_pair = [
        make_event("login_establishment", seconds=10),
        make_event("session_start", seconds=0),
    ]
    second_pair = [
        make_event(
            "login_establishment",
            seconds=30,
            audit_session_id=42,
            user="training-user-b",
            event_id="login-b",
        ),
        make_event(
            "session_start",
            seconds=20,
            audit_session_id=42,
            user="training-user-b",
            event_id="start-b",
        ),
    ]
    original = first_pair + second_pair
    interleaved = [
        second_pair[1],
        first_pair[0],
        second_pair[0],
        first_pair[1],
    ]
    expected = correlate_linux_audit_login_start_co_observation(original)

    assert correlate_linux_audit_login_start_co_observation(
        list(reversed(original))
    ) == expected
    assert correlate_linux_audit_login_start_co_observation(
        interleaved
    ) == expected
    assert [result["audit_session_id"] for result in expected] == [
        41,
        42,
    ]


def test_rationale_remains_bounded_and_non_directional():
    rationale = " ".join(correlate_pair()[0]["rationale"]).lower()

    for forbidden in (
        "login transitioned",
        "session successfully created",
        "same ssh session confirmed",
        "same pam transaction confirmed",
    ):
        assert forbidden not in rationale
