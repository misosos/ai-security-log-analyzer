from datetime import datetime, timezone
from pathlib import Path

from app.analyzer.pipeline import (
    assess_risk,
    correlate_attacks,
    detect_attacks,
    load_normalized_logs,
)
from app.loader.linux_audit_loader import (
    GroupedAuditEvent,
    load_linux_audit_events,
    parse_audit_record,
)
from app.models.schemas import LinuxAuditContext
from app.parser.linux_audit import parse_linux_audit_events


def audit_line(
    record_type="USER_AUTH",
    timestamp="1789693201.123",
    serial="101",
    details=None,
    node=None,
):
    if details is None:
        details = (
            "pid=4101 uid=0 auid=1000 ses=7 "
            "msg='op=PAM:authentication "
            'acct="training-admin" '
            'exe="/usr/sbin/sshd" '
            "hostname=training-client "
            "addr=198.51.100.10 terminal=ssh "
            "res=failed'"
        )

    prefix = f"node={node} " if node is not None else ""

    return prefix + (
        f"type={record_type} "
        f"msg=audit({timestamp}:{serial}): {details}"
    )


def grouped_event(*lines):
    records = tuple(
        sorted(
            (parse_audit_record(line) for line in lines),
            key=lambda record: (record.record_type, record.raw),
        )
    )
    first = records[0]

    return GroupedAuditEvent(
        event_id=first.event_id,
        timestamp=first.timestamp,
        serial=first.serial,
        records=records,
    )


def test_parse_valid_audit_record_and_quoted_fields():
    record = parse_audit_record(audit_line(
        details=(
            "uid=0 auid=1000 ses=7 "
            "msg='op=PAM:authentication "
            'acct="training admin" '
            'exe="/usr/sbin/sshd" '
            "hostname=training-client "
            "addr=198.51.100.10 terminal=ssh "
            "res=failed'"
        ),
    ))

    assert record.record_type == "USER_AUTH"
    assert record.event_id == "1789693201.123:101"
    assert record.serial == 101
    assert record.timestamp == datetime(
        2026,
        9,
        18,
        1,
        0,
        1,
        123000,
        tzinfo=timezone.utc,
    )
    assert record.fields["acct"] == "training admin"
    assert record.fields["op"] == "PAM:authentication"


def test_parse_malformed_audit_preamble_returns_none():
    assert parse_audit_record("USER_AUTH res=failed") is None
    assert parse_audit_record(
        "type=USER_AUTH msg=audit(not-a-time): res=failed"
    ) is None
    assert parse_audit_record(audit_line(
        details="msg='acct=training-user res=failed",
    )) is None


def test_grouping_uses_full_event_identity_and_handles_interleaving(
    tmp_path,
):
    event_a_auth = audit_line(serial="101")
    event_b_auth = audit_line(
        timestamp="1789693202.123",
        serial="101",
    )
    event_a_account = audit_line(
        record_type="USER_ACCT",
        serial="101",
    )
    event_b_eoe = audit_line(
        record_type="EOE",
        timestamp="1789693202.123",
        serial="101",
        details="",
    )
    path = tmp_path / "interleaved-audit.log"
    path.write_text(
        "\n".join([
            event_b_auth,
            event_a_auth,
            event_b_eoe,
            event_a_account,
        ]),
        encoding="utf-8",
    )

    events = load_linux_audit_events(
        path,
        source_instance="host-a",
    )

    assert [event.event_id for event in events] == [
        "1789693201.123:101",
        "1789693202.123:101",
    ]
    assert [
        tuple(record.record_type for record in event.records)
        for event in events
    ] == [
        ("USER_ACCT", "USER_AUTH"),
        ("EOE", "USER_AUTH"),
    ]


def test_grouping_separates_different_serials_and_flushes_at_eof(
    tmp_path,
):
    path = tmp_path / "audit.log"
    path.write_text(
        "\n".join([
            audit_line(serial="102"),
            audit_line(serial="101"),
        ]),
        encoding="utf-8",
    )

    events = load_linux_audit_events(path)

    assert [event.serial for event in events] == [101, 102]
    assert all(
        "EOE" not in {
            record.record_type
            for record in event.records
        }
        for event in events
    )


def test_grouping_is_deterministic_and_skips_malformed_lines(
    tmp_path,
):
    lines = [
        audit_line(record_type="USER_ACCT"),
        "not an audit record",
        audit_line(),
    ]
    first_path = tmp_path / "first.log"
    second_path = tmp_path / "second.log"
    first_path.write_text("\n".join(lines), encoding="utf-8")
    second_path.write_text(
        "\n".join(reversed(lines)),
        encoding="utf-8",
    )

    first = load_linux_audit_events(first_path)
    second = load_linux_audit_events(second_path)

    assert first == second


def test_parse_user_auth_failure_preserves_observed_fields():
    result = parse_linux_audit_events(
        grouped_event(audit_line())
    )[0]

    assert result.event_type == "authentication_attempt"
    assert result.source == "linux_audit"
    assert result.user == "training-admin"
    assert result.src_ip == "198.51.100.10"
    assert result.application is None
    assert result.protocol is None
    assert result.authentication.outcome == "failure"
    assert result.authentication.method is None
    assert result.authentication.service is None
    assert result.linux_audit.operation == "PAM:authentication"
    assert result.linux_audit.executable == "/usr/sbin/sshd"
    assert result.linux_audit.process_user_id == 0
    assert result.linux_audit.audit_user_id == 1000
    assert result.linux_audit.audit_session_id == 7
    assert result.linux_audit.terminal == "ssh"
    assert result.linux_audit.hostname == "training-client"


def test_parse_user_auth_success_is_not_user_login():
    line = audit_line(details=(
        "uid=0 auid=1000 ses=7 "
        "msg='op=PAM:authentication acct=training-user "
        "exe=/usr/sbin/sshd hostname=training-client "
        "addr=198.51.100.11 terminal=ssh res=success'"
    ))

    result = parse_linux_audit_events(grouped_event(line))[0]

    assert result.event_type == "authentication_attempt"
    assert result.event_type != "user_login"
    assert result.authentication.outcome == "success"


def test_unknown_outcome_is_preserved_conservatively():
    line = audit_line(details=(
        "uid=0 auid=1000 ses=7 "
        "msg='op=PAM:authentication acct=training-user "
        "addr=198.51.100.11 res=error'"
    ))

    result = parse_linux_audit_events(grouped_event(line))[0]

    assert result.authentication.outcome == "unknown"


def test_unknown_identity_address_and_audit_ids_are_not_inferred():
    line = audit_line(details=(
        "uid=invalid auid=4294967295 ses=4294967295 "
        "msg='op=PAM:authentication acct=(unknown) "
        "hostname=? addr=? terminal=? res=failed'"
    ))

    result = parse_linux_audit_events(grouped_event(line))[0]

    assert result.user is None
    assert result.src_ip is None
    assert result.linux_audit.process_user_id is None
    assert result.linux_audit.audit_user_id is None
    assert result.linux_audit.audit_session_id is None
    assert result.linux_audit.terminal is None
    assert result.linux_audit.hostname is None


def test_uid_and_auid_do_not_fall_back_to_target_user():
    line = audit_line(details=(
        "uid=1000 auid=1001 ses=9 "
        "msg='op=PAM:authentication addr=198.51.100.12 "
        "res=failed'"
    ))

    result = parse_linux_audit_events(grouped_event(line))[0]

    assert result.user is None
    assert result.linux_audit.process_user_id == 1000
    assert result.linux_audit.audit_user_id == 1001


def test_unusable_addresses_are_not_remote_sources():
    for value in ["?", "localhost", "127.0.0.1", "0.0.0.0"]:
        line = audit_line(details=(
            "msg='op=PAM:authentication acct=training-user "
            f"addr={value} res=failed'"
        ))

        result = parse_linux_audit_events(grouped_event(line))[0]

        assert result.src_ip is None


def test_unsupported_records_have_no_semantic_output():
    for record_type in ["CRED_ACQ", "CRED_DISP"]:
        event = grouped_event(audit_line(record_type=record_type))

        assert parse_linux_audit_events(event) == []


def test_grouped_semantic_records_keep_distinct_raw_evidence():
    auth = audit_line()
    account = audit_line(record_type="USER_ACCT")

    results = parse_linux_audit_events(
        grouped_event(auth, account)
    )

    assert [result.event_type for result in results] == [
        "authentication_attempt",
        "account_authorization_attempt",
    ]
    assert [result.raw for result in results] == [auth, account]
    assert all(
        result.linux_audit.record_types == (
            "USER_ACCT",
            "USER_AUTH",
        )
        for result in results
    )


def test_user_acct_success_preserves_account_authorization_semantics():
    line = audit_line(
        record_type="USER_ACCT",
        details=(
            "pid=4201 uid=0 auid=1100 ses=17 "
            "msg='op=PAM:accounting acct=training-admin "
            "exe=/usr/sbin/sshd hostname=training-client-a "
            "addr=198.51.100.20 terminal=ssh res=success'"
        ),
    )

    result = parse_linux_audit_events(grouped_event(line))[0]

    assert result.event_type == "account_authorization_attempt"
    assert result.event_type != "authentication_attempt"
    assert result.event_type != "login_failed"
    assert result.event_type != "user_login"
    assert result.user == "training-admin"
    assert result.src_ip == "198.51.100.20"
    assert result.authentication.outcome == "success"
    assert result.authentication.method is None
    assert result.authentication.service is None
    assert result.linux_audit.operation == "PAM:accounting"
    assert result.linux_audit.executable == "/usr/sbin/sshd"
    assert result.linux_audit.process_user_id == 0
    assert result.linux_audit.audit_user_id == 1100
    assert result.linux_audit.audit_session_id == 17
    assert result.linux_audit.terminal == "ssh"
    assert result.linux_audit.hostname == "training-client-a"


def test_user_acct_failure_and_unknown_outcomes_are_bounded():
    failed = audit_line(
        record_type="USER_ACCT",
        details="msg='acct=training-user res=failed'",
    )
    unknown = audit_line(
        record_type="USER_ACCT",
        serial="102",
        details="msg='acct=training-reviewer res=denied'",
    )
    missing = audit_line(
        record_type="USER_ACCT",
        serial="103",
        details="msg='acct=training-observer'",
    )

    assert (
        parse_linux_audit_events(grouped_event(failed))[0]
        .authentication.outcome
        == "failure"
    )
    assert (
        parse_linux_audit_events(grouped_event(unknown))[0]
        .authentication.outcome
        == "unknown"
    )
    assert (
        parse_linux_audit_events(grouped_event(missing))[0]
        .authentication.outcome
        == "unknown"
    )


def test_user_acct_unknown_identity_and_address_are_not_inferred():
    line = audit_line(
        record_type="USER_ACCT",
        details=(
            "uid=1000 auid=1001 ses=4294967295 "
            "msg='op=PAM:accounting acct=? hostname=? "
            "addr=127.0.0.1 terminal=? res=failed'"
        ),
    )

    result = parse_linux_audit_events(grouped_event(line))[0]

    assert result.user is None
    assert result.src_ip is None
    assert result.linux_audit.process_user_id == 1000
    assert result.linux_audit.audit_user_id == 1001
    assert result.linux_audit.audit_session_id is None
    assert result.linux_audit.terminal is None
    assert result.linux_audit.hostname is None


def test_semantic_output_is_independent_of_record_arrival_order():
    auth = audit_line()
    account = audit_line(record_type="USER_ACCT")

    forward = parse_linux_audit_events(
        grouped_event(auth, account)
    )
    reverse = parse_linux_audit_events(
        grouped_event(account, auth)
    )

    assert forward == reverse
    assert [result.event_type for result in forward] == [
        "authentication_attempt",
        "account_authorization_attempt",
    ]


def test_multiple_same_type_records_are_all_preserved():
    first = audit_line(
        record_type="USER_ACCT",
        details="msg='acct=training-a res=success'",
    )
    second = audit_line(
        record_type="USER_ACCT",
        details="msg='acct=training-b res=failed'",
    )

    results = parse_linux_audit_events(
        grouped_event(second, first)
    )

    assert len(results) == 2
    assert [result.user for result in results] == [
        "training-a",
        "training-b",
    ]
    assert [result.authentication.outcome for result in results] == [
        "success",
        "failure",
    ]


def test_user_acct_fixture_preserves_each_semantic_observation():
    logs = load_normalized_logs([
        {
            "source": "linux_audit",
            "path": "sample_logs/linux_audit_user_acct.log",
        }
    ])

    assert [log.event_type for log in logs] == [
        "authentication_attempt",
        "account_authorization_attempt",
        "account_authorization_attempt",
        "account_authorization_attempt",
    ]
    assert [log.authentication.outcome for log in logs] == [
        "success",
        "success",
        "failure",
        "unknown",
    ]


def test_user_acct_does_not_change_detection_correlation_or_risk():
    logs = load_normalized_logs([
        {
            "source": "linux_audit",
            "path": "sample_logs/linux_audit_user_acct.log",
        }
    ])
    detections = detect_attacks(logs)

    assert all(
        result["features"]["failure_count"] == 0
        for result in detections.values()
    )
    assert all(
        result["features"]["login_succeeded"] is False
        for result in detections.values()
    )
    assert all(
        not detection.is_detected
        for result in detections.values()
        for detection in result["detections"].values()
    )

    analysis = correlate_attacks(logs, detections)

    assert analysis["global_correlation"][
        "multi_ip_authentication"
    ] == []
    assert analysis["global_correlation"][
        "distributed_authentication_to_success"
    ] == []
    assert all(
        not correlation["is_correlated"]
        for result in analysis["results"].values()
        for correlation in result["correlation"].values()
    )

    assessed = assess_risk(analysis)

    assert all(
        result["risk_level"] == "LOW"
        for result in assessed["results"].values()
    )


def test_user_login_success_preserves_login_establishment_semantics():
    line = audit_line(
        record_type="USER_LOGIN",
        details=(
            "pid=4301 uid=0 auid=1200 ses=27 "
            "msg='op=login acct=training-admin "
            "exe=/usr/sbin/sshd hostname=training-client-a "
            "addr=198.51.100.30 terminal=ssh res=success'"
        ),
    )

    result = parse_linux_audit_events(grouped_event(line))[0]

    assert result.event_type == "login_establishment"
    assert result.event_type != "user_login"
    assert result.event_type != "login_failed"
    assert result.event_type != "authentication_attempt"
    assert result.event_type != "account_authorization_attempt"
    assert result.user == "training-admin"
    assert result.src_ip == "198.51.100.30"
    assert result.authentication.outcome == "success"
    assert result.authentication.method is None
    assert result.authentication.service is None
    assert result.linux_audit.operation == "login"
    assert result.linux_audit.executable == "/usr/sbin/sshd"
    assert result.linux_audit.process_user_id == 0
    assert result.linux_audit.audit_user_id == 1200
    assert result.linux_audit.audit_session_id == 27
    assert result.linux_audit.terminal == "ssh"
    assert result.linux_audit.hostname == "training-client-a"


def test_user_login_failure_and_unknown_outcomes_are_bounded():
    failed = audit_line(
        record_type="USER_LOGIN",
        details="msg='acct=training-user res=failed'",
    )
    unsupported = audit_line(
        record_type="USER_LOGIN",
        serial="102",
        details="msg='acct=training-reviewer res=denied'",
    )
    missing = audit_line(
        record_type="USER_LOGIN",
        serial="103",
        details="msg='acct=training-observer'",
    )

    assert (
        parse_linux_audit_events(grouped_event(failed))[0]
        .authentication.outcome
        == "failure"
    )
    assert (
        parse_linux_audit_events(grouped_event(unsupported))[0]
        .authentication.outcome
        == "unknown"
    )
    assert (
        parse_linux_audit_events(grouped_event(missing))[0]
        .authentication.outcome
        == "unknown"
    )


def test_user_login_unknown_identity_address_and_ids_are_not_inferred():
    line = audit_line(
        record_type="USER_LOGIN",
        details=(
            "uid=1000 auid=4294967295 ses=4294967295 "
            "msg='op=login acct=(unknown) hostname=? "
            "addr=? terminal=? res=failed'"
        ),
    )

    result = parse_linux_audit_events(grouped_event(line))[0]

    assert result.user is None
    assert result.src_ip is None
    assert result.linux_audit.process_user_id == 1000
    assert result.linux_audit.audit_user_id is None
    assert result.linux_audit.audit_session_id is None
    assert result.linux_audit.terminal is None
    assert result.linux_audit.hostname is None


def test_all_supported_semantic_records_survive_in_stage_order():
    authentication = audit_line(record_type="USER_AUTH")
    authorization = audit_line(record_type="USER_ACCT")
    login = audit_line(record_type="USER_LOGIN")

    results = parse_linux_audit_events(grouped_event(
        login,
        authentication,
        authorization,
    ))

    assert [result.event_type for result in results] == [
        "authentication_attempt",
        "account_authorization_attempt",
        "login_establishment",
    ]
    assert [result.raw for result in results] == [
        authentication,
        authorization,
        login,
    ]
    assert all(
        result.linux_audit.record_types == (
            "USER_ACCT",
            "USER_AUTH",
            "USER_LOGIN",
        )
        for result in results
    )


def test_multiple_user_login_records_survive_deterministically():
    first = audit_line(
        record_type="USER_LOGIN",
        details="msg='acct=training-a res=success'",
    )
    second = audit_line(
        record_type="USER_LOGIN",
        details="msg='acct=training-b res=failed'",
    )

    forward = parse_linux_audit_events(
        grouped_event(first, second)
    )
    reverse = parse_linux_audit_events(
        grouped_event(second, first)
    )

    assert forward == reverse
    assert len(forward) == 2
    assert [result.user for result in forward] == [
        "training-a",
        "training-b",
    ]
    assert [result.raw for result in forward] == [
        first,
        second,
    ]


def test_user_login_fixture_preserves_each_semantic_observation():
    logs = load_normalized_logs([
        {
            "source": "linux_audit",
            "path": "sample_logs/linux_audit_user_login.log",
        }
    ])

    assert [log.event_type for log in logs] == [
        "authentication_attempt",
        "account_authorization_attempt",
        "login_establishment",
        "login_establishment",
        "login_establishment",
        "login_establishment",
        "login_establishment",
    ]
    assert [
        log.authentication.outcome
        for log in logs
        if log.event_type == "login_establishment"
    ] == [
        "success",
        "failure",
        "unknown",
        "success",
        "failure",
    ]


def test_user_login_does_not_change_detection_correlation_or_risk():
    logs = load_normalized_logs([
        {
            "source": "linux_audit",
            "path": "sample_logs/linux_audit_user_login.log",
        }
    ])
    detections = detect_attacks(logs)

    assert all(
        result["features"]["failure_count"] == 0
        for result in detections.values()
    )
    assert all(
        result["features"]["login_succeeded"] is False
        for result in detections.values()
    )
    assert all(
        not detection.is_detected
        for result in detections.values()
        for detection in result["detections"].values()
    )

    analysis = correlate_attacks(logs, detections)

    assert analysis["global_correlation"][
        "multi_ip_authentication"
    ] == []
    assert analysis["global_correlation"][
        "distributed_authentication_to_success"
    ] == []
    assert all(
        not correlation["is_correlated"]
        for result in analysis["results"].values()
        for correlation in result["correlation"].values()
    )

    assessed = assess_risk(analysis)

    assert all(
        result["risk_level"] == "LOW"
        for result in assessed["results"].values()
    )


def test_user_start_preserves_session_start_semantics():
    line = audit_line(
        record_type="USER_START",
        details=(
            "pid=4401 uid=0 auid=1300 ses=37 "
            "msg='op=PAM:session_open acct=training-admin "
            "exe=/usr/sbin/sshd hostname=training-client-a "
            "addr=198.51.100.40 terminal=ssh res=success'"
        ),
    )

    result = parse_linux_audit_events(grouped_event(line))[0]

    assert result.event_type == "session_start"
    assert result.event_type != "user_login"
    assert result.event_type != "login_establishment"
    assert result.event_type != "authentication_attempt"
    assert result.user == "training-admin"
    assert result.src_ip == "198.51.100.40"
    assert result.authentication.outcome == "success"
    assert result.authentication.method is None
    assert result.authentication.service is None
    assert result.linux_audit.operation == "PAM:session_open"
    assert result.linux_audit.executable == "/usr/sbin/sshd"
    assert result.linux_audit.process_user_id == 0
    assert result.linux_audit.audit_user_id == 1300
    assert result.linux_audit.audit_session_id == 37
    assert result.linux_audit.terminal == "ssh"
    assert result.linux_audit.hostname == "training-client-a"


def test_user_end_preserves_session_end_semantics():
    line = audit_line(
        record_type="USER_END",
        details=(
            "pid=4401 uid=0 auid=1300 ses=37 "
            "msg='op=PAM:session_close acct=training-admin "
            "exe=/usr/sbin/sshd hostname=training-client-a "
            "addr=198.51.100.40 terminal=ssh res=success'"
        ),
    )

    result = parse_linux_audit_events(grouped_event(line))[0]

    assert result.event_type == "session_end"
    assert result.event_type != "user_login"
    assert result.event_type != "login_establishment"
    assert result.user == "training-admin"
    assert result.src_ip == "198.51.100.40"
    assert result.authentication.outcome == "success"
    assert result.authentication.method is None
    assert result.authentication.service is None
    assert result.linux_audit.operation == "PAM:session_close"
    assert result.linux_audit.audit_session_id == 37


def test_session_stage_failure_and_unknown_outcomes_are_bounded():
    cases = [
        ("USER_START", "failed", "failure"),
        ("USER_START", "denied", "unknown"),
        ("USER_START", None, "unknown"),
        ("USER_END", "failed", "failure"),
        ("USER_END", "denied", "unknown"),
        ("USER_END", None, "unknown"),
    ]

    for index, (record_type, source_result, expected) in enumerate(
        cases,
        start=1,
    ):
        result_field = (
            f" res={source_result}"
            if source_result is not None
            else ""
        )
        line = audit_line(
            record_type=record_type,
            serial=str(500 + index),
            details=(
                "msg='acct=training-user"
                f"{result_field}'"
            ),
        )

        result = parse_linux_audit_events(grouped_event(line))[0]

        assert result.authentication.outcome == expected


def test_session_stage_unknown_context_and_sentinel_ids_are_not_inferred():
    for record_type in ["USER_START", "USER_END"]:
        line = audit_line(
            record_type=record_type,
            details=(
                "uid=1000 auid=4294967295 ses=4294967295 "
                "msg='acct=? hostname=? addr=127.0.0.1 "
                "terminal=? res=failed'"
            ),
        )

        result = parse_linux_audit_events(grouped_event(line))[0]

        assert result.user is None
        assert result.src_ip is None
        assert result.linux_audit.process_user_id == 1000
        assert result.linux_audit.audit_user_id is None
        assert result.linux_audit.audit_session_id is None
        assert result.linux_audit.terminal is None
        assert result.linux_audit.hostname is None


def test_all_five_semantic_records_survive_in_presentation_order():
    records = {
        "authentication_attempt": audit_line(
            record_type="USER_AUTH",
        ),
        "account_authorization_attempt": audit_line(
            record_type="USER_ACCT",
        ),
        "login_establishment": audit_line(
            record_type="USER_LOGIN",
        ),
        "session_start": audit_line(
            record_type="USER_START",
        ),
        "session_end": audit_line(
            record_type="USER_END",
        ),
    }

    results = parse_linux_audit_events(grouped_event(
        records["session_end"],
        records["login_establishment"],
        records["authentication_attempt"],
        records["session_start"],
        records["account_authorization_attempt"],
    ))

    assert [result.event_type for result in results] == list(records)
    assert [result.raw for result in results] == list(records.values())
    assert all(
        result.linux_audit.record_types == (
            "USER_ACCT",
            "USER_AUTH",
            "USER_END",
            "USER_LOGIN",
            "USER_START",
        )
        for result in results
    )


def test_multiple_session_records_survive_deterministically():
    for record_type, event_type in [
        ("USER_START", "session_start"),
        ("USER_END", "session_end"),
    ]:
        first = audit_line(
            record_type=record_type,
            details="msg='acct=training-a res=success'",
        )
        second = audit_line(
            record_type=record_type,
            details="msg='acct=training-b res=failed'",
        )

        forward = parse_linux_audit_events(
            grouped_event(first, second)
        )
        reverse = parse_linux_audit_events(
            grouped_event(second, first)
        )

        assert forward == reverse
        assert [result.event_type for result in forward] == [
            event_type,
            event_type,
        ]
        assert [result.raw for result in forward] == [
            first,
            second,
        ]


def test_session_fixture_preserves_each_semantic_observation():
    logs = load_normalized_logs([
        {
            "source": "linux_audit",
            "path": "sample_logs/linux_audit_session.log",
        }
    ])

    assert len(logs) == 14
    assert [log.event_type for log in logs[:5]] == [
        "authentication_attempt",
        "account_authorization_attempt",
        "login_establishment",
        "session_start",
        "session_end",
    ]
    assert [
        log.authentication.outcome
        for log in logs
        if log.event_type == "session_start"
    ] == ["success", "failure", "unknown", "success", "failure"]
    assert [
        log.authentication.outcome
        for log in logs
        if log.event_type == "session_end"
    ] == [
        "success",
        "success",
        "failure",
        "unknown",
        "success",
        "failure",
    ]


def test_session_events_do_not_change_analysis_or_risk():
    logs = load_normalized_logs([
        {
            "source": "linux_audit",
            "path": "sample_logs/linux_audit_session.log",
        }
    ])
    session_logs = [
        log
        for log in logs
        if log.event_type in {"session_start", "session_end"}
    ]
    detections = detect_attacks(session_logs)

    assert all(
        result["features"]["failure_count"] == 0
        for result in detections.values()
    )
    assert all(
        result["features"]["login_succeeded"] is False
        for result in detections.values()
    )
    assert all(
        not detection.is_detected
        for result in detections.values()
        for detection in result["detections"].values()
    )

    analysis = correlate_attacks(session_logs, detections)

    assert analysis["global_correlation"][
        "multi_ip_authentication"
    ] == []
    assert analysis["global_correlation"][
        "distributed_authentication_to_success"
    ] == []
    assert all(
        not correlation["is_correlated"]
        for result in analysis["results"].values()
        for correlation in result["correlation"].values()
    )

    assessed = assess_risk(analysis)

    assert all(
        result["risk_level"] == "LOW"
        for result in assessed["results"].values()
    )


def test_pipeline_loads_linux_audit_fixture_without_detection():
    logs = load_normalized_logs([
        {
            "source": "linux_audit",
            "path": "sample_logs/linux_audit_auth.log",
        }
    ])

    assert len(logs) == 3
    assert [log.event_type for log in logs] == [
        "authentication_attempt",
        "account_authorization_attempt",
        "authentication_attempt",
    ]
    assert [log.authentication.outcome for log in logs] == [
        "failure",
        "success",
        "success",
    ]
    assert logs[0].linux_audit.record_types == (
        "USER_ACCT",
        "USER_AUTH",
    )
    assert logs[1].linux_audit.record_types == (
        "USER_ACCT",
        "USER_AUTH",
    )
    assert logs[2].linux_audit.record_types == (
        "EOE",
        "USER_AUTH",
    )

    analysis = detect_attacks(logs)

    assert all(
        not detection.is_detected
        for result in analysis.values()
        for detection in result["detections"].values()
    )


REALISTIC_LIFECYCLE_FIXTURE = (
    "sample_logs/linux_audit_lifecycle_realistic.log"
)


def load_realistic_lifecycle_logs():
    return load_normalized_logs([{
        "source": "linux_audit",
        "path": REALISTIC_LIFECYCLE_FIXTURE,
    }])


def test_realistic_lifecycle_preserves_distinct_stage_events():
    logs = load_realistic_lifecycle_logs()

    assert [log.linux_audit.event_id for log in logs] == [
        "1790000000.001:501",
        "1790000001.002:502",
        "1790000002.003:503",
        "1790000003.004:504",
        "1790000004.005:505",
        "1790000005.006:506",
        "1790000006.007:507",
        "1790000007.008:508",
        "1790000008.009:509",
        "1790000009.010:510",
        "1790000010.011:511",
        "1790000012.013:513",
        "1790000013.014:514",
        "1790000014.015:515",
        "1790000015.016:516",
    ]
    assert [log.event_type for log in logs] == [
        "authentication_attempt",
        "account_authorization_attempt",
        "login_establishment",
        "session_start",
        "authentication_attempt",
        "account_authorization_attempt",
        "session_start",
        "session_end",
        "session_start",
        "session_start",
        "session_start",
        "session_end",
        "session_end",
        "login_establishment",
        "session_end",
    ]
    assert all(
        len(log.linux_audit.record_types) == 1
        for log in logs
        if log.linux_audit.event_id != "1790000004.005:505"
    )
    assert logs[4].linux_audit.record_types == (
        "EOE",
        "USER_AUTH",
    )


def test_realistic_lifecycle_preserves_observed_stage_fields():
    logs = load_realistic_lifecycle_logs()
    authentication = logs[0]
    login = logs[2]
    failed_authentication = logs[4]
    failed_authorization = logs[5]
    local_start = logs[6]

    assert authentication.timestamp == datetime(
        2026,
        9,
        21,
        14,
        13,
        20,
        1000,
        tzinfo=timezone.utc,
    )
    assert authentication.user == "training-admin"
    assert authentication.src_ip == "198.51.100.50"
    assert authentication.authentication.outcome == "success"
    assert authentication.linux_audit.operation == "PAM:authentication"
    assert authentication.linux_audit.executable == "/usr/sbin/sshd"
    assert authentication.linux_audit.process_user_id == 0
    assert authentication.linux_audit.audit_user_id is None
    assert authentication.linux_audit.audit_session_id is None
    assert authentication.linux_audit.terminal == "ssh"
    assert authentication.linux_audit.hostname == "training-client-a"
    assert authentication.raw.startswith("type=USER_AUTH ")

    assert login.linux_audit.audit_user_id == 1500
    assert login.linux_audit.audit_session_id == 51
    assert failed_authentication.authentication.outcome == "failure"
    assert failed_authentication.linux_audit.audit_user_id is None
    assert failed_authentication.linux_audit.audit_session_id is None
    assert failed_authorization.event_type == (
        "account_authorization_attempt"
    )
    assert failed_authorization.authentication.outcome == "failure"
    assert failed_authorization.linux_audit.audit_user_id is None
    assert failed_authorization.linux_audit.audit_session_id is None
    assert local_start.user == "training-batch"
    assert local_start.src_ip is None
    assert local_start.linux_audit.audit_user_id == 0
    assert local_start.linux_audit.audit_session_id == 52
    assert local_start.linux_audit.hostname is None


def test_realistic_lifecycle_is_independent_of_line_adjacency(
    tmp_path,
):
    lines = Path(REALISTIC_LIFECYCLE_FIXTURE).read_text(
        encoding="utf-8",
    ).splitlines()
    reversed_path = tmp_path / "reversed-audit.log"
    reversed_path.write_text(
        "\n".join(reversed(lines)),
        encoding="utf-8",
    )

    expected = load_realistic_lifecycle_logs()
    actual = load_normalized_logs([{
        "source": "linux_audit",
        "path": reversed_path,
    }])

    assert actual == expected


def test_realistic_lifecycle_preserves_incomplete_and_ambiguous_observations():
    logs = load_realistic_lifecycle_logs()

    assert any(
        log.event_type == "session_start"
        and log.user == "training-batch"
        for log in logs
    )
    assert not any(
        log.event_type == "login_establishment"
        and log.user == "training-batch"
        for log in logs
    )
    assert any(
        log.event_type == "session_start"
        and log.linux_audit.audit_session_id == 53
        for log in logs
    )
    assert not any(
        log.event_type == "session_end"
        and log.linux_audit.audit_session_id == 53
        for log in logs
    )
    assert any(
        log.event_type == "login_establishment"
        and log.user == "training-login-only"
        for log in logs
    )
    assert not any(
        log.event_type == "session_start"
        and log.user == "training-login-only"
        for log in logs
    )

    repeated = [
        log
        for log in logs
        if log.user == "training-shared"
        and log.src_ip == "198.51.100.60"
    ]
    assert [
        log.linux_audit.audit_session_id
        for log in repeated
    ] == [54, 55, 54, 55]


def test_realistic_lifecycle_characterizes_source_and_pid_gaps():
    first = load_linux_audit_events(
        REALISTIC_LIFECYCLE_FIXTURE,
        source_instance="audit-host-a",
    )
    second = load_linux_audit_events(
        REALISTIC_LIFECYCLE_FIXTURE,
        source_instance="audit-host-b",
    )

    assert first != second
    assert first[0].source_instance == "audit-host-a"
    assert second[0].source_instance == "audit-host-b"
    assert first[0].records[0].fields["pid"] == "5100"

    normalized = parse_linux_audit_events(first[0])[0]

    assert normalized.source == "linux_audit"
    assert normalized.linux_audit.source_instance == "audit-host-a"
    assert normalized.linux_audit.node is None
    assert not hasattr(normalized.linux_audit, "process_id")
    assert "pid=5100" in normalized.raw


def test_realistic_lifecycle_does_not_change_analysis_or_risk():
    logs = load_realistic_lifecycle_logs()
    detections = detect_attacks(logs)

    assert all(
        result["features"]["failure_count"] == 0
        for result in detections.values()
    )
    assert all(
        result["features"]["login_succeeded"] is False
        for result in detections.values()
    )
    assert all(
        not detection.is_detected
        for result in detections.values()
        for detection in result["detections"].values()
    )

    analysis = correlate_attacks(logs, detections)

    assert analysis["global_correlation"] == {
        "multi_ip_authentication": [],
        "distributed_authentication_to_success": [],
    }
    assert all(
        not correlation["is_correlated"]
        for result in analysis["results"].values()
        for correlation in result["correlation"].values()
    )

    assessed = assess_risk(analysis)

    assert all(
        result["risk_level"] == "LOW"
        for result in assessed["results"].values()
    )


SOURCE_IDENTITY_FIXTURE = (
    "sample_logs/linux_audit_source_identity.log"
)


def test_linux_audit_context_provenance_fields_are_optional():
    context = LinuxAuditContext(
        event_id="1790100000.001:601",
        record_types=("USER_START",),
    )

    assert context.source_instance is None
    assert context.node is None


def test_node_prefixed_record_preserves_opaque_node_and_raw():
    line = audit_line(
        record_type="USER_START",
        node="192.0.2.10",
    )
    record = parse_audit_record(
        line,
        source_instance="configured-feed",
    )

    assert record.node == "192.0.2.10"
    assert record.source_instance == "configured-feed"
    assert record.raw == line


def test_node_preamble_is_parsed_conservatively():
    assert parse_audit_record(
        audit_line(node="custom-name")
    ).node == "custom-name"
    assert parse_audit_record(
        "node= type=USER_START "
        "msg=audit(1790100000.001:601): res=success"
    ) is None
    assert parse_audit_record(
        "node=host-a msg=audit(1790100000.001:601): "
        "res=success"
    ) is None
    assert parse_audit_record(
        "node=host-a type=USER_START "
        "msg=audit(not-a-time): res=success"
    ) is None
    assert parse_audit_record(
        "node=host-a type=USER_START "
        "msg=audit(1790100000.001:601): "
        "msg='acct=training-user"
    ) is None


def test_grouping_scopes_event_id_by_node_and_missing_node(tmp_path):
    node_a_auth = audit_line(node="producer-a.example")
    node_a_account = audit_line(
        record_type="USER_ACCT",
        node="producer-a.example",
    )
    node_b = audit_line(node="producer-b.example")
    node_less = audit_line()
    path = tmp_path / "multi-node.log"
    path.write_text(
        "\n".join([
            node_b,
            node_a_account,
            node_less,
            node_a_auth,
        ]),
        encoding="utf-8",
    )

    events = load_linux_audit_events(
        path,
        source_instance="central-feed",
    )

    assert len(events) == 3
    assert [event.node for event in events] == [
        None,
        "producer-a.example",
        "producer-b.example",
    ]
    assert [len(event.records) for event in events] == [1, 2, 1]
    assert all(
        event.source_instance == "central-feed"
        for event in events
    )


def test_multi_node_grouping_is_independent_of_arrival_order(tmp_path):
    lines = [
        audit_line(node="producer-a.example"),
        audit_line(
            record_type="USER_ACCT",
            node="producer-a.example",
        ),
        audit_line(node="producer-b.example"),
        audit_line(),
    ]
    first_path = tmp_path / "first.log"
    second_path = tmp_path / "second.log"
    first_path.write_text("\n".join(lines), encoding="utf-8")
    second_path.write_text(
        "\n".join(reversed(lines)),
        encoding="utf-8",
    )

    first = load_linux_audit_events(
        first_path,
        source_instance="central-feed",
    )
    second = load_linux_audit_events(
        second_path,
        source_instance="central-feed",
    )

    assert first == second


def test_pipeline_preserves_source_instance_node_hostname_and_address():
    logs = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "prod-audit-feed",
        "path": SOURCE_IDENTITY_FIXTURE,
    }])

    producer_a = next(
        log
        for log in logs
        if log.user == "training-source-a"
    )
    node_less = next(
        log
        for log in logs
        if log.user == "training-node-less"
    )

    assert producer_a.source == "linux_audit"
    assert producer_a.linux_audit.source_instance == (
        "prod-audit-feed"
    )
    assert producer_a.linux_audit.node == "producer-a.example"
    assert producer_a.linux_audit.hostname == "remote-a.example"
    assert producer_a.src_ip == "198.51.100.70"
    assert producer_a.raw.startswith(
        "node=producer-a.example type=USER_START "
    )
    assert node_less.linux_audit.node is None
    assert node_less.linux_audit.source_instance == (
        "prod-audit-feed"
    )


def test_all_supported_stages_preserve_source_provenance(tmp_path):
    record_types = [
        "USER_AUTH",
        "USER_ACCT",
        "USER_LOGIN",
        "USER_START",
        "USER_END",
    ]
    path = tmp_path / "all-stages.log"
    path.write_text(
        "\n".join(
            audit_line(
                record_type=record_type,
                serial=str(700 + index),
                node="producer-a.example",
            )
            for index, record_type in enumerate(record_types)
        ),
        encoding="utf-8",
    )

    logs = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "all-stage-feed",
        "path": path,
    }])

    assert [log.event_type for log in logs] == [
        "authentication_attempt",
        "account_authorization_attempt",
        "login_establishment",
        "session_start",
        "session_end",
    ]
    assert all(
        log.linux_audit.source_instance == "all-stage-feed"
        and log.linux_audit.node == "producer-a.example"
        for log in logs
    )


def test_source_instance_is_not_inferred_from_source_or_path():
    logs = load_normalized_logs([{
        "source": "linux_audit",
        "path": SOURCE_IDENTITY_FIXTURE,
    }])

    assert all(
        log.linux_audit.source_instance is None
        for log in logs
    )
    assert all(
        log.linux_audit.source_instance != log.source
        for log in logs
    )
    assert all(
        log.linux_audit.source_instance
        != SOURCE_IDENTITY_FIXTURE
        for log in logs
    )


def test_different_source_instances_remain_distinct_after_normalization():
    first = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "feed-a",
        "path": SOURCE_IDENTITY_FIXTURE,
    }])
    second = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "feed-b",
        "path": SOURCE_IDENTITY_FIXTURE,
    }])

    assert [
        log.linux_audit.source_instance
        for log in first
    ] == ["feed-a"] * len(first)
    assert [
        log.linux_audit.source_instance
        for log in second
    ] == ["feed-b"] * len(second)
    assert [log.linux_audit.node for log in first] == [
        log.linux_audit.node for log in second
    ]


def test_source_identity_fixture_does_not_change_analysis_or_risk():
    logs = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "prod-audit-feed",
        "path": SOURCE_IDENTITY_FIXTURE,
    }])
    detections = detect_attacks(logs)

    assert all(
        result["features"]["failure_count"] == 0
        for result in detections.values()
    )
    assert all(
        result["features"]["login_succeeded"] is False
        for result in detections.values()
    )
    assert all(
        not detection.is_detected
        for result in detections.values()
        for detection in result["detections"].values()
    )

    analysis = correlate_attacks(logs, detections)

    assert analysis["global_correlation"] == {
        "multi_ip_authentication": [],
        "distributed_authentication_to_success": [],
    }
    assert all(
        not correlation["is_correlated"]
        for result in analysis["results"].values()
        for correlation in result["correlation"].values()
    )

    assessed = assess_risk(analysis)

    assert all(
        result["risk_level"] == "LOW"
        for result in assessed["results"].values()
    )
