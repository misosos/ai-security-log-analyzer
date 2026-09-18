CORROBORATING_FIELDS = (
    "audit_user_id",
    "executable",
    "terminal",
    "src_ip",
    "hostname",
    "process_user_id",
    "operation",
)

REQUIRED_MATCHED_FIELDS = (
    "source",
    "source_instance",
    "node",
    "audit_session_id",
    "user",
)


def _is_eligible_endpoint(event, event_type):
    if event.source != "linux_audit":
        return False

    if event.event_type != event_type:
        return False

    if event.linux_audit is None:
        return False

    if event.authentication is None:
        return False

    if event.authentication.outcome != "success":
        return False

    context = event.linux_audit

    return all((
        context.source_instance is not None,
        context.node is not None,
        context.audit_session_id is not None,
        event.user is not None,
    ))


def _exact_key(event):
    context = event.linux_audit

    return (
        context.source_instance,
        context.node,
        context.audit_session_id,
        event.user,
    )


def _context_value(event, field):
    if field == "src_ip":
        return event.src_ip

    return getattr(event.linux_audit, field)


def _classify_context(login, start):
    matched_fields = list(REQUIRED_MATCHED_FIELDS)
    missing_fields = []
    context_differences = []

    for field in CORROBORATING_FIELDS:
        login_value = _context_value(login, field)
        start_value = _context_value(start, field)

        if login_value is None or start_value is None:
            missing_fields.append(field)
        elif login_value == start_value:
            matched_fields.append(field)
        else:
            context_differences.append(field)

    return matched_fields, missing_fields, context_differences


def correlate_linux_audit_login_start_co_observation(logs):
    grouped = {}

    for event in logs:
        if _is_eligible_endpoint(event, "login_establishment"):
            group = grouped.setdefault(
                _exact_key(event),
                {"logins": [], "starts": []},
            )
            group["logins"].append(event)
        elif _is_eligible_endpoint(event, "session_start"):
            group = grouped.setdefault(
                _exact_key(event),
                {"logins": [], "starts": []},
            )
            group["starts"].append(event)

    correlations = []

    for group in grouped.values():
        logins = group["logins"]
        starts = group["starts"]

        if len(logins) != 1 or len(starts) != 1:
            continue

        login = logins[0]
        start = starts[0]
        login_auid = login.linux_audit.audit_user_id
        start_auid = start.linux_audit.audit_user_id

        if (
            login_auid is not None
            and start_auid is not None
            and login_auid != start_auid
        ):
            continue

        (
            matched_fields,
            missing_fields,
            context_differences,
        ) = _classify_context(login, start)
        context = login.linux_audit

        correlations.append({
            "is_correlated": True,
            "type": "linux_audit_login_start_co_observation",
            "source": "linux_audit",
            "source_instance": context.source_instance,
            "node": context.node,
            "audit_session_id": context.audit_session_id,
            "user": login.user,
            "login_event_id": context.event_id,
            "start_event_id": start.linux_audit.event_id,
            "login_timestamp": login.timestamp,
            "start_timestamp": start.timestamp,
            "matched_fields": matched_fields,
            "missing_fields": missing_fields,
            "context_differences": context_differences,
            "rationale": [
                "successful USER_LOGIN observation이 관찰됨",
                "successful USER_START observation이 관찰됨",
                "required source-scoped Linux Audit context가 일치함",
                "각 endpoint에서 unique eligible observation이 관찰됨",
                "이 relation은 observation ordering, physical session "
                "identity, PAM transaction identity, SSH connection "
                "identity, 사용자·공격자 활동, 침해 또는 인과관계를 "
                "확인하지 않음",
            ],
        })

    correlations.sort(
        key=lambda result: (
            result["source_instance"],
            result["node"],
            result["audit_session_id"],
            result["user"],
            result["login_timestamp"],
            result["start_timestamp"],
            result["login_event_id"],
            result["start_event_id"],
        )
    )

    return correlations
