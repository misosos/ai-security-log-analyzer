CORROBORATING_FIELDS = (
    "audit_user_id",
    "executable",
    "terminal",
    "src_ip",
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


def _classify_context(start, end):
    matched_fields = list(REQUIRED_MATCHED_FIELDS)
    missing_fields = []
    context_differences = []

    for field in CORROBORATING_FIELDS:
        start_value = _context_value(start, field)
        end_value = _context_value(end, field)

        if start_value is None or end_value is None:
            missing_fields.append(field)
        elif start_value == end_value:
            matched_fields.append(field)
        else:
            context_differences.append(field)

    return matched_fields, missing_fields, context_differences


def correlate_linux_audit_session_lifecycle(logs):
    grouped = {}

    for event in logs:
        if _is_eligible_endpoint(event, "session_start"):
            group = grouped.setdefault(
                _exact_key(event),
                {"starts": [], "ends": []},
            )
            group["starts"].append(event)
        elif _is_eligible_endpoint(event, "session_end"):
            group = grouped.setdefault(
                _exact_key(event),
                {"starts": [], "ends": []},
            )
            group["ends"].append(event)

    correlations = []

    for group in grouped.values():
        starts = group["starts"]
        ends = group["ends"]

        if len(starts) != 1 or len(ends) != 1:
            continue

        start = starts[0]
        end = ends[0]

        if start.timestamp >= end.timestamp:
            continue

        start_auid = start.linux_audit.audit_user_id
        end_auid = end.linux_audit.audit_user_id

        if (
            start_auid is not None
            and end_auid is not None
            and start_auid != end_auid
        ):
            continue

        (
            matched_fields,
            missing_fields,
            context_differences,
        ) = _classify_context(start, end)

        interval = (
            end.timestamp - start.timestamp
        ).total_seconds()
        context = start.linux_audit

        correlations.append({
            "is_correlated": True,
            "type": "linux_audit_session_lifecycle",
            "source": "linux_audit",
            "source_instance": context.source_instance,
            "node": context.node,
            "audit_session_id": context.audit_session_id,
            "user": start.user,
            "start_event_id": context.event_id,
            "end_event_id": end.linux_audit.event_id,
            "start_timestamp": start.timestamp,
            "end_timestamp": end.timestamp,
            "observed_session_lifecycle_interval_seconds": (
                interval
            ),
            "matched_fields": matched_fields,
            "missing_fields": missing_fields,
            "context_differences": context_differences,
            "rationale": [
                "동일한 source-scoped Linux Audit session context와 "
                "일치하는 USER_START 및 USER_END observation이 관찰됨",
                "두 Linux Audit endpoint observation 사이의 관찰 "
                f"간격은 {interval:.1f}초임",
                "이 relation은 physical session identity, 사용자 활동, "
                "공격자 활동, 침해 또는 인과관계를 확인하지 않음",
            ],
        })

    correlations.sort(
        key=lambda result: (
            result["start_timestamp"],
            result["end_timestamp"],
            result["source_instance"],
            result["node"],
            result["audit_session_id"],
            result["user"],
            result["start_event_id"],
            result["end_event_id"],
        )
    )

    return correlations
