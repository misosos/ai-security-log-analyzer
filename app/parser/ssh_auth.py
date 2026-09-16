from app.models.schemas import NormalizedEvent


def parse_ssh_auth_log(log):
    parts = log.split()

    timestamp = parts[0] + " " + parts[1]

    event_type = None
    user = None
    src_ip = None

    if "Failed password for" in log:
        event_type = "login_failed"

        user_index = parts.index("for") + 1
        user = parts[user_index]

        ip_index = parts.index("from") + 1
        src_ip = parts[ip_index]

    elif "Accepted password for" in log:
        event_type = "user_login"

        user_index = parts.index("for") + 1
        user = parts[user_index]

        ip_index = parts.index("from") + 1
        src_ip = parts[ip_index]

    return NormalizedEvent(
        timestamp=timestamp,
        event_type=event_type,
        source="ssh",
        user=user,
        src_ip=src_ip,
        dst_ip=None,
        application="sshd",
        protocol="ssh",
        user_agent=None,
        raw=log,
    )