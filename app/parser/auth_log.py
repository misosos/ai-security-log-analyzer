def parse_auth_log(log):
    parts = log.split()

    timestamp = parts[0] + " " + parts[1]
    level = parts[2]
    event = parts[3]

    data = {}

    for part in parts[4:]:
        if "=" in part:
            key, value = part.split("=")
            data[key] = value

    return {
        "timestamp": timestamp,
        "level": level,
        "event": event,
        **data
    }