from app.parser.auth_log import parse_auth_log
from app.parser.ssh_auth import parse_ssh_auth_log
from app.parser.access_log import parse_access_log


PARSERS = {
    "application": {
        "parser": parse_auth_log,
        "timezone": "Asia/Seoul",
    },
    "ssh": {
        "parser": parse_ssh_auth_log,
        "timezone": "Asia/Seoul",
    },
    "access": {
        "parser": parse_access_log,
        "timezone": None,
    },
}


def get_parser(source):
    return PARSERS[source]["parser"]


def get_timezone(source):
    return PARSERS[source]["timezone"]