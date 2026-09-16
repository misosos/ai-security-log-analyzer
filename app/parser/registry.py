from app.parser.auth_log import parse_auth_log
from app.parser.ssh_auth import parse_ssh_auth_log
from app.parser.access_log import parse_access_log


PARSERS = {
    "application": parse_auth_log,
    "ssh": parse_ssh_auth_log,
    "access": parse_access_log,
}


def get_parser(source):
    return PARSERS[source]