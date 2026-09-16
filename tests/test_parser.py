from datetime import datetime, timedelta, timezone

from app.parser.access_log import parse_access_log
from app.parser.registry import get_parser


def test_parse_access_log():
    line = '192.168.1.10 - - [14/Sep/2026:12:00:01 +0900] "GET /index.php HTTP/1.1" 200 1024'

    result = parse_access_log(line)

    assert result.src_ip == "192.168.1.10"
    assert result.timestamp == datetime(
        2026,
        9,
        14,
        12,
        0,
        1,
        tzinfo=timezone(timedelta(hours=9)),
    )

    assert result.http.method == "GET"
    assert result.http.path == "/index.php"
    assert result.http.status_code == 200
    assert result.http.response_size == 1024


def test_parse_access_log_without_response_size():
    line = '192.168.1.10 - - [14/Sep/2026:12:00:01 +0900] "GET /index.php HTTP/1.1" 200 -'

    result = parse_access_log(line)

    assert result.http.status_code == 200
    assert result.http.response_size is None


def test_parse_access_log_invalid_request():
    line = '192.168.1.10 - - [14/Sep/2026:12:00:01 +0900] "GET" 200 1024'

    result = parse_access_log(line)

    assert result is None


def test_parse_access_log_server_error():
    line = '192.168.1.30 - - [14/Sep/2026:12:02:20 +0900] "POST /api/login HTTP/1.1" 500 128'

    result = parse_access_log(line)

    assert result.src_ip == "192.168.1.30"
    assert result.http.method == "POST"
    assert result.http.path == "/api/login"
    assert result.http.status_code == 500
    assert result.http.response_size == 128


def test_get_access_parser():
    parser = get_parser("access")

    assert parser is parse_access_log