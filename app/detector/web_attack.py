from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from urllib.parse import unquote

from app.models.schemas import Evidence, DetectionResult


_MAX_TARGET_CHARS = 2048
_MAX_DECODED_CHARS = 2048
_MAX_DECODE_PASSES = 4  # at most three changes and one fixed-point check
_MAX_SUBJECT_REQUESTS = 4096
_SCAN_REQUEST_COUNT = 6
_SCAN_DISTINCT_TARGETS = 6
_SCAN_CLIENT_ERRORS = 3
_SCAN_WINDOW_SECONDS = 60
_PATTERN_ORDER = (
    "SQLI_BOOLEAN_EXPRESSION", "SQLI_UNION_SELECT", "SQLI_COMMENT_SEQUENCE",
    "XSS_SCRIPT_ELEMENT", "XSS_EVENT_HANDLER", "XSS_SCRIPT_SCHEME",
    "SENSITIVE_ENV_FILE", "SENSITIVE_VCS_METADATA", "SENSITIVE_CONFIG_FILE",
    "WEB_SCAN_DISTINCT_TARGETS",
)
_ASCII_LOWER = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
)
_HEX = frozenset("0123456789abcdefABCDEF")


@dataclass(frozen=True, repr=False)
class _WebRequest:
    timestamp: datetime
    method: str
    status: int
    path: str = field(repr=False)
    query: str = field(repr=False)


def _bounded_decode(value: str) -> str | None:
    """One contract for new web rules; legacy traversal retains its old semantics."""
    if type(value) is not str or not 0 < len(value) <= _MAX_TARGET_CHARS:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    decoded = value
    # Three percent-decoding layers at most; the fourth pass must be stable.
    for _ in range(_MAX_DECODE_PASSES):
        for index, char in enumerate(decoded):
            if char == "%" and (
                index + 2 >= len(decoded)
                or decoded[index + 1] not in _HEX
                or decoded[index + 2] not in _HEX
            ):
                return None
        try:
            next_value = unquote(decoded, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            return None
        if len(next_value) > _MAX_DECODED_CHARS or any(
            ord(char) < 32 or ord(char) == 127 for char in next_value
        ):
            return None
        if next_value == decoded:
            return decoded.translate(_ASCII_LOWER)
        decoded = next_value
    return None


def _canonical_request(event) -> _WebRequest | None:
    if event.event_type != "http_request" or event.http is None:
        return None
    http = event.http
    if (
        type(event.timestamp) is not datetime
        or event.timestamp.tzinfo is not timezone.utc
        or type(http.method) is not str
        or re.fullmatch(r"[A-Z]{1,16}", http.method) is None
        or type(http.status_code) is not int
        or not 100 <= http.status_code <= 599
        or type(http.path) is not str
        or type(http.query) not in {str, type(None)}
        or len(http.path) + len(http.query or "") > _MAX_TARGET_CHARS
    ):
        return None
    path = _bounded_decode(http.path)
    query = _bounded_decode(http.query) if http.query else ""
    if path is None or query is None:
        return None
    return _WebRequest(event.timestamp, http.method, http.status_code, path, query)


def _pattern_matches(request: _WebRequest) -> tuple[str, ...]:
    query = request.query
    path = request.path
    found = []
    if re.search(r"(?:'|\")\s*(?:or|and)\s+\d+\s*=\s*\d+", query):
        found.append("SQLI_BOOLEAN_EXPRESSION")
    if re.search(
        r"\bunion\s+(?:all\s+)?select\s+(?:\d+\b|[a-z_][a-z0-9_]*\s*,)",
        query,
    ):
        found.append("SQLI_UNION_SELECT")
    if re.search(r"(?:'|\")\s*(?:;\s*)?(?:select|or|and)\b[^\n]{0,48}(?:--|/\*)", query):
        found.append("SQLI_COMMENT_SEQUENCE")
    if re.search(r"<script(?:\s|>)", query):
        found.append("XSS_SCRIPT_ELEMENT")
    if re.search(r"<[a-z][^>]{0,80}\s+on(?:error|load|click)\s*=", query):
        found.append("XSS_EVENT_HANDLER")
    if re.search(r"\bjavascript\s*:", query):
        found.append("XSS_SCRIPT_SCHEME")
    if re.search(r"(?:^|/)\.env(?:$|/)", path):
        found.append("SENSITIVE_ENV_FILE")
    if re.search(r"(?:^|/)\.git/(?:config|head)(?:$|/)", path):
        found.append("SENSITIVE_VCS_METADATA")
    if re.search(r"(?:^|/)[^/]{1,80}\.(?:bak|old|orig)(?:$|/)", path):
        found.append("SENSITIVE_CONFIG_FILE")
    return tuple(found)


def _web_detection(kind: str, matches: list[tuple[str, _WebRequest, int]]) -> DetectionResult:
    if not matches:
        return DetectionResult(False, None, [])
    # The current per-subject contract has one slot per type. Report the
    # earliest approved category and the count of matching request events.
    # One event may match several categories of the same type.
    matches.sort(key=lambda pair: (pair[1].timestamp, _PATTERN_ORDER.index(pair[0])))
    pattern = matches[0][0]
    first = matches[0][1].timestamp
    last = max(request.timestamp for _, request, _ in matches)
    source = "web_observation_detector"
    return DetectionResult(True, kind, [
        Evidence("pattern_id", pattern, source, time_range=(first, last)),
        Evidence("request_count", len({index for _, _, index in matches}), source),
    ])


def detect_web_observations(events) -> dict[str, DetectionResult]:
    """Return four independent, privacy-safe, per-subject observations."""
    if type(events) is not list or len(events) > _MAX_SUBJECT_REQUESTS:
        raise ValueError("Web observation input contract failed.") from None
    requests = []
    for event in events:
        request = _canonical_request(event)
        if request is None:
            continue
        # The parser has no ingestion identity: equal lines may be separate requests.
        requests.append(request)
    requests.sort(key=lambda item: (item.timestamp, item.method, item.path, item.query, item.status))
    matches = {
        "sql_injection_like": [], "xss_like": [], "sensitive_resource_probing_like": [],
    }
    for index, request in enumerate(requests):
        for pattern in _pattern_matches(request):
            if pattern.startswith("SQLI_"):
                matches["sql_injection_like"].append((pattern, request, index))
            elif pattern.startswith("XSS_"):
                matches["xss_like"].append((pattern, request, index))
            else:
                matches["sensitive_resource_probing_like"].append((pattern, request, index))
    result = {kind: _web_detection(kind, values) for kind, values in matches.items()}
    result["web_scanning_like"] = DetectionResult(False, None, [])
    for start_index, first in enumerate(requests):
        window = []
        distinct = set()
        errors = 0
        for request in requests[start_index:]:
            delta = (request.timestamp - first.timestamp).total_seconds()
            if delta > _SCAN_WINDOW_SECONDS:
                break
            window.append(request)
            distinct.add((request.path, request.query))
            errors += 400 <= request.status < 500
        if (
            len(window) >= _SCAN_REQUEST_COUNT
            and len(distinct) >= _SCAN_DISTINCT_TARGETS
            and errors >= _SCAN_CLIENT_ERRORS
        ):
            last = window[-1]
            result["web_scanning_like"] = DetectionResult(True, "web_scanning_like", [
                Evidence("pattern_id", "WEB_SCAN_DISTINCT_TARGETS", "web_observation_detector",
                         time_range=(first.timestamp, last.timestamp)),
                Evidence("request_count", len(window), "web_observation_detector"),
                Evidence("distinct_target_count", len(distinct), "web_observation_detector"),
                Evidence("client_error_count", errors, "web_observation_detector"),
                Evidence("time_window_seconds", (last.timestamp - first.timestamp).total_seconds(),
                         "web_observation_detector"),
            ])
            return result
    return result

def decode_url(value):
    decoded = value

    while True:
        next_decoded = unquote(decoded)

        if next_decoded == decoded:
            break

        decoded = next_decoded

    return decoded


def is_path_traversal(path):
    decoded_path = decode_url(path)

    return (
        "../" in decoded_path
        or "..\\" in decoded_path
    )


def detect_path_traversal(
    path,
    query=None,
    method=None,
    status_code=None,
    response_size=None,
    timestamp=None,
):

    decoded_path = decode_url(path)

    decoded_query = None

    if query:
        decoded_query = decode_url(query)

    values_to_check = [
        decoded_path
    ]

    if decoded_query:
        values_to_check.append(decoded_query)

    for value in values_to_check:

        if (
            "../" not in value
            and "..\\" not in value
        ):
            continue

        if "../" in value:
            path_pattern = "../"
        else:
            path_pattern = "..\\"

        evidence = [
            Evidence(
                type="url_decoded_path",
                value=decoded_path,
                source="path_traversal_detector",
                timestamp=timestamp,
            ),
            Evidence(
                type="path_pattern",
                value=path_pattern,
                source="path_traversal_detector",
                timestamp=timestamp,
            ),
        ]

        if decoded_query:
            evidence.append(
                Evidence(
                    type="url_decoded_query",
                    value=decoded_query,
                    source="path_traversal_detector",
                    timestamp=timestamp,
                )
            )

        if method:
            evidence.append(
                Evidence(
                    type="http_method",
                    value=method,
                    source="path_traversal_detector",
                    timestamp=timestamp,
                )
            )

        if status_code is not None:
            evidence.append(
                Evidence(
                    type="http_status_code",
                    value=status_code,
                    source="path_traversal_detector",
                    timestamp=timestamp,
                )
            )

        if response_size is not None:
            evidence.append(
                Evidence(
                    type="http_response_size",
                    value=response_size,
                    source="path_traversal_detector",
                    timestamp=timestamp,
                )
            )

        return DetectionResult(
            is_detected=True,
            detection_type="path_traversal",
            evidence=evidence,
        )

    return DetectionResult(
        is_detected=False,
        detection_type=None,
        evidence=[],
    )
