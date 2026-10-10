"""Explicit, privacy-safe extraction of the four web observation contracts."""

from dataclasses import dataclass
from datetime import datetime, timezone
import math
from types import MappingProxyType

from app.models.schemas import DetectionResult, Evidence


WEB_TYPES = (
    "sql_injection_like", "xss_like", "sensitive_resource_probing_like",
    "web_scanning_like",
)
WEB_PATTERN_IDS = MappingProxyType({
    "sql_injection_like": frozenset({
        "SQLI_BOOLEAN_EXPRESSION", "SQLI_UNION_SELECT", "SQLI_COMMENT_SEQUENCE",
    }),
    "xss_like": frozenset({
        "XSS_SCRIPT_ELEMENT", "XSS_EVENT_HANDLER", "XSS_SCRIPT_SCHEME",
    }),
    "sensitive_resource_probing_like": frozenset({
        "SENSITIVE_ENV_FILE", "SENSITIVE_VCS_METADATA", "SENSITIVE_CONFIG_FILE",
    }),
    "web_scanning_like": frozenset({"WEB_SCAN_DISTINCT_TARGETS"}),
})
WEB_DISPLAY = MappingProxyType({
    "sql_injection_like": "SQL Injection-like",
    "xss_like": "XSS-like",
    "sensitive_resource_probing_like": "Sensitive Resource Probing-like",
    "web_scanning_like": "Web Scanning-like",
})
WEB_PATTERN_LABELS = MappingProxyType({
    "SQLI_BOOLEAN_EXPRESSION": "SQL 논리 비교 구문",
    "SQLI_UNION_SELECT": "SQL 결합 조회 구문",
    "SQLI_COMMENT_SEQUENCE": "SQL 주석 결합 구문",
    "XSS_SCRIPT_ELEMENT": "스크립트 요소 구문",
    "XSS_EVENT_HANDLER": "이벤트 핸들러 구문",
    "XSS_SCRIPT_SCHEME": "스크립트 스킴 구문",
    "SENSITIVE_ENV_FILE": "환경 설정 파일 탐색",
    "SENSITIVE_VCS_METADATA": "버전 관리 메타데이터 탐색",
    "SENSITIVE_CONFIG_FILE": "백업·설정 파일 탐색",
    "WEB_SCAN_DISTINCT_TARGETS": "여러 대상·클라이언트 오류 관찰",
})
WEB_LIMITATION = MappingProxyType({
    "sql_injection_like": "요청 패턴만으로 데이터베이스 명령 실행이나 데이터 접근 성공을 판단할 수 없습니다.",
    "xss_like": "요청 패턴만으로 스크립트가 저장되거나 사용자 브라우저에서 실행되었다고 판단할 수 없습니다.",
    "sensitive_resource_probing_like": "요청과 HTTP 상태만으로 민감한 리소스가 존재하거나 내용이 노출되었다고 판단할 수 없습니다.",
    "web_scanning_like": "여러 경로 요청만으로 자동화 도구 사용이나 악의적 목적을 판단할 수 없습니다.",
})
WEB_NEXT_STEP = MappingProxyType({
    "sql_injection_like": "같은 시간대의 애플리케이션 오류·데이터베이스 감사·프록시 응답 기록을 확인하십시오.",
    "xss_like": "응답 본문·출력 인코딩·CSP 위반·브라우저 보안 기록을 확인하십시오.",
    "sensitive_resource_probing_like": "애플리케이션·프록시·파일 접근 기록에서 실제 리소스 접근 여부를 확인하십시오.",
    "web_scanning_like": "같은 출발지의 요청 빈도·응답 상태·사용자 에이전트 변화와 승인된 점검 활동 여부를 확인하십시오.",
})


class WebObservationProjectionError(ValueError):
    def __init__(self):
        super().__init__("Web observation contract failed.")


@dataclass(frozen=True)
class WebObservationEvidence:
    detection_type: str
    pattern_id: str
    request_count: int
    start_utc: datetime
    end_utc: datetime
    distinct_target_count: int | None = None
    client_error_count: int | None = None
    time_window_seconds: int | float | None = None


def _fail() -> None:
    raise WebObservationProjectionError() from None


def _integer(value) -> int:
    if type(value) is not int or not 1 <= value <= 4096:
        _fail()
    return value


def validate_web_evidence(value: WebObservationEvidence) -> WebObservationEvidence:
    if (
        type(value) is not WebObservationEvidence
        or value.detection_type not in WEB_PATTERN_IDS
        or value.pattern_id not in WEB_PATTERN_IDS[value.detection_type]
        or type(value.start_utc) is not datetime
        or value.start_utc.tzinfo is not timezone.utc
        or type(value.end_utc) is not datetime
        or value.end_utc.tzinfo is not timezone.utc
        or value.start_utc > value.end_utc
    ):
        _fail()
    _integer(value.request_count)
    if value.detection_type != "web_scanning_like":
        if any(item is not None for item in (
            value.distinct_target_count, value.client_error_count,
            value.time_window_seconds,
        )):
            _fail()
        return value
    if (
        type(value.distinct_target_count) is not int
        or not 6 <= value.distinct_target_count <= value.request_count
        or type(value.client_error_count) is not int
        or not 3 <= value.client_error_count <= value.request_count
        or type(value.time_window_seconds) not in {int, float}
        or not math.isfinite(value.time_window_seconds)
        or not 0 <= value.time_window_seconds <= 60
        or (value.end_utc - value.start_utc).total_seconds()
        != value.time_window_seconds
    ):
        _fail()
    return value


def project_web_observation(slot: str, raw: DetectionResult) -> WebObservationEvidence:
    if (
        slot not in WEB_PATTERN_IDS
        or type(raw) is not DetectionResult
        or raw.is_detected is not True
        or raw.detection_type != slot
        or type(raw.evidence) is not list
    ):
        _fail()
    expected = (
        ("pattern_id", "request_count", "distinct_target_count",
         "client_error_count", "time_window_seconds")
        if slot == "web_scanning_like"
        else ("pattern_id", "request_count")
    )
    if tuple(item.type for item in raw.evidence if type(item) is Evidence) != expected or len(raw.evidence) != len(expected):
        _fail()
    if any(type(item) is not Evidence or item.source != "web_observation_detector" for item in raw.evidence):
        _fail()
    pattern, count = raw.evidence[:2]
    if type(pattern.value) is not str or pattern.value not in WEB_PATTERN_IDS[slot]:
        _fail()
    if (
        pattern.timestamp is not None or type(pattern.time_range) is not tuple
        or len(pattern.time_range) != 2
    ):
        _fail()
    start, end = pattern.time_range
    if (
        type(start) is not datetime or start.tzinfo is not timezone.utc
        or type(end) is not datetime or end.tzinfo is not timezone.utc
        or start > end
    ):
        _fail()
    if count.timestamp is not None or count.time_range is not None:
        _fail()
    request_count = _integer(count.value)
    if slot != "web_scanning_like":
        return validate_web_evidence(WebObservationEvidence(
            slot, pattern.value, request_count, start, end,
        ))
    distinct, errors, window = raw.evidence[2:]
    if any(item.timestamp is not None or item.time_range is not None for item in (distinct, errors, window)):
        _fail()
    distinct_count = _integer(distinct.value)
    if type(errors.value) is not int or not 0 <= errors.value <= request_count:
        _fail()
    seconds = window.value
    if (
        type(seconds) not in {int, float}
        or not math.isfinite(seconds)
        or not 0 <= seconds <= 60
        or (end - start).total_seconds() != seconds
        or request_count < 6 or distinct_count < 6 or distinct_count > request_count
        or errors.value < 3
    ):
        _fail()
    return validate_web_evidence(WebObservationEvidence(
        slot, pattern.value, request_count, start, end,
        distinct_count, errors.value, seconds,
    ))
