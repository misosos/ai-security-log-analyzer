"""Brute Window의 내부 consumer 계약을 검증하는 shadow 전용 코드."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from app.models.schemas import DetectionResult, Evidence, NormalizedEvent


@dataclass(frozen=True)
class BruteWindowContext:
    """선택 창과 실제 정규화 이벤트 membership을 보유하는 내부 자료."""

    subject_ip: str
    target_account: str = field(repr=False)
    start_utc: datetime
    end_utc: datetime
    failure_count: int
    member_events: tuple[NormalizedEvent, ...] = field(repr=False)


def _utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("invalid_window_context") from None
    return value.astimezone(timezone.utc)


def _validate_context(context: BruteWindowContext) -> None:
    if (
        type(context) is not BruteWindowContext
        or type(context.subject_ip) is not str
        or not context.subject_ip
        or type(context.target_account) is not str
        or not context.target_account
        or type(context.failure_count) is not int
        or context.failure_count < 5
        or type(context.member_events) is not tuple
        or len(context.member_events) != context.failure_count
    ):
        raise ValueError("invalid_window_context") from None
    start, end = _utc(context.start_utc), _utc(context.end_utc)
    if end < start or (end - start).total_seconds() > 60:
        raise ValueError("invalid_window_context") from None
    timestamps = []
    for event in context.member_events:
        if (
            type(event) is not NormalizedEvent
            or event.event_type != "login_failed"
            or event.src_ip != context.subject_ip
            or event.user != context.target_account
        ):
            raise ValueError("invalid_window_context") from None
        timestamp = _utc(event.timestamp)
        if not start <= timestamp <= end:
            raise ValueError("invalid_window_context") from None
        timestamps.append(timestamp)
    if not timestamps or min(timestamps) != start or max(timestamps) != end:
        raise ValueError("invalid_window_context") from None


def build_brute_window_context(
    events: Iterable[NormalizedEvent], subject_ip: str, decision,
) -> BruteWindowContext:
    """Candidate C 결정에서 실제 창 소속 실패를 다시 구성하고 검증한다."""
    window = getattr(decision, "window", None)
    if not getattr(decision, "detected", False) or window is None:
        raise ValueError("invalid_window_context") from None
    account = getattr(window, "target_account", None)
    if type(account) is not str or not account:
        raise ValueError("invalid_window_context") from None
    start, end = _utc(datetime.fromisoformat(window.start_time.replace("Z", "+00:00"))), _utc(
        datetime.fromisoformat(window.end_time.replace("Z", "+00:00"))
    )
    members = tuple(
        event for event in events
        if type(event) is NormalizedEvent
        and event.event_type == "login_failed"
        and event.src_ip == subject_ip
        and event.user == account
        and start <= _utc(event.timestamp) <= end
    )
    context = BruteWindowContext(
        subject_ip=subject_ip,
        target_account=account,
        start_utc=start,
        end_utc=end,
        failure_count=getattr(window, "failure_count", -1),
        member_events=members,
    )
    _validate_context(context)
    if (
        getattr(window, "unique_target_count", None) != 1
        or getattr(window, "window_seconds", None) != (end - start).total_seconds()
    ):
        raise ValueError("invalid_window_context") from None
    return context


def build_window_detection(context: BruteWindowContext) -> DetectionResult:
    """기존 evidence schema를 유지하면서 선택 창만 설명한다."""
    _validate_context(context)
    seconds = (context.end_utc - context.start_utc).total_seconds()
    return DetectionResult(
        is_detected=True,
        detection_type="brute_force",
        evidence=[
            Evidence(
                "multiple_login_failures",
                context.failure_count,
                "brute_force_detector",
                time_range=(context.start_utc, context.end_utc),
            ),
            Evidence("single_target_user", 1, "brute_force_detector"),
            Evidence(
                "failures_within_short_window",
                seconds,
                "brute_force_detector",
            ),
        ],
    )


def correlate_window_end_to_success(
    context: BruteWindowContext,
    events: Iterable[NormalizedEvent],
    correlation_window_seconds: int | float = 60,
) -> dict:
    """창의 마지막 실패 뒤 같은 IP·계정의 성공만 관계 후보로 삼는다.

    같은 최소 시각에 여러 성공 행이 있으면 event identity가 없어 실패-폐쇄한다.
    """
    _validate_context(context)
    if (
        type(correlation_window_seconds) not in (int, float)
        or correlation_window_seconds < 0
    ):
        raise ValueError("invalid_window_context") from None
    successes = []
    for event in events:
        if (
            type(event) is not NormalizedEvent
            or event.event_type != "user_login"
            or event.user != context.target_account
            or event.src_ip != context.subject_ip
        ):
            continue
        timestamp = _utc(event.timestamp)
        delta = (timestamp - context.end_utc).total_seconds()
        if 0 < delta <= correlation_window_seconds:
            successes.append((timestamp, event))
    if not successes:
        return _no_correlation()
    earliest = min(timestamp for timestamp, _ in successes)
    matches = [event for timestamp, event in successes if timestamp == earliest]
    if len(matches) != 1:
        return _no_correlation()
    success = matches[0]
    delta = (earliest - context.end_utc).total_seconds()
    return {
        "is_correlated": True,
        "type": "brute_force_to_successful_login",
        "user": context.target_account,
        "failure_timestamp": context.end_utc,
        "success_timestamp": earliest,
        "time_delta_seconds": delta,
        "rationale": [
            "선택된 반복 실패 창 종료 뒤 같은 IP와 계정에서 로그인 성공이 관찰됨",
            f"선택 창 종료와 로그인 성공 관찰 사이의 시간 차이는 {delta:.1f}초임",
        ],
    }


def _no_correlation() -> dict:
    return {
        "is_correlated": False,
        "type": None,
        "user": None,
        "rationale": [],
    }
