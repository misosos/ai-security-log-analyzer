from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
import math

from app.models.schemas import DetectionResult, Evidence, NormalizedEvent


BRUTE_FORCE_MIN_FAILURES = 5
BRUTE_FORCE_WINDOW_SECONDS = 60


class AnalysisRunOwner:
    """비공개 분석 실행 capability; 같은 프로세스의 동일 실행만 묶는다."""

    __slots__ = ("__analysis", "__bound")

    def __init__(self) -> None:
        self.__analysis = None
        self.__bound = False

    def _bind_analysis(self, analysis: object) -> None:
        if self.__bound:
            raise ValueError("invalid_analysis_context") from None
        self.__analysis = analysis
        self.__bound = True

    def is_bound_to(self, analysis: object) -> bool:
        return self.__bound and self.__analysis is analysis

    def __repr__(self) -> str:
        return "AnalysisRunOwner(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class BruteWindowContext:
    """Brute 탐지에만 쓰는 비공개 창과 실제 인증 실패 행."""

    subject_ip: str
    target_account: str = field(repr=False)
    start_utc: datetime
    end_utc: datetime
    failure_count: int
    member_events: tuple[NormalizedEvent, ...] = field(repr=False)
    _run_owner: AnalysisRunOwner | None = field(
        default=None, init=False, repr=False, compare=False,
    )

    def __repr__(self) -> str:
        return "BruteWindowContext(<redacted>)"


def _new_brute_window_context(
    *, subject_ip: str, target_account: str, start_utc: datetime,
    end_utc: datetime, failure_count: int,
    member_events: tuple[NormalizedEvent, ...], run_owner: AnalysisRunOwner,
) -> BruteWindowContext:
    if type(run_owner) is not AnalysisRunOwner:
        raise ValueError("invalid_brute_window_context") from None
    context = BruteWindowContext(
        subject_ip=subject_ip,
        target_account=target_account,
        start_utc=start_utc,
        end_utc=end_utc,
        failure_count=failure_count,
        member_events=member_events,
    )
    object.__setattr__(context, "_run_owner", run_owner)
    return context


def _utc_timestamp(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("invalid_brute_window_context") from None
    return value.astimezone(timezone.utc)


def validate_brute_window_context(
    context: BruteWindowContext,
    *,
    subject_ip: str | None = None,
) -> None:
    """비공개 context의 귀속·시간·멤버십 invariant를 다시 확인한다."""
    if (
        type(context) is not BruteWindowContext
        or type(context._run_owner) is not AnalysisRunOwner
        or type(context.subject_ip) is not str
        or not context.subject_ip
        or not _same_ip(context.subject_ip, context.subject_ip)
        or (
            subject_ip is not None
            and not _same_ip(context.subject_ip, subject_ip)
        )
    ):
        raise ValueError("invalid_brute_window_context") from None
    if (
        type(context.target_account) is not str
        or not context.target_account
        or type(context.failure_count) is not int
        or context.failure_count < BRUTE_FORCE_MIN_FAILURES
        or type(context.member_events) is not tuple
        or len(context.member_events) != context.failure_count
    ):
        raise ValueError("invalid_brute_window_context") from None
    start = _utc_timestamp(context.start_utc)
    end = _utc_timestamp(context.end_utc)
    if context.start_utc.tzinfo is not timezone.utc or context.end_utc.tzinfo is not timezone.utc:
        raise ValueError("invalid_brute_window_context") from None
    if end < start or (end - start).total_seconds() > BRUTE_FORCE_WINDOW_SECONDS:
        raise ValueError("invalid_brute_window_context") from None
    timestamps = []
    for event in context.member_events:
        if (
            type(event) is not NormalizedEvent
            or event.event_type != "login_failed"
            or not _same_ip(event.src_ip, context.subject_ip)
            or event.user != context.target_account
        ):
            raise ValueError("invalid_brute_window_context") from None
        timestamp = _utc_timestamp(event.timestamp)
        if not start <= timestamp <= end:
            raise ValueError("invalid_brute_window_context") from None
        timestamps.append(timestamp)
    if not timestamps or min(timestamps) != start or max(timestamps) != end:
        raise ValueError("invalid_brute_window_context") from None


def select_brute_window_contexts(
    logs,
    run_owner: AnalysisRunOwner | None = None,
) -> dict[str, BruteWindowContext]:
    """Candidate C per-account 창을 O(n log n) 정렬과 선형 탐색으로 고른다.

    사용자 정보가 없는 실패는 어떤 계정의 임계값에도 포함하지 않는다.
    입력 순서, 원문, ID는 후보 선택에 사용하지 않는다.
    """
    if run_owner is None:
        run_owner = AnalysisRunOwner()
    if type(run_owner) is not AnalysisRunOwner:
        raise ValueError("invalid_analysis_context") from None
    grouped: dict[str, dict[str, list[NormalizedEvent]]] = {}
    invalid_subjects: set[str] = set()
    for event in logs:
        if type(event) is not NormalizedEvent or event.event_type != "login_failed":
            continue
        if type(event.src_ip) is not str or not event.src_ip:
            continue
        # 시간 해석 불가가 있는 주체는 후보를 안전하게 만들지 않는다.
        try:
            _utc_timestamp(event.timestamp)
        except ValueError:
            invalid_subjects.add(event.src_ip)
            continue
        if type(event.user) is not str or not event.user:
            continue
        grouped.setdefault(event.src_ip, {}).setdefault(event.user, []).append(event)

    selected: dict[str, BruteWindowContext] = {}
    for subject_ip, by_account in grouped.items():
        if subject_ip in invalid_subjects:
            continue
        candidates: list[tuple[tuple, BruteWindowContext]] = []
        for account, account_events in by_account.items():
            ordered = sorted(
                account_events,
                key=lambda event: _utc_timestamp(event.timestamp),
            )
            times = [_utc_timestamp(event.timestamp) for event in ordered]
            left = 0
            right = 0
            while right < len(times):
                end = times[right]
                group_end = right
                while group_end + 1 < len(times) and times[group_end + 1] == end:
                    group_end += 1
                while (
                    left <= group_end
                    and (end - times[left]).total_seconds()
                    > BRUTE_FORCE_WINDOW_SECONDS
                ):
                    left += 1
                if group_end - left + 1 < BRUTE_FORCE_MIN_FAILURES:
                    right = group_end + 1
                    continue
                members = tuple(ordered[left:group_end + 1])
                start = times[left]
                context = _new_brute_window_context(
                    subject_ip=subject_ip,
                    target_account=account,
                    start_utc=start,
                    end_utc=end,
                    failure_count=len(members),
                    member_events=members,
                    run_owner=run_owner,
                )
                validate_brute_window_context(context, subject_ip=subject_ip)
                key = (end, start, (end - start).total_seconds(), -len(members))
                candidates.append((key, context))
                # 이 계정의 가장 빠른 qualifying 종료만 정책상 후보다.
                break
        if not candidates:
            continue
        best_key = min(key for key, _ in candidates)
        best = [context for key, context in candidates if key == best_key]
        if len({context.target_account for context in best}) != 1:
            continue
        selected[subject_ip] = best[0]
    return selected


def brute_window_context_owner(
    context: BruteWindowContext | None,
) -> AnalysisRunOwner | None:
    if type(context) is not BruteWindowContext:
        return None
    owner = context._run_owner
    return owner if type(owner) is AnalysisRunOwner else None


def brute_force_detection_from_context(context: BruteWindowContext) -> DetectionResult:
    """기존 Evidence schema로 선택된 Brute 창만 설명한다."""
    validate_brute_window_context(context)
    seconds = (context.end_utc - context.start_utc).total_seconds()
    return DetectionResult(
        True,
        "brute_force",
        [
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


def brute_evidence_matches_context(
    detection: DetectionResult,
    context: BruteWindowContext,
    *,
    subject_ip: str | None = None,
) -> bool:
    """Evidence가 비공개 context와 정확히 맞는 경우만 승인한다."""
    try:
        validate_brute_window_context(context, subject_ip=subject_ip)
        if (
            type(detection) is not DetectionResult
            or detection.is_detected is not True
            or type(detection.detection_type) is not str
            or detection.detection_type != "brute_force"
            or type(detection.evidence) is not list
            or len(detection.evidence) != 3
        ):
            return False
        items = {item.type: item for item in detection.evidence if type(item) is Evidence}
        if len(items) != 3 or set(items) != {
            "multiple_login_failures",
            "single_target_user",
            "failures_within_short_window",
        }:
            return False
        failed = items["multiple_login_failures"]
        target = items["single_target_user"]
        window = items["failures_within_short_window"]
        seconds = (context.end_utc - context.start_utc).total_seconds()
        return (
            type(failed.source) is str
            and failed.source == "brute_force_detector"
            and type(failed.value) is int
            and failed.value == context.failure_count
            and type(failed.time_range) is tuple
            and len(failed.time_range) == 2
            and all(
                type(value) is datetime and value.tzinfo is timezone.utc
                for value in failed.time_range
            )
            and _utc_timestamp(failed.time_range[0]) == context.start_utc
            and _utc_timestamp(failed.time_range[1]) == context.end_utc
            and type(target.source) is str
            and target.source == "brute_force_detector"
            and type(target.value) is int
            and target.value == 1
            and target.timestamp is None
            and target.time_range is None
            and type(window.source) is str
            and window.source == "brute_force_detector"
            and type(window.value) in (int, float)
            and math.isfinite(window.value)
            and window.value == seconds
            and window.timestamp is None
            and window.time_range is None
        )
    except (TypeError, ValueError, AttributeError, OverflowError):
        return False


def _same_ip(first: object, second: object) -> bool:
    if type(first) is not str or type(second) is not str:
        return False
    try:
        return ip_address(first) == ip_address(second)
    except ValueError:
        return False


def is_login_failure(log):
    return log.event_type == "login_failed"


def group_failures_by_ip(logs):
    failures = {}

    for log in logs:
        if not is_login_failure(log):
            continue

        ip = log.src_ip

        if ip not in failures:
            failures[ip] = []

        failures[ip].append(log)

    return failures


def is_within_window(logs, window_seconds):
    if not logs:
        return False

    timestamps = [
        log.timestamp
        for log in logs
    ]

    start = min(timestamps)
    end = max(timestamps)

    return (end - start).total_seconds() <= window_seconds


def summarize_ip_failures(logs):
    grouped = group_failures_by_ip(logs)
    results = {}

    for ip, failures in grouped.items():
        users = set()

        for log in failures:
            user = log.user

            if user:
                users.add(user)

        features = {
            "failure_count": len(failures),
            "target_users": sorted(users),
            "login_succeeded": has_login_success(logs, ip),
            "within_window": is_within_window(
                failures,
                60
            ),
            "window_seconds": get_failure_window_seconds(
                failures
            ),
            "average_interval": get_average_interval(
                failures
            ),
            "interval_variability": get_interval_variability(
                failures
            ),
            "unique_target_count": len(users),
        }

        results[ip] = features

    return results


def has_login_success(logs, ip):
    for log in logs:
        if (
            log.src_ip == ip
            and log.event_type == "user_login"
        ):
            return True

    return False


def get_failure_window_seconds(logs):
    if not logs:
        return 0

    timestamps = [
        log.timestamp
        for log in logs
    ]

    start = min(timestamps)
    end = max(timestamps)

    return (end - start).total_seconds()


def get_average_interval(logs):
    if len(logs) < 2:
        return 0

    timestamps = [
        log.timestamp
        for log in logs
    ]

    timestamps.sort()

    intervals = []

    for i in range(1, len(timestamps)):
        interval = (
            timestamps[i] - timestamps[i - 1]
        ).total_seconds()

        intervals.append(interval)

    return sum(intervals) / len(intervals)


def get_interval_variability(logs):
    if len(logs) < 3:
        return 0

    timestamps = [
        log.timestamp
        for log in logs
    ]

    timestamps.sort()

    intervals = []

    for i in range(1, len(timestamps)):
        interval = (
            timestamps[i] - timestamps[i - 1]
        ).total_seconds()

        intervals.append(interval)

    average = sum(intervals) / len(intervals)

    differences = []

    for interval in intervals:
        differences.append(
            abs(interval - average)
        )

    average_difference = (
        sum(differences) / len(differences)
    )

    return average_difference


def detect_brute_force(features, failures):
    evidence = []

    enough_failures = (
        features["failure_count"] >= 5
    )

    single_target = (
        features["unique_target_count"] == 1
    )

    concentrated_in_time = (
        features["within_window"]
    )

    if (
        enough_failures
        and single_target
        and concentrated_in_time
    ):
        timestamps = [
            log.timestamp
            for log in failures
        ]

        start_time = min(timestamps)
        end_time = max(timestamps)

        evidence.append(
            Evidence(
                type="multiple_login_failures",
                value=features["failure_count"],
                source="brute_force_detector",
                time_range=(
                    start_time,
                    end_time,
                ),
            )
        )

        evidence.append(
            Evidence(
                type="single_target_user",
                value=features["unique_target_count"],
                source="brute_force_detector",
            )
        )

        evidence.append(
            Evidence(
                type="failures_within_short_window",
                value=features["window_seconds"],
                source="brute_force_detector",
            )
        )

        return DetectionResult(
            is_detected=True,
            detection_type="brute_force",
            evidence=evidence,
        )

    return DetectionResult(
        is_detected=False,
        detection_type=None,
        evidence=[],
    )
