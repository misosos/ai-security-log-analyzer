"""평가 전용 Brute Force 시간창 후보; production pipeline에서 호출하지 않는다."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable

from app.detector.brute_force import detect_brute_force, summarize_ip_failures


MIN_FAILURES = 5
WINDOW_SECONDS = 60
POLICY_NAMES = ("whole_span", "sliding_global", "sliding_window", "per_account")


@dataclass(frozen=True)
class WindowEvidence:
    failure_count: int
    unique_target_count: int
    window_seconds: float
    start_time: str
    end_time: str
    average_interval: float
    interval_variability: float
    target_account: str | None


@dataclass(frozen=True)
class PolicyDecision:
    detected: bool
    candidate_present: bool
    full_failure_count: int
    window: WindowEvidence | None
    selection: str | None
    candidate_windows_considered: int
    exclusion: str | None = None
    selection_comparison: dict[str, WindowEvidence | None] | None = None


def _aware_utc_events(events: Iterable[object], subject: str) -> tuple[list[tuple[datetime, str | None]], str | None]:
    records = []
    for event in events:
        if getattr(event, "event_type", None) != "login_failed" or getattr(event, "src_ip", None) != subject:
            continue
        timestamp = getattr(event, "timestamp", None)
        if not isinstance(timestamp, datetime) or timestamp.tzinfo is None or timestamp.utcoffset() is None:
            return [], "invalid_timestamp"
        records.append((timestamp.astimezone(timezone.utc), getattr(event, "user", None)))
    # Equal-time events are retained. Their relative order carries no meaning.
    records.sort(key=lambda row: row[0])
    return records, None


def _make_evidence(rows: list[tuple[datetime, str | None]], account: str | None) -> WindowEvidence:
    times = sorted(timestamp for timestamp, _ in rows)
    intervals = [(times[index] - times[index - 1]).total_seconds() for index in range(1, len(times))]
    average = sum(intervals) / len(intervals) if intervals else 0.0
    variability = sum(abs(value - average) for value in intervals) / len(intervals) if intervals else 0.0
    start, end = times[0], times[-1]
    return WindowEvidence(
        failure_count=len(rows),
        unique_target_count=len({user for _, user in rows if user}),
        window_seconds=(end - start).total_seconds(),
        start_time=start.isoformat().replace("+00:00", "Z"),
        end_time=end.isoformat().replace("+00:00", "Z"),
        average_interval=average,
        interval_variability=variability,
        target_account=account,
    )


def enumerate_candidate_windows(
    rows: list[tuple[datetime, str | None]], *, require_global_single_account: bool = False,
    grouped_account: str | None = None,
) -> list[WindowEvidence]:
    known_accounts = {user for _, user in rows if user}
    if require_global_single_account and len(known_accounts) != 1:
        return []
    if grouped_account is not None:
        rows = [(timestamp, user) for timestamp, user in rows if user == grouped_account]
    if not rows:
        return []
    # Account policy candidates deliberately use the known-account set; the
    # per-account candidate separately excludes unattributed failures from its
    # count. This difference is surfaced for review rather than hidden.
    distinct_times = sorted({timestamp for timestamp, _ in rows})
    candidates: list[WindowEvidence] = []
    for start in distinct_times:
        for end in distinct_times:
            span = (end - start).total_seconds()
            if span > WINDOW_SECONDS:
                break
            interval = [(timestamp, user) for timestamp, user in rows if start <= timestamp <= end]
            if len(interval) < MIN_FAILURES:
                continue
            accounts = {user for _, user in interval if user}
            if len(accounts) != 1:
                continue
            candidates.append(_make_evidence(interval, next(iter(accounts))))
    return candidates


def select_window(candidates: list[WindowEvidence], strategy: str = "fastest_threshold") -> WindowEvidence | None:
    """Select deterministically without event IDs, raw strings, or input indices."""
    if not candidates:
        return None
    if strategy == "earliest":
        key = lambda item: (item.start_time, item.end_time, item.window_seconds, -item.failure_count)
    elif strategy == "shortest":
        key = lambda item: (item.window_seconds, item.end_time, item.start_time, -item.failure_count)
    elif strategy == "most_failures":
        key = lambda item: (-item.failure_count, item.end_time, item.start_time, item.window_seconds)
    elif strategy == "fastest_threshold":
        key = lambda item: (item.end_time, item.start_time, item.window_seconds, -item.failure_count)
    else:
        raise ValueError("unknown_window_selection")
    best_key = min(key(item) for item in candidates)
    best = [item for item in candidates if key(item) == best_key]
    accounts = {item.target_account for item in best}
    if len(accounts) > 1:
        # A lexical username tie-break would inject arbitrary identity semantics.
        return None
    return best[0]


def evaluate_candidate_policies(events: Iterable[object], subject: str) -> dict[str, PolicyDecision]:
    rows, exclusion = _aware_utc_events(events, subject)
    full_count = len(rows)
    if exclusion:
        rejected = PolicyDecision(False, False, full_count, None, None, 0, exclusion)
        return {name: rejected for name in POLICY_NAMES[1:]}
    global_candidates = enumerate_candidate_windows(rows, require_global_single_account=True)
    local_candidates = enumerate_candidate_windows(rows)
    accounts = sorted({user for _, user in rows if user})
    grouped_candidates = [
        candidate
        for account in accounts
        for candidate in enumerate_candidate_windows(rows, grouped_account=account)
    ]
    definitions = {
        "sliding_global": global_candidates,
        "sliding_window": local_candidates,
        "per_account": grouped_candidates,
    }
    output = {}
    for name, candidates in definitions.items():
        selected = select_window(candidates)
        selections = {
            strategy: select_window(candidates, strategy)
            for strategy in ("earliest", "shortest", "most_failures", "fastest_threshold")
        }
        output[name] = PolicyDecision(
            detected=selected is not None,
            candidate_present=bool(candidates),
            full_failure_count=full_count,
            window=selected,
            selection=("fastest_threshold" if selected else "ambiguous_tie" if candidates else None),
            candidate_windows_considered=len(candidates),
            selection_comparison=selections,
            exclusion="window_selection_ambiguous" if candidates and selected is None else None,
        )
    return output


def evaluate_whole_span(events: Iterable[object], subject: str) -> PolicyDecision:
    subject_events = [
        event for event in events
        if getattr(event, "event_type", None) == "login_failed" and getattr(event, "src_ip", None) == subject
    ]
    if not subject_events:
        return PolicyDecision(False, False, 0, None, None, 0)
    features = summarize_ip_failures(subject_events).get(subject)
    result = detect_brute_force(features, subject_events)
    if not result.is_detected:
        return PolicyDecision(False, False, len(subject_events), None, None, 0)
    # Whole-span evidence is projected into the same safe evaluation shape.
    rows, exclusion = _aware_utc_events(subject_events, subject)
    if exclusion:
        return PolicyDecision(False, False, len(subject_events), None, None, 0, exclusion)
    evidence = _make_evidence(rows, next(iter({user for _, user in rows if user}), None))
    return PolicyDecision(True, True, len(subject_events), evidence, "whole_span", 1)


def decision_dict(decision: PolicyDecision) -> dict[str, object]:
    return asdict(decision)
