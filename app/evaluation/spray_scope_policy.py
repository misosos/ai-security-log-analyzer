"""Evaluation-only alternatives for the existing Password Spray-like scope."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import timezone

from app.models.schemas import NormalizedEvent


SPRAY_FAILURES = 4
SPRAY_TARGETS = 3
SPRAY_WINDOW_SECONDS = 60


@dataclass(frozen=True)
class SprayWindow:
    subject: str
    start_time: str
    end_time: str
    failure_count: int
    known_target_count: int
    sources: tuple[str, ...]


@dataclass(frozen=True)
class SprayDecision:
    detected: bool
    window: SprayWindow | None


def _utc_key(event: NormalizedEvent) -> tuple:
    timestamp = event.timestamp
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("invalid_evaluation_event") from None
    return (
        timestamp.astimezone(timezone.utc),
        event.source,
        event.user or "",
        event.event_type,
        event.authentication.method if event.authentication is not None else "",
        event.authentication.service if event.authentication is not None else "",
        event.raw,
    )


def _select_window(
    events: list[NormalizedEvent], subject: str, *, known_accounts_only: bool,
) -> SprayDecision:
    failures = [
        event for event in events
        if event.src_ip == subject and event.event_type == "login_failed"
        and (not known_accounts_only or bool(event.user))
    ]
    failures.sort(key=_utc_key)

    counts: Counter[str] = Counter()
    left = 0
    for right, event in enumerate(failures):
        user = event.user or ""
        if user:
            counts[user] += 1

        end = event.timestamp.astimezone(timezone.utc)
        while left <= right:
            start = failures[left].timestamp.astimezone(timezone.utc)
            if (end - start).total_seconds() <= SPRAY_WINDOW_SECONDS:
                break
            old_user = failures[left].user or ""
            if old_user:
                counts[old_user] -= 1
                if counts[old_user] == 0:
                    del counts[old_user]
            left += 1

        if right - left + 1 < SPRAY_FAILURES or len(counts) < SPRAY_TARGETS:
            continue

        # The first qualifying end wins. Shrink to the shortest qualifying
        # window at that end, yielding deterministic evidence independent of
        # the fixture's original line order.
        while left < right:
            old_user = failures[left].user or ""
            next_user = failures[left + 1].user or ""
            remaining_failures = right - left
            remaining_targets = len(counts) - int(bool(old_user) and counts[old_user] == 1)
            if remaining_failures < SPRAY_FAILURES or remaining_targets < SPRAY_TARGETS:
                break
            if old_user:
                counts[old_user] -= 1
                if counts[old_user] == 0:
                    del counts[old_user]
            left += 1

        selected = failures[left:right + 1]
        start = selected[0].timestamp.astimezone(timezone.utc)
        end = selected[-1].timestamp.astimezone(timezone.utc)
        known_users = {item.user for item in selected if item.user}
        return SprayDecision(True, SprayWindow(
            subject=subject,
            start_time=start.isoformat().replace("+00:00", "Z"),
            end_time=end.isoformat().replace("+00:00", "Z"),
            failure_count=len(selected),
            known_target_count=len(known_users),
            sources=tuple(sorted({item.source for item in selected})),
        ))

    return SprayDecision(False, None)


def evaluate_sliding_ip_window(
    events: list[NormalizedEvent], subjects: tuple[str, ...],
) -> dict[str, SprayDecision]:
    """Allow missing-account failures in the count, but never as targets."""
    return {subject: _select_window(events, subject, known_accounts_only=False) for subject in subjects}


def evaluate_known_account_window(
    events: list[NormalizedEvent], subjects: tuple[str, ...],
) -> dict[str, SprayDecision]:
    """Count only failures whose account field is present."""
    return {subject: _select_window(events, subject, known_accounts_only=True) for subject in subjects}
