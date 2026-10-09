"""Independent expected endpoints for the existing authentication relations."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from itertools import permutations

import pytest

from app.correlation.attack_chain import (
    correlate_authentication_transition,
    correlate_brute_force_to_success,
    correlate_password_spray_to_success,
)
from app.models.schemas import AuthenticationContext, DetectionResult, NormalizedEvent


BASE = datetime(2026, 10, 8, tzinfo=timezone.utc)


def event(kind: str, seconds: float, *, account: str = "synthetic_a",
          subject: str = "192.0.2.10", source: str = "application") -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE + timedelta(seconds=seconds), event_type=kind,
        source=source, user=account, src_ip=subject, dst_ip=None,
        application=None, protocol=None, user_agent=None, raw="synthetic event",
        authentication=AuthenticationContext(
            outcome="success" if kind == "user_login" else "failure",
            method=None, service="synthetic",
        ),
    )


CORRELATORS = (
    lambda logs: correlate_authentication_transition(logs),
    lambda logs: correlate_brute_force_to_success(
        logs, DetectionResult(True, "brute_force", [])),
    lambda logs: correlate_password_spray_to_success(
        logs, DetectionResult(True, "password_spraying_like", [])),
)


@pytest.mark.parametrize("correlate", CORRELATORS)
def test_closest_success_is_independent_of_input_order(correlate):
    failure = event("login_failed", 0)
    near = event("user_login", 10)
    far = event("user_login", 20)
    for arranged in permutations((failure, near, far)):
        relation = correlate(list(arranged))
        assert relation["is_correlated"] is True
        assert relation["failure_timestamp"] == failure.timestamp
        assert relation["success_timestamp"] == near.timestamp
        assert relation["time_delta_seconds"] == 10


@pytest.mark.parametrize("correlate", CORRELATORS)
def test_same_time_distinct_success_is_ambiguous_but_exact_duplicate_is_one_fact(correlate):
    failure = event("login_failed", 0)
    success = event("user_login", 10)
    exact_duplicate = deepcopy(success)
    assert correlate([failure, success, exact_duplicate])["success_timestamp"] == success.timestamp
    distinct = deepcopy(success)
    distinct.source = "ssh"
    assert correlate([failure, success, distinct])["is_correlated"] is False
    assert correlate([distinct, failure, success])["is_correlated"] is False
    indistinguishable_from_approved_fields = deepcopy(success)
    indistinguishable_from_approved_fields.raw = "different synthetic record"
    assert correlate([failure, success, indistinguishable_from_approved_fields])["is_correlated"] is False


@pytest.mark.parametrize("correlate", CORRELATORS)
def test_earlier_outside_account_subject_candidates_cannot_win(correlate):
    failure = event("login_failed", 0)
    near = event("user_login", 10)
    distractors = (
        event("user_login", -1),
        event("user_login", 61),
        event("user_login", 1, account="synthetic_b"),
        event("user_login", 1, subject="2001:db8::10"),
    )
    relation = correlate(list(distractors) + [near, failure])
    assert relation["success_timestamp"] == near.timestamp
    assert relation["time_delta_seconds"] == 10


@pytest.mark.parametrize("correlate", CORRELATORS)
def test_microsecond_nearest_success_and_equal_delta_ambiguity(correlate):
    failure = event("login_failed", 0)
    nearest = event("user_login", 1.000001)
    later = event("user_login", 1.000002)
    assert correlate([later, failure, nearest])["success_timestamp"] == nearest.timestamp
    another_failure = event("login_failed", 20)
    another_success = event("user_login", 21.000001)
    assert correlate([failure, nearest, another_failure, another_success])["is_correlated"] is False
