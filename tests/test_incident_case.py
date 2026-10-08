import builtins
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, is_dataclass
from datetime import datetime, timedelta, timezone
import json
import os
import random
import socket
import time

import pytest

from app.analyzer.incident_case import (
    CASE_RULE_PRECEDENCE,
    CASE_SPRAY_SUCCESS_STATUS,
    IncidentCaseAssembly,
    IncidentCaseAssemblyError,
    IncidentCaseCorrelationInput,
    IncidentCaseDetectionInput,
    IncidentCaseSubjectInput,
    assemble_incident_cases,
)
from app.models.schemas import DetectionResult, Evidence


BASE = datetime(2026, 10, 8, 0, 0, tzinfo=timezone.utc)
PRIVATE = "PRIVATE-ORIGINAL-ACCOUNT-CREDENTIAL-TOKEN-COOKIE"


def empty_detection():
    return DetectionResult(False, None, [])


def authentication_detection(
    detection_type="brute_force",
    *,
    start=BASE,
    end=BASE + timedelta(seconds=20),
    failed_count=5,
    target_count=1,
):
    is_brute = detection_type == "brute_force"
    source = (
        "brute_force_detector"
        if is_brute
        else "password_spray_detector"
    )
    target_type = (
        "single_target_user" if is_brute else "multiple_target_users"
    )
    return DetectionResult(
        True,
        detection_type,
        [
            Evidence(
                "multiple_login_failures",
                failed_count,
                source,
                time_range=(start, end),
            ),
            Evidence(target_type, target_count, source),
            Evidence(
                "failures_within_short_window",
                (end - start).total_seconds(),
                source,
            ),
        ],
    )


def path_detection(timestamp=BASE, private=PRIVATE):
    return DetectionResult(
        True,
        "path_traversal",
        [
            Evidence(
                "url_decoded_path",
                f"/private/{private}/../../etc/passwd",
                "path_traversal_detector",
                timestamp=timestamp,
            ),
            Evidence(
                "url_decoded_query",
                f"credential={private}",
                "path_traversal_detector",
                timestamp=timestamp,
            ),
        ],
    )


def correlation(
    slot="authentication",
    correlation_type="failed_to_successful_login",
    *,
    account="analyst",
    failure=BASE + timedelta(seconds=20),
    success=BASE + timedelta(seconds=40),
):
    return IncidentCaseCorrelationInput(
        slot=slot,
        is_correlated=True,
        correlation_type=correlation_type,
        account=account,
        failure_timestamp=failure,
        success_timestamp=success,
        time_delta_seconds=(success - failure).total_seconds(),
    )


def subject(
    ip="192.0.2.1",
    *,
    targets=("analyst",),
    detections=(),
    correlations=(),
    risk="MEDIUM",
    confidence="MEDIUM",
):
    return IncidentCaseSubjectInput(
        subject_ip=ip,
        target_accounts=targets,
        detections=detections,
        correlations=correlations,
        risk_level=risk,
        confidence=confidence,
    )


def detection_input(slot, detection):
    return IncidentCaseDetectionInput(slot, detection)


def scalar_tree(value):
    if is_dataclass(value):
        return {
            item.name: scalar_tree(getattr(value, item.name))
            for item in fields(value)
        }
    if isinstance(value, tuple):
        return [scalar_tree(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def test_generic_authentication_transition_case_uses_existing_relation_only():
    result = assemble_incident_cases((subject(
        correlations=(correlation(account=PRIVATE),),
        risk="LOW",
        confidence="MEDIUM",
    ),))

    assert len(result.cases) == 1
    case = result.cases[0]
    assert case.rule_id == "CASE-AUTH-TRANSITION-01"
    assert tuple(
        observation.observation_kind for observation in case.observations
    ) == (
        "authentication_failure_fact",
        "authentication_success_fact",
    )
    assert tuple(relation.relation_type for relation in case.relations) == (
        "failed_to_successful_login",
    )
    assert case.included_highest_risk == "LOW"
    assert case.included_highest_confidence == "MEDIUM"
    assert case.start_time_utc == BASE + timedelta(seconds=20)
    assert case.end_time_utc == BASE + timedelta(seconds=40)
    assert case.duration_seconds == 20
    assert PRIVATE not in repr(result)


def test_brute_case_absorbs_exact_generic_endpoint_without_fact_duplication():
    specific = correlation(
        "brute_force_to_success",
        "brute_force_to_successful_login",
        failure=BASE + timedelta(seconds=60),
        success=BASE + timedelta(seconds=120),
    )
    generic = correlation(
        failure=BASE + timedelta(seconds=60),
        success=BASE + timedelta(seconds=120),
    )
    result = assemble_incident_cases((subject(
        detections=(detection_input(
            "brute_force",
            authentication_detection(end=BASE + timedelta(seconds=60)),
        ),),
        correlations=(generic, specific),
        risk="HIGH",
        confidence="HIGH",
    ),))

    assert CASE_RULE_PRECEDENCE[0] == "CASE-BRUTE-SUCCESS-01"
    assert len(result.cases) == 1
    case = result.cases[0]
    assert case.rule_id == "CASE-BRUTE-SUCCESS-01"
    assert len(case.observations) == 3
    assert sum(
        observation.observation_kind.endswith("_fact")
        for observation in case.observations
    ) == 2
    assert tuple(relation.relation_type for relation in case.relations) == (
        "brute_force_to_successful_login",
        "failed_to_successful_login",
    )
    assert case.duration_seconds == 120
    assert result.independent_observations == ()


def test_brute_case_accepts_exact_120_second_boundary():
    result = assemble_incident_cases((subject(
        detections=(detection_input(
            "brute_force",
            authentication_detection(end=BASE + timedelta(seconds=60)),
        ),),
        correlations=(correlation(
            "brute_force_to_success",
            "brute_force_to_successful_login",
            failure=BASE + timedelta(seconds=60),
            success=BASE + timedelta(seconds=120),
        ),),
    ),))

    assert result.cases[0].duration_seconds == 120


def test_brute_case_over_120_seconds_fails_closed():
    result = assemble_incident_cases((subject(
        detections=(detection_input(
            "brute_force",
            authentication_detection(end=BASE + timedelta(seconds=60)),
        ),),
        correlations=(correlation(
            "brute_force_to_success",
            "brute_force_to_successful_login",
            failure=BASE + timedelta(seconds=60, microseconds=1),
            success=BASE + timedelta(seconds=120, microseconds=1),
        ),),
    ),))

    assert result.cases == ()
    assert len(result.independent_observations) == 2
    assert {
        item.reason for item in result.independent_observations
    } == {"no_supported_relation", "relationship_not_proven"}


def test_brute_case_requires_exact_target_membership_and_detection_subject():
    result = assemble_incident_cases((subject(
        targets=("different-account",),
        detections=(detection_input(
            "brute_force", authentication_detection()
        ),),
        correlations=(correlation(
            "brute_force_to_success",
            "brute_force_to_successful_login",
        ),),
    ),))

    assert result.cases == ()
    assert len(result.independent_observations) == 2


def test_brute_case_requires_exact_typed_target_count_contract():
    result = assemble_incident_cases((subject(
        targets=("analyst", "other"),
        detections=(detection_input(
            "brute_force", authentication_detection(target_count=1)
        ),),
        correlations=(correlation(
            "brute_force_to_success",
            "brute_force_to_successful_login",
        ),),
    ),))

    assert result.cases == ()
    assert len(result.independent_observations) == 2
    assert "brute_force_invalid_contract" in {
        item.observation.observation_type
        for item in result.independent_observations
    }


def test_partially_overlapping_generic_relation_remains_independent():
    specific = correlation(
        "brute_force_to_success",
        "brute_force_to_successful_login",
    )
    generic = correlation(
        failure=BASE + timedelta(seconds=20, microseconds=1),
        success=BASE + timedelta(seconds=40),
    )
    result = assemble_incident_cases((subject(
        detections=(detection_input(
            "brute_force", authentication_detection()
        ),),
        correlations=(specific, generic),
    ),))

    assert tuple(case.rule_id for case in result.cases) == (
        "CASE-BRUTE-SUCCESS-01",
    )
    assert tuple(len(case.relations) for case in result.cases) == (1,)
    assert len(result.independent_observations) == 1
    assert result.independent_observations[0].reason == (
        "relationship_not_proven"
    )


def test_password_spray_rule_is_documented_no_go_and_inputs_stay_independent():
    result = assemble_incident_cases((subject(
        targets=("analyst", "operator", "reviewer"),
        detections=(detection_input(
            "password_spray",
            authentication_detection(
                "password_spraying_like",
                failed_count=4,
                target_count=3,
            ),
        ),),
        correlations=(correlation(
            "password_spray_to_success",
            "password_spray_to_successful_login",
        ),),
    ),))

    assert result.cases == ()
    assert len(result.independent_observations) == 2
    assert result.unsupported_case_rules[0].rule_id == (
        "CASE-SPRAY-SUCCESS-01"
    )
    assert result.unsupported_case_rules[0].status_code == (
        CASE_SPRAY_SUCCESS_STATUS
    )


def test_same_ip_account_or_time_without_relation_never_groups():
    brute = detection_input("brute_force", authentication_detection())
    result = assemble_incident_cases((subject(
        targets=("analyst",),
        detections=(brute,),
        correlations=(),
    ),))

    assert result.cases == ()
    assert len(result.independent_observations) == 1
    assert result.independent_observations[0].reason == (
        "no_supported_relation"
    )


def test_path_traversal_and_unrelated_brute_force_remain_independent():
    result = assemble_incident_cases((subject(
        detections=(
            detection_input("brute_force", authentication_detection()),
            detection_input("path_traversal", path_detection()),
        ),
    ),))

    assert result.cases == ()
    assert tuple(
        item.observation.observation_type
        for item in result.independent_observations
    ) == ("brute_force", "path_traversal")


def test_post_authentication_and_unknown_relations_are_preserved_independently():
    post = correlation(
        "post_authentication",
        "successful_login_to_file_access",
    )
    unknown = IncidentCaseCorrelationInput(
        "authentication",
        True,
        "future-private-correlation",
        PRIVATE,
        BASE,
        BASE + timedelta(seconds=1),
        1,
    )
    result = assemble_incident_cases((subject(correlations=(unknown, post)),))

    assert result.cases == ()
    assert len(result.independent_observations) == 2
    assert {
        item.observation.observation_type
        for item in result.independent_observations
    } == {
        "successful_login_to_file_access",
        "unsupported_correlation",
    }
    assert PRIVATE not in repr(result)


def test_naive_timestamps_are_not_inferred_and_stay_independent():
    naive = datetime(2026, 10, 8, 0, 0)
    result = assemble_incident_cases((subject(correlations=(correlation(
        failure=naive,
        success=naive + timedelta(seconds=10),
    ),)),))

    assert result.cases == ()
    independent = result.independent_observations[0]
    assert independent.reason == "invalid_timestamp"
    assert independent.observation.start_time_utc is None
    assert independent.observation.end_time_utc is None


def test_microseconds_are_preserved():
    failure = BASE + timedelta(microseconds=1)
    success = BASE + timedelta(seconds=1, microseconds=2)
    case = assemble_incident_cases((subject(correlations=(correlation(
        failure=failure,
        success=success,
    ),)),)).cases[0]

    assert case.start_time_utc == failure
    assert case.end_time_utc == success
    assert case.duration_seconds == 1.000001


def test_duplicate_exact_relation_is_deduplicated_deterministically():
    relation = correlation(account=PRIVATE)
    result = assemble_incident_cases((subject(
        correlations=(relation, deepcopy(relation)),
    ),))

    assert len(result.cases) == 1
    assert len(result.cases[0].relations) == 1
    assert len(result.cases[0].observations) == 2


def test_distinct_detection_observations_with_same_type_are_preserved():
    first = authentication_detection(
        start=BASE,
        end=BASE + timedelta(seconds=10),
    )
    second = authentication_detection(
        start=BASE + timedelta(seconds=20),
        end=BASE + timedelta(seconds=30),
    )
    result = assemble_incident_cases((subject(detections=(
        detection_input("brute_force", first),
        detection_input("brute_force", second),
    )),))

    assert len(result.independent_observations) == 2
    assert tuple(
        item.observation.start_time_utc
        for item in result.independent_observations
    ) == (BASE, BASE + timedelta(seconds=20))


def test_distinct_observations_sharing_a_timestamp_are_preserved():
    brute = authentication_detection(start=BASE, end=BASE)
    path = path_detection(timestamp=BASE)
    result = assemble_incident_cases((subject(detections=(
        detection_input("brute_force", brute),
        detection_input("path_traversal", path),
    )),))

    assert len(result.independent_observations) == 2
    assert {
        item.observation.observation_type
        for item in result.independent_observations
    } == {"brute_force", "path_traversal"}


def test_input_permutation_and_repeated_invocation_are_equal():
    high = subject(
        "2001:db8::2",
        correlations=(correlation(account="z"),),
        risk="HIGH",
        confidence="LOW",
    )
    low = subject(
        "192.0.2.10",
        correlations=(correlation(account="a"),),
        risk="LOW",
        confidence="HIGH",
    )

    first = assemble_incident_cases((low, high))
    second = assemble_incident_cases((high, low))
    third = assemble_incident_cases((low, high))

    assert first == second == third


def test_review_order_uses_risk_confidence_time_and_numeric_ip():
    subjects = (
        subject(
            "2001:db8::1",
            correlations=(correlation(account="v6"),),
            risk="MEDIUM",
            confidence="HIGH",
        ),
        subject(
            "192.0.2.2",
            correlations=(correlation(account="later"),),
            risk="HIGH",
            confidence="LOW",
        ),
        subject(
            "192.0.2.10",
            correlations=(correlation(account="ten"),),
            risk="MEDIUM",
            confidence="HIGH",
        ),
        subject(
            "192.0.2.1",
            correlations=(correlation(account="one"),),
            risk="MEDIUM",
            confidence="HIGH",
        ),
    )

    ordered = assemble_incident_cases(subjects).cases

    assert tuple(case.subject_ip for case in ordered) == (
        "192.0.2.2",
        "192.0.2.1",
        "192.0.2.10",
        "2001:db8::1",
    )


def test_ambiguous_detection_membership_raises_bounded_error():
    first = detection_input("brute_force", authentication_detection())
    second = detection_input(
        "brute_force",
        authentication_detection(failed_count=6),
    )
    with pytest.raises(IncidentCaseAssemblyError) as caught:
        assemble_incident_cases((subject(
            detections=(first, second),
            correlations=(correlation(
                "brute_force_to_success",
                "brute_force_to_successful_login",
            ),),
        ),))

    assert caught.value.code == "ambiguous_membership"
    assert str(caught.value) == (
        "Incident case assembly failed: ambiguous observation membership."
    )


@pytest.mark.parametrize("invalid", [[], {}, "subject", None])
def test_exact_tuple_input_boundary(invalid):
    with pytest.raises(IncidentCaseAssemblyError):
        assemble_incident_cases(invalid)


@pytest.mark.parametrize("risk", ["UNKNOWN", "high", "", None])
def test_unknown_risk_or_confidence_fails_closed(risk):
    with pytest.raises(IncidentCaseAssemblyError):
        assemble_incident_cases((subject(risk=risk),))
    with pytest.raises(IncidentCaseAssemblyError):
        assemble_incident_cases((subject(confidence=risk),))


def test_canonical_ip_collision_fails_closed():
    with pytest.raises(IncidentCaseAssemblyError) as caught:
        assemble_incident_cases((
            subject("2001:db8::1"),
            subject("2001:0db8:0:0:0:0:0:1"),
        ))
    assert caught.value.code == "ambiguous_membership"


def test_results_are_frozen_tuple_based_and_retain_no_raw_objects():
    detection = authentication_detection()
    relation = correlation()
    result = assemble_incident_cases((subject(
        detections=(detection_input("brute_force", detection),),
        correlations=(relation,),
    ),))

    assert type(result) is IncidentCaseAssembly
    assert type(result.cases) is tuple
    assert type(result.independent_observations) is tuple
    assert type(result.unsupported_case_rules) is tuple
    with pytest.raises(FrozenInstanceError):
        result.cases = ()

    def walk(value):
        assert not isinstance(value, (list, dict, set, DetectionResult, Evidence))
        if is_dataclass(value):
            for item in fields(value):
                walk(getattr(value, item.name))
        elif isinstance(value, tuple):
            for item in value:
                walk(item)

    walk(result)


def test_assembler_is_pure_deterministic_and_does_not_mutate_inputs(monkeypatch):
    source = (subject(
        detections=(detection_input(
            "brute_force", authentication_detection()
        ),),
        correlations=(correlation(
            "brute_force_to_success",
            "brute_force_to_successful_login",
        ),),
    ),)
    original = deepcopy(source)

    def forbidden(*args, **kwargs):
        raise AssertionError("external operation attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(time, "time", forbidden)
    monkeypatch.setattr(random, "random", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)

    first = assemble_incident_cases(source)
    second = assemble_incident_cases(source)

    assert first == second
    assert source == original


def test_privacy_canaries_are_absent_from_result_repr_and_scalar_tree():
    private_values = (
        PRIVATE,
        "PRIVATE-FULL-QUERY",
        "PRIVATE-RAW-LOG",
        "PRIVATE-ABSOLUTE-PATH",
        "PRIVATE-FILENAME",
        "PRIVATE-ARGV",
        "PRIVATE-PROCTITLE",
        "PRIVATE-CWD",
        "PRIVATE-PATH-RECORD",
        "PRIVATE-INTERNAL-REPR",
        "PRIVATE-EXCEPTION-CONTENT",
    )
    source = (subject(
        targets=(PRIVATE,),
        detections=(detection_input(
            "path_traversal",
            path_detection(private="-".join(private_values)),
        ),),
        correlations=(correlation(account=PRIVATE),),
    ),)

    result = assemble_incident_cases(source)
    serialized = json.dumps(
        scalar_tree(result), ensure_ascii=False, sort_keys=True
    )

    for private in private_values:
        assert private not in repr(result)
        assert private not in serialized


def test_bounded_errors_never_copy_private_input_or_internal_repr():
    private_subject = f"{PRIVATE}-not-an-ip"
    with pytest.raises(IncidentCaseAssemblyError) as caught:
        assemble_incident_cases((subject(private_subject),))

    assert PRIVATE not in str(caught.value)
    assert PRIVATE not in repr(caught.value)
    assert "Traceback" not in repr(caught.value)


def test_structural_preview_uses_only_bounded_non_secret_scalars():
    result = assemble_incident_cases((subject(
        targets=(PRIVATE,),
        detections=(detection_input(
            "brute_force", authentication_detection()
        ),),
        correlations=(correlation(
            "brute_force_to_success",
            "brute_force_to_successful_login",
            account=PRIVATE,
        ),),
        risk="HIGH",
        confidence="HIGH",
    ),))
    case = result.cases[0]
    preview = {
        "rule": case.rule_id,
        "observation_count": len(case.observations),
        "supporting_relation_count": len(case.relations),
        "included_highest_risk": case.included_highest_risk,
        "timeline_start": case.start_time_utc.isoformat(),
        "timeline_end": case.end_time_utc.isoformat(),
        "independent_count_by_type": {},
    }
    serialized = json.dumps(preview, sort_keys=True)

    assert PRIVATE not in serialized
    assert preview == {
        "rule": "CASE-BRUTE-SUCCESS-01",
        "observation_count": 3,
        "supporting_relation_count": 1,
        "included_highest_risk": "HIGH",
        "timeline_start": "2026-10-08T00:00:00+00:00",
        "timeline_end": "2026-10-08T00:00:40+00:00",
        "independent_count_by_type": {},
    }
