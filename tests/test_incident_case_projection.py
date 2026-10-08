import builtins
from dataclasses import FrozenInstanceError, fields, is_dataclass, replace
from datetime import datetime, timedelta, timezone
import os
import random
import socket
import time

import pytest

from app.analyzer.incident_case import (
    IncidentCaseAssembly,
    IncidentCaseCorrelationInput,
    IncidentCaseDetectionInput,
    IncidentCaseEvidenceScalar,
    IncidentCaseSubjectInput,
    assemble_incident_cases,
)
from app.analyzer.incident_case_projection import (
    InvestigationCaseProjectionError,
    build_investigation_case_projection,
)
from app.models.schemas import DetectionResult, Evidence


BASE = datetime(2026, 10, 8, 0, 0, tzinfo=timezone.utc)
PRIVATE = "PRIVATE-ACCOUNT-CREDENTIAL-TOKEN-COOKIE"
PRIVATE_PATH = "/private/operator/secret.log"


def _authentication_detection(
    detection_type="brute_force",
    *,
    start=BASE,
    end=BASE + timedelta(seconds=20),
    target_count=1,
):
    is_brute = detection_type == "brute_force"
    source = "brute_force_detector" if is_brute else "password_spray_detector"
    target_type = "single_target_user" if is_brute else "multiple_target_users"
    return DetectionResult(
        True,
        detection_type,
        [
            Evidence(
                "multiple_login_failures",
                5,
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


def _path_detection():
    return DetectionResult(
        True,
        "path_traversal",
        [
            Evidence(
                "url_decoded_path",
                f"{PRIVATE_PATH}/../../etc/passwd",
                "path_traversal_detector",
                timestamp=BASE,
            ),
            Evidence(
                "url_decoded_query",
                f"credential={PRIVATE}",
                "path_traversal_detector",
                timestamp=BASE,
            ),
        ],
    )


def _correlation(
    slot="authentication",
    correlation_type="failed_to_successful_login",
    *,
    account=PRIVATE,
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


def _subject(
    ip="192.0.2.1",
    *,
    targets=(PRIVATE,),
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


def _detection_input(slot, detection):
    return IncidentCaseDetectionInput(slot, detection)


def _auth_assembly(**subject_kwargs):
    return assemble_incident_cases((_subject(
        correlations=(_correlation(),),
        **subject_kwargs,
    ),))


def _brute_assembly(*, generic=True, microseconds=0):
    failure = BASE + timedelta(seconds=20, microseconds=microseconds)
    success = BASE + timedelta(seconds=40, microseconds=microseconds)
    correlations = [
        _correlation(
            "brute_force_to_success",
            "brute_force_to_successful_login",
            failure=failure,
            success=success,
        ),
    ]
    if generic:
        correlations.append(_correlation(failure=failure, success=success))
    return assemble_incident_cases((_subject(
        detections=(_detection_input(
            "brute_force",
            _authentication_detection(end=failure),
        ),),
        correlations=tuple(correlations),
        risk="HIGH",
        confidence="HIGH",
    ),))


def _scalar_tree(value):
    if is_dataclass(value):
        return tuple(
            (item.name, _scalar_tree(getattr(value, item.name)))
            for item in fields(value)
        )
    if isinstance(value, tuple):
        return tuple(_scalar_tree(item) for item in value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _walk(value):
    yield value
    if is_dataclass(value):
        for item in fields(value):
            yield from _walk(getattr(value, item.name))
    elif isinstance(value, tuple):
        for item in value:
            yield from _walk(item)


def test_exact_assembly_boundary_and_bounded_error():
    class AssemblySubclass(IncidentCaseAssembly):
        pass

    with pytest.raises(InvestigationCaseProjectionError) as error:
        build_investigation_case_projection({})
    with pytest.raises(InvestigationCaseProjectionError):
        build_investigation_case_projection(AssemblySubclass((), (), ()))

    assert str(error.value) == "Investigation case projection failed."
    assert repr(error.value) == (
        "InvestigationCaseProjectionError('Investigation case projection failed.')"
    )


def test_projection_is_frozen_tuple_based_and_retains_no_phase_one_objects():
    assembly = _brute_assembly()
    projection = build_investigation_case_projection(assembly)

    with pytest.raises(FrozenInstanceError):
        projection.title = "changed"
    assert type(projection.cases) is tuple
    assert type(projection.cases[0].timeline_entries) is tuple
    assert type(projection.report_limitations) is tuple
    assert not any(isinstance(value, (list, dict, set)) for value in _walk(projection))
    assert not any(
        value.__class__.__module__ == "app.analyzer.incident_case"
        for value in _walk(projection)
    )


def test_builder_is_pure_and_does_not_mutate_or_reenter_pipeline(monkeypatch):
    assembly = _brute_assembly()
    before = _scalar_tree(assembly)

    def forbidden(*args, **kwargs):
        raise AssertionError("forbidden side effect")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(time, "time", forbidden)
    monkeypatch.setattr(random, "random", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(
        "app.analyzer.incident_case.assemble_incident_cases",
        forbidden,
    )

    first = build_investigation_case_projection(assembly)
    second = build_investigation_case_projection(assembly)

    assert first == second
    assert _scalar_tree(assembly) == before
    assert _scalar_tree(first) == _scalar_tree(second)


def test_case_identity_summary_and_assembler_review_order_are_preserved():
    assembly = assemble_incident_cases((
        _subject(
            "2001:db8::1",
            correlations=(_correlation(account="ipv6"),),
            risk="LOW",
            confidence="HIGH",
        ),
        _subject(
            "192.0.2.9",
            correlations=(_correlation(account="ipv4"),),
            risk="HIGH",
            confidence="LOW",
        ),
    ))
    projection = build_investigation_case_projection(assembly)

    assert tuple(case.row.case_label for case in projection.cases) == (
        "조사 사례 1",
        "조사 사례 2",
    )
    assert tuple(case.row.subject_ip for case in projection.cases) == tuple(
        case.subject_ip for case in assembly.cases
    )
    assert projection.summary.case_count == 2
    assert (
        projection.summary.high_case_count
        + projection.summary.medium_case_count
        + projection.summary.low_case_count
    ) == projection.summary.case_count
    assert projection.summary.cases_with_supported_relation_count == 2


def test_account_alias_is_explicitly_unavailable_without_phase_one_reference():
    projection = build_investigation_case_projection(_brute_assembly())

    assert projection.account_alias_status == "ACCOUNT_REFERENCE_UNAVAILABLE"
    assert projection.cases[0].row.account_alias is None
    assert all(
        entry.account_alias is None
        for entry in projection.cases[0].timeline_entries
    )
    assert "계정 별칭" in projection.account_alias_message
    assert PRIVATE not in repr(projection)


def test_case_row_uses_fixed_korean_contract_without_rendering_rule_id():
    projection = build_investigation_case_projection(_brute_assembly())
    case = projection.cases[0]

    assert case.row.risk_label == "포함된 최고 위험도"
    assert case.row.confidence_label == "포함된 최고 신뢰도"
    assert case.row.included_highest_risk == "HIGH"
    assert case.row.included_highest_confidence == "HIGH"
    assert case.row.primary_detection_display_name == "Brute Force"
    assert case.row.primary_relation_display_name == (
        "Brute Force → Successful Login"
    )
    assert "기존 상관분석" in case.row.grouping_explanation
    assert case.rule_code not in case.row.grouping_explanation
    assert case.rule_code not in case.row.case_label


def test_timeline_separates_fact_detection_and_relation_in_canonical_order():
    case = build_investigation_case_projection(_brute_assembly()).cases[0]

    assert tuple(entry.category for entry in case.timeline_entries) == (
        "DETECTION_OBSERVATION",
        "OBSERVED_FACT",
        "SUPPORTED_RELATION",
        "SUPPORTED_RELATION",
        "OBSERVED_FACT",
    )
    assert tuple(entry.sequence for entry in case.timeline_entries) == (1, 2, 3, 4, 5)
    relation = case.timeline_entries[2]
    fact = case.timeline_entries[1]
    assert fact.interpretation_label == (
        "기존 상관분석에서 관계가 확인된 인증 관찰입니다."
    )
    assert "endpoint" not in fact.interpretation_label
    assert relation.start_time.canonical_utc == BASE + timedelta(seconds=20)
    assert relation.end_time.canonical_utc == BASE + timedelta(seconds=40)
    assert relation.interpretation_label.endswith("인과관계를 의미하지 않습니다.")
    assert case.timeline_entries_without_time == ()


def test_timestamp_projection_uses_explicit_kst_and_preserves_microseconds():
    projection = build_investigation_case_projection(
        _brute_assembly(generic=False, microseconds=123456)
    )
    failure = projection.cases[0].timeline_entries[1].start_time

    assert failure.display_kst == (
        "2026-10-08 09:00:20.123456 KST (UTC+09:00)"
    )
    assert failure.display_utc == "2026-10-08T00:00:20.123456Z"
    assert ".000000" not in projection.cases[0].row.start_time.display_utc


def test_detection_evidence_is_explicitly_projected_with_units():
    case = build_investigation_case_projection(_brute_assembly()).cases[0]
    detection = case.timeline_entries[0]

    assert tuple((item.label, item.value, item.unit) for item in detection.evidence) == (
        ("실패 횟수", 5, "회"),
        ("대상 계정 수", 1, "개"),
        ("시간 범위", 20.0, "초"),
    )
    assert detection.evidence_state == "AVAILABLE"


def test_assessment_limitations_unverified_items_and_next_steps_are_bounded():
    case = build_investigation_case_projection(_brute_assembly()).cases[0]

    assert case.assessment.included_highest_risk == "HIGH"
    assert "새 위험 점수가 아닙니다" in case.assessment.risk_context
    assert len(case.limitations) == 1
    assert case.limitations[0].limitation_id == "brute_relation_not_account_takeover"
    assert len(case.unverified_items) == 7
    assert {item.label for item in case.unverified_items} == {"확인되지 않은 사항"}
    assert len(case.next_steps) == 3
    assert {item.label for item in case.next_steps} == {"다음 조사 단계"}
    forbidden_actions = ("차단", "잠금", "삭제", "종료")
    assert not any(
        action in step.text
        for step in case.next_steps
        for action in forbidden_actions
    )


def test_report_limitations_are_deduplicated_and_state_ip_semantics():
    projection = build_investigation_case_projection(_auth_assembly())
    ids = tuple(item.limitation_id for item in projection.report_limitations)

    assert len(ids) == len(set(ids)) == 7
    text = " ".join(item.text for item in projection.report_limitations)
    assert "민감한 보안 조사 정보" in text
    assert "동일 IP가 동일 사용자를" in text
    assert "인과관계" in text
    assert "공격 성공을 입증하지 않습니다" in text


def test_independent_path_brute_and_spray_are_preserved_without_raw_evidence():
    spray = _authentication_detection(
        "password_spraying_like",
        target_count=3,
    )
    assembly = assemble_incident_cases((_subject(
        targets=(PRIVATE, "operator", "reviewer"),
        detections=(
            _detection_input("brute_force", _authentication_detection()),
            _detection_input("password_spray", spray),
            _detection_input("path_traversal", _path_detection()),
        ),
        correlations=(_correlation(
            "password_spray_to_success",
            "password_spray_to_successful_login",
        ),),
    ),))
    projection = build_investigation_case_projection(assembly)

    assert projection.summary.independent_observation_count == 4
    assert {item.display_type for item in projection.independent_observations} == {
        "Brute Force 계약 미검증 관찰",
        "Password Spraying-like",
        "Password Spraying-like → Successful Login",
        "Path Traversal",
    }
    path = next(
        item for item in projection.independent_observations
        if item.display_type == "Path Traversal"
    )
    assert path.evidence == ()
    assert path.evidence_state == "APPROVED_EVIDENCE_UNAVAILABLE"
    assert "자동 결합하지 않습니다" in path.reason_text
    assert projection.summary.spray_no_go_observation_count == 2
    assert any(notice.notice_id == "spray_case_no_go" for notice in projection.notices)


def test_missing_timestamp_is_visible_and_never_synthesized():
    naive = datetime(2026, 10, 8, 0, 0)
    assembly = assemble_incident_cases((_subject(correlations=(_correlation(
        failure=naive,
        success=naive + timedelta(seconds=10),
    ),)),))
    projection = build_investigation_case_projection(assembly)
    item = projection.independent_observations[0]

    assert item.timestamp_state == "NO_TIME"
    assert item.timestamp_state_label == "시간 정보 없음"
    assert item.start_time is None
    assert item.end_time is None
    assert projection.summary.observations_without_time_count == 1
    assert any(
        notice.notice_id == "observations_without_time"
        for notice in projection.notices
    )


def test_empty_states_never_claim_safe_normal_or_clean():
    empty = assemble_incident_cases(())
    projection = build_investigation_case_projection(empty)
    notice_text = " ".join(
        f"{notice.text} {notice.context}" for notice in projection.notices
    )

    assert projection.summary.case_count == 0
    assert projection.summary.independent_observation_count == 0
    assert {notice.notice_id for notice in projection.notices} >= {
        "no_cases",
        "no_independent_observations",
        "no_detection_observations",
        "no_supported_relations",
        "no_next_steps",
    }
    assert "보안 문제의 부재를 의미하지 않습니다" in notice_text
    assert all(word not in notice_text for word in ("안전", "정상", "깨끗함", "문제없음"))


def test_projection_is_stable_across_input_permutation_and_repetition():
    high = _subject(
        "2001:db8::2",
        correlations=(_correlation(account="z"),),
        risk="HIGH",
        confidence="LOW",
    )
    low = _subject(
        "192.0.2.10",
        correlations=(_correlation(account="a"),),
        risk="LOW",
        confidence="HIGH",
    )

    first = build_investigation_case_projection(
        assemble_incident_cases((low, high))
    )
    second = build_investigation_case_projection(
        assemble_incident_cases((high, low))
    )
    third = build_investigation_case_projection(
        assemble_incident_cases((low, high))
    )

    assert first == second == third
    assert _scalar_tree(first) == _scalar_tree(second)


def test_unknown_evidence_rule_risk_and_relation_contracts_fail_closed():
    independent_assembly = assemble_incident_cases((_subject(detections=(
        _detection_input("brute_force", _authentication_detection()),
    )),))
    independent = independent_assembly.independent_observations[0]
    bad_observation = replace(
        independent.observation,
        evidence=(IncidentCaseEvidenceScalar(
            "failed_attempt_count", 5
        ),),
    )
    bad_independent = replace(independent, observation=bad_observation)
    bad_evidence = replace(
        independent_assembly,
        independent_observations=(bad_independent,),
    )

    case_assembly = _brute_assembly()
    bad_risk_case = replace(case_assembly.cases[0], included_highest_risk="UNKNOWN")
    bad_risk = replace(case_assembly, cases=(bad_risk_case,))
    reversed_relations = replace(
        case_assembly.cases[0],
        relations=tuple(reversed(case_assembly.cases[0].relations)),
    )
    bad_relations = replace(case_assembly, cases=(reversed_relations,))
    bad_rule_case = replace(case_assembly.cases[0], rule_id=[])
    bad_rule = replace(case_assembly, cases=(bad_rule_case,))
    bad_reason_item = replace(independent, reason=[])
    bad_reason = replace(
        independent_assembly,
        independent_observations=(bad_reason_item,),
    )

    for malformed in (
        bad_evidence,
        bad_risk,
        bad_relations,
        bad_rule,
        bad_reason,
    ):
        with pytest.raises(InvestigationCaseProjectionError):
            build_investigation_case_projection(malformed)


def test_privacy_canaries_are_absent_from_projection_scalar_repr_and_errors():
    assembly = assemble_incident_cases((_subject(
        detections=(_detection_input("path_traversal", _path_detection()),),
        correlations=(_correlation(account=PRIVATE),),
    ),))
    projection = build_investigation_case_projection(assembly)
    rendered = repr(projection) + repr(_scalar_tree(projection))
    canaries = (
        PRIVATE,
        PRIVATE_PATH,
        "credential=",
        "../../etc/passwd",
        "argv=PRIVATE",
        "PROCTITLE=PRIVATE",
        "CWD=/private",
        "PATH=/private",
        "secret.log",
    )

    assert all(canary not in rendered for canary in canaries)

    bad_subject = replace(assembly.cases[0], subject_ip=PRIVATE)
    bad_assembly = replace(assembly, cases=(bad_subject,))
    with pytest.raises(InvestigationCaseProjectionError) as error:
        build_investigation_case_projection(bad_assembly)
    error_text = str(error.value) + repr(error.value)
    assert all(canary not in error_text for canary in canaries)


def test_accessibility_ready_semantics_are_text_only_and_have_stable_order():
    projection = build_investigation_case_projection(_brute_assembly())
    case = projection.cases[0]

    assert projection.title == "조사 사례"
    assert case.timeline_label == "시간순 조사 흐름"
    assert tuple(entry.category_label for entry in case.timeline_entries) == (
        "탐지 관찰",
        "관찰된 사실",
        "지원되는 관계",
        "지원되는 관계",
        "관찰된 사실",
    )
    field_names = {
        item.name
        for value in _walk(projection)
        if is_dataclass(value)
        for item in fields(value)
    }
    assert not field_names.intersection({
        "color", "icon", "css_class", "dom_id", "url", "filename"
    })


def test_structural_preview_uses_only_bounded_synthetic_fields():
    projection = build_investigation_case_projection(_brute_assembly())
    case = projection.cases[0]
    preview = (
        projection.summary.case_count,
        projection.summary.independent_observation_count,
        (
            projection.summary.high_case_count,
            projection.summary.medium_case_count,
            projection.summary.low_case_count,
        ),
        case.row.case_label,
        case.row.subject_label,
        case.row.included_highest_risk,
        tuple(entry.category for entry in case.timeline_entries),
        case.row.start_time.display_kst,
        case.row.start_time.display_utc,
        len(case.limitations),
        len(case.next_steps),
    )

    assert preview[:4] == (1, 0, (1, 0, 0), "조사 사례 1")
    assert PRIVATE not in repr(preview)
