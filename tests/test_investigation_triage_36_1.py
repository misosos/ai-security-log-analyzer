from dataclasses import FrozenInstanceError
import ast
import json
from pathlib import Path
import logging
import threading

import pytest
from hypothesis import given, strategies as st

from app.investigation_triage_36_1 import (
    CORPUS_DIGEST,
    DTO_FIELDS,
    OUTPUT_FIELDS,
    EvidenceCompleteness,
    ReviewPriority,
    SafeInvestigationDTO,
    TriageAdmission,
    TriageError,
    build_investigation_assistance,
    create_safe_investigation_dto,
    fixed_result,
    validate_assistance_json,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((ROOT / "tests/fixtures/investigation_triage_36_1.json").read_text())


def dto(**overrides):
    values = {
        "schema_version": 1,
        "request_id": "r_0123456789abcdef01234567",
        "case_ref": "c_fedcba9876543210fedcba98",
        "source_role": "application",
        "observation_categories": ("authentication",),
        "detection_codes": ("brute_force",),
        "relation_codes": (),
        "risk_band": "LOW",
        "case_status": "open",
        "event_count_bucket": "2_5",
        "time_window_bucket": "5_60m",
        "evidence_completeness": "complete",
        "limitation_codes": ("DETECTION_IS_NOT_COMPROMISE",),
        "corpus_digest": CORPUS_DIGEST,
    }
    values.update(overrides)
    return create_safe_investigation_dto(**values)


def test_safe_dto_is_closed_frozen_bounded_and_opaque():
    item = dto()
    assert isinstance(item, SafeInvestigationDTO)
    assert tuple(item.to_mapping()) == DTO_FIELDS
    assert item.corpus_digest == CORPUS_DIGEST
    assert "brute_force" not in repr(item)
    assert "0123456789abcdef" not in repr(item)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        item.risk_band = "HIGH"

    mapping = item.to_mapping()
    with pytest.raises(TriageError) as error:
        SafeInvestigationDTO.from_mapping({**mapping, "unexpected": "PRIVATE_CANARY"})
    assert error.value.code == "DTO_INVALID"
    assert "PRIVATE_CANARY" not in str(error.value)
    assert "PRIVATE_CANARY" not in repr(error.value)
    with pytest.raises(TriageError) as error:
        SafeInvestigationDTO.from_mapping({key: value for key, value in mapping.items() if key != "risk_band"})
    assert error.value.code == "DTO_INVALID"


@pytest.mark.parametrize("field,value", [
    ("schema_version", True),
    ("schema_version", 1.0),
    ("source_role", "web"),
    ("observation_categories", ("authentication", "authentication")),
    ("detection_codes", ("brute_force", "unknown_detector")),
    ("relation_codes", ("failed_to_successful_login", "failed_to_successful_login")),
    ("risk_band", "CRITICAL"),
    ("case_status", "closed-with-free-text"),
    ("event_count_bucket", True),
    ("time_window_bucket", "exact-2026-10-27T00:00:00Z"),
    ("evidence_completeness", "complete-ish"),
    ("limitation_codes", ("UNKNOWN_LIMITATION",)),
    ("corpus_digest", "0" * 64),
    ("request_id", "same-stable-public-case-id"),
    ("case_ref", "same-stable-public-case-id"),
    ("observation_categories", ("x" * 257,)),
    ("detection_codes", ("brute_force",) * 17),
])
def test_safe_dto_rejects_invalid_values_with_fixed_error(field, value):
    with pytest.raises(TriageError) as error:
        dto(**{field: value})
    assert error.value.code == "DTO_INVALID"
    assert "x" * 32 not in str(error.value)


def test_safe_dto_rejects_privacy_canaries_without_reflection():
    canaries = (
        "account=PRIVATE_ACCOUNT_CANARY",
        "192.0.2.83", "2001:db8::83", "host-canary.invalid",
        "/synthetic/private-canary.log", "PRIVATE_RAW_LINE_CANARY",
        "credential=TOKEN_CANARY", "PRIVATE_EXCEPTION_CANARY",
    )
    for canary in canaries:
        with pytest.raises(TriageError) as error:
            dto(observation_categories=(canary,))
        assert error.value.code == "DTO_INVALID"
        assert canary not in str(error.value)
        assert canary not in repr(error.value)


def test_priority_is_deterministic_independent_of_risk_count_time_and_timezone(monkeypatch):
    complete = dto()
    results = [build_investigation_assistance(complete) for _ in range(3)]
    assert results[0].review_priority is ReviewPriority.REVIEW_SOON
    assert results[0].to_json() == results[1].to_json() == results[2].to_json()
    assert tuple(json.loads(results[0].to_json())) == OUTPUT_FIELDS

    changed = dto(risk_band="HIGH", event_count_bucket="21_plus", time_window_bucket="under_5m")
    assert build_investigation_assistance(changed).review_priority is results[0].review_priority
    monkeypatch.setenv("TZ", "UTC")
    import time
    time.tzset()
    utc = build_investigation_assistance(complete).to_json()
    monkeypatch.setenv("TZ", "Asia/Seoul")
    time.tzset()
    seoul = build_investigation_assistance(complete).to_json()
    assert utc == seoul


def test_reference_priority_edges_and_analysis_inputs_are_read_only():
    item = dto(evidence_completeness="partial")
    before = json.dumps(item.to_mapping(), sort_keys=True, separators=(",", ":"))
    assert build_investigation_assistance(item).review_priority is ReviewPriority.REVIEW_SOON
    assert json.dumps(item.to_mapping(), sort_keys=True, separators=(",", ":")) == before
    assert build_investigation_assistance(dto(evidence_completeness="conflicting")).review_priority is ReviewPriority.UNDETERMINED
    assert build_investigation_assistance(dto(evidence_completeness="unknown")).review_priority is ReviewPriority.UNDETERMINED
    assert build_investigation_assistance(dto(detection_codes=(), relation_codes=(), observation_categories=("web_request",))).review_priority is ReviewPriority.REVIEW_LATER
    assert build_investigation_assistance(dto(source_role="unknown")).review_priority is ReviewPriority.UNDETERMINED


def test_module_has_no_model_publication_analysis_or_public_surface_imports():
    source = (ROOT / "app/investigation_triage_36_1.py").read_text()
    tree = ast.parse(source)
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    prohibited = ("google", "openai", "ollama", "app.api", "app.analyzer",
                  "app.checkpoint", "app.live", "app.publication", "requests")
    assert not any(name.startswith(prohibited) for name in imports)


def test_checklist_citations_are_verified_subset_and_category_specific():
    item = dto(relation_codes=("failed_to_successful_login",))
    result = build_investigation_assistance(item)
    approved = set(item.verified_citation_ids)
    cited = set(result.all_citation_ids())
    assert cited
    assert cited <= approved
    assert "relation-gone:not-resolved" not in cited
    assert any(value.startswith("failed-success:") for value in cited)
    assert all(step.citation_ids for step in result.investigation_steps)
    assert all(reason.citation_ids for reason in result.priority_reasons)
    assert result.explanation.citation_ids


def test_invalid_verified_citations_fail_closed_and_fixed_unavailable_has_no_claim():
    with pytest.raises(TriageError) as error:
        dto(verified_citation_ids=("forged:section",))
    assert error.value.code == "CITATION_INVALID"
    item = dto()
    unavailable = fixed_result(item, "unavailable")
    assert unavailable.status == "unavailable"
    assert unavailable.review_priority is ReviewPriority.UNDETERMINED
    assert unavailable.investigation_steps == ()
    assert unavailable.explanation.text == ""
    assert unavailable.all_citation_ids() == ()


def test_output_validator_rejects_partial_unknown_duplicate_and_private_content():
    item = dto()
    valid = build_investigation_assistance(item).to_json()
    parsed = json.loads(valid)
    assert validate_assistance_json(valid, item).to_json() == valid

    cases = [
        json.dumps({**parsed, "extra": "PRIVATE_CANARY"}),
        json.dumps({key: value for key, value in parsed.items() if key != "status"}),
        valid.replace('"schema_version":1', '"schema_version":true'),
        valid.replace('"status":"available"', '"status":"not-real"'),
        valid.replace('"status":"available"', '"status":"available","status":"available"'),
        valid.replace('"status":"available"', '"status":"available","extra":NaN'),
    ]
    for raw in cases:
        with pytest.raises(TriageError):
            validate_assistance_json(raw, item)

    for bad_text in (
        "<script>run</script>", "[visit](https://invalid.example)", "https://invalid.example",
        "run shell command", "account=PRIVATE", "192.0.2.83", "2001:db8::83",
        "host-canary.invalid", "/synthetic/a", "safe\u202eunsafe", "safe\u0001text",
        "x" * 513,
    ):
        mutate = json.loads(valid)
        mutate["explanation"]["text"] = bad_text
        with pytest.raises(TriageError) as error:
            validate_assistance_json(json.dumps(mutate, ensure_ascii=False), item)
        assert error.value.code == "OUTPUT_INVALID"
        assert bad_text[:32] not in str(error.value)


def test_output_validator_requires_citations_for_every_claim_and_discards_all():
    item = dto()
    value = json.loads(build_investigation_assistance(item).to_json())
    value["priority_reasons"][0]["citation_ids"] = []
    with pytest.raises(TriageError) as error:
        validate_assistance_json(json.dumps(value), item)
    assert error.value.code == "OUTPUT_INVALID"

    value = json.loads(build_investigation_assistance(item).to_json())
    value["explanation"]["citation_ids"] = ["not-input:forged"]
    with pytest.raises(TriageError):
        validate_assistance_json(json.dumps(value), item)


def test_non_available_status_is_fixed_and_never_partial_success():
    item = dto()
    for status in ("refused", "unavailable"):
        result = fixed_result(item, status)
        loaded = validate_assistance_json(result.to_json(), item)
        assert loaded.status == status
        assert loaded.priority_reasons == ()
        assert loaded.investigation_steps == ()
        assert loaded.explanation.text == ""


def test_safe_json_parser_rejects_duplicate_keys_and_byte_overflow():
    item = dto()
    raw = json.dumps(item.to_mapping(), separators=(",", ":"))
    with pytest.raises(TriageError) as duplicate:
        SafeInvestigationDTO.from_json(raw[:-1] + ',"schema_version":1}')
    assert duplicate.value.code == "DTO_INVALID"
    with pytest.raises(TriageError) as oversized:
        SafeInvestigationDTO.from_json(b" " * 4097)
    assert oversized.value.code == "DTO_INVALID"
    with pytest.raises(TriageError) as invalid_utf8:
        SafeInvestigationDTO.from_json(b"\xff")
    assert invalid_utf8.value.code == "DTO_INVALID"
    with pytest.raises(TriageError):
        SafeInvestigationDTO.from_json(b'{"schema_version":NaN}')


def test_admission_is_bounded_and_repeat_close_is_safe():
    guard = TriageAdmission()
    assert guard.try_enter()
    assert not guard.try_enter()
    guard.leave()
    assert guard.try_enter()
    guard.close()
    guard.close()
    guard.leave()
    assert not guard.try_enter()
    assert "PRIVATE" not in repr(guard)


def test_concurrent_admission_has_one_winner_and_errors_do_not_log_canaries(caplog):
    guard = TriageAdmission()
    assert guard.try_enter()
    answers = []
    contender = threading.Thread(target=lambda: answers.append(guard.try_enter()))
    with caplog.at_level(logging.DEBUG):
        contender.start()
        contender.join(timeout=1)
        assert not contender.is_alive()
        guard.leave()
        guard.close()
        guard.close()
        with pytest.raises(TriageError) as error:
            dto(observation_categories=("account=PRIVATE_SYNTHETIC_CANARY",))
    assert answers == [False]
    for output in (str(error.value), repr(error.value), caplog.text):
        assert "PRIVATE_SYNTHETIC_CANARY" not in output


def test_internal_exception_canary_becomes_fixed_unavailable(monkeypatch):
    import app.investigation_triage_36_1 as triage

    item = dto()
    monkeypatch.setattr(
        triage, "load_corpus",
        lambda: (_ for _ in ()).throw(RuntimeError("PRIVATE_INTERNAL_EXCEPTION_CANARY")),
    )
    result = build_investigation_assistance(item)
    assert result.status == "unavailable"
    for value in (str(result), repr(result), result.to_json()):
        assert "PRIVATE_INTERNAL_EXCEPTION_CANARY" not in value


def test_output_validator_rejects_priority_mismatch_and_free_claim_even_with_citation():
    item = dto()
    value = json.loads(build_investigation_assistance(item).to_json())
    value["review_priority"] = "review_now"
    with pytest.raises(TriageError):
        validate_assistance_json(json.dumps(value), item)
    value = json.loads(build_investigation_assistance(item).to_json())
    value["explanation"]["text"] = "이 사례는 공격에 성공했습니다."
    with pytest.raises(TriageError):
        validate_assistance_json(json.dumps(value, ensure_ascii=False), item)


def test_input_and_output_byte_caps_are_checked_before_json_parse():
    item = dto()
    encoded = item.to_mapping()
    encoded["verified_citation_ids"] = list(item.verified_citation_ids)
    assert len(json.dumps(encoded, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= 4096
    output = build_investigation_assistance(item).to_json()
    with pytest.raises(TriageError) as error:
        validate_assistance_json(output + (" " * (8193 - len(output.encode("utf-8")))), item)
    assert error.value.code == "OUTPUT_INVALID"


def test_dto_rejects_duplicate_verified_citation_without_reflecting_values():
    item = dto()
    values = item.to_mapping()
    citation = values["verified_citation_ids"][0]
    values["verified_citation_ids"] = [citation, citation]
    with pytest.raises(TriageError) as error:
        SafeInvestigationDTO.from_mapping(values)
    assert error.value.code == "DTO_INVALID"
    assert citation not in str(error.value)
    assert citation not in repr(error.value)


@given(
    risk=st.sampled_from(("LOW", "MEDIUM", "HIGH", "UNKNOWN")),
    count=st.sampled_from(("0", "1", "2_5", "6_20", "21_plus")),
    window=st.sampled_from(("under_5m", "5_60m", "over_60m", "unknown")),
)
def test_property_priority_does_not_depend_on_risk_or_count_buckets(risk, count, window):
    item = dto(risk_band=risk, event_count_bucket=count, time_window_bucket=window)
    assert build_investigation_assistance(item).review_priority is ReviewPriority.REVIEW_SOON


def test_evaluation_fixture_contains_at_least_44_named_synthetic_cases():
    assert FIXTURES["schema_version"] == 1
    assert len(FIXTURES["cases"]) >= 44
    assert len({row["id"] for row in FIXTURES["cases"]}) == len(FIXTURES["cases"])
    assert {row["kind"] for row in FIXTURES["cases"]} >= {
        "brute_force", "password_spray", "failed_success_relation", "path_traversal",
        "suspicious_process", "incomplete", "conflicting", "benign", "stale",
        "high_risk_incomplete", "low_risk_repeated", "unsupported", "injection",
        "privacy_account", "privacy_ipv4", "privacy_ipv6", "privacy_hostname",
        "privacy_path", "malformed_dto", "unknown_field", "missing_field",
        "duplicate_key", "invalid_citation", "category_mismatch", "over_citation",
        "citation_free", "html", "markdown_link", "url", "command", "severity_inflation",
        "severity_minimization", "unicode_control", "non_finite", "max_input",
        "input_overflow", "max_output", "output_overflow", "excessive_list",
        "duplicate_citation", "timeout", "corpus_unavailable", "retrieval_conflict",
        "resource_boundary",
    }


def test_fixture_evaluation_contract_records_security_counts_not_false_success():
    from tests.evaluate_investigation_triage_36_1 import evaluate_fixtures

    report = evaluate_fixtures()
    assert report.fixture_count >= 44
    assert report.schema_validated == 100
    assert report.invalid_citation == 0
    assert report.unsupported_claim == 0
    assert report.privacy_leak == 0
    assert report.tool_action_executed == 0
    assert report.injection_executed == 0
    assert report.fixed_unavailable == 2
    assert report.deterministic_refusal == 100
    assert report.analysis_mutation == 0
    assert report.citation_precision == 100
    assert report.citation_completeness > 0
    assert report.benign_false_refusal_rate == 0
    assert 0 <= report.benign_false_refusal_rate <= 100


def test_fixture_expected_values_do_not_emit_canaries_on_failure(capsys):
    from tests.evaluate_investigation_triage_36_1 import main

    assert main() == 0
    output = capsys.readouterr().out
    assert "fixtures=44" in output
    for forbidden in ("PRIVATE_ACCOUNT_CANARY", "192.0.2.83", "2001:db8::83", "PRIVATE_EXCEPTION_CANARY"):
        assert forbidden not in output
