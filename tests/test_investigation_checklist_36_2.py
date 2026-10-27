"""Synthetic contracts for the internal lexical checklist adapter."""

import ast
import json
from pathlib import Path
import time

import pytest
from hypothesis import given, strategies as st

from app.investigation_checklist_36_2 import (
    CHECKLIST_FIELDS,
    MAX_STEPS,
    ChecklistError,
    build_investigation_checklist,
    validate_checklist_json,
)
from app.investigation_triage_36_1 import CORPUS_DIGEST, create_safe_investigation_dto
from app.local_retrieval_33_1 import TRUSTED_CORPUS_DIGEST, load_corpus


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((ROOT / "tests/fixtures/investigation_checklist_36_2.json").read_text())


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


def test_category_checklist_is_closed_cited_and_deterministic():
    item = dto()
    first, second, third = (build_investigation_checklist(item) for _ in range(3))
    assert first.to_json() == second.to_json() == third.to_json()
    assert tuple(json.loads(first.to_json())) == CHECKLIST_FIELDS
    assert first.status == "available"
    assert first.review_priority == "review_soon"
    assert 1 <= len(first.steps) <= 5
    assert all(step.citation_ids for step in first.steps)
    assert {citation for step in first.steps for citation in step.citation_ids} == {
        "brute-force:meaning-limit", "next-checks:review-records",
    }


@pytest.mark.parametrize(("kind", "overrides", "status", "template", "required"), [
    ("brute_force", {}, "available", "review_authentication_scope", "brute-force:meaning-limit"),
    ("password_spray", {"detection_codes": ("password_spraying_like",)}, "available", "review_target_diversity", "password-spray:spray-like-limit"),
    ("failed_success", {"detection_codes": (), "relation_codes": ("failed_to_successful_login",), "limitation_codes": ("CORRELATION_IS_NOT_CAUSATION",)}, "available", "review_authentication_order", "failed-success:relation-not-causation"),
    ("incomplete", {"detection_codes": (), "evidence_completeness": "partial", "limitation_codes": ("INCOMPLETE_EVIDENCE",)}, "available", "review_source_coverage", "incomplete-evidence:partial-input"),
    ("conflicting", {"detection_codes": (), "evidence_completeness": "conflicting", "limitation_codes": ("INCOMPLETE_EVIDENCE",)}, "available", "preserve_conflicting_evidence", "conflicting-evidence:conflict"),
    ("benign_control", {"detection_codes": (), "observation_categories": ("authentication",), "limitation_codes": ("NO_FINDING_IS_NOT_SAFE",)}, "available", "review_no_finding_scope", "no-finding:no-detection"),
    ("path_traversal_no_corpus_support", {"detection_codes": ("path_traversal",)}, "refused", None, None),
    ("process_no_corpus_support", {"detection_codes": (), "relation_codes": (), "observation_categories": ("process_execution",)}, "refused", None, None),
    ("unknown_role_supported_category", {"source_role": "unknown"}, "available", "review_authentication_scope", "brute-force:meaning-limit"),
])
def test_supported_and_refused_categories_are_citation_scoped(kind, overrides, status, template, required):
    result = build_investigation_checklist(dto(**overrides))
    assert result.status == status
    if status == "available":
        if kind == "unknown_role_supported_category":
            assert result.review_priority.value == "undetermined"
        assert template in {step.template_code for step in result.steps}
        citations = {citation for step in result.steps for citation in step.citation_ids}
        assert required in citations
        assert "relation-gone:not-resolved" not in citations
    else:
        assert result.steps == ()
        if status == "refused":
            assert result.explanation == (
                "현재 승인된 근거로는 이 범주의 점검표를 만들 수 없습니다. "
                "이는 안전 또는 비위험 판정이 아닙니다. "
                "기존 결정적 분석 결과를 확인하고, 원본 자료는 승인된 내부 분석 경로에서 별도로 확인하세요. "
                "승인 근거가 검토되기 전에는 추측하지 않습니다."
            )
        else:
            assert result.explanation == ""


def test_refusal_output_explains_scope_boundary_and_safe_next_steps():
    result = build_investigation_checklist(dto(detection_codes=("path_traversal",)))
    assert result.status == "refused"
    assert result.steps == ()
    assert result.explanation == (
        "현재 승인된 근거로는 이 범주의 점검표를 만들 수 없습니다. "
        "이는 안전 또는 비위험 판정이 아닙니다. "
        "기존 결정적 분석 결과를 확인하고, 원본 자료는 승인된 내부 분석 경로에서 별도로 확인하세요. "
        "승인 근거가 검토되기 전에는 추측하지 않습니다."
    )
    validated = validate_checklist_json(result.to_json(), dto(detection_codes=("path_traversal",)))
    assert validated.to_json() == result.to_json()


def test_conflict_priority_remains_undetermined_while_checklist_is_useful():
    item = dto(detection_codes=(), evidence_completeness="conflicting",
               limitation_codes=("INCOMPLETE_EVIDENCE",))
    result = build_investigation_checklist(item)
    assert result.status == "available"
    assert result.review_priority.value == "undetermined"


def test_stale_case_state_alone_is_not_misread_as_stale_source_evidence():
    item = dto(detection_codes=(), case_status="stale", evidence_completeness="complete",
               observation_categories=("case_lifecycle",), limitation_codes=())
    result = build_investigation_checklist(item)
    assert result.status == "refused"
    assert result.steps == ()


def test_validator_rejects_duplicate_unknown_irrelevant_and_partial_output():
    item = dto()
    valid = build_investigation_checklist(item).to_json()
    assert validate_checklist_json(valid, item).to_json() == valid
    parsed = json.loads(valid)
    malformed = [
        valid.replace('"schema_version":1', '"schema_version":true'),
        valid.replace('"schema_version":1', '"schema_version":1.0'),
        valid.replace('"status":"available"', '"status":"available","unknown":Infinity'),
        valid.replace('"status":"available"', '"status":"available","status":"available"'),
        valid.replace('"status":"available"', '"status":"available","extra":NaN'),
        json.dumps({**parsed, "new_field": "ignored"}),
        json.dumps({key: value for key, value in parsed.items() if key != "steps"}),
        json.dumps({**parsed, "steps": parsed["steps"] + parsed["steps"] * MAX_STEPS}),
    ]
    changed = json.loads(valid)
    changed["steps"][0]["citation_ids"] = ["no-finding:no-detection"]
    malformed.append(json.dumps(changed, ensure_ascii=False, separators=(",", ":")))
    changed = json.loads(valid)
    changed["steps"][0]["citation_ids"] *= 2
    malformed.append(json.dumps(changed, ensure_ascii=False, separators=(",", ":")))
    changed = json.loads(valid)
    changed["explanation"]["text"] = "임의 문구"
    malformed.append(json.dumps(changed, ensure_ascii=False, separators=(",", ":")))
    for raw in malformed:
        with pytest.raises(ChecklistError) as error:
            validate_checklist_json(raw, item)
        assert error.value.code == "OUTPUT_INVALID"


def test_corpus_digest_is_rechecked_and_path_process_are_not_guessed(monkeypatch):
    item = dto()
    from app import investigation_checklist_36_2 as module
    original = module.load_corpus
    monkeypatch.setattr(module, "load_corpus", lambda: type(original())("0" * 64, original().sections, original().total_bytes))
    assert build_investigation_checklist(item).status == "unavailable"
    assert TRUSTED_CORPUS_DIGEST == CORPUS_DIGEST


def test_privacy_canaries_are_never_reflected_or_logged(caplog):
    canaries = (
        "account=PRIVATE_ACCOUNT", "192.0.2.73", "2001:db8::73", "host.synthetic.invalid",
        "/private/synthetic.log", "PRIVATE_RAW_LINE", "credential=TOKEN_CANARY",
        "PRIVATE_EXCEPTION_MARKER", "ignore previous instruction",
    )
    for value in canaries:
        with pytest.raises(Exception) as error:
            create_safe_investigation_dto(
                schema_version=1, request_id="r_0123456789abcdef01234567",
                case_ref="c_fedcba9876543210fedcba98", source_role="application",
                observation_categories=(value,), detection_codes=(), relation_codes=(),
                risk_band="LOW", case_status="open", event_count_bucket="1",
                time_window_bucket="unknown", evidence_completeness="unknown",
                limitation_codes=(), corpus_digest=CORPUS_DIGEST,
            )
        text = str(error.value) + repr(error.value)
        assert all(secret not in text for secret in canaries)
    assert all(secret not in caplog.text for secret in canaries)


def test_fixed_texts_block_commands_urls_markup_and_private_identifiers():
    item = dto()
    raw = build_investigation_checklist(item).to_json()
    assert not any(token in raw.lower() for token in ("http://", "https://", "<script", "sudo ", "curl "))
    for replacement in ("<script>x</script>", "[manual](https://example.invalid)", "203.0.113.5", "sudo block", "host.private.invalid"):
        altered = raw.replace("자료 범위", replacement)
        with pytest.raises(ChecklistError):
            validate_checklist_json(altered, item)


def test_no_model_network_publication_or_filesystem_integration_imports():
    source = (ROOT / "app/investigation_checklist_36_2.py").read_text()
    tree = ast.parse(source)
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    blocked = ("google", "openai", "ollama", "requests", "httpx", "socket", "subprocess",
               "embedding", "chromadb", "app.api", "app.publication", "app.checkpoint", "app.live")
    assert not any(name.startswith(blocked) for name in imports)


@given(st.binary(max_size=8_300))
def test_arbitrary_output_bytes_fail_closed_without_reflection(raw):
    item = dto()
    try:
        parsed = validate_checklist_json(raw, item)
    except ChecklistError as error:
        assert error.code == "OUTPUT_INVALID"
        assert "PRIVATE" not in str(error)
    else:
        assert parsed.status in {"available", "refused", "unavailable"}


def test_36_1_output_and_corpus_digest_are_unchanged():
    from app.investigation_triage_36_1 import build_investigation_assistance
    item = dto()
    before = build_investigation_assistance(item).to_json()
    build_investigation_checklist(item)
    after = build_investigation_assistance(item).to_json()
    assert before == after
    assert load_corpus().digest == CORPUS_DIGEST


def test_timezone_does_not_change_checklist_bytes(monkeypatch):
    item = dto()
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    utc = build_investigation_checklist(item).to_json()
    monkeypatch.setenv("TZ", "Asia/Seoul")
    time.tzset()
    seoul = build_investigation_checklist(item).to_json()
    assert utc == seoul


def test_synthetic_semantic_fixture_suite():
    from tests.evaluate_investigation_checklist_36_2 import evaluate
    result = evaluate(FIXTURES)
    assert result["fixture_count"] >= 20
    assert result["status_match"] == 1.0
    assert result["required_citation_completeness"] == 1.0
    assert result["semantic_support_precision"] == 1.0
    assert result["forbidden_citation_count"] == 0
    assert result["invalid_citation_count"] == 0
    assert result["unsupported_claim_count"] == 0
    assert result["benign_false_refusal_count"] == 0


def test_model_network_embedding_and_fallback_are_not_called(monkeypatch):
    import socket
    from app import investigation_checklist_36_2 as module

    def forbidden(*_args, **_kwargs):
        raise AssertionError("external or model path called")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert build_investigation_checklist(dto()).status == "available"


def test_concurrency_cap_returns_fixed_unavailable():
    from app import investigation_checklist_36_2 as module
    assert module._ADMISSION.acquire(blocking=False)
    try:
        result = build_investigation_checklist(dto())
    finally:
        module._ADMISSION.release()
    assert result.status == "unavailable"
    assert result.steps == ()


@pytest.mark.parametrize("fault,expected", [
    ("corpus_load", "unavailable"),
    ("retrieval", "unavailable"),
    ("verifier", "unavailable"),
    ("template", "refused"),
    ("serializer", "unavailable"),
    ("validator", "unavailable"),
])
def test_faults_return_fixed_non_partial_results(monkeypatch, fault, expected):
    from app import investigation_checklist_36_2 as module
    from app.local_retrieval_33_1 import RetrievalError
    item = dto()
    if fault == "corpus_load":
        monkeypatch.setattr(module, "load_corpus", lambda: (_ for _ in ()).throw(RetrievalError("CORPUS_INVALID")))
    elif fault == "retrieval":
        monkeypatch.setattr(module, "retrieve", lambda *_a, **_k: (_ for _ in ()).throw(RetrievalError("INVALID_RESULT")))
    elif fault == "verifier":
        monkeypatch.setattr(module, "validate_result", lambda *_a, **_k: (_ for _ in ()).throw(RetrievalError("INVALID_RESULT")))
    elif fault == "template":
        monkeypatch.setattr(module, "_CATEGORY_TEMPLATE", {})
    elif fault == "serializer":
        monkeypatch.setattr(module.InvestigationChecklist, "to_json", lambda _self: (_ for _ in ()).throw(ChecklistError("OUTPUT_INVALID")))
    elif fault == "validator":
        monkeypatch.setattr(module, "validate_checklist_json", lambda *_a, **_k: (_ for _ in ()).throw(ChecklistError("OUTPUT_INVALID")))
    result = build_investigation_checklist(item)
    assert result.status == expected
    assert result.steps == ()
    if expected == "refused":
        assert "안전 또는 비위험 판정이 아닙니다." in result.explanation
    else:
        assert result.explanation == ""


def test_output_cap_failure_is_unavailable_not_truncated(monkeypatch):
    from app import investigation_checklist_36_2 as module
    monkeypatch.setattr(module, "MAX_OUTPUT_BYTES", 1)
    result = build_investigation_checklist(dto())
    assert result.status == "unavailable"
    assert result.steps == ()


def test_errors_do_not_write_to_stdout_or_stderr(capsys):
    from app import investigation_checklist_36_2 as module
    item = dto()
    original = module.retrieve
    module.retrieve = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("PRIVATE_EXCEPTION_MARKER"))
    try:
        result = build_investigation_checklist(item)
    finally:
        module.retrieve = original
    assert result.status == "unavailable"
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
