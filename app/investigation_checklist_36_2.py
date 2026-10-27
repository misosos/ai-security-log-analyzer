"""Internal fixed-template investigation checklists backed by approved lexical citations."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import threading

from app.investigation_triage_36_1 import (
    ReviewPriority,
    SafeInvestigationDTO,
    TriageError,
    _safe_evidence,
    build_investigation_assistance,
)
from app.local_retrieval_33_1 import (
    QueryCategory, RetrievalError, ResultStatus, build_index, load_corpus, retrieve, validate_result,
)


MAX_OUTPUT_BYTES = 8_192
MAX_STEPS = 5
MAX_TEXT_BYTES = 512
MAX_CONCURRENT_REQUESTS = 1
_REFUSAL_EXPLANATION = (
    "현재 승인된 근거로는 이 범주의 점검표를 만들 수 없습니다. "
    "이는 안전 또는 위험하지 않다는 판정이 아닙니다. "
    "기존 결정적 분석 결과를 확인하고, 원본 자료는 승인된 내부 분석 경로에서 별도로 확인하세요. "
    "승인 근거가 검토되기 전에는 추측하지 않습니다."
)
CHECKLIST_FIELDS = (
    "schema_version", "request_id", "case_ref", "review_priority", "steps",
    "explanation", "uncertainty", "limitation_codes", "generated_by", "status",
)
STEP_FIELDS = ("template_code", "text", "purpose_code", "citation_ids", "limitation_codes")
_ADMISSION = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

_CITATION_BY_CATEGORY = {
    "brute_force": "brute-force:meaning-limit",
    "password_spray": "password-spray:spray-like-limit",
    "failed_success_relation": "failed-success:relation-not-causation",
    "incomplete": "incomplete-evidence:partial-input",
    "conflicting": "conflicting-evidence:conflict",
    "benign": "no-finding:no-detection",
}
_CATEGORY_TEMPLATE = {
    "brute_force": (
        "review_authentication_scope", "authentication_scope",
        "반복 인증 실패 관찰의 자료 범위와 주변 운영 맥락을 확인하세요.",
        "반복 실패 관찰은 침해나 공격 성공을 확정하지 않습니다.",
        ("DETECTION_IS_NOT_COMPROMISE",),
    ),
    "password_spray": (
        "review_target_diversity", "authentication_scope",
        "여러 계정에 관련된 실패 관찰의 범위와 자료 coverage를 확인하세요.",
        "이 패턴은 같은 비밀번호 사용, 단일 행위자 또는 침해를 입증하지 않습니다.",
        ("DETECTION_IS_NOT_COMPROMISE",),
    ),
    "failed_success_relation": (
        "review_authentication_order", "relation_scope",
        "실패와 성공으로 기록된 각 관찰 및 시간 순서를 따로 확인하세요.",
        "실패 뒤 성공의 시간 관계는 인과관계나 무단 성공을 입증하지 않습니다.",
        ("CORRELATION_IS_NOT_CAUSATION",),
    ),
    "incomplete": (
        "review_source_coverage", "evidence_completeness",
        "누락되었거나 오래된 자료 범위와 시간 경계를 확인하세요.",
        "불완전한 자료는 현재 분석이 확정할 수 있는 범위를 제한합니다.",
        ("INCOMPLETE_EVIDENCE",),
    ),
    "conflicting": (
        "preserve_conflicting_evidence", "evidence_conflict",
        "서로 다른 근거가 각각 어떤 범위의 관찰을 뒷받침하는지 확인하세요.",
        "서로 다른 근거는 각 범위를 보존해 검토해야 하며 하나의 원인으로 단정하지 않습니다.",
        ("INCOMPLETE_EVIDENCE",),
    ),
    "benign": (
        "review_no_finding_scope", "analysis_limit",
        "현재 입력에서 탐지되지 않은 범위와 수집 coverage를 확인하세요.",
        "현재 탐지 결과가 없다는 사실은 안전이나 사건 부재를 증명하지 않습니다.",
        ("NO_FINDING_IS_NOT_SAFE",),
    ),
}
_GENERIC_TEMPLATE = (
    "confirm_manual_coverage", "manual_coverage",
    "관련 자료와 시간 범위가 충분히 포함됐는지 수동으로 확인하세요.",
    ("INCOMPLETE_EVIDENCE",),
)
_ALLOWED_TEMPLATE_CODES = frozenset(
    {value[0] for value in _CATEGORY_TEMPLATE.values()} | {_GENERIC_TEMPLATE[0]}
)
_ALLOWED_PURPOSE_CODES = frozenset(
    {value[1] for value in _CATEGORY_TEMPLATE.values()} | {_GENERIC_TEMPLATE[1]}
)
_ALLOWED_LIMITATIONS = frozenset(
    code for value in _CATEGORY_TEMPLATE.values() for code in value[4]
) | frozenset(_GENERIC_TEMPLATE[3])
_RETRIEVAL_QUERY = {
    "brute_force": ("brute force meaning limit", QueryCategory.EXPLAIN_DETECTION,
                    "brute-force:meaning-limit", "authentication detection"),
    "password_spray": ("password spray meaning limit", QueryCategory.EXPLAIN_DETECTION,
                        "password-spray:spray-like-limit", "authentication detection"),
    "failed_success_relation": ("failed success relation causation", QueryCategory.EXPLAIN_RELATION,
                                "failed-success:relation-not-causation", "authentication relation"),
    "incomplete": ("incomplete evidence", QueryCategory.EXPLAIN_LIMITATION,
                   "incomplete-evidence:partial-input", "completeness"),
    "conflicting": ("conflicting evidence", QueryCategory.EXPLAIN_LIMITATION,
                    "conflicting-evidence:conflict", "evidence limits"),
    "benign": ("no detection safe", QueryCategory.EXPLAIN_LIMITATION,
               "no-finding:no-detection", "analysis limitation"),
}


class ChecklistError(Exception):
    """Fixed-message error that never reflects input or implementation details."""

    _MESSAGES = {
        "INPUT_INVALID": "Investigation checklist input is invalid.",
        "CORPUS_UNAVAILABLE": "Approved investigation guidance is unavailable.",
        "RETRIEVAL_REFUSED": "No directly relevant approved guidance is available.",
        "OUTPUT_INVALID": "Investigation checklist output is invalid.",
        "BUSY": "Investigation checklist is temporarily unavailable.",
    }

    def __init__(self, code: str):
        self.code = code if code in self._MESSAGES else "INPUT_INVALID"
        super().__init__(self._MESSAGES[self.code])


@dataclass(frozen=True, slots=True, repr=False)
class ChecklistStep:
    template_code: str
    text: str
    purpose_code: str
    citation_ids: tuple[str, ...] = field(repr=False)
    limitation_codes: tuple[str, ...]

    def __repr__(self) -> str:
        return "ChecklistStep(<redacted>)"

    def to_mapping(self) -> dict:
        return {
            "template_code": self.template_code,
            "text": self.text,
            "purpose_code": self.purpose_code,
            "citation_ids": list(self.citation_ids),
            "limitation_codes": list(self.limitation_codes),
        }


@dataclass(frozen=True, slots=True, repr=False)
class InvestigationChecklist:
    schema_version: int
    request_id: str = field(repr=False)
    case_ref: str = field(repr=False)
    review_priority: ReviewPriority
    steps: tuple[ChecklistStep, ...]
    explanation: str
    explanation_citation_ids: tuple[str, ...] = field(repr=False)
    uncertainty: tuple[str, ...]
    limitation_codes: tuple[str, ...]
    generated_by: str
    status: str

    def __repr__(self) -> str:
        return "InvestigationChecklist(<redacted>)"

    def to_mapping(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "case_ref": self.case_ref,
            "review_priority": self.review_priority.value,
            "steps": [step.to_mapping() for step in self.steps],
            "explanation": {
                "text": self.explanation,
                "citation_ids": list(self.explanation_citation_ids),
            },
            "uncertainty": list(self.uncertainty),
            "limitation_codes": list(self.limitation_codes),
            "generated_by": self.generated_by,
            "status": self.status,
        }

    def to_json(self) -> str:
        try:
            raw = json.dumps(self.to_mapping(), ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")
            if len(raw) > MAX_OUTPUT_BYTES:
                raise ChecklistError("OUTPUT_INVALID") from None
            return raw.decode("utf-8")
        except ChecklistError:
            raise
        except Exception:
            raise ChecklistError("OUTPUT_INVALID") from None


def _fixed_result(item: SafeInvestigationDTO, status: str) -> InvestigationChecklist:
    return InvestigationChecklist(
        schema_version=1,
        request_id=item.request_id,
        case_ref=item.case_ref,
        review_priority=ReviewPriority.UNDETERMINED,
        steps=(),
        explanation=_REFUSAL_EXPLANATION if status == "refused" else "",
        explanation_citation_ids=(),
        uncertainty=("insufficient_context",),
        limitation_codes=tuple(item.limitation_codes),
        generated_by="lexical_template",
        status=status,
    )


def _categories(item: SafeInvestigationDTO) -> tuple[str, ...]:
    detections = set(item.detection_codes)
    relations = set(item.relation_codes)
    observation = set(item.observation_categories)
    result: list[str] = []
    if "unknown" in observation:
        return ("unsupported",)
    if item.evidence_completeness == "conflicting":
        result.append("conflicting")
    elif item.evidence_completeness in {"partial", "unknown"}:
        result.append("incomplete")
    elif item.case_status == "stale":
        result.append("stale_case")
    if "failed_to_successful_login" in relations:
        result.append("failed_success_relation")
    if "brute_force" in detections:
        result.append("brute_force")
    if "password_spraying_like" in detections:
        result.append("password_spray")
    if "path_traversal" in detections:
        result.append("path_traversal")
    if "process_execution" in observation:
        result.append("suspicious_process_execution")
    if not result and not detections and not relations and observation:
        result.append("benign")
    return tuple(result)


def _unavailable(item: SafeInvestigationDTO) -> InvestigationChecklist:
    return _fixed_result(item, "unavailable")


def _verified_ids(item: SafeInvestigationDTO, categories: tuple[str, ...], corpus) -> set[str]:
    """Run the frozen Phase 33.1 lexical contract and return only verified topic hits."""
    evidence = _safe_evidence(item.to_mapping())
    index = build_index(corpus)
    sections = {
        f"{section.document_id}:{section.section_id}": section
        for section in corpus.sections
        if section.approved and section.review_status == "approved"
    }
    requests = [("next checks application ssh", QueryCategory.NEXT_CHECKS,
                 "next-checks:review-records", "operator follow-up")]
    requests.extend(_RETRIEVAL_QUERY[category] for category in categories)
    verified: set[str] = set()
    for query, query_category, expected_id, approved_topic in requests:
        result = retrieve(query, query_category, evidence, corpus=corpus, index=index, top_k=5)
        result = validate_result(result, corpus, requested_top_k=5)
        if result.status is not ResultStatus.OK:
            raise ChecklistError("RETRIEVAL_REFUSED") from None
        found = {
            f"{citation.document_id}:{citation.section_id}"
            for citation in result.citations
            if f"{citation.document_id}:{citation.section_id}" in sections
            and sections[f"{citation.document_id}:{citation.section_id}"].approved_topic == approved_topic
        }
        if expected_id not in found:
            raise ChecklistError("RETRIEVAL_REFUSED") from None
        verified.add(expected_id)
    return verified


def build_investigation_checklist(item: SafeInvestigationDTO) -> InvestigationChecklist:
    """Build fixed Korean steps only when each claim has a directly mapped citation."""
    if type(item) is not SafeInvestigationDTO:
        raise ChecklistError("INPUT_INVALID") from None
    if not _ADMISSION.acquire(blocking=False):
        return _fixed_result(item, "unavailable")
    try:
        try:
            corpus = load_corpus()
            if corpus.digest != item.corpus_digest:
                return _unavailable(item)
            # Reuses Phase 36.1 priority and its Phase 33.1 retrieval/verifier path.
            assistance = build_investigation_assistance(item)
            if assistance.status != "available":
                return _fixed_result(item, assistance.status)
            categories = _categories(item)
            if (item.source_role == "unknown" or not categories
                    or any(category not in _CATEGORY_TEMPLATE for category in categories)):
                return _fixed_result(item, "refused")
            verified_now = _verified_ids(item, categories, corpus)
            sections = {
                f"{section.document_id}:{section.section_id}": section
                for section in corpus.sections if section.approved and section.review_status == "approved"
            }
            steps: list[ChecklistStep] = []
            used: set[str] = set()
            for category in categories:
                template = _CATEGORY_TEMPLATE[category]
                citation_id = _CITATION_BY_CATEGORY[category]
                section = sections.get(citation_id)
                if (section is None or section.approved_topic not in {
                    "authentication detection", "authentication relation", "completeness",
                    "evidence limits", "analysis limitation",
                } or citation_id not in verified_now):
                    return _fixed_result(item, "refused")
                if citation_id in used:
                    continue
                steps.append(ChecklistStep(
                    template_code=template[0], text=template[2], purpose_code=template[1],
                    citation_ids=(citation_id,), limitation_codes=template[4],
                ))
                used.add(citation_id)
            generic_id = "next-checks:review-records"
            if generic_id not in verified_now or generic_id not in sections:
                return _fixed_result(item, "refused")
            if generic_id not in used:
                steps.append(ChecklistStep(
                    template_code=_GENERIC_TEMPLATE[0], text=_GENERIC_TEMPLATE[2],
                    purpose_code=_GENERIC_TEMPLATE[1], citation_ids=(generic_id,),
                    limitation_codes=_GENERIC_TEMPLATE[3],
                ))
                used.add(generic_id)
            if len(steps) > MAX_STEPS:
                return _fixed_result(item, "refused")
            explanation_category = next(
                (category for category in categories if category in _CATEGORY_TEMPLATE), None,
            )
            if explanation_category is None:
                return _fixed_result(item, "refused")
            explanation = _CATEGORY_TEMPLATE[explanation_category][3]
            explanation_id = _CITATION_BY_CATEGORY[explanation_category]
            result = InvestigationChecklist(
                schema_version=1,
                request_id=item.request_id,
                case_ref=item.case_ref,
                review_priority=assistance.review_priority,
                steps=tuple(steps),
                explanation=explanation,
                explanation_citation_ids=(explanation_id,),
                uncertainty=tuple(assistance.uncertainty),
                limitation_codes=tuple(item.limitation_codes),
                generated_by="lexical_template",
                status="available",
            )
            return validate_checklist_json(result.to_json(), item)
        except ChecklistError as error:
            if error.code == "RETRIEVAL_REFUSED":
                return _fixed_result(item, "refused")
            return _unavailable(item)
        except (TriageError, RetrievalError):
            return _unavailable(item)
        except Exception:
            return _unavailable(item)
    finally:
        _ADMISSION.release()


def _reject_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError


def validate_checklist_json(raw: str | bytes, item: SafeInvestigationDTO) -> InvestigationChecklist:
    """Validate the complete closed result; no partial repair or truncation is performed."""
    try:
        if type(item) is not SafeInvestigationDTO or type(raw) not in {str, bytes}:
            raise ChecklistError("OUTPUT_INVALID")
        if type(raw) is bytes:
            if len(raw) > MAX_OUTPUT_BYTES:
                raise ChecklistError("OUTPUT_INVALID")
            text = raw.decode("utf-8", errors="strict")
        else:
            if len(raw.encode("utf-8", errors="strict")) > MAX_OUTPUT_BYTES:
                raise ChecklistError("OUTPUT_INVALID")
            text = raw
        parsed = json.loads(text, object_pairs_hook=_reject_pairs, parse_constant=_reject_constant)
        if type(parsed) is not dict or tuple(parsed) != CHECKLIST_FIELDS:
            raise ChecklistError("OUTPUT_INVALID")
        if type(parsed["schema_version"]) is not int or parsed["schema_version"] != 1:
            raise ChecklistError("OUTPUT_INVALID")
        if parsed["request_id"] != item.request_id or parsed["case_ref"] != item.case_ref:
            raise ChecklistError("OUTPUT_INVALID")
        priority = ReviewPriority(parsed["review_priority"])
        status = parsed["status"]
        if type(status) is not str or status not in {"available", "refused", "unavailable"}:
            raise ChecklistError("OUTPUT_INVALID")
        if parsed["generated_by"] != "lexical_template":
            raise ChecklistError("OUTPUT_INVALID")
        steps_raw = parsed["steps"]
        if type(steps_raw) is not list or len(steps_raw) > MAX_STEPS:
            raise ChecklistError("OUTPUT_INVALID")
        active_corpus = load_corpus()
        if active_corpus.digest != item.corpus_digest:
            raise ChecklistError("OUTPUT_INVALID")
        categories = _categories(item)
        if (item.source_role == "unknown" or not categories
                or any(category not in _CATEGORY_TEMPLATE for category in categories)):
            verified = set()
        else:
            verified = _verified_ids(item, categories, active_corpus)
        known = {
            f"{section.document_id}:{section.section_id}": section
            for section in active_corpus.sections
            if section.approved and section.review_status == "approved"
        }
        seen_templates: set[str] = set()
        seen_citations: set[str] = set()
        steps: list[ChecklistStep] = []
        for step in steps_raw:
            if type(step) is not dict or tuple(step) != STEP_FIELDS:
                raise ChecklistError("OUTPUT_INVALID")
            code, text_value, purpose = step["template_code"], step["text"], step["purpose_code"]
            if (type(code) is not str or code not in _ALLOWED_TEMPLATE_CODES
                    or type(purpose) is not str or purpose not in _ALLOWED_PURPOSE_CODES
                    or code in seen_templates):
                raise ChecklistError("OUTPUT_INVALID")
            template_info = next(
                (value for value in (*_CATEGORY_TEMPLATE.values(), _GENERIC_TEMPLATE)
                 if value[0] == code), None,
            )
            expected_text = template_info[2]
            expected_limits = template_info[4] if code != _GENERIC_TEMPLATE[0] else _GENERIC_TEMPLATE[3]
            if type(text_value) is not str or text_value != expected_text or len(text_value.encode("utf-8")) > MAX_TEXT_BYTES:
                raise ChecklistError("OUTPUT_INVALID")
            citations = step["citation_ids"]
            if (type(citations) is not list or not citations or len(citations) > 2
                    or len(set(citations)) != len(citations)
                    or any(type(value) is not str or value not in verified or value not in known
                           for value in citations)):
                raise ChecklistError("OUTPUT_INVALID")
            # This is a structural gate; semantic support is separately labeled in the eval fixtures.
            expected_citation = (
                _CITATION_BY_CATEGORY[next(key for key, value in _CATEGORY_TEMPLATE.items()
                                           if value[0] == code)]
                if code != _GENERIC_TEMPLATE[0] else "next-checks:review-records"
            )
            if citations != [expected_citation] or purpose != template_info[1]:
                raise ChecklistError("OUTPUT_INVALID")
            limits = step["limitation_codes"]
            if (type(limits) is not list or tuple(limits) != tuple(expected_limits)
                    or any(type(value) is not str or value not in _ALLOWED_LIMITATIONS for value in limits)):
                raise ChecklistError("OUTPUT_INVALID")
            if seen_citations.intersection(citations):
                raise ChecklistError("OUTPUT_INVALID")
            seen_citations.update(citations)
            seen_templates.add(code)
            steps.append(ChecklistStep(code, text_value, purpose, tuple(citations), tuple(limits)))
        explanation = parsed["explanation"]
        if type(explanation) is not dict or tuple(explanation) != ("text", "citation_ids"):
            raise ChecklistError("OUTPUT_INVALID")
        explain_text, explain_ids = explanation["text"], explanation["citation_ids"]
        if status == "available":
            if not steps or type(explain_text) is not str or not explain_text:
                raise ChecklistError("OUTPUT_INVALID")
            if (item.source_role == "unknown" or not categories
                    or any(category not in _CATEGORY_TEMPLATE for category in categories)):
                raise ChecklistError("OUTPUT_INVALID")
            if len(explain_text.encode("utf-8")) > MAX_TEXT_BYTES:
                raise ChecklistError("OUTPUT_INVALID")
            if type(explain_ids) is not list or len(explain_ids) != 1 or explain_ids[0] not in verified:
                raise ChecklistError("OUTPUT_INVALID")
            explanation_category = next((key for key, value in _CATEGORY_TEMPLATE.items()
                                         if value[3] == explain_text), None)
            if (explanation_category is None
                    or explain_ids != [_CITATION_BY_CATEGORY[explanation_category]]
                    or explain_ids[0] not in known):
                raise ChecklistError("OUTPUT_INVALID")
            expected_templates = {_CATEGORY_TEMPLATE[category][0] for category in categories}
            expected_templates.add(_GENERIC_TEMPLATE[0])
            if seen_templates != expected_templates:
                raise ChecklistError("OUTPUT_INVALID")
        else:
            expected_explanation = _REFUSAL_EXPLANATION if status == "refused" else ""
            if (steps or explain_text != expected_explanation or explain_ids != []
                    or priority is not ReviewPriority.UNDETERMINED):
                raise ChecklistError("OUTPUT_INVALID")
        uncertainty = parsed["uncertainty"]
        limitations = parsed["limitation_codes"]
        if (type(uncertainty) is not list or len(uncertainty) > 4
                or len(set(uncertainty)) != len(uncertainty)
                or any(value not in {"evidence_conflict_or_unknown", "evidence_scope_incomplete", "insufficient_context"}
                       for value in uncertainty)
                or type(limitations) is not list or len(limitations) > 16
                or tuple(limitations) != tuple(item.limitation_codes)):
            raise ChecklistError("OUTPUT_INVALID")
        if status == "available":
            reference = build_investigation_assistance(item)
            if (reference.status != "available" or priority is not reference.review_priority
                    or tuple(uncertainty) != tuple(reference.uncertainty)):
                raise ChecklistError("OUTPUT_INVALID")
        result = InvestigationChecklist(
            1, item.request_id, item.case_ref, priority, tuple(steps), explain_text,
            tuple(explain_ids), tuple(uncertainty), tuple(limitations),
            "lexical_template", status,
        )
        canonical = json.dumps(result.to_mapping(), ensure_ascii=False, separators=(",", ":"),
                               allow_nan=False).encode("utf-8")
        if canonical != (raw if type(raw) is bytes else raw.encode("utf-8")):
            raise ChecklistError("OUTPUT_INVALID")
        return result
    except ChecklistError:
        raise
    except Exception:
        raise ChecklistError("OUTPUT_INVALID") from None
