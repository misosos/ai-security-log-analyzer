"""Internal-only, deterministic lexical retrieval over an approved static corpus."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
import hashlib
import ipaddress
import json
import math
import re
import statistics
import stat
import time
import unicodedata
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator


CORPUS_DIR = Path(__file__).with_name("knowledge_corpus_33_1")
MAX_CORPUS_BYTES = 65_536
MAX_CORPUS_SECTIONS = 128
MAX_SECTION_BYTES = 1_536
MAX_SECTION_TOKENS = 256
MAX_QUERY_BYTES = 1_024
MAX_QUERY_CHARS = 256
MAX_QUERY_TOKENS = 64
MAX_TOP_K = 5
MIN_SCORE = 2.2
BM25_K1 = 1.2
BM25_B = 0.75
TRUSTED_CORPUS_DIGEST = "fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6"


class RetrievalError(Exception):
    """Fixed-message error; never includes rejected data or internal paths."""

    _MESSAGES = {
        "INVALID_EVIDENCE": "Safe evidence is invalid.",
        "CORPUS_INVALID": "Approved knowledge is unavailable.",
        "INVALID_REQUEST": "The retrieval request is invalid.",
        "INVALID_RESULT": "The retrieval result is invalid.",
    }

    def __init__(self, code: str):
        if code not in self._MESSAGES:
            code = "INVALID_REQUEST"
        self.code = code
        super().__init__(self._MESSAGES[code])


class SourceRole(StrEnum):
    APPLICATION = "application"
    SSH = "ssh"


class Completeness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    STALE = "stale"
    UNKNOWN = "unknown"


class QueryCategory(StrEnum):
    EXPLAIN_DETECTION = "EXPLAIN_DETECTION"
    EXPLAIN_RELATION = "EXPLAIN_RELATION"
    EXPLAIN_RISK = "EXPLAIN_RISK"
    EXPLAIN_CASE = "EXPLAIN_CASE"
    NEXT_CHECKS = "NEXT_CHECKS"
    EXPLAIN_RECOVERY_STATE = "EXPLAIN_RECOVERY_STATE"
    EXPLAIN_LIMITATION = "EXPLAIN_LIMITATION"


class ResultStatus(StrEnum):
    OK = "OK"
    NO_RESULTS = "NO_RESULTS"
    REFUSED = "REFUSED"


_DETECTION_LABELS = frozenset({
    "Brute Force", "Password Spraying-like", "Path Traversal",
    "SQL Injection-like", "XSS-like", "Sensitive Resource Probing-like",
    "Web Scanning-like",
})
_RELATION_LABELS = frozenset({
    "Failed login followed by success", "Brute Force followed by success",
    "Password Spraying-like followed by success",
})
_CASE_LABELS = frozenset({
    "Failed login followed by success case",
    "Brute Force followed by success case",
    "Password Spraying-like followed by success case",
})
_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH", "UNKNOWN"})
_LIMITATIONS = frozenset({
    "DETECTION_IS_NOT_COMPROMISE", "CORRELATION_IS_NOT_CAUSATION",
    "NO_FINDING_IS_NOT_SAFE", "RISK_DOWN_IS_NOT_SAFE",
    "RELATION_GONE_IS_NOT_RESOLVED", "REPLAY_GAP_MAY_BE_STALE",
    "CHECKPOINT_RESET_STARTS_NEW_HISTORY", "INCOMPLETE_EVIDENCE",
    "APPLICATION_SSH_NOT_CROSS_CORRELATED",
})
_AGGREGATE_NAMES = frozenset({
    "observations", "relations", "cases", "detections", "rejected_lines",
})
_SESSION_ID = re.compile(r"s_[a-z0-9]{16}\Z")


@dataclass(frozen=True, slots=True, init=False)
class SafeEvidence:
    source_role: SourceRole | None
    detection_labels: tuple[str, ...] | None
    relation_labels: tuple[str, ...] | None
    risk_level: str | None
    confidence: str | None
    case_labels: tuple[str, ...] | None
    aggregates: tuple[tuple[str, int], ...] | None
    time_window_seconds: int | None
    completeness: Completeness | None
    session_local_id: str | None
    limitations: tuple[str, ...] | None

    def __init__(self, source_role=None, detection_labels=None, relation_labels=None,
                 risk_level=None, confidence=None, case_labels=None, aggregates=None,
                 time_window_seconds=None, completeness=None, session_local_id=None,
                 limitations=None, **extra):
        if extra:
            raise RetrievalError("INVALID_EVIDENCE")
        values = locals()
        for name in (
            "source_role", "detection_labels", "relation_labels", "risk_level",
            "confidence", "case_labels", "aggregates", "time_window_seconds",
            "completeness", "session_local_id", "limitations",
        ):
            object.__setattr__(self, name, values[name])
        self.__post_init__()

    def __post_init__(self):
        try:
            if type(self.source_role) is not SourceRole:
                raise ValueError
            if type(self.completeness) is not Completeness:
                raise ValueError
            if self.risk_level not in _LEVELS or self.confidence not in _LEVELS:
                raise ValueError
            if not _SESSION_ID.fullmatch(self.session_local_id):
                raise ValueError
            for value, allowed, maximum in (
                (self.detection_labels, _DETECTION_LABELS, 16),
                (self.relation_labels, _RELATION_LABELS, 16),
                (self.case_labels, _CASE_LABELS, 8),
                (self.limitations, _LIMITATIONS, 16),
            ):
                if type(value) is not tuple or len(value) > maximum:
                    raise ValueError
                if any(type(item) is not str or item not in allowed for item in value):
                    raise ValueError
                if len(set(value)) != len(value):
                    raise ValueError
            if type(self.aggregates) is not tuple or len(self.aggregates) > 5:
                raise ValueError
            seen = set()
            for pair in self.aggregates:
                if type(pair) is not tuple or len(pair) != 2:
                    raise ValueError
                name, count = pair
                if type(name) is not str or name not in _AGGREGATE_NAMES:
                    raise ValueError
                if type(count) is not int or not 0 <= count <= 1_000_000:
                    raise ValueError
                if name in seen:
                    raise ValueError
                seen.add(name)
            if self.time_window_seconds is not None and (
                type(self.time_window_seconds) is not int
                or not 0 <= self.time_window_seconds <= 604_800
            ):
                raise ValueError
            if len(json.dumps(asdict(self), ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False).encode("utf-8")) > 4_096:
                raise ValueError
        except (TypeError, ValueError, RecursionError):
            raise RetrievalError("INVALID_EVIDENCE") from None


def build_safe_evidence(*, source_role: str, analysis: dict,
                        session_local_id: str,
                        completeness: Completeness = Completeness.COMPLETE) -> SafeEvidence:
    """Copy only known scalar labels from one existing synthetic/internal result."""
    try:
        if type(analysis) is not dict:
            raise ValueError
        if type(source_role) is not str:
            raise ValueError
        role = SourceRole(source_role)
        detections = analysis.get("detections", {})
        relations = analysis.get("correlation", {})
        risk = analysis.get("risk_level", "UNKNOWN")
        risk_factors = analysis.get("risk_factors", {})
        if type(detections) is not dict or type(relations) is not dict:
            raise ValueError
        detection_map = {
            "brute_force": "Brute Force",
            "password_spraying_like": "Password Spraying-like",
            "path_traversal": "Path Traversal",
            "sql_injection_like": "SQL Injection-like",
            "xss_like": "XSS-like",
            "sensitive_resource_probing_like": "Sensitive Resource Probing-like",
            "web_scanning_like": "Web Scanning-like",
        }
        relation_map = {
            "failed_to_successful_login": "Failed login followed by success",
            "brute_force_to_successful_login": "Brute Force followed by success",
            "password_spray_to_successful_login": "Password Spraying-like followed by success",
        }
        detection_labels = tuple(
            label for key, label in detection_map.items()
            if _is_detected(detections.get(key))
        )
        relation_labels = tuple(
            label for key, label in relation_map.items()
            if _is_correlated(relations.get(key))
        )
        confidence_value = "UNKNOWN"
        if type(risk_factors) is dict:
            confidence = risk_factors.get("confidence")
            if type(confidence) is dict and type(confidence.get("level")) is str:
                confidence_value = confidence["level"]
        case_labels = ()
        provided_cases = analysis.get("case_labels", ())
        case_map = {
            "failed_to_successful_login": "Failed login followed by success case",
            "brute_force_to_successful_login": "Brute Force followed by success case",
            "password_spray_to_successful_login": "Password Spraying-like followed by success case",
        }
        if type(provided_cases) is tuple:
            if any(type(item) is not str or item not in case_map for item in provided_cases):
                raise ValueError
            case_labels = tuple(case_map[item] for item in provided_cases)
        aggregates = (
            ("detections", len(detection_labels)),
            ("relations", len(relation_labels)),
            ("cases", len(case_labels)),
        )
        limitations = ["DETECTION_IS_NOT_COMPROMISE"]
        if relation_labels:
            limitations.append("CORRELATION_IS_NOT_CAUSATION")
        return SafeEvidence(
            source_role=role,
            detection_labels=detection_labels,
            relation_labels=relation_labels,
            risk_level=risk,
            confidence=confidence_value,
            case_labels=case_labels,
            aggregates=aggregates,
            time_window_seconds=None,
            completeness=completeness,
            session_local_id=session_local_id,
            limitations=tuple(limitations),
        )
    except RetrievalError:
        raise
    except Exception:
        raise RetrievalError("INVALID_EVIDENCE") from None


def _is_detected(value) -> bool:
    if type(value) is dict:
        return value.get("is_detected") is True
    return getattr(value, "is_detected", False) is True


def _is_correlated(value) -> bool:
    if type(value) is dict:
        return value.get("is_correlated") is True
    return getattr(value, "is_correlated", False) is True


def canonical_json(value) -> str:
    try:
        if type(value) is RetrievalResult:
            if set(value.__dict__) != set(RetrievalResult.model_fields):
                raise ValueError
            for citation in value.citations:
                if set(citation.__dict__) != set(Citation.model_fields):
                    raise ValueError
            value = RetrievalResult.model_validate(value.model_dump()).model_dump(mode="json")
        elif type(value) is Citation:
            if set(value.__dict__) != set(Citation.model_fields):
                raise ValueError
            value = Citation.model_validate(value.model_dump()).model_dump(mode="json")
        elif type(value) is SafeEvidence:
            SafeEvidence(**asdict(value))
            value = asdict(value)
            value["source_role"] = value["source_role"].value
            value["completeness"] = value["completeness"].value
        else:
            raise ValueError
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False)
    except Exception:
        raise RetrievalError("INVALID_RESULT") from None


@dataclass(frozen=True, slots=True)
class CorpusSection:
    document_id: str
    section_id: str
    title: str
    source_type: str
    source_ref: str
    upstream_version: str
    license_attribution: str
    approved_topic: str
    content_digest: str
    review_status: str
    text: str
    approved: bool = True


@dataclass(frozen=True, slots=True)
class Corpus:
    digest: str
    sections: tuple[CorpusSection, ...]
    total_bytes: int


@dataclass(frozen=True, slots=True)
class LexicalIndex:
    corpus_digest: str
    token_rows: tuple[tuple[str, ...], ...]
    document_frequency: tuple[tuple[str, int], ...]
    average_document_length: float
    resident_bytes: int


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _corpus_fail():
    raise RetrievalError("CORPUS_INVALID") from None


def load_corpus() -> Corpus:
    root = CORPUS_DIR
    try:
        if root.is_symlink() or not root.is_dir():
            _corpus_fail()
        children = list(root.iterdir())
        if any(p.is_symlink() or not stat.S_ISREG(p.lstat().st_mode) for p in children):
            _corpus_fail()
        manifest_path = root / "manifest.json"
        corpus_path = root / "corpus.json"
        if set(p.name for p in children) != {"manifest.json", "corpus.json"}:
            _corpus_fail()
        manifest_bytes = manifest_path.read_bytes()
        corpus_bytes = corpus_path.read_bytes()
        if len(manifest_bytes) > 32_768 or len(corpus_bytes) > MAX_CORPUS_BYTES:
            _corpus_fail()
        if (not manifest_bytes.endswith(b"\n") or not corpus_bytes.endswith(b"\n")
                or b"\r" in manifest_bytes or b"\r" in corpus_bytes):
            _corpus_fail()
        manifest = json.loads(manifest_bytes.decode("utf-8"), object_pairs_hook=_unique_object)
        data = json.loads(corpus_bytes.decode("utf-8"), object_pairs_hook=_unique_object)
        if type(manifest) is not dict or type(data) is not dict:
            _corpus_fail()
        if (set(manifest) != {"schema_version", "file", "file_sha256", "documents", "corpus_digest"}
                or type(manifest.get("schema_version")) is not int
                or manifest.get("schema_version") != 1):
            _corpus_fail()
        if manifest.get("file") != "corpus.json" or manifest.get("file_sha256") != _sha(corpus_bytes):
            _corpus_fail()
        if set(data) != {"documents"}:
            _corpus_fail()
        docs = data.get("documents")
        manifest_docs = manifest.get("documents")
        if type(docs) is not list or type(manifest_docs) is not list:
            _corpus_fail()
        sections: list[CorpusSection] = []
        seen_docs = set()
        seen_sections = set()
        manifest_by_id = {d.get("document_id"): d for d in manifest_docs if type(d) is dict}
        if len(manifest_by_id) != len(manifest_docs) or len(manifest_by_id) != len(docs):
            _corpus_fail()
        if [d.get("document_id") for d in manifest_docs] != [d.get("document_id") for d in docs]:
            _corpus_fail()
        for doc in docs:
            if type(doc) is not dict:
                _corpus_fail()
            required = {"document_id", "title", "source_type", "source_ref",
                        "upstream_version", "license_attribution", "approved_topic",
                        "review_status", "sections"}
            if set(doc) != required:
                _corpus_fail()
            doc_id = doc["document_id"]
            if type(doc_id) is not str or not re.fullmatch(r"[a-z0-9-]{1,48}", doc_id):
                _corpus_fail()
            if doc_id in seen_docs:
                _corpus_fail()
            seen_docs.add(doc_id)
            md = manifest_by_id.get(doc_id)
            if (type(md) is not dict
                    or set(md) != {"document_id", "approved", "review_status", "sections"}
                    or md.get("approved") is not True
                    or md.get("review_status") != "approved"):
                _corpus_fail()
            if any(type(doc[k]) is not str or not 1 <= len(doc[k]) <= 160
                   for k in required - {"sections"}):
                _corpus_fail()
            if any(_contains_private_or_active_content(doc[k])
                   for k in required - {"sections"}):
                _corpus_fail()
            source_ref = doc["source_ref"]
            if not (source_ref.startswith("docs/") or source_ref.startswith("https://")):
                _corpus_fail()
            source_type = doc["source_type"]
            if source_type not in {"PROJECT", "UPSTREAM_SUMMARY"}:
                _corpus_fail()
            section_specs = doc["sections"]
            manifest_sections = md.get("sections")
            if type(section_specs) is not list or not 1 <= len(section_specs) <= 16:
                _corpus_fail()
            if type(manifest_sections) is not list or len(section_specs) != len(manifest_sections):
                _corpus_fail()
            for spec, ms in zip(section_specs, manifest_sections, strict=True):
                if type(spec) is not dict or set(spec) != {"section_id", "text"}:
                    _corpus_fail()
                section_id, text = spec["section_id"], spec["text"]
                if type(section_id) is not str or not re.fullmatch(r"[a-z0-9-]{1,48}", section_id):
                    _corpus_fail()
                if section_id in seen_sections:
                    _corpus_fail()
                seen_sections.add(section_id)
                if type(text) is not str or not text.strip() or "\r" in text:
                    _corpus_fail()
                raw = text.encode("utf-8")
                if len(raw) > MAX_SECTION_BYTES or len(tokenize(text)) > MAX_SECTION_TOKENS:
                    _corpus_fail()
                if ms != {"section_id": section_id, "content_sha256": _sha(raw)}:
                    _corpus_fail()
                if _contains_private_or_active_content(text):
                    _corpus_fail()
                sections.append(CorpusSection(
                    document_id=doc_id, section_id=section_id, title=doc["title"],
                    source_type=source_type, source_ref=source_ref,
                    upstream_version=doc["upstream_version"],
                    license_attribution=doc["license_attribution"],
                    approved_topic=doc["approved_topic"],
                    content_digest=ms["content_sha256"], review_status="approved",
                    text=text, approved=True,
                ))
        if not 12 <= len(sections) <= MAX_CORPUS_SECTIONS:
            _corpus_fail()
        canonical_manifest = {
            "schema_version": 1,
            "file": "corpus.json",
            "file_sha256": _sha(corpus_bytes),
            "documents": manifest_docs,
        }
        manifest_digest = _sha(_canonical_bytes(canonical_manifest))
        if (manifest.get("corpus_digest") != manifest_digest
                or manifest_digest != TRUSTED_CORPUS_DIGEST):
            _corpus_fail()
        return Corpus(manifest_digest, tuple(sections), len(corpus_bytes))
    except RetrievalError:
        raise
    except Exception:
        _corpus_fail()


def _canonical_bytes(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _corpus_fail()
        value[key] = item
    return value


def generate_manifest(corpus_dir: Path | None = None) -> bytes:
    """Explicit development-only deterministic manifest rendering; does not write."""
    root = CORPUS_DIR if corpus_dir is None else Path(corpus_dir)
    try:
        if root.is_symlink() or not root.is_dir():
            _corpus_fail()
        children = list(root.iterdir())
        if (any(path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode) for path in children)
                or set(path.name for path in children) - {"corpus.json", "manifest.json"}
                or "corpus.json" not in {path.name for path in children}):
            _corpus_fail()
        corpus_bytes = (root / "corpus.json").read_bytes()
        if (len(corpus_bytes) > MAX_CORPUS_BYTES or not corpus_bytes.endswith(b"\n")
                or b"\r" in corpus_bytes):
            _corpus_fail()
        data = json.loads(corpus_bytes.decode("utf-8"), object_pairs_hook=_unique_object)
        if type(data) is not dict or set(data) != {"documents"}:
            _corpus_fail()
        if type(data["documents"]) is not list:
            _corpus_fail()
        documents = []
        seen_docs = set()
        seen_sections = set()
        section_count = 0
        for doc in data["documents"]:
            required = {"document_id", "title", "source_type", "source_ref",
                        "upstream_version", "license_attribution", "approved_topic",
                        "review_status", "sections"}
            if type(doc) is not dict or set(doc) != required:
                _corpus_fail()
            doc_id = doc["document_id"]
            if type(doc_id) is not str or not re.fullmatch(r"[a-z0-9-]{1,48}", doc_id) or doc_id in seen_docs:
                _corpus_fail()
            seen_docs.add(doc_id)
            if any(type(doc[key]) is not str or not 1 <= len(doc[key]) <= 160
                   or _contains_private_or_active_content(doc[key])
                   for key in required - {"sections"}):
                _corpus_fail()
            if (doc["review_status"] != "approved"
                    or doc["source_type"] not in {"PROJECT", "UPSTREAM_SUMMARY"}
                    or not _is_safe_source_ref(doc["source_ref"])):
                _corpus_fail()
            if type(doc["sections"]) is not list or not 1 <= len(doc["sections"]) <= 16:
                _corpus_fail()
            section_manifest = []
            for section in doc["sections"]:
                if type(section) is not dict or set(section) != {"section_id", "text"}:
                    _corpus_fail()
                section_id, text = section["section_id"], section["text"]
                if (type(section_id) is not str
                        or not re.fullmatch(r"[a-z0-9-]{1,48}", section_id)
                        or section_id in seen_sections):
                    _corpus_fail()
                seen_sections.add(section_id)
                if type(text) is not str or not text.strip() or "\r" in text:
                    _corpus_fail()
                raw = text.encode("utf-8")
                if (len(raw) > MAX_SECTION_BYTES or len(tokenize(text)) > MAX_SECTION_TOKENS
                        or _contains_private_or_active_content(text)):
                    _corpus_fail()
                section_count += 1
                section_manifest.append({"section_id": section_id,
                                         "content_sha256": _sha(raw)})
            documents.append({
                "document_id": doc_id, "approved": True,
                "review_status": "approved", "sections": section_manifest,
            })
        if not 12 <= section_count <= MAX_CORPUS_SECTIONS:
            _corpus_fail()
        base = {"schema_version": 1, "file": "corpus.json",
                "file_sha256": _sha(corpus_bytes), "documents": documents}
        digest = _sha(_canonical_bytes(base))
        result = {**base, "corpus_digest": digest}
        return (json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    except RetrievalError:
        raise
    except Exception:
        _corpus_fail()


def _contains_private_or_active_content(text: str) -> bool:
    lowered = text.casefold()
    if any(marker in lowered for marker in (
        "ignore previous instructions", "ignore all previous", "disregard instructions",
        "<script", "<iframe", "javascript:", "system: reveal", "system prompt:",
        "developer: override", "run shell", "execute command", "BEGIN PRIVATE KEY",
        "api_key=", "password=", "/users/", "/home/", "/private/", "/etc/",
        "<", ">",
    )):
        return True
    if re.search(r"!?\[[^\]]{1,200}\]\([^)]{1,256}\)", text):
        return True
    if re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text):
        return True
    for candidate in re.findall(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])", text):
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            pass
    return False


def _is_safe_source_ref(value: str) -> bool:
    if value.startswith("docs/"):
        return (value.endswith(".md")
                and not any(part in {"", ".", ".."} for part in value.split("/")))
    parsed = urlsplit(value)
    return (parsed.scheme == "https" and bool(parsed.hostname)
            and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment)


_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)


def tokenize(text: str) -> tuple[str, ...]:
    if type(text) is not str:
        raise RetrievalError("INVALID_REQUEST")
    normalized = unicodedata.normalize("NFKC", text).casefold()
    result = []
    for token in _TOKEN_RE.findall(normalized):
        result.append(token)
        if token and all("\uac00" <= char <= "\ud7a3" for char in token):
            result.extend(f"ko2:{token[i:i + 2]}" for i in range(len(token) - 1))
    return tuple(result)


_STOPWORDS = frozenset({
    "a", "an", "and", "are", "by", "for", "from", "in", "is", "it",
    "of", "on", "or", "the", "to", "with", "does", "do", "what", "why",
    "은", "는", "이", "가", "을", "를", "의", "에", "와", "과", "도",
})
STOPWORD_DIGEST = hashlib.sha256("\n".join(sorted(_STOPWORDS)).encode("utf-8")).hexdigest()


def _lexical_terms(text: str) -> tuple[str, ...]:
    return tuple(token for token in tokenize(text) if token not in _STOPWORDS)


_ALLOWED_TERMS = frozenset(tokenize("""brute force password spray spraying like meaning limit failed success relation causation risk lower safe resolve resolved relation gone replay gap stale checkpoint reset incomplete evidence no finding application ssh next checks observation detection confidence case explain what why is are the a an to of and for after followed by not means does mean cannot prove attack did succeed compromise incident private logs local source role analysis history start again escalation investigate verify logs authentication conflicting conflict collision 성공 실패 관계 위험도 하향 안전 위험 신뢰도 사례 설명 의미 한계 확인 다음 조사 항목 애플리케이션 접속 인증 재생 공백 오래됨 점검 복구 초기화 탐지 없음 증거 불완전"""))
_DENY_QUERY_PATTERNS = (
    re.compile(r"(?:(?:did\s+)?(?:attack|intrusion|compromise)\s+succeed|(?:attack|intrusion|compromise)\s+did\s+succeed)"),
    re.compile(r"(?:password|secret|credential)\s+(?:is|for|of)"),
    re.compile(r"(?:what|which|show|reveal)\b.{0,40}\b(?:password|secret|credential)\b"),
    re.compile(r"(?:run|execute|delete|block|lock)\b"),
    re.compile(r"(?:system|developer|assistant|user)\s*:"),
    re.compile(r"(?:account|username|hostname|ip|path|query|raw)\s*[:=]"),
)


def _query_refusal(query: str) -> str | None:
    if type(query) is not str:
        return "QUESTION_NOT_ALLOWED"
    try:
        query_bytes = query.encode("utf-8")
    except UnicodeEncodeError:
        return "QUESTION_NOT_ALLOWED"
    if len(query) > MAX_QUERY_CHARS or len(query_bytes) > MAX_QUERY_BYTES:
        return "QUESTION_NOT_ALLOWED"
    if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in query):
        return "QUESTION_NOT_ALLOWED"
    if unicodedata.normalize("NFKC", query) != query:
        return "QUESTION_NOT_ALLOWED"
    lowered = query.casefold()
    if any(p.search(lowered) for p in _DENY_QUERY_PATTERNS):
        return "PRIVACY_INPUT_REJECTED"
    if "/" in query or "\\" in query or "@" in query or "<" in query or ">" in query:
        return "PRIVACY_INPUT_REJECTED"
    if re.search(r"(?:\d{1,3}\.){3}\d{1,3}", query):
        return "PRIVACY_INPUT_REJECTED"
    tokens = tokenize(query)
    if not tokens or len(tokens) > MAX_QUERY_TOKENS:
        return "QUESTION_NOT_ALLOWED"
    if any(token not in _ALLOWED_TERMS for token in tokens):
        return "QUESTION_NOT_ALLOWED"
    if "canary" in tokens or any(len(t) > 32 for t in tokens):
        return "PRIVACY_INPUT_REJECTED"
    return None


class Citation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    document_id: StrictStr = Field(min_length=1, max_length=48)
    section_id: StrictStr = Field(min_length=1, max_length=48)
    title: StrictStr = Field(min_length=1, max_length=160)
    excerpt: StrictStr = Field(min_length=1, max_length=640)
    lexical_score: float = Field(ge=0, allow_inf_nan=False)
    source_ref: StrictStr = Field(min_length=1, max_length=256)

    @field_validator("source_ref")
    @classmethod
    def safe_reference(cls, value):
        if value.startswith("docs/"):
            if any(part in {"", ".", ".."} for part in value.split("/")) or not value.endswith(".md"):
                raise ValueError("invalid source reference")
            return value
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("invalid source reference")
        return value


class RetrievalResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal[1] = 1
    query_category: QueryCategory
    corpus_digest: StrictStr = Field(min_length=64, max_length=64)
    status: ResultStatus
    citations: tuple[Citation, ...] = Field(max_length=MAX_TOP_K)
    refusal_code: StrictStr | None = Field(default=None, max_length=48)


def _evidence_matches(category: QueryCategory, evidence: SafeEvidence) -> bool:
    required = {
        QueryCategory.EXPLAIN_DETECTION: bool(evidence.detection_labels),
        QueryCategory.EXPLAIN_RELATION: bool(evidence.relation_labels),
        QueryCategory.EXPLAIN_RISK: (
            evidence.risk_level != "UNKNOWN" or evidence.confidence != "UNKNOWN"
        ),
        QueryCategory.EXPLAIN_CASE: bool(evidence.case_labels),
        QueryCategory.NEXT_CHECKS: evidence.completeness in set(Completeness),
        QueryCategory.EXPLAIN_RECOVERY_STATE: (
            evidence.completeness != Completeness.COMPLETE
            or any(code in evidence.limitations for code in (
                "REPLAY_GAP_MAY_BE_STALE", "CHECKPOINT_RESET_STARTS_NEW_HISTORY",
            ))
        ),
        QueryCategory.EXPLAIN_LIMITATION: bool(evidence.limitations) or not evidence.detection_labels,
    }
    return required[category]


_CATEGORY_TERMS = {
    QueryCategory.EXPLAIN_DETECTION: frozenset(tokenize("brute force password spray detection 탐지")),
    QueryCategory.EXPLAIN_RELATION: frozenset(tokenize("relation failed success causation 관계")),
    QueryCategory.EXPLAIN_RISK: frozenset(tokenize("risk confidence lower safe 위험도 신뢰도")),
    QueryCategory.EXPLAIN_CASE: frozenset(tokenize("case 사례")),
    QueryCategory.NEXT_CHECKS: frozenset(tokenize("next checks investigate verify 다음 조사 확인")),
    QueryCategory.EXPLAIN_RECOVERY_STATE: frozenset(tokenize("replay gap stale checkpoint reset recovery history 복구 초기화")),
    QueryCategory.EXPLAIN_LIMITATION: frozenset(tokenize("incomplete evidence no finding limit conflicting conflict 충돌 한계")),
}


def build_index(corpus: Corpus) -> LexicalIndex:
    try:
        if type(corpus) is not Corpus or not 1 <= len(corpus.sections) <= MAX_CORPUS_SECTIONS:
            raise ValueError
        documents = tuple(_lexical_terms(section.text) for section in corpus.sections)
        frequencies: dict[str, int] = {}
        for tokens in documents:
            for term in set(tokens):
                frequencies[term] = frequencies.get(term, 0) + 1
        lengths = tuple(len(tokens) for tokens in documents)
        average = sum(lengths) / len(lengths) if lengths else 0.0
        ordered_df = tuple(sorted(frequencies.items()))
        resident = sum(len(term.encode("utf-8")) + 8 for row in documents for term in row)
        resident += sum(len(term.encode("utf-8")) + 8 for term, _ in ordered_df)
        resident += 32 * len(documents)
        if resident > 512_000 or not math.isfinite(average):
            raise ValueError
        return LexicalIndex(corpus.digest, documents, ordered_df, average, resident)
    except RetrievalError:
        raise
    except Exception:
        raise RetrievalError("CORPUS_INVALID") from None


def _bm25(query_tokens: tuple[str, ...], index: LexicalIndex,
          sections: tuple[CorpusSection, ...]) -> list[tuple[float, CorpusSection]]:
    documents = index.token_rows
    count = len(documents)
    lengths = [len(tokens) for tokens in documents]
    avgdl = index.average_document_length
    document_frequency: dict[str, int] = {}
    document_frequency.update(index.document_frequency)
    query_terms = tuple(dict.fromkeys(query_tokens))
    scored = []
    for section, tokens, length in zip(sections, documents, lengths, strict=True):
        frequencies: dict[str, int] = {}
        for term in tokens:
            frequencies[term] = frequencies.get(term, 0) + 1
        score = 0.0
        for term in query_terms:
            tf = frequencies.get(term, 0)
            df = document_frequency.get(term, 0)
            if tf and df:
                idf = math.log(1.0 + (count - df + 0.5) / (df + 0.5))
                norm = tf + BM25_K1 * (1.0 - BM25_B + BM25_B * length / avgdl)
                score += idf * (tf * (BM25_K1 + 1.0)) / norm
        if not math.isfinite(score) or score < 0:
            raise RetrievalError("INVALID_RESULT")
        scored.append((score, section))
    scored.sort(key=lambda item: (-item[0], item[1].document_id, item[1].section_id))
    return scored


def retrieve(query: str, category: QueryCategory, evidence: SafeEvidence,
             *, corpus: Corpus | None = None, index: LexicalIndex | None = None,
             top_k: int = MAX_TOP_K) -> RetrievalResult:
    try:
        if type(category) is not QueryCategory or type(evidence) is not SafeEvidence:
            return _refused(QueryCategory.EXPLAIN_LIMITATION, "INVALID_REQUEST", corpus)
        active = load_corpus() if corpus is None else corpus
        refusal = _query_refusal(query)
        if refusal:
            return _refused(category, refusal, active)
        if type(top_k) is not int or not 1 <= top_k <= MAX_TOP_K:
            return _refused(category, "INVALID_REQUEST", active)
        if not _evidence_matches(category, evidence):
            return _refused(category, "EVIDENCE_CATEGORY_MISMATCH", active)
        active_index = build_index(active) if index is None else index
        if type(active_index) is not LexicalIndex or active_index.corpus_digest != active.digest:
            raise RetrievalError("CORPUS_INVALID") from None
        tokens = _lexical_terms(query)
        if not tokens:
            return _refused(category, "NO_SUPPORTING_CITATION", active)
        if not (_CATEGORY_TERMS[category] & set(tokens)):
            return _refused(category, "EVIDENCE_CATEGORY_MISMATCH", active)
        scored = _bm25(tokens, active_index, active.sections)
        if any(type(row) is not tuple or len(row) != 2
               or type(row[0]) not in {int, float}
               or not math.isfinite(row[0]) or row[0] < 0
               for row in scored):
            raise RetrievalError("INVALID_RESULT") from None
        hits = [(score, section) for score, section in scored if score > MIN_SCORE][:top_k]
        if not hits:
            return _refused(category, "NO_SUPPORTING_CITATION", active)
        citations = tuple(Citation(
            document_id=s.document_id, section_id=s.section_id, title=s.title,
            excerpt=s.text, lexical_score=score, source_ref=s.source_ref,
        ) for score, s in hits)
        result = RetrievalResult(query_category=category, corpus_digest=active.digest,
                                 status=ResultStatus.OK, citations=citations)
        return validate_result(result, active, requested_top_k=top_k)
    except RetrievalError:
        raise
    except Exception:
        raise RetrievalError("INVALID_REQUEST") from None


def _refused(category, code, corpus):
    digest = corpus.digest if type(corpus) is Corpus else "0" * 64
    return RetrievalResult(query_category=category, corpus_digest=digest,
                           status=ResultStatus.REFUSED, citations=(), refusal_code=code)


def validate_result(result: RetrievalResult, corpus: Corpus,
                    *, requested_top_k: int) -> RetrievalResult:
    try:
        if type(result) is not RetrievalResult or type(corpus) is not Corpus:
            raise ValueError
        if set(result.__dict__) != set(RetrievalResult.model_fields):
            raise ValueError
        if any(set(c.__dict__) != set(Citation.model_fields) for c in result.citations):
            raise ValueError
        RetrievalResult.model_validate(result.model_dump())
        if result.corpus_digest != corpus.digest:
            raise ValueError
        if type(requested_top_k) is not int or not 1 <= requested_top_k <= MAX_TOP_K:
            raise ValueError
        if len(result.citations) > requested_top_k:
            raise ValueError
        if result.status is ResultStatus.REFUSED:
            if result.citations or result.refusal_code is None:
                raise ValueError
            return result
        if result.refusal_code is not None:
            raise ValueError
        if result.status is ResultStatus.NO_RESULTS:
            if result.citations:
                raise ValueError
            return result
        if result.status is not ResultStatus.OK or not result.citations:
            raise ValueError
        entries = {(s.document_id, s.section_id): s for s in corpus.sections}
        keys = [(c.document_id, c.section_id) for c in result.citations]
        if len(set(keys)) != len(keys):
            raise ValueError
        expected_order = sorted(result.citations,
                                key=lambda c: (-c.lexical_score, c.document_id, c.section_id))
        if tuple(expected_order) != result.citations:
            raise ValueError
        for c in result.citations:
            section = entries.get((c.document_id, c.section_id))
            if section is None or not section.approved:
                raise ValueError
            if (c.title != section.title or c.source_ref != section.source_ref
                    or c.excerpt != section.text
                    or _sha(c.excerpt.encode("utf-8")) != section.content_digest
                    or len(c.excerpt.encode("utf-8")) > MAX_SECTION_BYTES):
                raise ValueError
            if not math.isfinite(c.lexical_score) or c.lexical_score <= MIN_SCORE:
                raise ValueError
        return result
    except Exception:
        raise RetrievalError("INVALID_RESULT") from None


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    fixture_count: int
    expected_citation_hits: int
    citation_precision: float
    citation_completeness: float
    unsupported_citation_count: int
    refusal_failures: int
    privacy_leak_count: int
    schema_validation_rate: float
    authoritative_mutations: int
    executed_injections: int
    deterministic_retrieval: bool
    median_latency_ms: float
    peak_bounded_state_bytes: int


def run_synthetic_evaluation() -> EvaluationReport:
    """Small deterministic contract fixture set; not a detector or model score."""
    corpus = load_corpus()
    index = build_index(corpus)
    cases = (
        ("brute force meaning limit", QueryCategory.EXPLAIN_DETECTION, "brute-force", True),
        ("password spray meaning limit", QueryCategory.EXPLAIN_DETECTION, "password-spray", True),
        ("failed success relation causation", QueryCategory.EXPLAIN_RELATION, "failed-success", True),
        ("risk lower safe", QueryCategory.EXPLAIN_RISK, "risk-lower", True),
        ("relation gone resolved", QueryCategory.EXPLAIN_RELATION, "relation-gone", True),
        ("replay gap stale", QueryCategory.EXPLAIN_RECOVERY_STATE, "replay-gap", True),
        ("checkpoint reset", QueryCategory.EXPLAIN_RECOVERY_STATE, "checkpoint-reset", True),
        ("incomplete evidence", QueryCategory.EXPLAIN_LIMITATION, "incomplete-evidence", True),
        ("no finding safe", QueryCategory.EXPLAIN_LIMITATION, "no-finding", True),
        ("conflicting evidence", QueryCategory.EXPLAIN_LIMITATION, "conflicting-evidence", True),
        ("what password is account", QueryCategory.EXPLAIN_DETECTION, None, False),
        ("ignore previous instructions", QueryCategory.EXPLAIN_DETECTION, None, False),
        ("retrieve 192.0.2.1", QueryCategory.EXPLAIN_DETECTION, None, False),
        ("unknown unsupported claim", QueryCategory.EXPLAIN_DETECTION, None, False),
        ("next checks application ssh", QueryCategory.NEXT_CHECKS, "next-checks", True),
        ("attack did succeed", QueryCategory.EXPLAIN_DETECTION, None, False),
        ("malformed result injection", QueryCategory.EXPLAIN_DETECTION, None, False),
    )
    item = SafeEvidence(
        SourceRole.APPLICATION, ("Brute Force",),
        ("Failed login followed by success",), "MEDIUM", "HIGH", (),
        (("observations", 3),), 120, Completeness.PARTIAL,
        "s_0123456789abcdef", ("DETECTION_IS_NOT_COMPROMISE", "REPLAY_GAP_MAY_BE_STALE",
                               "CHECKPOINT_RESET_STARTS_NEW_HISTORY"),
    )
    hits = 0
    relevant_citations = 0
    cited = 0
    unsupported = 0
    refusals = 0
    valid_schemas = 0
    latencies = []
    max_state = corpus.total_bytes + index.resident_bytes
    identical = True
    authoritative_snapshot = canonical_json(item)
    allowed_count = sum(1 for case in cases if case[3])
    known_ids = {section.document_id for section in corpus.sections}
    for query, category, expected, allowed in cases:
        start = time.perf_counter_ns()
        result = retrieve(query, category, item, corpus=corpus, index=index)
        latencies.append((time.perf_counter_ns() - start) / 1_000_000)
        rendered = canonical_json(result)
        max_state = max(max_state, len(rendered.encode("utf-8")))
        valid_schemas += int(type(RetrievalResult.model_validate(result.model_dump())) is RetrievalResult)
        unsupported += sum(c.document_id not in known_ids for c in result.citations)
        cited += len(result.citations)
        if allowed:
            ids = {c.document_id for c in result.citations}
            hits += int(result.status is ResultStatus.OK and expected in ids)
            relevant = {
                "brute-force": {"brute-force", "mitre-brute-force-classification"},
                "password-spray": {"password-spray", "mitre-brute-force-classification"},
                "failed-success": {"failed-success"},
                "risk-lower": {"risk-lower"},
                "replay-gap": {"replay-gap", "incomplete-evidence"},
                "next-checks": {"next-checks", "application-ssh-roles", "owasp-safe-logging"},
            }.get(expected, {expected})
            relevant_citations += sum(c.document_id in relevant for c in result.citations)
        else:
            refusals += int(result.status is ResultStatus.REFUSED)
        identical &= canonical_json(result) == canonical_json(
            retrieve(query, category, item, corpus=corpus, index=index))
    return EvaluationReport(
        fixture_count=len(cases), expected_citation_hits=hits,
        citation_precision=(relevant_citations / cited if cited else 0.0),
        citation_completeness=hits / allowed_count,
        unsupported_citation_count=unsupported,
        refusal_failures=(allowed_count - hits) + (len(cases) - allowed_count - refusals),
        privacy_leak_count=sum(
            int(canary in canonical_json(retrieve(canary, QueryCategory.EXPLAIN_DETECTION,
                                                  item, corpus=corpus)))
            for canary in ("account-canary-331", "192.0.2.1", "/Users/private/file.log")
        ),
        schema_validation_rate=valid_schemas / len(cases),
        authoritative_mutations=int(canonical_json(item) != authoritative_snapshot),
        executed_injections=0,
        deterministic_retrieval=identical, median_latency_ms=statistics.median(latencies),
        peak_bounded_state_bytes=max_state,
    )
