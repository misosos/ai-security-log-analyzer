"""Test-only helpers for the disposable multilingual E5 retrieval pilot.

Nothing in this module is imported by application code. It deliberately emits
only verified citation records and aggregate measurements; vectors stay in
the caller's process memory.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import stat

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from app import local_retrieval_33_1 as baseline


MODEL_REPOSITORY = "intfloat/multilingual-e5-small"
MODEL_REVISION = "614241f622f53c4eeff9890bdc4f31cfecc418b3"
MODEL_LICENSE = "MIT"
EXPECTED_MODEL_FILES = frozenset({
    "model.safetensors", "config.json", "tokenizer.json",
    "tokenizer_config.json", "special_tokens_map.json",
})
MAX_MODEL_FILES = 5
MAX_PASSAGES = 8
MAX_QUERY_BYTES = 1024
MAX_PASSAGE_BYTES = 1536
MAX_TOKENS = 512
MAX_TOP_K = 5
COSINE_THRESHOLD = 0.65  # fixed before held-out evaluation; pilot heuristic only
RRF_CONSTANT = 60


class PilotError(Exception):
    _MESSAGES = {
        "MANIFEST_INVALID": "Pilot model manifest is invalid.",
        "MODEL_FILE_SET_INVALID": "Pilot model files are invalid.",
        "MODEL_DIGEST_INVALID": "Pilot model file integrity check failed.",
        "CORPUS_DIGEST_MISMATCH": "Pilot corpus integrity check failed.",
        "INPUT_INVALID": "Pilot input is invalid.",
        "MODEL_RUNTIME_INVALID": "Pilot model runtime failed safely.",
        "SCORE_INVALID": "Pilot retrieval score is invalid.",
        "CITATION_INVALID": "Pilot citation validation failed.",
    }

    def __init__(self, code: str):
        if code not in self._MESSAGES:
            code = "INPUT_INVALID"
        self.code = code
        super().__init__(self._MESSAGES[code])


@dataclass(frozen=True, slots=True)
class ModelFilePin:
    size_bytes: int
    sha256: str


MODEL_FILE_PINS: dict[str, ModelFilePin] = {
    "model.safetensors": ModelFilePin(
        470_641_600,
        "1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477",
    ),
    "config.json": ModelFilePin(
        655, "69137736cab8b8903a07fe8afaafdda25aac55415a12a55d1bffa9f581abf959",
    ),
    "tokenizer.json": ModelFilePin(
        17_082_730,
        "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39",
    ),
    "tokenizer_config.json": ModelFilePin(
        443, "a1d6bc8734a6f635dc158508bef000f8e2e5a759c7d92f984b2c86e5ff53425b",
    ),
    "special_tokens_map.json": ModelFilePin(
        167, "d05497f1da52c5e09554c0cd874037a083e1dc1b9cfd48034d1c717f1afc07a7",
    ),
}


@dataclass(frozen=True, slots=True)
class PilotManifest:
    repository: str
    revision: str
    license: str
    files: tuple[tuple[str, int, str], ...]
    digest: str


@dataclass(frozen=True, slots=True)
class RuntimeWheel:
    filename: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class RuntimeWheelManifest:
    runtime_lock_sha256: str
    wheels: tuple[RuntimeWheel, ...]
    total_bytes: int


def load_runtime_wheel_manifest(path: Path) -> RuntimeWheelManifest:
    try:
        raw = Path(path).read_bytes()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        if (type(value) is not dict or set(value) != {
                "schema_version", "runtime_lock_sha256", "wheel_count", "wheel_bytes", "wheels"}
                or value["schema_version"] != 1
                or type(value["runtime_lock_sha256"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", value["runtime_lock_sha256"])
                or type(value["wheel_count"]) is not int or type(value["wheel_bytes"]) is not int
                or type(value["wheels"]) is not list or not 1 <= len(value["wheels"]) <= 128):
            _fixed_error("MANIFEST_INVALID")
        rows = []
        names = set()
        for row in value["wheels"]:
            if (type(row) is not dict or set(row) != {"file", "size_bytes", "sha256"}
                    or type(row["file"]) is not str
                    or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,180}\.whl", row["file"])
                    or row["file"] in names or type(row["size_bytes"]) is not int
                    or row["size_bytes"] <= 0 or type(row["sha256"]) is not str
                    or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
                _fixed_error("MANIFEST_INVALID")
            names.add(row["file"])
            rows.append(RuntimeWheel(row["file"], row["size_bytes"], row["sha256"]))
        rows.sort(key=lambda item: item.filename)
        total = sum(item.size_bytes for item in rows)
        if (value["wheel_count"] != len(rows) or value["wheel_bytes"] != total
                or [row["file"] for row in value["wheels"]] != [row.filename for row in rows]):
            _fixed_error("MANIFEST_INVALID")
        return RuntimeWheelManifest(value["runtime_lock_sha256"], tuple(rows), total)
    except PilotError:
        raise
    except Exception:
        _fixed_error("MANIFEST_INVALID")


def verify_runtime_wheelhouse(wheelhouse: Path,
                              manifest: RuntimeWheelManifest) -> None:
    try:
        root = Path(wheelhouse)
        if root.is_symlink() or not root.is_dir():
            _fixed_error("MODEL_FILE_SET_INVALID")
        children = list(root.iterdir())
        expected = {row.filename: row for row in manifest.wheels}
        if (len(children) != len(expected) or {item.name for item in children} != set(expected)
                or any(item.is_symlink() or not stat.S_ISREG(item.lstat().st_mode)
                       for item in children)):
            _fixed_error("MODEL_FILE_SET_INVALID")
        for item in children:
            pin = expected[item.name]
            content = item.read_bytes()
            if len(content) != pin.size_bytes or _sha(content) != pin.sha256:
                _fixed_error("MODEL_DIGEST_INVALID")
    except PilotError:
        raise
    except Exception:
        _fixed_error("MODEL_DIGEST_INVALID")


def render_runtime_pins(manifest: RuntimeWheelManifest) -> bytes:
    """Create a temporary exact wheel-only requirements file with one hash per dist."""
    try:
        packages = {}
        for wheel in manifest.wheels:
            tokens = wheel.filename[:-4].split("-")
            if len(tokens) not in {5, 6}:
                _fixed_error("MANIFEST_INVALID")
            name = tokens[0].replace("_", "-").casefold()
            version = tokens[1]
            if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,100}", name) or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,80}", version):
                _fixed_error("MANIFEST_INVALID")
            if name in packages:
                _fixed_error("MANIFEST_INVALID")
            packages[name] = f"{name}=={version} --hash=sha256:{wheel.sha256}"
        rendered = ("\n".join(packages[name] for name in sorted(packages)) + "\n").encode("utf-8")
        if len(rendered) > 32_768:
            _fixed_error("MANIFEST_INVALID")
        return rendered
    except PilotError:
        raise
    except Exception:
        _fixed_error("MANIFEST_INVALID")


@dataclass(frozen=True, slots=True)
class RankedSection:
    document_id: str
    section_id: str
    score: float


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    case_id: str
    query: str
    category: baseline.QueryCategory
    expected: tuple[str, ...]
    relevant: tuple[str, ...]
    refusal: str | None


def load_evaluation_cases(path: Path) -> tuple[EvaluationCase, ...]:
    """Load the closed, synthetic-only 33.1 + multilingual fixture contract."""
    try:
        raw = Path(path).read_bytes()
        if len(raw) > 24_000 or not raw.endswith(b"\n") or b"\r" in raw:
            _fixed_error("INPUT_INVALID")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        if (type(data) is not dict or set(data) != {"schema_version", "corpus_digest", "cases"}
                or type(data["schema_version"]) is not int or data["schema_version"] != 1
                or data["corpus_digest"] != baseline.TRUSTED_CORPUS_DIGEST
                or type(data["cases"]) is not list or len(data["cases"]) < 17
                or len(data["cases"]) > 64):
            _fixed_error("INPUT_INVALID")
        result = []
        seen = set()
        for row in data["cases"]:
            common = {"id", "query", "category", "expected"}
            if type(row) is not dict or not common <= set(row) or set(row) - (common | {"relevant", "refusal", "repeat"}):
                _fixed_error("INPUT_INVALID")
            case_id, query = row["id"], row["query"]
            if (type(case_id) is not str or not re.fullmatch(r"[a-z][a-z0-9]{0,7}", case_id)
                    or case_id in seen or type(query) is not str):
                _fixed_error("INPUT_INVALID")
            seen.add(case_id)
            repeat = row.get("repeat", 1)
            if type(repeat) is not int or not 1 <= repeat <= 256:
                _fixed_error("INPUT_INVALID")
            query *= repeat
            try:
                category = baseline.QueryCategory(row["category"])
            except Exception:
                _fixed_error("INPUT_INVALID")
            expected, relevant, refusal = row["expected"], row.get("relevant", []), row.get("refusal")
            if (type(expected) is not list or len(expected) > MAX_TOP_K
                    or any(type(item) is not str for item in expected)
                    or type(relevant) is not list or len(relevant) > 8
                    or any(type(item) is not str for item in relevant)
                    or (refusal is not None and type(refusal) is not str)
                    or (not expected and refusal is None)
                    or (expected and refusal is not None)):
                _fixed_error("INPUT_INVALID")
            result.append(EvaluationCase(case_id, query, category,
                                         tuple(expected), tuple(relevant or expected), refusal))
        return tuple(result)
    except PilotError:
        raise
    except Exception:
        _fixed_error("INPUT_INVALID")


class CandidateCitation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    document_id: StrictStr = Field(min_length=1, max_length=48)
    section_id: StrictStr = Field(min_length=1, max_length=48)
    title: StrictStr = Field(min_length=1, max_length=160)
    excerpt: StrictStr = Field(min_length=1, max_length=640)
    score: float = Field(ge=0, allow_inf_nan=False)
    source_ref: StrictStr = Field(min_length=1, max_length=256)


def _fixed_error(code: str):
    raise PilotError(code) from None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def load_pilot_manifest(model_dir: Path, manifest_path: Path, *, pins=None) -> PilotManifest:
    """Verify a closed exact-revision file set without following symlinks."""
    active_pins = MODEL_FILE_PINS if pins is None else pins
    try:
        root = Path(model_dir)
        manifest_file = Path(manifest_path)
        if (root.is_symlink() or not root.is_dir() or manifest_file.is_symlink()
                or not manifest_file.is_file() or len(active_pins) != MAX_MODEL_FILES
                or set(active_pins) != EXPECTED_MODEL_FILES):
            _fixed_error("MANIFEST_INVALID")
        raw_manifest = manifest_file.read_bytes()
        if len(raw_manifest) > 4096 or not raw_manifest.endswith(b"\n") or b"\r" in raw_manifest:
            _fixed_error("MANIFEST_INVALID")
        value = json.loads(raw_manifest.decode("utf-8"), object_pairs_hook=_unique_pairs)
        if (type(value) is not dict or set(value) != {
                "schema_version", "repository", "revision", "license", "files"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["repository"] != MODEL_REPOSITORY
                or value["revision"] != MODEL_REVISION or value["license"] != MODEL_LICENSE
                or type(value["files"]) is not list or len(value["files"]) != MAX_MODEL_FILES):
            _fixed_error("MANIFEST_INVALID")
        children = list(root.iterdir())
        if (len(children) != MAX_MODEL_FILES or {p.name for p in children} != EXPECTED_MODEL_FILES
                or any(p.is_symlink() or not stat.S_ISREG(p.lstat().st_mode) for p in children)):
            _fixed_error("MODEL_FILE_SET_INVALID")
        rows = []
        seen = set()
        for row in value["files"]:
            if type(row) is not dict or set(row) != {"path", "size_bytes", "sha256"}:
                _fixed_error("MANIFEST_INVALID")
            name, size, digest = row["path"], row["size_bytes"], row["sha256"]
            if (type(name) is not str or name not in EXPECTED_MODEL_FILES or name in seen
                    or type(size) is not int or size <= 0
                    or type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                _fixed_error("MANIFEST_INVALID")
            seen.add(name)
            pin = active_pins[name]
            file_path = root / name
            data = file_path.read_bytes()
            if len(data) != pin.size_bytes or _sha(data) != pin.sha256:
                _fixed_error("MODEL_DIGEST_INVALID")
            if size != pin.size_bytes or digest != pin.sha256:
                _fixed_error("MANIFEST_INVALID")
            rows.append((name, size, digest))
        if seen != EXPECTED_MODEL_FILES:
            _fixed_error("MANIFEST_INVALID")
        return PilotManifest(MODEL_REPOSITORY, MODEL_REVISION, MODEL_LICENSE,
                             tuple(sorted(rows)), _sha(_canonical(value)))
    except PilotError:
        raise
    except Exception:
        _fixed_error("MANIFEST_INVALID")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fixed_error("MANIFEST_INVALID")
        result[key] = value
    return result


def validate_query(query: str, category: baseline.QueryCategory,
                   evidence: baseline.SafeEvidence) -> str | None:
    """Reuse the lexical baseline's closed question/refusal gates unchanged."""
    if type(category) is not baseline.QueryCategory or type(evidence) is not baseline.SafeEvidence:
        return "INVALID_REQUEST"
    reason = baseline._query_refusal(query)
    if reason:
        return reason
    if not baseline._evidence_matches(category, evidence):
        return "EVIDENCE_CATEGORY_MISMATCH"
    tokens = baseline.tokenize(query)
    if not (baseline._CATEGORY_TERMS[category] & set(tokens)):
        return "EVIDENCE_CATEGORY_MISMATCH"
    return None


class LocalEmbeddingRuntime:
    """Minimal inference wrapper; model and vectors are process-local only."""

    def __init__(self, model_dir: Path):
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer

            self._torch = torch
            torch.set_num_threads(1)
            torch.set_num_interop_threads(1)
            torch.use_deterministic_algorithms(True)
            self._tokenizer = AutoTokenizer.from_pretrained(
                str(model_dir), local_files_only=True, trust_remote_code=False, use_fast=True,
            )
            self._model = AutoModel.from_pretrained(
                str(model_dir), local_files_only=True, trust_remote_code=False,
                use_safetensors=True, dtype=torch.float32,
            ).to("cpu")
            self._model.eval()
        except PilotError:
            raise
        except Exception:
            _fixed_error("MODEL_RUNTIME_INVALID")

    def encode(self, texts: tuple[str, ...], *, query: bool):
        if type(texts) is not tuple or not 1 <= len(texts) <= MAX_PASSAGES:
            _fixed_error("INPUT_INVALID")
        limit = MAX_QUERY_BYTES if query else MAX_PASSAGE_BYTES
        if any(type(text) is not str or len(text.encode("utf-8")) > limit for text in texts):
            _fixed_error("INPUT_INVALID")
        try:
            torch = self._torch
            prefix = "query: " if query else "passage: "
            inputs = self._tokenizer([prefix + text for text in texts], padding=True,
                                     truncation=True, max_length=MAX_TOKENS,
                                     return_tensors="pt")
            if inputs["input_ids"].shape[1] > MAX_TOKENS:
                _fixed_error("INPUT_INVALID")
            with torch.inference_mode():
                output = self._model(**inputs)
                hidden = output.last_hidden_state
                mask = inputs["attention_mask"].unsqueeze(-1).to(hidden.dtype)
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
                normalized = torch.nn.functional.normalize(pooled, p=2, dim=1)
            if normalized.shape[1] != 384 or not torch.isfinite(normalized).all():
                _fixed_error("MODEL_RUNTIME_INVALID")
            return normalized
        except PilotError:
            raise
        except Exception:
            _fixed_error("MODEL_RUNTIME_INVALID")

    def close(self):
        # Python/OS memory is released normally; this is not a secure wipe.
        try:
            del self._model
            del self._tokenizer
            self._torch = None
        except Exception:
            _fixed_error("MODEL_RUNTIME_INVALID")


def rank_cosine(rows: tuple[RankedSection, ...], *, threshold: float,
                top_k: int = MAX_TOP_K) -> tuple[RankedSection, ...]:
    try:
        if (type(rows) is not tuple or type(top_k) is not int or not 1 <= top_k <= MAX_TOP_K
                or type(threshold) not in {float, int} or not math.isfinite(threshold)
                or threshold < 0):
            _fixed_error("INPUT_INVALID")
        seen = set()
        output = []
        for row in rows:
            if type(row) is not RankedSection:
                _fixed_error("SCORE_INVALID")
            key = (row.document_id, row.section_id)
            if (type(row.document_id) is not str or type(row.section_id) is not str
                    or key in seen or type(row.score) not in {int, float}
                    or not math.isfinite(row.score) or row.score < 0 or row.score > 1):
                _fixed_error("SCORE_INVALID")
            seen.add(key)
            score = round(float(row.score), 6)
            if score >= threshold:
                output.append(RankedSection(row.document_id, row.section_id, score))
        output.sort(key=lambda item: (-item.score, item.document_id, item.section_id))
        return tuple(output[:top_k])
    except PilotError:
        raise
    except Exception:
        _fixed_error("SCORE_INVALID")


def fuse_rrf(lexical: tuple[tuple[str, str], ...],
             embedding: tuple[tuple[str, str], ...], *,
             top_k: int = MAX_TOP_K) -> tuple[RankedSection, ...]:
    try:
        if (type(lexical) is not tuple or type(embedding) is not tuple
                or type(top_k) is not int or not 1 <= top_k <= MAX_TOP_K
                or len(lexical) > MAX_TOP_K or len(embedding) > MAX_TOP_K):
            _fixed_error("INPUT_INVALID")
        scores: dict[tuple[str, str], float] = {}
        for rows in (lexical, embedding):
            if len(set(rows)) != len(rows):
                _fixed_error("SCORE_INVALID")
            for rank, key in enumerate(rows, 1):
                if (type(key) is not tuple or len(key) != 2
                        or any(type(part) is not str for part in key)):
                    _fixed_error("SCORE_INVALID")
                scores[key] = scores.get(key, 0.0) + 1.0 / (RRF_CONSTANT + rank)
        ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
        return tuple(RankedSection(doc, section, score) for (doc, section), score in ordered[:top_k])
    except PilotError:
        raise
    except Exception:
        _fixed_error("SCORE_INVALID")


def build_candidate_citations(rows: tuple[RankedSection, ...], corpus,
                              corpus_digest: str) -> tuple[CandidateCitation, ...]:
    if corpus_digest != corpus.digest:
        _fixed_error("CORPUS_DIGEST_MISMATCH")
    try:
        sections = {(item.document_id, item.section_id): item for item in corpus.sections}
        citations = []
        for row in rows:
            section = sections.get((row.document_id, row.section_id))
            if section is None or not section.approved:
                _fixed_error("CITATION_INVALID")
            citations.append(CandidateCitation(
                document_id=section.document_id, section_id=section.section_id,
                title=section.title, excerpt=section.text, score=row.score,
                source_ref=section.source_ref,
            ))
        return validate_candidate_citations(tuple(citations), corpus, requested_top_k=MAX_TOP_K)
    except PilotError:
        raise
    except Exception:
        _fixed_error("CITATION_INVALID")


def validate_candidate_citations(citations: tuple[CandidateCitation, ...], corpus,
                                 *, requested_top_k: int) -> tuple[CandidateCitation, ...]:
    """Verify identity, exact approved text, digest-bound corpus and safe reference."""
    try:
        if (type(citations) is not tuple or type(requested_top_k) is not int
                or not 0 <= len(citations) <= requested_top_k <= MAX_TOP_K):
            _fixed_error("CITATION_INVALID")
        entries = {(item.document_id, item.section_id): item for item in corpus.sections}
        keys = [(item.document_id, item.section_id) for item in citations]
        if len(keys) != len(set(keys)):
            _fixed_error("CITATION_INVALID")
        order = sorted(citations, key=lambda item: (-item.score, item.document_id, item.section_id))
        if tuple(order) != citations:
            _fixed_error("CITATION_INVALID")
        for item in citations:
            if type(item) is not CandidateCitation:
                _fixed_error("CITATION_INVALID")
            section = entries.get((item.document_id, item.section_id))
            if (section is None or not section.approved or item.title != section.title
                    or item.source_ref != section.source_ref or item.excerpt != section.text
                    or _sha(item.excerpt.encode("utf-8")) != section.content_digest
                    or len(item.excerpt.encode("utf-8")) > baseline.MAX_SECTION_BYTES
                    or not math.isfinite(item.score) or item.score < 0):
                _fixed_error("CITATION_INVALID")
            if item.source_ref.startswith("https://") and any(
                    part in item.source_ref for part in ("?", "#", "@")):
                _fixed_error("CITATION_INVALID")
        return citations
    except PilotError:
        raise
    except Exception:
        _fixed_error("CITATION_INVALID")
