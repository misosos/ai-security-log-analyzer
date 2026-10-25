import json
from pathlib import Path

from app.local_retrieval_33_1 import (
    TRUSTED_CORPUS_DIGEST,
    generate_manifest,
    load_corpus,
)


ROOT = Path(__file__).resolve().parents[1]


def test_phase_33_1_docs_keep_internal_only_and_ai_roadmap_boundaries():
    record = (ROOT / "docs/local_ai_lexical_retrieval_33_1.md").read_text()
    design = (ROOT / "docs/local_ai_investigation_assistant_33_0.md").read_text()
    readme = (ROOT / "README.md").read_text()
    index = (ROOT / "docs/index.md").read_text()
    for text in (
        "internal/test-only baseline 구현·검증 완료",
        "검색 결과는 승인 문서의 근거 후보이며 AI 답변이나 권위 있는 분석 결과가 아니다",
        "k1 = 1.2", "91d498b9f40152dba3767371296a93f2fee682eb6bfc8742fd41859e6bf45115",
        "TRUSTED_CORPUS_DIGEST",
        "citation precision", "33.2A:", "33.2B:", "Gemini helper",
        "운영 SLA/최악 지연 보장이 아니다",
    ):
        assert text in record
    assert "local_ai_lexical_retrieval_33_1.md" in design
    assert "Phase 33.1의 결정적 lexical retrieval은 조사 사례 안에서 사용자가 요청할 때만" in readme
    assert "local_investigation_guidance_33_4.md" in readme
    assert "local_ai_lexical_retrieval_33_1.md" in index


def test_corpus_manifest_generation_is_explicit_deterministic_and_pinned():
    manifest_path = ROOT / "app/knowledge_corpus_33_1/manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    assert manifest_bytes == generate_manifest()
    manifest = json.loads(manifest_bytes)
    assert manifest["corpus_digest"] == TRUSTED_CORPUS_DIGEST
    corpus = load_corpus()
    assert corpus.digest == TRUSTED_CORPUS_DIGEST
    assert len({section.document_id for section in corpus.sections}) == 18
    assert len(corpus.sections) == 18
