# Phase 36.1 — deterministic investigation triage reference

Phase 36.2는 이 DTO와 priority 기준선을 변경하지 않고, category별 직접 citation이 확인된 내부 checklist를 추가했습니다. 구체적인 지원 category, fixed refusal, 구조/의미 평가 및 사용자 검수 상태는 [Phase 36.2 기록](lexical_investigation_checklist_36_2.md)을 참조하십시오.

후속 상태: Phase 36.3은 이 기준선을 변경하지 않고, 명시적인 사례 상세 POST 요청에만 내부 검토 priority를 별도 응답 필드로 제공합니다. source role 정보가 없는 사례의 priority는 계속 `undetermined`이며 기존 risk는 그대로 둡니다. API/UI 경계와 제한은 [Phase 36.3 기록](investigation_checklist_api_ui_36_3.md)에 있습니다.

## Decision

**Status: `PHASE_36_2_READY` for the deterministic internal reference contract only.** 시작 SHA `ee2d595d18119f3c217a8d39e5a16d348750c2a0`의 push run `40473731051`은 정확한 SHA에서 `completed/success`였고 artifact 0개였다. 기존 `v0.4.0` tag/release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`을 유지했다. 구현 TDD는 새 module import 부재로 인한 초기 collection 실패에서 시작했다. 이번 단계는 기존 deterministic 분석 결과를 그대로 두고 내부 호출용 review assistance 기준선을 추가한다. 이 기능은 보안 사실 판정, 탐지, 위험도 계산 또는 대응 권한이 아닙니다. 우선순위는 **검토 순서를 정하기 위한 프로젝트 휴리스틱**입니다.

## Scope and evidence boundary

- 모델, provider, Gemini, embedding, Ollama, 네트워크, 파일 입력, subprocess를 호출하지 않습니다.
- API, OpenAPI, SSE, UI, HTML report, 일반 CLI 경로와 연결하지 않습니다.
- checkpoint, queue, publication, detection, relation, risk, case를 쓰지 않습니다.
- The reference must not modify authoritative analysis, publication, checkpoint, or SSE state.
- 실제 사용자 자료와 조직 운영은 `NO_GO`; 자동 대응도 구현하지 않습니다.
- Phase 35.4B Vector/VM 보류와 독립된 변경입니다. 이 단계는 Vector 실행이나 안전성을 검증하지 않습니다.
- 평가 fixture는 합성 전용입니다. 한국어 문장 의미 품질은 자동 PASS가 아니며 별도 수동 검수가 필요합니다.

## SafeInvestigationDTO

`app/investigation_triage_36_1.py`의 frozen, slots 기반 `SafeInvestigationDTO`는 다음 닫힌 key만 받습니다: `schema_version`, request-scoped opaque `request_id`와 `case_ref`, `source_role`, 관찰 category, detection/relation code, 기존 context에서 제공된 risk band, bounded case/count/time bucket, completeness, limitation code, 검증된 citation ID, Phase 33.1 corpus digest.

unknown/missing key, 허용되지 않은 enum, bool-as-int, duplicate list item, 과도한 문자열/list, 잘못된 opaque reference, corpus digest 불일치를 고정 오류로 거부합니다. 원문, 계정, IP, hostname, 경로, 정확한 시각, checkpoint, 자유 질문, rationale, credential, URL, HTML, 임의 metadata는 DTO에 넣지 않습니다. repr와 예외는 입력을 반사하지 않습니다. ID는 request scope의 불투명 참조이며 안정적인 cross-case 식별자로 사용하지 않습니다.

## Priority reference

결과의 review priority는 기존 risk score/band와 별도입니다. 계산은 source/observation category, detection/relation code 및 evidence completeness만 사용합니다. risk band, count/time bucket, case status는 priority 계산에 영향을 주지 않습니다.

| 조건 | 제안 |
|---|---|
| unknown source/category 또는 conflicting/unknown evidence | `undetermined` |
| partial evidence | `review_soon` |
| 기존 relation 또는 supported detection code | `review_soon` |
| supported observation만 있고 충분한 evidence | `review_later` |
| 컨텍스트 없음 | `undetermined` |

현재 정책은 `review_now`를 내지 않습니다. 우선순위는 위험도, 침해 여부, 사건의 긴급성, 운영 대응 시한을 뜻하지 않습니다. 반복 횟수나 위험 band로 긴급도를 추론하지 않습니다.

## Retrieval and checklist

승인된 Phase 33.1 lexical corpus와 corpus digest 및 citation verifier를 재사용합니다. embedding, vector DB, 웹 검색, 사용자 사례의 corpus 영구 추가는 없습니다. checklist는 시간/자료 coverage, 관찰 맥락, relation 순서, 상충 근거 확인 같은 정적 검토 문장만 제공합니다. 명령 실행, 차단·잠금, 자동 티켓, case 종료 또는 분석 변경은 없습니다.

각 출력 claim은 고정 문구/code allowlist와 입력 DTO에서 검증된 citation subset을 통과해야 합니다. citation은 절차·기술 근거이지 해당 사건에서 행위가 발생했다는 증거가 아닙니다. category가 맞지 않는 citation은 거부합니다. Phase 33.1의 과잉 citation 회귀 사례 `relation-gone:not-resolved`는 기준선에서 제거하지 않았으며, 이 adapter의 relation 출력 후보로 쓰지 않습니다. 구조적 citation 검증은 citation이 문장 의미를 충분히 뒷받침하는지 평가하는 일을 대신하지 않습니다.

## Output contract

출력은 닫힌 `investigation-assistance/v1` key 순서와 함께 `schema_version`, request/case reference, review priority, citation이 달린 priority reasons, 조사 단계, 설명, uncertainty, limitation codes, `generated_by=deterministic_reference`, status를 포함합니다. 전체 JSON은 8 KiB, 이유 4개, 단계 5개, uncertainty 4개, distinct citation 8개, 각 text 512 UTF-8 bytes 이하입니다. duplicate key, NaN/Infinity, unknown/missing key, bool-as-int, 잘못된 enum, 중복 list, HTML/Markdown link/URL, command-like text, 식별자 형태, control/bidi 문자는 전체 응답 거부를 일으킵니다. 부분 허용이나 자동 repair는 없습니다. `refused`와 `unavailable`은 claim이 없는 고정 결과입니다.

## Research Basis

- NIST SP 800-61 Rev. 3 (2025)는 incident response를 조직 위험관리와 연결합니다. 이에 따라 이 reference는 조직 맥락을 알지 못한 채 “지금 대응”을 결정하지 않고, 단지 analyst review 순서를 보조합니다. [NIST publication](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- MITRE ATT&CK DET0463은 brute-force 탐지 전략을 관측 가능한 인증 실패 telemetry에 연결합니다. 이 DTO는 원시 이벤트/정확한 시간창을 받지 않으므로 외부 탐지 threshold를 복사하거나 공격 성공을 추정하지 않습니다. [MITRE detection strategy](https://attack.mitre.org/detectionstrategies/DET0463/)
- NIST AI 600-1, OWASP Prompt Injection, Improper Output Handling, Vector and Embedding Weaknesses는 instruction/data 분리, 출력 검증, retrieval poisoning 위험을 검토하는 설계 근거입니다. 이 구현은 모델을 호출하지 않으며 이 통제들이 향후 모델 준수를 보장한다고 주장하지 않습니다. [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf), [OWASP prompt injection](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html), [OWASP improper output handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/), [OWASP vector and embedding weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/).
- Project evidence: Phase 33.1 lexical corpus/verifier and Phase 33.4 guidance are the only retrieval basis. The existing over-citation behavior remains a regression case.

These official sources and project contracts were checked on 2026-10-27. They inform the design but are not runtime/provider tests.

## Observable Evidence Mapping

The DTO accepts only already-normalized role/category/code/completeness buckets. It does not ingest events, identifiers, timestamps, or rationale and therefore cannot create a detection or assert an attack outcome. Supported relation/detection codes are copied as categories for review context only. Missing or conflicting evidence maps to `undetermined`; the incomplete state suggests coverage review. No event threshold, time window, or risk criterion is introduced.

## Evaluation contract

`tests/fixtures/investigation_triage_36_1.json` contains 44 synthetic cases covering supported categories, uncertainty, privacy canaries, invalid DTO/output, citation mismatch, prompt injection, output limits and concurrency. `tests/evaluate_investigation_triage_36_1.py` runs the deterministic reference; `tests/benchmark_investigation_triage_36_1.py` measures it separately. Required counts include schema validation, deterministic refusal, citation completeness, privacy/tool/injection checks, analysis mutation and benign-control false refusal. An empty output or blanket refusal does not count as success. Korean semantic quality remains `NOT_TESTED` pending human review.

Evaluation on this finite fixture set: schema 100%, deterministic refusal 100%, fixed unavailable outcomes 2, citation precision/completeness 100%, privacy leaks 0, tool/action execution 0, injection execution 0, analysis mutation 0, benign-control false refusal 0%, and priority agreement with the fixture reference 100%. These are contract counts on synthetic fixtures, not effectiveness or security detection accuracy.

Phase 36.2A human comprehension acceptance reviewed eight synthetic checklist outputs: final 8/8 PASS. Item 6 first failed because the actual refusal DTO omitted its reason, non-safety boundary, and next steps; after fixed refusal guidance was added to the DTO, the same fixture passed. See [acceptance record](investigation_checklist_acceptance_36_2a.md). This is not a production UI test or real-user-log acceptance.

### Development benchmark

`uv run python -m tests.benchmark_investigation_triage_36_1` used 10 warm-ups and 100 samples per operation on Darwin 24.6.0 arm64, Python 3.12.7. Input was 492 bytes, output 885 bytes, and the in-memory lexical index reported 25,279 estimated resident bytes.

| Operation | Median ms | p95 ms | Max ms |
|---|---:|---:|---:|
| DTO validation | 13.7944 | 14.3479 | 15.5625 |
| Priority | 0.0005 | 0.0005 | 0.0008 |
| Lexical retrieval + DTO | 27.2054 | 28.6009 | 28.9722 |
| Citation validation | 13.8754 | 14.8392 | 16.3650 |
| Output validation | 0.2238 | 0.2304 | 0.2532 |
| Full triage | 14.0863 | 14.7737 | 15.3862 |

These small local measurements are noisy, depend on the host, and are not an operational SLA or a production capacity claim.

## Verification record

- Focused Phase 36.1 tests and documentation contracts: 40 passed; UTC and Asia/Seoul each produced the same 40-pass result and `fixtures=44 schema=100 refusal=100 citation=100 privacy_leaks=0 analysis_mutation=0` evaluator summary.
- Full local regression: 3,003 passed, with the repository's two existing warnings.
- Existing synthetic analysis evaluations: 79/79, Linux 21/21, risk 70/70, case 70/70.
- `uv sync --locked --dev`, `uv lock --check`, `npm ci --ignore-scripts --no-audit --no-fund`, Python compilation, Node syntax check, and `git diff --check` passed. Chromium/axe reported 14 states and `external_requests=0`.
- A test-only benchmark used 10 warm-ups and 100 samples. Dependency manifests and lockfiles are unchanged.
- This is local evidence. The new SHA has not been pushed; no new Ubuntu CI result is claimed. Vector remains `USER_ACTION_REQUIRED` / `ISOLATION_BLOCKED` and was not run.

Analysis summaries, publication, checkpoint, SSE cursor and corpus digest must remain unchanged across use. These are internal synthetic tests; this module is not connected to those systems.

## Roadmap and limitations

- **36.2:** lexical retrieval and fixed checklist templates, only after citation semantic review, synthetic evaluation and privacy/invariance contracts pass.
- **36.3:** isolated model/provider comparison requires separate supply-chain, privacy and resource gates; no Gemini fallback.
- **36.4:** explicit user action and plain-text UI/API acceptance are separate future decisions; automatic requests remain prohibited.

Current limitations: no model quality assessment, no human comprehension review, no incident urgency/organization context, no production surface, no actual user data, no organization operation, no automated response. Actual user material and organizational operation remain `NO_GO`.
