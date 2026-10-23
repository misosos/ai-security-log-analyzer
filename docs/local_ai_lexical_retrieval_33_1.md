# Phase 33.1 — 결정적 로컬 지식 검색·citation baseline

**상태: internal/test-only baseline 구현·검증 완료.** 검색 결과는 승인 문서의 근거 후보이며 AI 답변이나 권위 있는 분석 결과가 아니다. LLM, embedding, Ollama, llama.cpp, vector DB, 외부 요청은 사용하지 않았다. Gemini helper는 별도 경로로 남아 있으며 변경하지 않았다. 이 모듈은 production API·SSE·UI와 연결되지 않았고 자연어 답변·자동 보고서를 생성하지 않는다.

## 범위와 데이터 흐름

```text
allowlist-only SafeEvidence + bounded question/category
  → pinned static corpus and process-local lexical index
  → bounded BM25 section candidates
  → manifest/corpus/score/order citation validation
  → closed RetrievalResult (or fixed refusal code)
```

기존 detector, correlation, risk, case 결과는 읽기 전용 입력이다. 검색 결과로 이를 바꾸거나 새 사실을 만들 수 없다. AI/검색이 비활성인 기본 analyzer의 실행 경로는 변경되지 않았다.

## Safe evidence DTO

`SafeEvidence`는 frozen dataclass다. 생성자는 `SourceRole`, `Completeness` enum과 exact tuple만 받으며 dict·list·임의 iterable·추가 keyword를 거부한다. detection/relation/case 표시명, risk/confidence는 고정 allowlist만 허용한다. aggregate key도 승인된 다섯 이름, 값은 exact integer 0–1,000,000이다. session-local ID는 `s_` 뒤 16개 소문자 영숫자이고, 시간 범위는 최대 7일, 각 tuple과 전체 canonical serialization에도 상한이 있다.

`build_safe_evidence()`는 합성/internal 기존 결과에서 허용된 결과 flag·level만 복사한다. raw mapping을 저장하지 않으며 새 analyzer 계산을 수행하지 않는다. 원본 account/IP/hostname/path/query/raw line/rationale/evidence/checkpoint/internal identity/exception/HOME/config 경로는 필드로 존재하지 않는다. 고정 오류는 `INVALID_EVIDENCE`이며 예외 문자열을 담지 않는다. JSON helper는 허용 DTO만 직렬화하고 임의 dict를 받지 않는다. canary는 생성, `repr`, `asdict`, JSON, 오류 표면에 나타나지 않는지 검사한다.

## Corpus·manifest integrity

정적 corpus는 [corpus.json](../app/knowledge_corpus_33_1/corpus.json)에 18개 문서, 18개 section으로 들어 있다. 내용은 프로젝트 규칙·한계와 짧은 검토된 upstream 요약이다. 포함 주제는 Brute Force, Password Spraying-like, 실패 후 성공 관계, risk/confidence, risk 하향, 관계 소멸, case, application/SSH 역할, replay gap, checkpoint reset, privacy, operator 후속 확인, incomplete/no finding, conflicting evidence, ATT&CK 분류, NIST incident response, OWASP safe logging이다.

각 문서에는 stable document ID, section ID, title, `PROJECT`/`UPSTREAM_SUMMARY` source type, repo path 또는 HTTPS source, upstream version/date, license·attribution, approved topic, review status가 있다. section별 SHA-256과 corpus file SHA-256, 승인 상태, manifest/corpus digest는 [manifest.json](../app/knowledge_corpus_33_1/manifest.json)에 있다. 전체 corpus digest는 `fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6`로 runtime 코드에도 고정되어 있다.

Runtime은 고정 승인 디렉터리만 읽는다. UTF-8 strict, LF/final newline, regular file, no symlink, 파일 집합 exact match, 문서·section ID 중복 거부, manifest에 없는 파일·추가 JSON field·digest 불일치·비승인 상태·빈/과대 corpus·section을 거부한다. 문서 순서는 JSON 배열과 manifest 배열에 pin되며 tie-break는 ID를 사용한다. corpus는 최대 64 KiB, section 최대 128개, 문서당 section 최대 16, section 최대 1,536 UTF-8 bytes/256 tokens, index 최대 512,000 estimated resident bytes다. private path, credential/IP/email, HTML/script·위험 URL·일부 injection marker도 loader에서 차단한다.

Manifest는 runtime에서 고치지 않는다. 명시적 개발 명령 `uv run python -m tools.build_local_knowledge_manifest_33_1 --write`만 manifest를 새로 쓴다. 내용을 승인해 변경하면 새 digest를 검토하고 코드의 `TRUSTED_CORPUS_DIGEST` pin도 명시적으로 함께 갱신해야 한다. 변경된 manifest만으로는 runtime 통과하지 않는다. 생성기와 loader는 별도 entry point다.

Upstream 요약은 긴 원문을 복사하지 않았다. [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)의 v2.8 (2026-05-12 수정) 분류를 단순 표시명으로 요약하고 탐지 증거로 쓰지 않는다. [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)은 2025-04 발행 자료의 조사 범위·검증 원칙만 짧게 요약했다. [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)는 충분한 조사 맥락과 민감 데이터 최소화를 요약했다. License·attribution은 manifest source metadata에 기록했다.

## 질문·tokenization·ranking 계약

허용 category는 `EXPLAIN_DETECTION`, `EXPLAIN_RELATION`, `EXPLAIN_RISK`, `EXPLAIN_CASE`, `NEXT_CHECKS`, `EXPLAIN_RECOVERY_STATE`, `EXPLAIN_LIMITATION`뿐이다. 질문은 256 Unicode code point, 1,024 UTF-8 bytes, 64 raw lexical tokens 이내다. NFKC 정규화가 원문을 바꾸는 호환 문자는 거부한다. 질문은 고정 승인 어휘집에 있는 token만 허용하며 account/IP/hostname/path/query/raw/private request, 위험한 명령·역할 위조·공격 성공 단정 요청은 결과를 echo하지 않고 고정 refusal로 끝난다. 질문 intent token과 category, safe evidence category가 맞지 않아도 거부한다. 질문을 실행하거나 prompt로 보내지 않는다.

Tokenizer는 Python Unicode letter/number run에서 underscore와 punctuation을 분리하고 NFKC 후 casefold한다. Hangul token은 원 단어와 `ko2:` prefix를 붙인 인접 2음절 bigram을 함께 사용해 조사·어미 일부가 붙은 질문의 overlap을 돕는다. 영문 stemming·언어 모델·locale 동작은 없다. 고정 stopword 목록은 `_STOPWORDS`이며 SHA-256 `91d498b9f40152dba3767371296a93f2fee682eb6bfc8742fd41859e6bf45115`다. 목록 변경은 code/test와 평가 기준선 변경을 요구한다.

검색은 section 단위 BM25를 사용한다. 각 query term은 한 번만 점수에 반영한다. 사용 공식은

```text
IDF(t) = ln(1 + (N - df(t) + 0.5) / (df(t) + 0.5))
score(D,Q) = Σ IDF(t) · tf(t,D)·(k1+1) /
             (tf(t,D) + k1·(1-b + b·|D|/avgdl))
k1 = 1.2, b = 0.75
```

`N`은 section 수, `df`는 token이 등장하는 section 수, `|D|`와 `avgdl`은 stopword 제거 후 tokenizer token 수다. 이 값과 threshold `2.2`는 corpus digest를 고정한 개발 평가 heuristic이지 보편 relevance 기준이 아니다. 점수는 finite·non-negative여야 하며 threshold 미만이면 결과로 내지 않는다. 최대 top-k는 5, 기본은 5다. 정렬은 score 내림차순, 동점 document ID·section ID 오름차순이다. 시간대/locale/current time은 사용하지 않는다.

## Citation과 result 검증

닫힌 Pydantic `RetrievalResult`는 schema version, query category, corpus digest, status, citation tuple, fixed refusal code만 갖는다. Citation에는 manifest에 존재하는 document/section ID, title, bounded approved excerpt, BM25 score, repo-relative Markdown path 또는 HTTPS source reference가 있다. 결과 검증은 현재 corpus digest, exact section content hash, source/title 일치, 승인 여부, top-k, 중복, score finite/positive, ranking order를 확인한다. 결과에 query나 evidence는 저장되지 않는다. 임의 HTML/URL은 renderer가 없고 source reference allowlist만 통과한다.

모든 사실 주장의 모델은 아직 없으며 반환되는 것은 인용 후보뿐이다. 따라서 citation precision은 합성 fixture에서 expected section ID와 비교한다. 구조/존재/해시 검증은 semantic support를 자동 증명하지 않는다. 다른 corpus digest에서 생성한 과거 result는 현재 결과로 재검증되지 않는다.

## 테스트와 평가 결과

변경 전 전체 회귀 기준선은 `2531 passed, 2 warnings`였다. Test-first 계약은 구현 전 새 모듈 import 부재로 collection 실패했다. 개발 중 DTO extra field, 요청 거부, corpus/data bounds와 모델-copy 추가 필드 검증에서 회귀 실패를 각각 확인하고 수정했다.

Focused test는 **34 passed**다. 합성 retrieval evaluation은 17개 fixture이며 현재 결과는 다음과 같다.

| Metric | Result |
| --- | ---: |
| expected citation hit | 11/11 |
| citation precision / completeness | 0.941 / 1.000 |
| unsupported citation | 0 |
| refusal failures | 0 |
| privacy leakage | 0 |
| schema validation | 100% |
| authoritative mutation / injection execution | 0 / 0 |
| repeated result JSON | byte-identical |

고정 합성 평가에서 17 citation 중 16개가 그 query fixture의 사전 정의 관련 document set에 포함됐다. 남은 1개는 실패 후 성공 query에 relation lifecycle 문서가 함께 검색된 경우다. 이는 현재 lexical retrieval의 과잉 인용 사례로 남기며 검색 결과를 답변처럼 해석하지 않는다. 이 평가는 고정 합성 corpus의 retrieval 계약만 검사하며 LLM 설명 품질, SOC 운영 탐지율, 운영 입력 일반화는 측정하지 않는다. 다음 명령은 test-only 평가를 실행한다.

```bash
uv run pytest -q tests/test_local_lexical_retrieval_33_1.py
uv run python -m tests.benchmark_local_retrieval_33_1
```

Benchmark는 20회 warm-up 후 operation마다 200 표본을 기록한다. 2026-10-23, macOS Apple Silicon 개발 host, Python 3.12에서 측정한다. 아래 값은 해당 실행 표본의 ms이며 운영 SLA/최악 지연 보장이 아니다.

| Operation | Median | p95 | Max | Payload bytes |
| --- | ---: | ---: | ---: | ---: |
| corpus load/verify | 2.0489 | 2.1405 | 2.3969 | 0 |
| index build | 0.9877 | 1.0170 | 1.1178 | 0 |
| single search | 0.1023 | 0.1065 | 0.1131 | 742 |
| top-k search | 0.1084 | 0.1141 | 0.1971 | 1,402 |
| refusal | 0.0092 | 0.0096 | 0.0122 | 212 |
| citation validation | 0.0123 | 0.0125 | 0.0128 | 1,402 |
| adapter → retrieval | 0.1354 | 0.1638 | 0.4892 | 742 |

측정 corpus는 18 docs/18 sections/14,833 bytes, index estimated resident size는 25,279 bytes, digest는 `fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6`였다. Process-local index는 사용자 입력이나 로그를 저장하지 않는다.

## Fault·privacy·determinism

| Fault/공격 | 검증된 동작 |
| --- | --- |
| corpus/manifest 누락, 추가 파일, 잘못된 JSON/UTF-8, digest mismatch | fixed `CORPUS_INVALID`; 경로/예외 원문 없음 |
| duplicate document/section ID, symlink, oversized file/section | fixed corpus refusal; auto repair 없음 |
| permission/read failure | 고정 “Approved knowledge is unavailable.” 오류 |
| oversized/private/control/confusable/injection query | query echo 없이 고정 refusal; 검색·실행 없음 |
| tokenizer/index/score serialization fault | 고정 request/result/corpus error code; exception canary 미노출 |
| unknown/duplicate/forged citation, wrong corpus digest/order | result validation 거부 |
| UTC/Asia/Seoul/repeat | canonical result JSON byte 동일 |

합성 canary는 account, IP, hostname, absolute path, raw line, email, query, exception, private model-copy field를 포함한다. Public API/SSE/UI에는 이 모듈이 연결되지 않으며 HTTP/OpenAPI 표면도 바뀌지 않았다. Trusted analyzer 입력에는 분석에 필요한 원본이 존재할 수 있으나 adapter의 DTO·retrieval 출력으로 복사되지 않는 것이 이번 계약이다.

## Phase 경계와 다음 단계

- **33.0:** 설계·위협 모델·기존 Gemini 감사. Gemini helper는 IP-containing projection과 자유 문자열 응답을 쓰며 여전히 별도·미연결이다.
- **33.1:** safe evidence, approved static corpus, manifest pin, deterministic lexical retrieval/citation baseline. 현재 단계다.
- **33.2A:** 정적 embedding/runtime 공급망 gate. [조사 기록](local_embedding_supply_chain_gate_33_2a.md)은 E5-small을 조건부 후보로만 선정했으며 다운로드·실행을 승인하지 않는다.
- **33.2B:** [E5-small 합성 pilot](local_embedding_retrieval_pilot_33_2b.md)은 완료했다. Embedding-only completeness가 lexical보다 낮았고 hybrid는 lexical을 개선하지 않아 lexical 기준선을 유지한다. Model/API/UI에는 연결하지 않는다.
- **33.3:** 구조화 local LLM 설명 pilot은 별도 gate 이후다.

Production API·SSE·UI, 자연어 답변, external AI, 사용자 로그 corpus/query, Gemini 교체, production embedding integration, runtime install, automatic report generation은 미구현이다. Phase 33.2B 모델/runtime은 test-only 임시 환경에서 실행한 합성 비교에 한정된다.
