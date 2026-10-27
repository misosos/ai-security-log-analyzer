# Phase 33.0 — 검증 가능한 로컬 AI 조사 도우미 설계 gate

후속 설계: [Phase 36.0 AI investigation triage](ai_investigation_triage_design_36_0.md)는 기존 33.x의 경계를 확장하지 않고 사례 검토 우선순위를 별도 설계했다. deterministic analysis는 계속 권위가 있고, 36.1은 LLM 없는 기준선부터 시작한다. Phase 35.4B Vector/VM 보류 상태와 독립이다.

**상태: 설계 gate 통과, 구현은 미시작.** 이 단계에서는 저장소·공식 문서 정적 조사와 설계만 했다. 모델, embedding, Ollama, llama.cpp, vector DB를 설치·다운로드·실행하지 않았고 dependency, lockfile, production 코드, API, UI, CI를 변경하지 않았다. 이 문서는 기능 활성화나 provider 호출 승인이 아니다.

## 제품 경계

### 권위 있는 결정 계층

Parser, detection, correlation, risk, case와 safe publication은 결정적 파이프라인의 권위 있는 결과다. AI가 이 결과를 만들거나 삭제·수정하지 않는다.

### 보조 계층

향후 보조 기능은 기존 결과를 쉬운 말로 설명하고, 승인된 보안 지식을 찾아 출처를 붙이며, 비실행형 다음 확인 항목·불확실성·한계를 제안하고, 조사 보고서 초안을 작성할 수 있다. 모든 화면과 내보내기에는 **“조사 보조 설명이며 탐지·위험도·조사 사례의 권위 있는 결과가 아닙니다.”**를 표시한다.

### 금지 권한

새 탐지 생성, 기존 탐지 삭제, risk·case 변경, 침해 성공 확정, 자동 차단·계정 잠금·파일 삭제, shell/tool 실행, 임의 파일·네트워크 접근, 원본 로그 RAG 색인, 외부 서비스 자동 전송은 금지한다. AI가 꺼져 있거나 실패해도 기존 분석과 safe publication은 그대로 완료되어야 한다.

## 기존 Gemini 경로 감사

코드 기준은 `app/analyzer/llm.py`, `app/analyzer/prompt.py`, `app/analyzer/legacy_api_projection.py`, `app/models/schemas.py`다. Lock에는 `google-genai==2.24.0`이 고정되어 있다. 아래 판정은 구현을 읽은 정적 감사이며 provider 호출이나 네트워크 검증은 하지 않았다.

| 항목 | 판정 | 근거와 한계 |
| --- | --- | --- |
| 입력 | PARTIAL | `build_llm_input()`은 legacy public projection을 사용하고 raw evidence/rationale 대부분을 제외한다. 각 결과의 `ip`와 전체 요약의 IP별 목록은 포함된다. approved projection에 user-derived display label·HTTP method·시간도 들어갈 수 있다. |
| 개인정보 | FAIL | 개별 helper와 전체 helper가 IP를 Gemini에 전송한다. 기존 canary 테스트는 account/raw/path/query/filename/exception을 검사하지만 IP 제외를 보장하지 않는다. |
| 출력 계약 | FAIL | prompt는 설명 형식을 지시하지만 `interaction.output_text`를 자유 문자열로 그대로 반환한다. JSON schema·citation·HTML/Markdown 검증은 없다. API의 `AnalysisResponse.ai_summary`는 `str | None`이지만 route는 현재 `None`을 반환한다. |
| 분석 결과 변경 권한 | PARTIAL | 현재 helper는 입력 mapping을 수정하지 않고 텍스트를 반환한다. 그러나 반환 문장은 별도 신뢰 경계가 없고 소비자가 권위 있는 값으로 오인하지 않도록 하는 DTO/UI 계약도 없다. |
| 외부 통신 | FAIL | `genai.Client`와 `client.interactions.create(model="gemini-3.6-flash", ...)`는 Google Gemini provider 호출이다. 이 경로는 로컬 전용이 아니다. |
| timeout/retry/fallback | PARTIAL | helper가 명시적 timeout/retry/fallback을 설정하지 않는다. SDK 기본값은 pinned SDK 버전에 종속되며 앱 계약으로 고정되지 않았다. 사용자 정의 fallback은 없다. |
| prompt injection | PARTIAL | `SYSTEM_PROMPT`는 결과만 설명하라는 다수 제한을 둔다. 입력과 지시를 기술적으로 격리하지 않으며 prompt restriction만으로 injection을 막지 못한다. |
| 오류·로그 노출 | NOT_TESTED | helper는 예외를 변환·기록하지 않고 그대로 전파한다. 호출자별 로그·오류 노출을 전체 추적하는 테스트는 확인되지 않았다. |
| 평가 | PARTIAL | projection privacy와 provider 미호출 경계 테스트는 있다. 모델 답변, citation, 거부율, 지연 및 privacy leakage 평가 자료는 없다. |
| 비활성 동작 | PASS (현 연결 범위) | 기본 API·CLI·UI에서 helper 호출을 찾지 못했고 API `ai_summary`는 `None`이다. 테스트가 provider 미호출을 확인한다. 직접 helper 호출은 환경변수와 provider 통신을 시도할 수 있다. |

이번 Phase에서는 Gemini 코드를 고치거나 활성화하지 않는다. 기존 privacy 테스트가 IP canary를 포함하지 않는다는 점은 새 로컬 DTO가 기존 helper까지 안전하게 만든다는 근거로 사용하지 않는다.

## 제안: 별도 closed safe evidence DTO

새 AI 입력은 기존 public DTO를 통째로 재사용하지 않고 allowlist 기반 별도 버전 DTO로 만든다. 후보 필드는 schema version, source role enum, 승인된 detection/relation/case 표시명, risk/confidence enum, 제한된 집계, 필요한 경우 coarse time delta/range, 공개용 session-local ID, completeness enum, 승인된 limitation ID뿐이다.

IP, account, hostname, path/query, raw line, evidence/rationale 원문, checkpoint metadata, 내부 object identity, exception text, HOME/config 위치는 금지한다. 임의 추가 필드는 거부한다. 문자열 길이, 각 배열 항목 수, 전체 UTF-8 byte와 token budget에 상한을 둔다. 직렬화는 명시적 allowlist로 하고 recursive `asdict`, `vars`, `repr` fallback은 사용하지 않는다. Synthetic canary는 DTO `repr`, `asdict` 경로가 있다면 그 결과, JSON, prompt rendering, 예외 및 로그를 검사한다.

정확한 수치 상한은 33.1 fixture·payload 측정에서 고정한다. 33.0에서 제시하는 모든 크기 제한은 구현 전 설계 후보이며 운영 기준이 아니다.

## 승인된 지식 corpus와 digest

첫 corpus는 저장소에 추적되는 작은 정적 문서 집합으로 한정한다: 프로젝트 탐지 설명, risk/case의 의미와 한계, 운영자 후속 로그 확인 지침, 검토·허가된 ATT&CK 요약, NIST/OWASP 상위 조사 원칙, 제품의 checkpoint/replay/privacy 한계. 외부 원문은 라이선스·인용 조건을 검토하고 필요한 승인된 요약만 저장소에 둔다.

실제 로그, monitor config, checkpoint, `.env`, credential, 개인 HOME 자료, 동적 웹 수집, 모델이 만든 자료, 사람이 검토하지 않은 외부 문서는 제외한다. 각 문서에 stable document ID, title, URL 또는 repo path, upstream version/date, local SHA-256, license/attribution, approval state, topics, last-reviewed date를 기록한다. corpus manifest와 개별 content digest가 일치하지 않으면 index를 사용하지 않고 명시적으로 재생성 또는 중지한다. 저장된 embedding index가 manifest보다 우선하지 않는다.

## 검색과 citation 계약

Phase 33.1은 외부 서비스·모델 없이 결정적 lexical/BM25 계열 baseline을 먼저 비교한다. 작은 corpus에는 vector DB가 필요하지 않다. process-local bounded index와 정적 문서 digest로 시작하고 지속 저장은 피한다. Embedding은 후속 별도 gate다.

검색 결과로 넘길 수 있는 것은 document ID, section ID, 길이 제한된 승인 문장, relevance score, corpus digest뿐이다. 초기 설계 상한 후보는 top-k 5, chunk 1,536 UTF-8 bytes 및 256 tokens, 전체 context 8,192 bytes 및 2,048 tokens다. 이는 측정 전의 공학적 상한 후보이며 보안 표준이나 운영 SLA가 아니다. Unicode 정규화와 tokenization/ranking은 고정하고 score 내림차순, 동점은 document ID와 section ID 오름차순으로 정렬한다. timezone·locale·현재 시각과 무관해야 한다.

점수 임계값은 33.1 합성 평가로 정하고 버전 관리한다. 임계 미달, digest 불일치, 근거 부족이면 거부한다. 충돌하는 승인 문서는 충돌을 명시하고 근거가 허용하지 않는 해석을 선택하지 않는다. 모델이 제시한 citation은 최종 manifest의 document/section ID와 digest를 대조해 검증하며 미존재 citation은 결과 전체를 거부한다. 모든 사실 주장은 citation에 연결한다. 검색 문장 안의 명령형 표현도 지시가 아닌 인용 데이터다. 결정적 검색은 재현성을 높일 뿐 의미적 근거 충분성을 자동 증명하지 않는다.

## 구조화된 출력 초안

닫힌 출력 객체 후보는 `schema_version`, `request_id`, 제한된 `summary`, citation이 붙은 `claims[]`, citation이 붙은 비실행형 `next_checks[]`, `uncertainty[]`, 승인된 `limitations[]`, enum `refusal_reason`, 안전한 model/runtime ID, `corpus_digest`다. citation에는 검증된 문서 ID·section ID만 둔다. 자유 HTML, raw Markdown link, script/style, shell command, 위험한 URL scheme, 내부 prompt/chain-of-thought, 개인정보 재구성, 새 detection/risk/case 필드는 허용하지 않는다.

애플리케이션은 schema·길이·enum·citation·digest를 모두 검증한 뒤 일반 텍스트로 렌더한다. 링크를 만들 경우 검증된 문서 ID를 애플리케이션이 고정 경로로 변환한다. 문법적 schema 검증은 주장을 사실로 만들지 않으므로 citation support 평가는 별도로 수행한다.

## Threat model

기준 자료: [OWASP Prompt Injection](https://genai.owasp.org/glossaries/prompt-injection/), [LLM03 Supply Chain](https://genai.owasp.org/llmrisk/llm032025-supply-chain/), [LLM04 Data and Model Poisoning](https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/), [LLM05 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/), [LLM08 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/), [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf). 예방책은 향후 검증할 설계이며 구현 증거가 아니다.

| 자산·위협 | 예방 | 탐지 | 실패 동작 | 잔여 위험 |
| --- | --- | --- | --- | --- |
| 로그 간접 prompt injection | raw 로그 모델·RAG 입력 금지; 엄격한 safe DTO | synthetic injection/canary scan | AI 답변 거부, 기존 분석 유지 | 승인 label에도 의미 조작 가능성 |
| RAG 문서 injection·corpus poisoning | 검토된 정적 문서, 코드리뷰, 출처·digest 승인 | manifest/hash/변경 검토 | 불일치 corpus 검색 중단 | reviewer 실수, upstream 문서 변경 |
| embedding inversion·membership inference | 첫 단계 lexical; 사용자 데이터 embedding 금지 | index 구성 검사·합성 canary | index 폐기/비활성 | 공개 지식 embedding도 모델별 누출 분석 필요 |
| retrieval manipulation | 고정 tokenizer·rank·tie-break, 승인 corpus만 | fixture top-k 결정성·충돌 case | 낮은 점수·충돌이면 거부 | lexical/embedding miss·편향 |
| 모델/runtime 공급망·악성 GGUF/tokenizer | 수동 출처 검토, 고정 release와 SHA-256, 격리 실행; 자동 fetch 금지 | 독립 hash·signature/provenance 확인 | artifact mismatch면 실행 금지 | 서명자/빌드 체인 침해, native parser 취약점 |
| Ollama/llama.cpp API·무인증 loopback | 브라우저 직접 접근 금지, loopback 또는 Unix socket, random local capability, Host/Origin/CSRF 검사, 기능 최소화 | 포트·요청·외부 bind 검증 | 접근 경계 불명확하면 AI 비활성 | 같은 OS 계정 프로세스, DNS rebinding 구현 결함 |
| 외부 egress·DNS rebinding·자동 다운로드 | 모델 준비와 실행 분리, egress deny, cloud·update·fetch 비활성 | network deny test, DNS/Host test | 단 한 건 예상 밖 egress면 NO-GO | OS/runtime background service와 운영자 설정 |
| HTML/Markdown injection·hallucinated citation | closed schema, plain text, ID allowlist, citation 후검증 | malformed/unknown citation fixture | 답변 전체 거부 | 자연어 인용의 의미적 부정확성 |
| 과대 context·resource exhaustion·동시 요청 | hard byte/token/time/RAM 상한, 동시 요청 1, retry 없음 | 최대 입력·timeout·동시성 시험 | 요청 거부/중단; 기존 분석 유지 | OS scheduler/GPU memory 예측 한계 |
| model timeout/crash | optional isolated worker/runtime, bounded call | health/timeout 상태 | AI unavailable; 분석 결과 보존 | crash dump·swap에 일시 입력 잔존 가능 |
| crash dump/swap/backup·prompt 로그 | prompt/output 기본 로그 금지, 지속 저장 금지, synthetic-only traces | 임시 경로·report scan | 노출 시 pilot 중단·자료 제거 절차 | secure erase 보장 불가 |
| 출력 개인정보·test report 잔존 | 출력 allowlist와 canary scan, 실패 메시지는 고정 code | stdout/stderr/JSON/trace scan | report/artifact 게시 금지 | 모델이 safe label을 식별정보로 조합할 가능성 |

Fail-closed는 DTO 위반, corpus/index digest 불일치, 미승인 문서, threshold 미달, citation mismatch, unknown schema/field, oversized input/output, HTML/위험 URL, timeout/crash, 런타임 접근 제어 불확실, egress 관측 중 하나라도 발생하면 AI 설명을 내지 않는 것이다. 감지·위험도·사례·status·기존 safe publication은 변경하거나 숨기지 않는다. 첫 pilot은 retry를 하지 않는다. 실패는 비민감 고정 code만 표시한다.

## Runtime·embedding 후보 정적 비교

2026-10-23에 공식 프로젝트 문서, release metadata와 model card를 확인했다. 설치·실행·artifact hash 다운로드 검증은 하지 않았다. “최신”은 조사 시점 표기이며 채택 이유가 아니다.

| 후보 | 정적 근거 및 평가 | 판정 |
| --- | --- | --- |
| Ollama runtime | [공식 release](https://github.com/ollama/ollama/releases/latest)는 stable v0.40.9 (2026-10-22) 표시. MIT, macOS Apple Silicon·Linux 지원. 기본 API는 `127.0.0.1:11434`, API 인증 없음; [FAQ](https://docs.ollama.com/faq)는 model pull의 Internet 사용, macOS/Windows 자동 업데이트, Linux install script, cloud 끄기 설정을 설명. [API](https://docs.ollama.com/api/introduction) cloud capability도 포함. [structured output](https://docs.ollama.com/capabilities/structured-outputs)은 schema constrained output을 제공하지만 앱 검증을 대체하지 않음. native runtime, model artifact 별도 라이선스/hash, egress/update 차단, 자원량, rollback 및 CI 오프라인 재현은 미검증. | CONDITIONAL GO — 격리·고정·수동 설치와 egress 검증 이후에만 검토 |
| llama.cpp runtime | [공식 release](https://github.com/ggml-org/llama.cpp/releases/latest)는 조사 시 stable v0.7.0 (2026-10-15; 더 새 prerelease는 stable로 취급하지 않음). MIT, C/C++ native, macOS/Ubuntu 빌드 가능. [server](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)는 schema 출력/embedding과 tool 관련 기능 지원. [security](https://github.com/ggml-org/llama.cpp/blob/master/SECURITY.md)는 untrusted model 격리와 hash 확인을 권고. 기본 local server 인증 없음; 모델은 별도 공급, helper script·artifact source/hash 고정 필요. 성능·RAM·GPU, binary reproducibility, installer와 rollback은 검증 안 됨. | CONDITIONAL GO — 최소 기능 server를 격리하고 tooling 비활성화한 뒤 재평가 |
| BGE family | [bge-small-en-v1.5](https://huggingface.co/BAAI/bge-small-en-v1.5) MIT, English; [BGE-M3](https://huggingface.co/BAAI/bge-m3) MIT, multilingual·큰 context 후보. Model card만으로 release hash/provenance/native runtime/설치·egress·자원·rollback을 고정하지 못함. | NOT_VERIFIED — 구체 snapshot/hash·license file 검토 필요 |
| E5 family | [e5-small-v2](https://huggingface.co/intfloat/e5-small-v2) MIT, English, 384 dimensions. Model ID로 loader를 쓰면 Hub fetch가 생길 수 있음. multilingual candidate와 exact artifact chain 미선택. | NOT_VERIFIED — artifact·loader offline 동작·자원 확인 전 보류 |
| sentence-transformers | [all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)는 Apache-2.0 English model; [library](https://github.com/huggingface/sentence-transformers/blob/main/pyproject.toml)는 Apache-2.0. Python stack의 PyTorch/Transformers/native dependency와 Hub model download, wheel hash·CI 크기·자원·rollback은 모델 선택 없이 확정 불가. | NOT_VERIFIED — dependency/lock 변경을 허용하는 후속 단계 전 보류 |
| 결정적 lexical/BM25 | 프로젝트 내부 정적 corpus에서 실행 가능; 모델·native runtime·외부 egress·자동 다운로드 없음. tokenizer/ranker 결정성, 품질·bounds는 33.1에서 검증 필요. | GO — 33.1 첫 baseline |
| 서버형 vector DB | 작은 정적 corpus에는 persistent service, network/auth, storage/backup, embedding 공급망이 불필요한 공격면을 더함. | NO-GO — 첫 pilot에 도입하지 않음 |
| process-local embedding index | 서버 DB보다 경계가 작지만 model/runtime/hash, persistence, inversion, retrieval 조작과 성능을 아직 검증하지 않음. | NOT_VERIFIED — lexical baseline과 비교 후에만 검토 |

모든 후보에서 license는 runtime/library와 모델 파일을 각각 확인해야 한다. 버전 이름만 고정한 것은 artifact hash 고정이 아니다. offline이라는 주장은 설치·최초 실행·업데이트·telemetry까지 network deny 실측 후에만 가능하다.

## Phase 33.1 synthetic 평가 계약

실제 사용자 자료 없이 고정 합성 fixture만 사용한다: brute force, password spray, failure 뒤 success, relation 소멸, risk 하향, replay gap, incomplete evidence, no finding, 충돌 문서, 근거 없는 질문, injection 문자열, 개인정보 추출 요청, 존재하지 않는 citation 유도, 과도한 context, timeout, malformed output. Fixture는 탐지 기대 결과와 설명 품질을 별도 축으로 기록한다.

측정값은 citation precision/completeness, unsupported claim rate, refusal correctness, privacy leakage count, schema validation success, deterministic retrieval, latency, memory, payload bytes다. 그럴듯함 평가나 AI 점수로 detector 성능을 대체하지 않는다.

33.1 진입 gate 후보: privacy leak 0; 존재하지 않는 citation 0; 출력 schema validation 100%; 권위 있는 분석 결과 mutation 0; injection fixture의 tool/command 실행 0; 근거 없는 질문의 올바른 거부; AI disabled 회귀 100%; corpus/index digest 고정 및 deterministic retrieval. Model/runtime digest와 egress 증명은 LLM 도입을 검토하는 33.3 전에 추가 gate다.

## 단계별 로드맵

| Phase | 범위 | Gate |
| --- | --- | --- |
| 33.0 | 설계·위협 모델·기존 Gemini 감사 | 이 문서; 구현 승인 아님 |
| 33.1 | 결정적 lexical retrieval baseline, citation 검증, 합성 평가; LLM 없음 | [구현·검증 기록](local_ai_lexical_retrieval_33_1.md); production API/UI 미연결 |
| 33.2A | 로컬 embedding 공급망·평가 gate 설계 | [정적 조사 기록](local_embedding_supply_chain_gate_33_2a.md); E5-small만 CONDITIONAL_GO, 실행 전 조건 미충족 |
| 33.2B | 한 후보의 합성 전용 격리 비교 | [E5-small pilot](local_embedding_retrieval_pilot_33_2b.md) 완료; production 연결은 NO_GO, memory hard cap·전용 VM isolation 근거 부족 |
| 33.3A | 구조화 local LLM 공급망·평가 설계 | [33.3A gate](local_llm_supply_chain_gate_33_3a.md); Qwen+llama.cpp 조건부 후보, 다운로드·실행 없음 |
| 33.3B/33.3C | 격리된 합성 설명 pilot 및 재시도 | [33.3B](local_llm_pilot_33_3b.md), [33.3C](local_llm_pilot_33_3c.md); 둘 다 `ISOLATION_BLOCKED`, model/runtime 미다운로드·미실행 |
| 33.3D | 사용자 제공 Ubuntu VM에서 실행 재시도 | [33.3D 기록](local_llm_pilot_33_3d.md); `SUPPLY_CHAIN_BLOCKED`, 사용자 VM 증거는 직접 검증하지 않았고 converter/runtime wheel closure 미고정으로 취득 전 중단 |
| 33.4 | injection·hallucination·privacy 독립 감사 | 독립 합성 공격 시험 통과 |
| 33.5 | UI opt-in·사용자 수용 | 별도 UX/privacy/접근성 검증 |
| 34.0 | River/PyOD anomaly detection shadow-mode 설계 | 별도 observable evidence·평가 설계 |

## Research basis, observable evidence, limitations

OWASP와 NIST 자료는 prompt injection, corpus/model poisoning, supply chain, output handling, embedding risk 및 GenAI risk management를 위협 분석에 사용했다. 이는 이 프로젝트의 공격률이나 특정 모델 취약성을 정량 증명하지 않는다. Runtime/model version·feature는 조사 시점의 공식 metadata이며 실제 설치·hash·offline 동작은 검증하지 않았다.

관측 가능한 현재 근거는 `app/analyzer/llm.py`의 projection→Gemini 호출과 raw `output_text` 반환, `app/analyzer/prompt.py`의 지시문, API response의 nullable string, 현재 API·CLI/UI에서 provider를 호출하지 않는 consumer/tests다. 이 근거로 “기존 Gemini는 local/private/safe”라고 결론 내릴 수 없다.

잔여 한계: 문서 정적 검토는 runtime network egress, SDK의 실제 기본 재시도/timeout, provider 보존 정책, 모델 정확도, citation 의미적 타당성, crash/swap 잔존, 실제 사용자 수용을 검증하지 않는다. Gemini 기존 경로는 이번 설계 단계에서 변경하지 않았다.
