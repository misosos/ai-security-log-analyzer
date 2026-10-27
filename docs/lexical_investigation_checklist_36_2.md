# Phase 36.2 — citation-verified lexical investigation checklist

**상태:** 내부 deterministic adapter의 합성 평가 PHASE_36_2_AUTOMATED_GO. no model, no network, no provider call. 한국어 사용자 이해도는 직접 검수 전까지 NOT_TESTED. 실제 로그·조직 운영은 NO_GO.

## 범위와 구조

app/investigation_checklist_36_2.py는 Phase 36.1의 frozen SafeInvestigationDTO, review-priority reference와 출력 기준을 재사용하고 Phase 33.1의 digest-pinned corpus, lexical search 및 citation verifier를 호출합니다. 고정 한국어 문구로 checklist를 구성합니다. 모델, Gemini, embedding, vector DB, HTTP, socket/network, process, 사용자 corpus는 사용하지 않습니다. CLI·API·SSE·UI·HTML·guidance·restricted report와 연결하지 않은 internal/test-only 코드입니다.

이번 adapter는 요청마다 corpus digest를 확인하고, 해당 category의 고정 query를 Phase 33.1 retrieve와 validate_result에 통과시킵니다. 현재 approval state 및 approved topic을 확인한 뒤, 사전에 정한 section ID가 실제 검색 결과에 있을 때만 그 citation을 씁니다. lexical score threshold·정렬·tie-break는 Phase 33.1 구현을 그대로 사용합니다. 결과는 승인 지식에 대한 근거이지 사례에서 행위가 발생했다는 증거가 아닙니다.

## 지원 범위 및 refusal

| 입력 category | 결과 | 직접 근거와 경계 |
|---|---|---|
| Brute Force | checklist | brute-force:meaning-limit; 반복 실패 관찰은 침해·성공·credential reuse를 증명하지 않음 |
| Password Spraying-like | checklist | password-spray:spray-like-limit; 같은 비밀번호·단일 행위자·침해를 증명하지 않음 |
| failed-then-success relation | checklist | failed-success:relation-not-causation; 시간 관계와 인과를 구분 |
| incomplete evidence | checklist | incomplete-evidence:partial-input; 자료·시간 범위의 한계를 보존 |
| conflicting observations | checklist | conflicting-evidence:conflict; 서로 다른 범위와 근거를 합치지 않음 |
| benign-like/no finding | checklist | no-finding:no-detection; 미탐지는 안전의 증거가 아님 |
| path traversal | fixed refusal | corpus에 path decoding을 직접 뒷받침하는 승인 section이 없음 |
| suspicious process execution | fixed refusal | 현재 corpus에 해당 관찰을 직접 뒷받침하는 승인 section이 없음 |
| unknown role/category 또는 지원하지 않는 detector/relation | fixed refusal | 추측하지 않음 |

Stale case 상태만으로 stale source evidence라고 추론하지 않습니다. evidence completeness도 불완전하거나 unknown으로 표시된 경우에만 completeness 문구를 사용합니다. Path traversal과 process execution 항목은 요구된 평가 category로 다루지만, citation이 없으므로 성공 checklist를 생성하지 않습니다.

## Closed checklist 계약

InvestigationChecklist는 immutable 결과입니다. JSON key 순서는 schema_version, request_id, case_ref, review_priority, steps, explanation, uncertainty, limitation_codes, generated_by, status로 고정합니다. 각 step은 template_code, text, purpose_code, citation_ids, limitation_codes만 허용하며 최대 다섯 단계입니다. 문구, 목적, citation mapping, limitation code는 고정 allowlist에만 있습니다. 실제 입력이나 corpus excerpt를 출력 문구로 복사하지 않습니다. citation은 요청 중 다시 검색·검증한 결과여야 하고, category와 section 의미가 맞아야 합니다. 불필요한 citation 반복·추가 citation은 거부합니다.

모든 step과 제한 설명은 인용한 승인 section의 일반 지식에 한정합니다. 자동 대응 지시, 명령, URL, 환경별 적용 가능성, 계정·IP·hostname·경로·원문, 새 공격 사실은 출력하지 않습니다. review_priority는 Phase 36.1 reference의 보조 값이며 기존 risk와 다릅니다. conflicting/unknown evidence의 priority가 undetermined여도 직접 근거가 있는 수동 checklist는 제공할 수 있습니다. 이는 priority를 확정했다는 뜻이 아닙니다.

출력 상한은 UTF-8 JSON 8 KiB, 최대 5 step, text당 512 bytes입니다. duplicate JSON key, non-finite number, 잘못된 enum, 추가·누락 key, citation 불일치, 허용되지 않은 텍스트, 상한 초과는 전체 거부됩니다. 부분 수락이나 자동 수정은 없습니다. 실패는 안전한 고정 refused/unavailable 결과 또는 fixed error category로 끝납니다. 제한된 동시 요청 수는 1입니다.

## Citation 검증과 의미 평가

구조적 검증(structural validation)은 corpus digest·section identity·approval·retrieval verifier·category mapping을 확인합니다. 의미 타당성 평가는 별도 합성 라벨로 수행합니다. tests/fixtures/investigation_checklist_36_2.json의 각 항목은 required/optional/forbidden citation ID, 예상 template과 금지 claim code를 수동 작성한 정적 label로 둡니다. 이 평가는 일반 자연어 의미를 자동으로 이해하거나 한국어 품질을 증명하지 않습니다. 빈 결과나 전면 refusal은 성공으로 집계하지 않으며 benign false refusal을 분리합니다.

현재 Phase 33.1 기준선의 17 citation 중 과잉 citation 1건(relation-gone:not-resolved)은 그대로 유지합니다. checklist adapter는 실패-성공 관계에서 failed-success:relation-not-causation만 직접 인용하고 over-citation ID는 허용하지 않습니다. Phase 33.1 retrieval 결과나 score, order를 변경하지 않았습니다.

자동 평가 fixture는 24개이며 Phase 36.1의 44개 fixture 및 평가를 별도 그대로 유지합니다. 이번 adapter fixture는 brute force, password spray, failed-success/correlation-not-causation, path traversal, process telemetry, incomplete/conflicting evidence, stale case, benign control, unsupported category, category mismatch, 의미상 무관 citation, over-citation, 누락 citation, prompt injection/privacy 입력 거부, command 변조, 최대 조합·output cap, digest 불일치, retrieval refusal, 반복 요청을 포함합니다. 현재 합성 평가: status match 24/24, required citation completeness 100%, semantic-support precision 100%, forbidden/invalid citation 0, unsupported claim 0, benign false refusal 0, meaningful available outputs 12. 이 수치는 label된 합성 사례에 한정됩니다.

## 개인정보와 분석 권한

입력 DTO는 Phase 36.1 closed schema를 유지합니다. 원문 로그, 계정, IP, hostname, 파일 경로, credential, 정확한 시각, 자유 질문은 checklist에 복사되지 않습니다. 내부 예외는 고정 메시지로 변환합니다. 체크리스트 결과는 탐지·관계·위험도·사례·checkpoint·publication·SSE cursor를 변경하지 않습니다. API/OpenAPI/SSE/UI/HTML/restricted report/guidance에 새 출력 경로를 추가하지 않았습니다.

합성 canary와 invalid output을 DTO·예외·repr·logger 경계에서 검사합니다. 모델·Gemini·HTTP·socket/network·embedding·Ollama/llama.cpp process 경로는 호출하지 않습니다. AI fallback도 없습니다. Phase 33.1 corpus에는 로그·사례를 추가하지 않습니다.

## 사용자 이해도 검수 준비

tests/fixtures/investigation_checklist_user_review_36_2.json에는 8개 고정 한국어 화면 문구를 검수 후보로 준비했습니다. 목적, risk와 priority 차이, 수동 checklist, citation과 사건 근거 구분, 불확실성, refusal 다음 행동, 식별자 비포함, 분석 불변을 다룹니다. 이는 캡처된 제품 화면이나 사용자의 응답이 아니며 사용자 이해도는 NOT_TESTED입니다.

## 실행·재현 측정

합성 microbenchmark는 warm-up 10회, 각 operation 100표본으로 corpus load/verify, lexical search, checklist category 선택, citation 검증, output 검증, 전체 checklist를 분리 측정합니다. median/p95/max, input/output byte, corpus section 수와 index resident 추정치를 출력합니다.

Darwin 24.6.0 arm64, Python 3.12.7의 100표본 결과:

| Operation | median ms | p95 ms | max ms |
|---|---:|---:|---:|
| corpus load/verify | 7.603 | 9.131 | 15.172 |
| lexical search | 0.421 | 0.695 | 1.038 |
| checklist category selection | 0.001 | 0.001 | 0.025 |
| citation verification | 4.713 | 5.929 | 7.182 |
| output validation | 27.171 | 32.176 | 33.571 |
| full checklist | 53.197 | 59.572 | 65.406 |

Input 621 bytes, output 960 bytes, corpus 18 sections, lexical index resident estimate 25,279 bytes. 이 개발용 측정은 운영 SLA, 용량 보장 또는 SOC 효율성 증거가 아닙니다.

## 테스트와 제한

tests/test_investigation_checklist_36_2.py, tests/evaluate_investigation_checklist_36_2.py, tests/benchmark_investigation_checklist_36_2.py를 사용합니다. 구조 유효성과 직접 의미 지지는 분리해 검사합니다.

TDD 첫 단계에서는 모듈 import 테스트가 새 모듈 부재로 실패했고, 문서 계약 테스트도 새 기록/link 부재로 실패했습니다. 구현 뒤 focused adapter·Phase 36.1·Phase 33.1 retrieval/guidance 테스트는 **131 passed**였습니다. adapter/documentation focused tests는 **34 passed**였고 UTC와 Asia/Seoul에서 adapter tests가 각각 **31 passed**였습니다. 전체 local suite는 **3038 passed, 기존 warning 2개**였습니다.

평가 요약:

- Phase 36.1: 44 fixtures, schema/refusal/citation 100%, privacy leak 0, analysis mutation 0.
- Phase 33.1: 17 fixtures, citation precision 0.941, completeness 1.000, unsupported citation 0, privacy leak 0, mutation 0, injection 0. 기존 과잉 인용 1건 유지.
- Phase 36.2: 24 fixtures, status 24/24, required citation completeness 100%, semantic-support precision 100%, invalid/forbidden citation 0, unsupported claim 0, benign false refusal 0; 12개 meaningful checklist output.
- 기존 synthetic boundary evaluation: 79/79, Linux process evaluation 21/21, risk/case 70/70.
- npm ci --ignore-scripts와 Chromium/axe: 14 states, external_requests=0.
- uv sync --locked --dev, uv lock --check, Python syntax, Node syntax, git diff --check 통과. dependency 및 lockfile 불변.

- 한국어 설명의 자연스러움·이해도: 직접 사용자 검수 전 NOT_TESTED.
- path traversal 및 suspicious process checklist: corpus direct support가 없어 refusal.
- 실제 사용자 로그·조직 운영·자동 대응: NO_GO.
- 모델 처리, hosted provider, embedding/vector DB: 사용·평가하지 않음.
- Phase 35.4B는 Vector VM blocker와 별개로 유지됩니다. Ubuntu VM 상태 USER_ACTION_REQUIRED / ISOLATION_BLOCKED; Vector는 실행하지 않았습니다. 이 Phase가 Vector 안전성 근거를 대신하지 않습니다.
- 합성 fixture 결과는 production readiness나 탐지 정확도 증거가 아닙니다.
