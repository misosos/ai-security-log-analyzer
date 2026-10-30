# Phase 36.9G-R2-R2-R2 — Trusted Provenance Independent Closure

## 1. Executive Summary

이번 단계는 Phase 36.9G-R2-R2-R1의 provenance 보완을 독립적으로 재검증했다. 시작 SHA의 GitHub CI와 로컬 기준선을 확인했고, 기존 HOLD 및 RED 테스트를 보존한 상태에서 provenance·Case·Correlation·Live·API 경계를 다시 실행했다. 추가 독립 테스트 5개와 관련 API/Live/Report 테스트 234개가 통과했다. 전체 회귀 결과는 문서 하단에 실제 실행 후 기록한다.

신뢰된 내부 흐름에서 단계별 Detection → Correlation → Risk → final owned result 결속이 현재 호출 경로에 적용됨을 확인했다. 기존 late-noise 사례는 선택 Window 5회/20초와 전체 IP Feature 6회/70초를 분리하고, Brute Correlation은 20초→80초의 60초 관계를 유지한다. 이 판정은 합성·로컬 검증 범위에 한정된다.

## 2. 시작 exact-SHA Gate

- 기준 Commit: `4ac05f2af50e1d0a22730c6f6b696b2cf16e1539`
- GitHub Actions Run: `41063117121`
- Branch/HEAD/local main/origin main/GitHub main: `main`, SHA 일치
- Ahead/behind: `0/0`; working tree: clean
- Run: `push`, `completed / success`, artifact 0개
- Locked Python 3.12, lockfile, 전체 pytest, Linux process/checkpoint·SSH, TCP Syslog, JSONL, restricted report, Chromium/axe, tracked-file 단계: 모두 성공
- v0.4.0 tag target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

기준선 `uv sync --locked --dev`, `uv lock --check`, 전체 pytest 실행은 성공했고 변경 전 결과는 `3362 passed, 2 warnings` (macOS, Python 3.12)였다.

## 3. Phase 이력

36.9G와 R2/R2-R1/R2-R2의 HOLD 문서는 각각 당시 교차 실행 Context, 다중 Owner, 결과 재포장 문제를 기록한다. R2-R2-R1은 신뢰된 파이프라인 단계별 결과 객체 결속을 추가했다. 이번 검증은 과거 문서를 수정하지 않았으며, 해당 변경이 실제 소비자 경로에서 유지되는지 확인했다.

## 4. R2-R2-R1 Remediation 감사

확인한 핵심 구현은 `AnalysisRunOwner`, `_OwnedAnalysisResult`, `BruteWindowContext`, `AnalysisWithSourceRoleSnapshot` 및 Case adapter, Live accumulator, restricted report 진입점이다. Static 경로는 `main._analyze_normalized_logs_with_context()`에서 새 Owner를 만들고 Detector → Correlation → Risk → final private mapping 순서로 처리한다. 공개 `analyze()`는 기존 plain `dict`를 반환한다. Source-role snapshot은 Analysis 객체 identity에 별도로 결속된다.

Restricted report는 같은 contextual pipeline을 사용한다. Live accumulator는 현재 Detection Proposal 검증 후 새 Owner를 만들고, 현재 Proposal의 Detector 결과를 결속한 뒤 Correlation, Risk, final mapping, Case adapter 순으로 진행한다. Local Text/File 및 Sample API는 private wrapper를 API 응답으로 직렬화하지 않고 Case/Report projection 후 닫힌 공개 DTO를 반환한다.

## 5. Threat Model

보호 대상으로 본 것은 정상적인 내부 실행 흐름에서 과거 Detection, Correlation, Risk 또는 Brute Context가 새 실행의 결과로 재사용되는 경우와 잘못 구성된 Wrapper가 Case/Correlation consumer에 전달되는 경우다. 같은 합성 입력이나 같은 `NormalizedEvent` 객체를 독립 실행에 재사용하는 것은 정상이며 각 실행은 새 Owner와 새 단계 산출물을 가져야 한다.

악의적인 동일 프로세스 코드가 private 메서드·리플렉션·저수준 객체 변경으로 Owner 상태나 참조 객체를 의도적으로 조작하는 행위는 별도 격리 위협이다. Python private 상태는 암호학적 인증이나 프로세스 경계가 아니다. 이 Phase는 그 범위까지 방어한다고 주장하지 않는다.

## 6. Trusted Provenance Pipeline

```text
NormalizedEvent
  → Detector 결과 및 BruteWindowContext
  → Correlation 결과
  → Risk 결과
  → Owner 결속 final private mapping
  → Case / Report 소비
  → 기존 공개 dict 또는 닫힌 DTO
```

Detector 단계는 subject별 `features` 및 `detections`의 객체 참조·항목을 기록한다. Correlation 단계는 Detector 결과가 같은 실행의 참조인지 확인한 뒤 entry와 correlation mapping을 결속한다. Risk 단계는 앞선 단계가 유지되는지 확인하고 Risk mapping/level을 결속한다. Finalization은 동일 Correlation 결과와 Risk가 반영된 mapping만 owned mapping으로 봉인한다. Case Adapter는 final owner binding과 Context/Evidence 계약을 다시 검사한다.

## 7. 단계별 객체 결속

기존 provenance 테스트는 과거 Detection 객체 교체, 과거 Correlation mapping 또는 relation 삽입, Detector Feature 변경, final 결과 변경을 검사한다. 이번 독립 테스트는 단계가 빠진 상태에서 재결속·Correlation·Risk·Finalization을 시도하면 고정 `invalid_analysis_context` 오류로 거부되는 것을 확인했다.

정상 경로에서는 같은 입력으로 별도 분석한 두 실행이 서로 다른 Owner 및 `results` mapping을 갖고 각자 Case를 만든다. 같은 값이나 동일 Event object identity만으로 실행 소유권을 공유하지 않는다.

## 8. Finalization 계약

R2-R1 감사에서 확인한 순서는 Detector 결속 → Correlation 결속 → Risk 결속 → finalization이다. 각 경계의 중복 결속은 거부된다. 완성된 mapping의 `results`가 다른 실행 결과로 교체되면 `is_bound_to()`가 실패하고 실제 `project_investigation_cases_from_analysis()`도 `IncidentCaseAdapterError`로 거부한다.

공개 일반 dict 복사 및 JSON projection은 기존 동작을 유지한다. 내부 private provenance를 공개 dict에 넣지 않는다. Finalization은 신뢰된 pipeline이 만든 객체 참조의 연속성을 확인하며, 임의의 same-process 코드가 private 상태와 객체를 직접 조작하는 데 대한 인증은 아니다.

## 9. 기존 RED 재검증

R2-R2 재포장 테스트 및 R2-R2-R1 provenance tests를 실행했다. 정상 독립 실행은 허용되고, 완성된 다른 실행의 `results`를 현재 owned run에 대입한 뒤 실제 Case projection을 호출하면 거부된다. 교차 실행 Detection/Correlation 및 Context 경계도 관련 기존 테스트와 함께 재실행했다. 기존 보안 assertion은 변경하지 않았다.

## 10. Cross-run 재사용

같은 late-noise fixture를 두 번 분석하면 두 Owner와 최상위 `results` 객체가 다르며 두 실행 모두 Case 1개를 생성한다. 그 뒤 B의 `results`를 A 결과로 교체하면 B Owner binding이 무효가 되고 B의 Case projection은 거부되며 A의 Case는 계속 정상 생성된다.

## 11. Repackaging 거부

R2-R2-R1 RED 테스트는 이전 결과 객체를 새 실행의 Detection, Correlation 또는 final mapping에 끼워 넣는 경로를 검사한다. 이번 독립 테스트는 Consumer에 이미 도달 가능한 final result 교체를 실제 Adapter에서 거부하는지 확인했다. 새 Owner의 정상 독립 pipeline 실행은 별도로 성공했다. 임의 same-process private factory 조작의 위조 불가능성을 보장한다고 해석하지 않는다.

## 12. Case Adapter

정상 합성 late-noise+success Case는 `CASE-BRUTE-SUCCESS-01`이다. Case timeline의 Detection observation은 실제 Context 시작·종료와 일치하고 Evidence는 5회, 계정 수 1, 20초다. Brute relation은 Context 종료 20초에서 후속 성공 80초까지이며 delta는 60초다. 공개 projection은 원문 계정을 표시하지 않고 계정 참조 불가 상태를 유지한다.

다른 실행 결과로 변조한 wrapper는 Case 생성 전에 거부된다. Context 없는 forged Sliding Window Evidence 및 malformed adapter 입력은 기존 consumer contract tests에서 계속 fail-closed다.

## 13. Correlation

대표 fixture에서 전체 IP 실패 6건/70초와 Brute Window 5건/20초를 분리했다. Brute relation failure endpoint는 선택 Window 종료 20초이고 성공은 80초, delta 60초다. 70초 late-noise 실패는 Brute relation endpoint로 쓰이지 않는다. 기존 provenance/consumer tests가 Context 부재와 다른 실행 참조를 거부하며 일반 Authentication Transition 및 Password Spray relation은 기존 별도 경로를 유지한다.

## 14. Static/Live Parity

독립 테스트는 Application parser가 만든 동일 관측 prefix를 순차 Live Proposal에 넣고 매 prefix마다 batch contextual static analysis와 비교했다. Detection, 전체 IP Feature, Correlation, revision 및 Case 존재 여부가 일치했다. 마지막 late-noise+success prefix에서도 Live Brute endpoint는 20초이고 Case 1개가 유지됐다.

추가로 기존 `test_live_analysis_prefix_parity.py`, accumulator, publication, privacy, worker 및 related focused tests를 실행했다. 이 검증은 같은 관측 prefix 비교이며 수집되지 않은 미래 이벤트를 포함한 batch와의 동등성을 주장하지 않는다.

## 15. Mixed Application/SSH

임시 합성 파일에 지원되는 Application 형식 실패 3건과 ISO-style `sshd` 실패 2건을 기록해 실제 Parser/`load_normalized_logs()`를 통과시켰다. 같은 IP·계정의 정규화 이벤트 5건이 20초 Window로 선택되고 Brute Detection이 생성됐다. 후속 성공이 없으므로 Brute-success Case가 없는 결과가 정상이다.

Parser가 지원하지 않는 offset timestamp 문법은 추가하지 않았다. 지원되는 Application/SSH parser가 naive local timestamp를 `Asia/Seoul`로 해석하고 pipeline이 UTC로 정규화하는 계약을 사용했다.

## 16. Offset-equivalent Timestamp

Selector에 전달한 aware `NormalizedEvent` 다섯 건은 UTC와 `+09:00` offset 표현을 섞되 같은 절대시각을 나타내도록 구성했다. UTC 변환 뒤 start/end/count는 입력 역순에서도 동일했다. 이는 Parser가 임의의 offset 문자열 문법을 지원한다는 주장이 아니라 selector의 aware timestamp 정규화 결정성을 확인한 결과다.

## 17. API E2E

Text/File API, Sample API, restricted analyst report 및 fault 경계 테스트를 포함한 consumer-focused 집합에서 `234 passed`였다. 해당 기존 테스트는 정상 합성 Brute 입력의 Parser→Analysis→Case/Report projection, 고정 응답 schema, checklist binding, invalid-input 오류 경계와 private 정보 비노출을 확인한다. API는 분석 내부 wrapper를 반환하지 않는다.

이번 신규 테스트는 내부 run 결과를 직접 대상으로 하므로 별도 HTTP 요청으로 모든 변형을 반복하지 않았다. Local API의 모든 입력 조합에 대한 신규 독립 matrix는 미실행으로 기록한다.

## 18. Source-role / Checklist / Report

Source-role snapshot은 실제 Analysis identity에 결속되고 Owner와 별개의 검증 역할을 유지한다. 기존 API/Checklist 테스트에서 현재 Case 기반 binding이 통과했다. Report/Checklist 공개 스키마는 변경되지 않았다. Restricted report는 contextual pipeline에서 Case projection을 수행한 뒤 공개 제한 DTO를 구성한다.

## 19. Password Spray 및 다른 Detector

Production 코드, Password Spray, 나머지 6개 Detector 및 Risk 산식은 이번 단계에서 변경하지 않았다. 36.9F/36.9E 관련 focused tests와 평가 CLI를 재실행했다. Spray는 전체 IP feature 및 기존 whole-span 계약을 계속 사용한다. Brute 전용 Context는 shared feature를 덮어쓰지 않는다.

## 20. Historical/Current Evaluation

재실행 결과:

- 36.9C Historical Brute: `TP 3 / FP 0 / FN 1 / TN 3`은 과거 기준선으로 유지한다.
- 36.9F 이후 Current Brute: 46개 corpus에서 `TP 4 / FP 0 / FN 0 / TN 3`.
- 36.9D Candidate C: 24개 corpus에서 `TP 17 / FP 0 / FN 1 / TN 5`.
- 36.9D Whole-span: `TP 9 / FP 0 / FN 9 / TN 5`.
- 다른 6 Detector의 현재 confusion matrix는 기존과 일치한다.
- Current Brute operational false-alert 후보: 합성 `bf_benign_retries` 1건; 36.9D 후보 정책별 known-benign 사례 2건.

Ground Truth, fixture ID 및 Historical FN 기록은 수정하지 않았다. 이 표본은 실환경 탐지 정확도가 아니다.

## 21. Privacy/Security

기존 API/Report/Checklist/Live privacy 테스트와 Sample API schema 테스트가 통과했다. 신규 검사는 Case timeline의 선택 Evidence와 계정 원문 부재를 확인했다. Owner/Context는 내부 repr에서 redacted이며 공개 응답 모델에 포함하지 않는다. 외부 네트워크 전송은 수행하지 않았다. 모든 입력은 저장소의 합성 fixture 또는 테스트 중 임시 합성 파일이다.

## 22. 합성 성능·결정성

macOS/Python 3.12에서 동일 synthetic event 집합을 정방향·역방향으로 selector에 넣었다. `tracemalloc`을 사용한 단일 bounded 측정:

| 이벤트 수 | 선택 결과 subject 수 | 1회 실행 시간(초) | peak Python 할당(bytes) | 역순 결과 |
|---:|---:|---:|---:|---|
| 100 | 0 | 0.003692 | 31,610 | 동일 |
| 1,000 | 0 | 0.036517 | 299,284 | 동일 |
| 5,000 | 0 | 0.119484 | 337,524 | 동일 |
| 10,000 | 1,000 | 0.690366 | 608,392 | 동일 |

합성 이벤트는 8개 주소 범위와 20개 계정, 120초 내 timestamp 분포로 생성했다. 측정은 반복 통계나 운영 보장이 아니며 macOS에서 관찰한 단일 실행이다. 코드의 정렬 후 계정별 two-pointer scan은 유지됐고 모든 조합을 무제한 열거하지 않는다. OS 수준 hard CPU/memory cap은 없다.

## 23. 전체 Regression

변경 전 기준선: `3362 passed, 2 warnings`.

- provenance/36.9F/36.9E/36.9D focused 묶음: `90 passed`.
- API/Live/Restricted Report focused 묶음: `234 passed, 2 warnings`.
- 신규 독립 테스트: `5 passed`.
- 전체 pytest: `3367 passed, 2 warnings` (macOS, Python 3.12; 기준선 대비 신규 5개).
- `uv run python -m app.evaluation`: Boundary 79/79, Risk 70/70, Case 70/70, Linux process 21/21; Parser 195/200 (ignored 2, rejected 3).
- Detector Accuracy text/json: 46 scenarios; Brute `4/0/0/3`; other six detector metrics unchanged.
- Brute Window text/json: 24 scenarios; Candidate C `17/0/1/5`, Whole-span `9/0/9/5`.
- `uv sync --locked --dev`, `uv lock --check`, `python3 -m compileall -q app tests`, `git diff --check`, 신규 파일 whitespace 검사가 성공했다.
- `npm run test:a11y --silent` 성공; 25개 scenario, 외부 요청 0건.

전체 pytest의 첫 실행은 Chromium/axe와 동시에 실행되어 기존 Hypothesis `test_arbitrary_output_bytes_fail_closed_without_reflection`의 200ms deadline을 한 번 초과했고 `1 failed, 3366 passed`를 보고했다. 해당 테스트 단독 재실행은 `1 passed`였고, 다른 부하를 겹치지 않은 전체 재실행은 `3367 passed, 2 warnings`였다. 테스트 설정이나 assertion은 변경하지 않았다.

로컬 테스트는 macOS에서 실행했다. 시작 SHA의 GitHub Linux CI 결과와 구분하며, 새 로컬 테스트가 추가된 후의 Linux CI는 아직 해당 커밋을 push하지 않았으므로 미실행이다.

## 24. 미검증·잔여 위험

- 동일 프로세스 악성 코드의 private 상태/객체 직접 조작은 이번 계약의 방어 범위가 아니다.
- 지원되지 않는 offset timestamp 문자열 문법은 Parser에서 지원하지 않는다.
- 합성 corpus와 단일 synthetic benchmark는 실제 조직 정확도나 부하 성능을 보장하지 않는다.
- 실제 사용자 자료, 조직 운영, 자동 대응은 `NO_GO`.
- 실환경 탐지 정확도 `UNVERIFIED`; 모델 기반 AI `NOT_TESTED`.
- Safari/VoiceOver/실제 모바일 `NOT_TESTED`.
- Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`.
- OS hard CPU/memory cap 및 강제 종료 후 secure erase 미보장.
- Renderer `KEEP_LEGACY`.

## 25. Closure 최종 판정

최종 전체 회귀와 diff 검사가 성공하면 판정은 `PHASE_36_9G_R2_R2_R2_TRUSTED_PROVENANCE_CLOSURE_LOCAL_CONDITIONAL_GO`다. 이는 로컬 합성·검증 경로에서의 조건부 종결이며 실운영 준비 승인이 아니다.

## 26. 다음 Phase 권고

조건부 종결 이후 `Phase 36.10A — Detection Readiness & Remaining Risk Prioritization`에서 Detector 7종, 지원 Parser 범위, 합성 FP/FN과 운영 false-alert 차이, Live/Static 범위, 개인정보·격리 및 실제 데이터 검증 전제조건을 재평가한다. 실제 로그 분석이나 운영 승인을 포함하지 않는다.
