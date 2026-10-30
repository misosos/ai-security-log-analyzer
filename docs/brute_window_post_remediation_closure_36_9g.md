# Phase 36.9G — Brute Window 사후 회귀 및 계약 종결

## 1. Executive Summary

**판정: `PHASE_36_9G_CONTEXT_ISOLATION_HOLD`**

36.9F의 late-noise 탐지 개선과 window Evidence·Correlation·Case 흐름은 기존 합성 테스트에서 재현된다. 그러나 별도 분석 실행의 `BruteWindowContext`를 값이 같은 다른 분석 wrapper에 옮겨 담으면 Case adapter가 이를 받아들여 Case를 생성하는 문제가 독립 재현됐다. 36.9G는 Context의 실행 소유권 격리 Acceptance Criterion을 충족하지 못한다.

이번 단계에서는 Production 코드를 수정하지 않았다. 재현 테스트는 현재 구현에서 의도적으로 실패한다. 새 기능이나 운영 승인을 뜻하지 않는다.

## 2. 시작 exact-SHA Gate

- 기준 SHA: `984a9f9cc7c59c826dcb061f1794ff08194ab0a3`
- GitHub Actions Run: `41036766597`
- Branch: `main`; HEAD/local main/origin main/GitHub main 일치
- Ahead/behind: `0/0`; 작업 트리 시작 시 clean
- Event `push`, exact head SHA 일치, `completed/success`, artifact 0개
- Locked Python 3.12, lock 검증, 전체 regression, Linux checkpoint/process 및 SSH recovery, TCP Syslog, JSONL, restricted report, Chromium/axe, tracked-file invariant 성공
- v0.4.0 target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

## 3. 36.9F 변경 파일 감사

`git diff --stat 71f5e605ae76c0603bc8b5cbbb79ae5bd3148b7c 984a9f9cc7c59c826dcb061f1794ff08194ab0a3`: 32개 파일, 1,136 insertions, 173 deletions.

| 영역 | 목적/분류 |
|---|---|
| `app/detector/brute_force.py`, `app/analyzer/pipeline.py`, `app/correlation/attack_chain.py` | 필수: Candidate C 선택, 선택 window Evidence, Brute 전용 correlation |
| `app/investigation_role_snapshot_36_4.py`, `app/analyzer/incident_case_adapter.py`, `app/analyzer/incident_case.py` | 간접 필수: private Context 전달, Brute의 내부 계정 scope, Case 검증 |
| `app/main.py`, local/sample API, restricted report, evaluation runner | 기존 호출 경계에 private wrapper 전달, 공개 결과 모양 유지 |
| `app/analyzer/risk.py`, `report_projection.py` | 전체 IP 통계와 선택 window rationale의 범위 구분 |
| Live accumulator 및 관련 테스트 | Live prefix에 Context를 재구성해 Correlation/Case 소비자에 전달 |
| 평가·회귀 테스트와 36.9F 문서 | 새 production 의미와 historical 결과 구분 |

리뷰에서 공개 schema 및 의존성/lockfile 변경은 발견되지 않았다. 36.9F 범위 중 source-role snapshot 모듈 수정은 기존 private wrapper를 재사용하기 위한 통합 경계 변경이다. 다만 이 wrapper가 Context의 분석 실행 소유권까지 결속하지 않는다는 잔여 결함이 확인됐다.

## 4. Brute 미탐 해결 재검증

기존 fixture `bf_burst_with_late_noise.log`의 5회/20초 + 70초 추가 실패는 36.9F 회귀 테스트에서 Parser → NormalizedEvent → selector → Evidence → 전체 feature 경로로 확인된다. 현재 코드 결과는 Brute 탐지 true, Evidence 5회/20초, IP 전체 6회/70초, `within_window=false`다.

기존 36.9F E2E 테스트는 API, Risk, Case 및 Report 경로도 확인한다. 다만 이번 36.9G에서 확인된 cross-run Context 재사용 결함 때문에 종합 계약 Closure 판정은 보류한다.

## 5. Candidate C 일치성 및 Window Evidence

36.9F 테스트는 24개 36.9D scenario에서 Production selector와 Candidate C의 탐지 여부, 선택 계정, 시작/종료 및 실패 수를 비교한다. 구현은 IP·계정별, aware UTC, 5회 이상, 60초 포함, earliest qualifying end 정책이며 계정 동률은 fail-closed한다. Missing account 행은 후보 계정 count에 들지 않고 중복 행은 제거하지 않는다.

독립적으로 확인된 추가 변형은 현재 테스트에 있는 정확히 60초/60초+1µs, naive timestamp, cross-account tie, reverse order 및 duplicate input이다. 여러 계정 burst 조합, offset-equivalent instant와 Application/SSH 혼합을 포함한 요구된 전체 36.9G 변형 표는 이 실행에서 별도 완성되지 않았다: `PARTIAL`.

## 6. 전체 IP Feature 및 Password Spray

36.9F 변경은 `summarize_ip_failures()`를 수정하지 않았다. 6회/70초 전체 feature와 5회/20초 Brute Evidence 분리가 기존 tests/evaluation에서 확인된다. Password Spray whole-span 입력, Evidence 및 결과는 기존 합성 regression에서 유지된다. 36.9G의 모든 명시된 Spray 변형을 별도 차등 행렬로 실행하는 것은 아직 `PARTIAL`이다.

## 7. Correlation, Case Adapter 및 Assembler

36.9F에서는 Brute→Success만 Context의 실제 member event와 Evidence를 확인하고 window end를 endpoint로 사용한다. 일반 Authentication Transition과 Spray correlation의 helper 경로는 별도다. 20→80초 60초 경계와 contextless correlation 거부는 기존 tests에 있다. Case adapter는 Context를 검증하고 Brute detection-specific account scope를 사용한다.

36.9G의 독립 격리 재현:

1. 합성 fixture를 두 번 분석해 실행 A와 B의 서로 다른 `NormalizedEvent` object 및 Context를 만든다.
2. 실행 B의 analysis 및 source-role snapshot에 실행 A의 Context mapping을 전달한 wrapper를 만든다.
3. `project_investigation_cases_from_analysis()`가 `IncidentCaseAdapterError`를 내야 한다는 독립 테스트를 추가했다.
4. 현재 구현은 이를 거부하지 않고 Case 1개를 생성한다.

재현 스크립트의 결과: `cross_run_case_context=ACCEPTED 1`. Context는 subject, Evidence 및 feature와 값으로 일치하지만, adapter/wrapper가 Context가 현재 analysis 실행에서 파생됐음을 검증하지 않는다. 이는 다른 요청의 Context 재사용 금지 조건 위반이며 `CONTEXT_ISOLATION_HOLD`다. 공개 API에서 직접 Context 입력 경로가 확인된 것은 아니지만 내부 typed wrapper 호출 계약 자체가 재사용을 허용한다.

최소 후속 remediation 후보는 analysis 실행별 불변 owner/capability를 Context와 wrapper에 결속하고, Case adapter에서 일치 여부를 검증하는 것이다. 공개 dict/schema에 token을 넣거나 전역 registry를 두지 않아야 한다. 이 문서는 그 수정안을 구현하지 않는다.

## 8. Live Monitoring 및 Source-role

36.9F 기존 테스트는 정적 분석과 동일 prefix에서 Case projection parity, live revision 업데이트, out-of-order 입력, late-noise 유지, SSE/publication 경계를 확인한다. 이번 36.9G에서는 서로 다른 prefix 상태를 결과 불일치로 오판하지 않는다는 계약을 유지한다. 하지만 독립적인 신규 parity matrix와 병렬 요청 격리 검증은 이 HOLD 실행에서 완료되지 않았다: `PARTIAL`.

Source-role은 `AnalysisSourceRoleSnapshot`의 analysis 객체 identity에 귀속되며 모호하면 `unknown`으로 둔다. 반면 Brute Context는 이와 동등한 owner binding을 갖지 않는 것이 이번 finding의 직접 원인이다.

## 9. Risk, Report, Checklist 및 API

36.9F 변경에서 Risk 산식은 유지되고 rationale의 전체/IP와 선택 window 범위가 분리된다. Report projection은 허용 문구를 제한적으로 받아들이고 공개 schema/renderer는 유지된다. Local Text/File E2E, checklist 및 canary 검사는 36.9F 테스트에 존재한다. 36.9G 신규 대규모 API matrix는 실행하지 않았다.

현재 finding은 Case adapter 입력에서 재현됐다. 따라서 그 wrapper를 소비하는 Case/Checklist/Report 경로를 완전한 실행 소유권 경계로 승인할 수 없다. API schema 자체에서 Context 노출이 관찰된 것은 아니다.

## 10. Historical vs Current 평가 및 expectation 감사

36.9C Historical Brute matrix는 TP3/FP0/FN1/TN3으로 과거 기록에 남아 있다. 36.9F Current는 TP4/FP0/FN0/TN3이며 독립 Behavioral label을 바꾼 흔적은 확인되지 않았다. 36.9D Candidate C 24개 결과는 별도 TP17/FP0/FN1/TN5다.

`app/evaluation/corpus.py`의 `brute_above`는 6회/50초 전체 실패 expectation에서 5회/40초 최초 qualifying window Evidence로 변경됐다. 해당 fixture는 0,10,20,30,40,50초에 6개 실패를 기록하므로 선택 창 0~40초의 5개 행이라는 변경 근거와 일치한다. 탐지 라벨과 독립 시나리오를 변경하지 않았다.

## 11. 테스트 개수 차이

36.9F 이전 3327 passed, 이후 3336 passed로 실행 수는 9 증가했다. 변경된 테스트 파일 AST 기준 `test_` 함수는 218개에서 231개로 13개 증가했다. 다섯 기존 함수는 새 계약으로 이름/내용을 교체했고 각 대응 테스트는 새 동작과 historical/legacy 경계를 검사한다. 36.9F 신규 focused 테스트 파일에는 10개 테스트 함수가 추가됐다. 함수 수와 pytest 수 차이는 parametrization/fixture collection 단위 차이이므로 총량 차이만으로 테스트 삭제를 추론하지 않는다. 다만 해당 테스트 변경 중 brute consumer 및 live identity assertions는 36.9F semantics로 대체됐으며, 구 동작을 historical helper 수준에서 따로 고정했는지에 대한 전면 collect-node 비교는 수행하지 않았다. 이번 36.9G는 별도 독립 test 함수 1개를 추가했으며 현재 실패가 Context 격리 finding이다.

## 12. 성능·결정성 및 Privacy/Security

Production selector는 정렬 후 two-pointer로 그룹별 `O(n log n)` 정렬 및 선형 scan을 수행하며 모든 구간 조합을 생성하지 않는다. 기존 tests는 reverse order, 정확한 경계, tie와 duplicate 사례를 다룬다. 36.9G에서 대규모 별도 benchmark는 실행하지 않았다. OS hard CPU/memory cap과 secure erase는 보장되지 않는다.

Context repr은 redacted이고 36.9F tests는 공개 JSON/Case/Report/API canary 비노출을 확인한다. 이번 finding은 Context의 실행 소유권 검증 부족이며 raw data 자체의 공개 누출은 재현되지 않았다. 그래도 잘못된 run의 보안 근거가 Case에 붙을 수 있어 integrity/privacy boundary 관점에서 remediation이 필요하다.

## 13. Regression 및 실행 근거

시작 전 `uv sync --locked --dev`, `uv lock --check`, `uv run pytest -q`를 실행했다. 전체 기준선은 `3336 passed, 2 warnings` (macOS, Python 3.12)이다. `app.evaluation`은 Boundary 79/79, Brute Force 11/0/0/58, Spray 2/0/0/67, Parser 195/200 (ignored 2, rejected 3), Risk 70/70, Case 70/70, Linux process 21/21을 재현했다. Detector Accuracy JSON은 46개, Current Brute `TP 4 / FP 0 / FN 0 / TN 3`, 합성 operational false-alert 후보 7건이다. Brute-window JSON은 24개, Whole-span `TP 9 / FP 0 / FN 9 / TN 5`, Candidate C per-account `TP 17 / FP 0 / FN 1 / TN 5`, known-benign 후보 2건이다. JSON 파일은 `/tmp`에 저장하고 parse 성공을 확인했다.

새 독립 재현 테스트 `tests/test_brute_window_contract_closure_36_9g.py`는 `1 failed`다. 실패는 기대한 `IncidentCaseAdapterError`가 발생하지 않고 Case 1개가 생성된 것이다. 새 테스트를 포함한 전체 pytest 재실행은 `1 failed, 3336 passed, 2 warnings`였다. 단 하나의 실패는 위에서 재현한 Context cross-run 수락이다.

이번 단계에서 Production 파일은 수정하지 않았다. `uv sync` 및 lock 검증은 성공했다. 시작 SHA GitHub Run은 Phase 시작 gate의 증거이며 새로운 closure test의 CI 증거가 아니다. Phase HOLD에서는 assertion을 완화하거나 xfail로 처리하지 않는다.

## 14. 잔여 위험 및 Closure 판정

**최종: `PHASE_36_9G_CONTEXT_ISOLATION_HOLD`**

차단 기준은 재현된 Case adapter cross-run Context 재사용이다. 요청별 소유권 binding과 거부 검증 전에는 36.9F 개선을 계약 종결로 승인하지 않는다. 나머지 36.9G 추가 경계/병렬 격리/성능 matrix 중 실행하지 않은 부분은 `PARTIAL/UNVERIFIED`다.

후속 작업은 단일 범위의 Context ownership remediation이다. 소유권 검증 테스트를 RED로 유지하고 private immutable run binding을 구현한 뒤 Case adapter, Correlation, API/Live, full regression 및 exact-SHA CI를 다시 검사한다. 36.9G에서 Production 코드를 직접 수정하지 않았다.

## 15. 다음 Phase 권고

36.9G가 HOLD이므로 36.10A로 넘어가지 않는다. 다음 후보는 `Phase 36.9G-R1 — Brute Window Context Run Ownership Remediation`으로 한정한다. 다른 window semantics, detector policy, schema, renderer 또는 실제 환경 평가를 함께 넣지 않는다.

## 16. 보안 경계

- 실제 사용자 자료: `NO_GO`
- 조직 운영: `NO_GO`
- 자동 대응: `NO_GO`
- 실제 운영 탐지 정확도: `UNVERIFIED`
- 모델 기반 AI: `NOT_TESTED`
- Safari/VoiceOver/실제 모바일: `NOT_TESTED`
- Vector/VM: `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`
- Renderer: `KEEP_LEGACY`
