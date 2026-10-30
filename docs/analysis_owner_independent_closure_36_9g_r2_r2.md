# Phase 36.9G-R2-R2 — Analysis Owner 독립 Closure

## 1. Executive Summary

**판정: `PHASE_36_9G_R2_R2_CONTEXT_ISOLATION_HOLD`**

R2-R1은 하나의 `_OwnedAnalysisResult`에 두 Owner를 직접 결속하는 경로와 Owner의 두 번째 mapping 생성을 막는다. 그러나 독립 재현에서 Run A의 분석 결과를 새 Run B의 Owner 소유 mapping에 복사하고, Run B의 동일 fixture 이벤트로 새 Brute Context를 만든 뒤 Case projection을 실행하자 Case 1개가 생성됐다. 새 mapping의 타입과 새 Owner의 결속은 검증되지만, 그 mapping 내용이 Run B의 신뢰된 분석 계산에서 만들어졌다는 출처는 검증되지 않는다.

Production 코드는 수정하지 않았다. 새 독립 RED 테스트는 이 결과를 요구된 정책(복사·재포장으로 기존 결과에 새 provenance를 부여하지 못함)과 대조해 실패한다. 나머지 고비용 closure matrix는 이 격리 결함 때문에 실행하지 않았다.

## 2. 시작 Gate

- 기준 SHA: `5e4d2f8c7e5c1fa27d2e68acee8179149e003c07`
- GitHub Actions Run `41051522852`: exact head SHA, `push`, `completed/success`
- Branch `main`; HEAD/local main/origin main 모두 기준 SHA, ahead/behind `0/0`
- 시작 working tree clean; `git diff --check` 통과
- 필수 job의 lock/Python 3.12, 전체 회귀, Linux process/checkpoint·SSH, TCP Syslog, JSONL, restricted report, Chromium/axe, tracked-file 단계가 모두 성공
- Run artifact: 0개 (`gh run download`에서 다운로드할 artifact 없음)
- v0.4.0 target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

## 3. 기존 HOLD 이력과 R2-R1 감사

36.9G, R1, R2 및 R2-R1 문서는 수정하지 않았다. R2-R1 diff는 Production 9개 파일, 문서 3개, 테스트 3개(총 15개 파일)였다. Owner/Context 내부 mapping을 정적 분석·Live·restricted report·Case 소비자에 전달하고 공개 `analyze()` 반환을 plain dict로 유지하는 변경은 목적과 직접 연결된다. 공개 schema, 탐지 threshold, Password Spray 규칙, Risk 산식, Case rule 변경은 이 diff에서 확인되지 않았다.

R2-R1 구현은 `AnalysisRunOwner._create_analysis_result()`에서 새 `_OwnedAnalysisResult`를 만들고, mapping과 Owner 양쪽 참조를 결속한다. 이미 결속된 Owner의 두 번째 mapping, 임의 일반 dict의 결속, 다른 Owner의 기존 owned mapping 결속은 거부한다. Wrapper와 adapter는 Owner의 mapping identity를 확인하고, source-role snapshot은 별도로 Analysis 객체 identity에 결속된다.

## 4. 소유권 계약의 독립 재현

### 통과한 직접 결속 검사

기존 R2-R1 테스트와 전체 suite에서 확인된 계약은 다음과 같다.

- Owner A가 새 mapping A 생성: 허용
- Owner A의 두 번째 mapping 생성: 거부
- Owner B가 mapping A를 `_bind_analysis()`로 claim: 거부
- Owner A가 별도 mapping B에 재결속: 거부
- 값이 같은 새 실행은 별도 Owner/mapping: 허용
- 정상 Run의 Case projection: 기존 테스트에서 유지

### 발견한 복사·재포장 우회

새 테스트 `tests/test_analysis_owner_closure_36_9g_r2_r2.py`는 독립 parser 입력을 사용했다.

1. Run A에서 정상 Analysis A, Owner A, Context A를 생성한다.
2. 같은 합성 fixture를 다시 읽어 Run B 이벤트를 만든다.
3. Owner B와 B 이벤트의 Context B를 생성한다.
4. Owner B가 새 owned mapping B를 만들고 `mapping B.update(Analysis A)`로 기존 결과 내용을 복사한다.
5. B mapping에 결속된 Source-role snapshot과 Context B로 Wrapper B를 만든다.
6. 실제 `project_investigation_cases_from_analysis(Wrapper B)`를 호출한다.

기대는 과거 결과를 새 실행으로 재포장했으므로 거부되는 것이다. 실제 결과는 `case_count=1`이다. 복사된 mapping은 새 객체지만 `results` 하위 dict는 A와 B에서 동일 객체로 공유된다. `_OwnedAnalysisResult`의 owner 표식은 “누가 mapping을 발급했는지”는 나타내지만, “mapping의 값이 그 run의 trusted pipeline 계산에서 채워졌는지”는 나타내지 않는다.

실행 결과: 신규 테스트 `1 failed`; 실패 assertion은 `case_count == 0` 기대에서 실제 `1`을 관측했다. 이는 테스트를 xfail 처리하거나 기대를 완화하지 않은 RED다.

## 5. 복제·재포장 경계

비변경 진단에서 `dict(owned)`, `owned.copy()`는 plain dict가 되어 owned 타입 검사에 통과하지 않았다. `copy.copy(owned)`는 `_OwnedAnalysisResult` 타입과 embedded Owner 참조를 보존하지만, 원본 Owner의 `is_bound_to(copy)`는 false다. `deepcopy` 결과도 원본 owner binding과 일치하지 않는다. 따라서 단순 복사만으로 원본 실행의 identity 결속을 얻는 경로는 거부될 수 있다.

하지만 새 Owner가 새 mapping을 발급한 뒤 이전 분석 값을 채워 넣는 재포장은 통과했다. 따라서 단순 mapping copy의 차단만으로 전체 provenance 계약을 종결할 수 없다. 이 문제는 Owner A/B를 같은 mapping에 직접 결속하는 기존 R2 결함의 재발은 아니지만, 값이 복사된 이전 Analysis를 새로 발급된 Owner가 자기 실행의 분석 결과로 받아들이게 한다.

`analyze()`는 내부 owned root mapping을 `dict(result)`로 반환해 plain dict 공개형을 유지한다. 이 작업에서 공개 스키마 변경은 확인되지 않았다. Root copy 이후 nested `results` 공유는 관측했지만, 외부 공개 API에서 그 mutation이 내부 신뢰된 실행을 변경하는 소비 경로는 이번 재현에서 사용하지 않았다. 이를 독립적인 보안 결함이라고 단정하지 않는다. 다만 내부 mapping builder가 nested mutable 결과를 복사해 채울 때 출처를 잃는 사실은 이번 RED의 직접 조건이다.

## 6. Wrapper·Case Adapter·Correlation

R1 Wrapper는 owned mapping의 Owner, Context의 Owner, Source-role snapshot의 Analysis identity를 일치시킨다. 직접 Case adapter도 `run_owner.is_bound_to(bound_analysis)`, owned mapping 타입, Context Owner, subject, membership, evidence를 검사한다. 이번 재현은 그 검사들을 모두 만족하는 새 B mapping을 만들었기 때문에 adapter는 정상적으로 통과한다. adapter에서 특정 비교가 누락된 것이 아니라, 새 owned mapping 발급 자체가 복사된 분석 값의 provenance를 보장하지 않는 것이 원인이다.

정상 Brute Correlation endpoint 정책은 코드상 선택 window 종료, 동일 IP·계정, 성공 strictly-after 및 최대 60초를 유지한다. 기존 전체 suite는 회귀 기준을 통과했다. 다만 이번 발견 이후 cross-run 재포장 입력에서 Correlation의 독립 교차 실행 행렬은 실행하지 않았으므로 closure 결과로 주장하지 않는다.

## 7. 정상 호출 경로 및 미완료 검증

코드 경로상 `main` contextual analysis, Live proposal, restricted report가 새 owner mapping을 발급해 결과를 채운다. Local Text/File 및 Sample 경로는 contextual analysis wrapper와 기존 projection/report 흐름을 사용한다. 기존 회귀 suite는 이 호출 경로들을 포함해 통과했다. 이번 phase에서 별도 API E2E, SSE, restricted report 개인정보 행렬, live proposal 교차-owner 행렬을 재실행하지 않았다.

다음은 이번 실행에서 **미실행**이며 PASS로 간주하지 않는다.

- 36.9D 24개 정책별 전체 window 비교 CLI
- UTC offset-equivalent/혼합 Application·SSH 독립 matrix
- 동일 prefix Static/Live parity 및 proposal discard/revision matrix
- Password Spray 차등 matrix와 다른 6개 Detector 개별 비교
- Case observation의 모든 시각·계정·rule 필드 독립 검증
- Text/File/Sample API·Restricted Report E2E
- 대규모 bounded benchmark 및 메모리 추세
- 전체 privacy canary matrix

격리 핵심 기준이 실패했으므로 이를 수행해도 closure를 상쇄하지 않는다. 후속 독립 재검증에서 수행해야 한다.

## 8. 평가·회귀 결과

- 시작/변경 전 전체 pytest: `3353 passed, 2 warnings` (macOS, Python 3.12)
- `uv sync --locked --dev`, `uv lock --check`: 성공
- 전체 pytest에는 기존 R2-R1 owner 및 R2 재현 테스트가 포함되어 모두 통과
- 기존 소유권/Brute focused suite 5개 파일: `27 passed, 2 warnings`
- 신규 독립 재현: `1 failed` (의도한 보안 기대가 현재 구현에서 위반됨)

이번 Phase에서 evaluation corpus, fixture ID, Ground Truth 또는 기존 평가 기대값을 변경하지 않았다. 기록된 기준선은 36.9C Historical `TP 3 / FP 0 / FN 1 / TN 3`, Current `TP 4 / FP 0 / FN 0 / TN 3`, 36.9D Candidate C `TP 17 / FP 0 / FN 1 / TN 5`, Whole-span `TP 9 / FP 0 / FN 9 / TN 5`다. 본 Phase에서는 CLI 평가를 재실행하지 않았으므로 이를 새 측정 결과로 표현하지 않는다.

## 9. 최소 후속 remediation 방향

현재 blank-map factory만으로는 mapping 값의 trusted 생성 provenance를 보장하지 못한다. 후속 수정은 owner-bound 결과를 만들고 내용을 채우는 작업을 하나의 좁은 trusted pipeline builder 안에 묶어야 한다. 기존 Analysis dict나 다른 run의 subject mapping을 받아 owner-bound mapping으로 포장하는 일반 경로가 없어야 한다. Context 선택, correlation, risk 결과와 동일 run의 최종 analysis mapping이 한 생성 흐름에서 연결되는지 검증해야 한다. 공개 `analyze()` plain dict, 기존 API schema, Password Spray·Risk·Case semantics는 유지한다.

이 remediator는 이번 closure에서 구현하지 않았다. Python private API는 악의적인 동일 프로세스 코드에 대한 암호학적 인증이 아니며, 계약 목표는 신뢰된 내부 흐름에서 우발적인 복사·재포장 및 교차 실행 사용을 막는 것이다.

## 10. 최종 판정 및 경계

**`PHASE_36_9G_R2_R2_CONTEXT_ISOLATION_HOLD`**

36.10A로 이동하지 않는다. 다음은 여전히 `NO_GO`: 실제 사용자 자료, 조직 운영, 자동 대응. 실환경 탐지 정확도 `UNVERIFIED`; 모델 기반 AI `NOT_TESTED`; Safari/VoiceOver/실제 모바일 `NOT_TESTED`; Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`; OS hard CPU/memory cap 및 secure erase 미보장; Renderer `KEEP_LEGACY`.
