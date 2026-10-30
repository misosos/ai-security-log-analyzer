# Phase 36.9G-R2-R1 — Analysis Owner 단일 결속 보완

## 1. Executive Summary

**판정: `PHASE_36_9G_R2_R1_UNIQUE_OWNER_BINDING_LOCAL_CONDITIONAL_GO`**

R2에서 재현된 결함은 Owner가 자신의 재결속만 막고, 같은 Analysis에 두 Owner가 붙는 것을 막지 못한 것이었다. 일반 `dict`는 인스턴스별 내부 속성을 가질 수 없고 weak reference도 지원하지 않아, 공개 결과를 바꾸지 않고 Analysis 객체만으로 역방향 소유자를 기억할 수 없었다.

Production은 private `dict` 하위 타입 `_OwnedAnalysisResult`를 사용한다. `AnalysisRunOwner._create_analysis_result()`가 새 빈 mapping을 만들면서 자신의 identity를 그 mapping에 저장하고, 해당 Owner도 그 mapping에 한 번 결속한다. Owner는 임의의 기존 mapping을 결속하는 API를 제공하지 않는다. 따라서 같은 Analysis를 Owner B에 재결속하는 동작은 실패하고, Owner A는 두 번째 mapping을 만들 수 없다. 공개 `analyze()` 결과는 기존 plain `dict`로 유지한다.

## 2. 시작 Gate 및 Dirty Tree 보존

- 기준 SHA: `ea0015836a34329e964c0285fbed8f665c826e7a`
- GitHub Actions Run `41044485341`: exact SHA, `push`, `completed/success`
- 필수 Python 3.12, lock, 전체 회귀, Linux process/checkpoint·SSH recovery, TCP Syslog, JSONL, restricted report, Chromium/axe, tracked-file 검사 성공
- Artifact: 0개
- 시작 branch `main`, HEAD/local main/origin main 일치, ahead/behind `0/0`
- v0.4.0 tag target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 불변

시작 시 R2가 남긴 `tests/test_brute_window_ownership_closure_36_9g_r2.py`, `docs/brute_window_context_ownership_closure_36_9g_r2.md`, `docs/index.md` 변경을 확인하고 보존했다. R2 HOLD 문서 자체는 수정하지 않았다.

## 3. 기존 RED와 원인

변경 전 R2 focused 테스트는 `2 passed, 1 failed`였다. 실패 재현은 Owner A가 이미 Analysis A에 결속된 뒤 Owner B가 같은 dict에 `_bind_analysis()`를 호출했을 때 예외가 발생하지 않는 것이었다. Owner B와 해당 Context를 새 wrapper에 넣으면 Case projection이 허용될 수 있었다.

기존 구조에는 Owner→Analysis 참조만 있었다. Analysis→Owner 역방향 표식도, 기존 Analysis dict를 다시 신뢰된 실행으로 포장하지 못하게 하는 경계도 없었다.

## 4. 대안 비교와 선택

### 공개 dict의 변경 또는 dict subclass 전면 노출

결과 mapping에 owner 키를 넣으면 닫힌 public schema를 변경한다. 모든 분석 반환 경로에 subclass를 노출하면 기존 exact-dict API 소비자 계약도 넓게 바뀐다. 채택하지 않았다.

### 전역/요청 간 registry

dict identity를 외부 side table에 보관하면 전역 수명, stale entry 및 요청 간 상태 관리가 추가된다. 금지된 공유 registry가 필요하므로 채택하지 않았다.

### Owner가 새 private mapping을 생성

Owner가 기존 dict를 받지 않고 새 빈 private mapping을 직접 생성한다. 그 객체에 Owner를 역방향으로 보유시키므로 두 번째 Owner의 결속을 객체 자체에서 거부할 수 있다. private contextual 경로에서만 사용하고 public 결과에서는 plain dict를 유지하므로 채택했다.

## 5. 생성·수명 및 일대일 결속

`AnalysisRunOwner._create_analysis_result()`는 실행마다 새 `_OwnedAnalysisResult`를 만들고 자신의 Owner 참조를 보관한다. 이어 `_bind_analysis()`가 그 결과를 단 한 번 연결한다.

- Owner A → 새 Analysis A: 허용
- Owner B → 이미 Owner A가 가진 Analysis A: 거부
- Owner A → 두 번째 Analysis B: 거부
- Owner B → 별도로 새로 생성한 Analysis B: 허용
- 임의의 일반 dict → `_bind_analysis()`: 거부

Owner의 생성 시각, dict 내용, IP, 계정 또는 이벤트 객체 identity를 소유권 증명으로 사용하지 않는다. 값이 같은 별도 실행은 별도의 결과 mapping과 Owner를 갖는다.

## 6. Context, Wrapper, Case Adapter

`AnalysisWithSourceRoleSnapshot`은 Brute Context가 있을 때 analysis mapping이 정확한 private owned mapping이며 wrapper의 Owner와 일치하는지 확인한다. `BruteWindowContext`의 owner identity·subject·event membership·Evidence 검증은 기존대로 유지한다.

Case adapter는 일반 public dict의 닫힌 키 검증을 그대로 유지한다. 내부 owned mapping은 검증을 위해 plain dict 복사본으로 키 집합을 검사하되, Context가 있는 경로에서는 원래 mapping의 owner binding도 별도로 확인한다. `build_incident_case_subject_inputs()` 직접 호출 또한 owned mapping과 일치하는 Owner를 요구한다.

기존 R2 RED 테스트는 다음 결과를 확인하도록 유지·갱신했다.

- 동일 Analysis에 Owner B를 직접 결속: `invalid_analysis_context`
- Owner B Context를 Analysis A wrapper에 재포장: 거부
- 정상 Run A projection: Case 1개 유지

새 테스트는 Owner의 1회 mapping 생성, 다른 Owner의 기존 mapping claim 거부, 정상 독립 실행, 직접 Case adapter의 잘못된 Owner 거부를 검증한다.

## 7. Correlation, Live 및 Source-role

정적 분석은 correlation 결과를 Owner가 생성한 private mapping에 채운 뒤 Risk를 계산한다. Restricted report도 같은 순서를 사용한다. Live proposal은 자체 결과 mapping을 proposal Owner로 생성하고 그 mapping에 subject 결과를 채운 뒤 Case input을 구성한다. 기존 Brute correlation은 계속 Context Owner identity와 실제 member event identity를 검사한다.

Source-role snapshot은 계속 Analysis 객체 identity에 결속된다. Owner는 role 근거를 대신하지 않는다. Legacy source-role 단위 테스트는 임의 dict 결속 대신 Owner가 생성한 빈 private 결과 mapping을 사용하도록 갱신했다.

## 8. Brute·Spray 및 공개 계약

탐지 임계값과 Candidate C selector는 변경하지 않았다. Brute Context는 계속 선택 window만 나타내고 전체 IP feature는 별도 유지한다. Password Spray, Correlation 선택 의미, Risk 산식, Case rule은 바꾸지 않았다.

`analyze()`는 내부 owned mapping을 기존 plain `dict`로 반환한다. API 응답 모델, `results`/`global_correlation` 키 집합, Evidence, Case DTO, Report 및 Checklist schema에는 owner 필드가 추가되지 않았다. `_OwnedAnalysisResult`의 owner는 slot에 보관되며 mapping key나 repr에 포함되지 않는다.

## 9. 검증 결과

- 변경 전 R2 RED 재현: `2 passed, 1 failed`
- 수정 중 focused Brute/Case/Live/API 검사: `207 passed, 2 warnings`
- owner/source-role/Live/SSH 핵심 focused 재검사: `53 passed, 2 warnings`
- 최종 전체 pytest: `3353 passed, 2 warnings` (macOS, Python 3.12)
- `uv sync --locked --dev`: 성공
- `uv lock --check`: 성공
- Evaluation boundary: `79/79`
- Detector accuracy corpus: 46개; Brute `TP 4 / FP 0 / FN 0 / TN 3`; operational false-alert 후보 7건
- 36.9D 24개: Candidate C `TP 17 / FP 0 / FN 1 / TN 5`; Whole-span `TP 9 / FP 0 / FN 9 / TN 5`
- 기존 Risk `70/70`, Case `70/70`, Linux process `21/21`; Parser `195/200` (ignored 2, rejected 3)
- Chromium/axe: `npm run test:a11y --silent` 통과, external requests 0
- `python3 -m compileall -q app tests`, `uv lock --check`: 통과
- `git diff --check` 및 untracked 신규 파일 whitespace 검사: 통과

평가 결과는 합성 자료의 고정 corpus 결과이며 실제 운영 정확도를 뜻하지 않는다.

## 10. 미해결 한계 및 보안 경계

이 방식은 신뢰된 동일 Python 프로세스 안의 생성 경계에서 실수로 인한 재결속·재포장을 막는 내부 계약이다. Python 객체의 private 속성은 악의적인 동일 프로세스 코드에 대한 암호학적 인증이 아니다. OS 수준 자원 상한, 강제 종료 뒤 secure erase, 실제 운영 입력의 탐지 정확도도 보장하지 않는다.

실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`; 실환경 정확도 `UNVERIFIED`; 모델 기반 AI `NOT_TESTED`; Safari/VoiceOver/실제 모바일 `NOT_TESTED`; Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`; 기존 renderer `KEEP_LEGACY`.

## 11. Rollback 및 다음 Gate

Rollback 대상은 `_OwnedAnalysisResult`, Owner 생성 지점, private contextual consumer type guard 변경으로 제한한다. Password Spray, selector, Evidence, Correlation 정책, API schema 또는 역사적 HOLD 문서는 rollback에서 변경하지 않는다.

다음 Phase 36.9G-R2-R2에서 새 커밋의 exact-SHA CI, cross-run Context, wrapper/Case adapter 우회, 정상 Correlation/Case, Live parity, mixed Application/SSH, offset-equivalent timestamp, API/privacy 및 전체 회귀를 독립 재검증해야 한다. 이번 로컬 결과만으로 36.9G 전체 Closure나 36.10A 진입을 승인하지 않는다.

## 12. 최종 판정

**`PHASE_36_9G_R2_R1_UNIQUE_OWNER_BINDING_LOCAL_CONDITIONAL_GO`**

이는 Owner↔Analysis의 신뢰된 내부 생성 경계를 보완한 로컬 결과다. R2-R2 독립 Closure가 별도로 필요하다.
