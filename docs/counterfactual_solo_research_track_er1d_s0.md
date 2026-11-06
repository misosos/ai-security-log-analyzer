# ER-1D-S0 — Solo Research Track 설계

## 1. Executive Summary

연구 질문: 동일한 고정 합성 로그에 입력 변형을 적용했을 때 실제 Detector 결과가 달라지는 이유를 검증 가능한 관측 사실과 정책 조건으로 어디까지 설명할 수 있는가? 대상은 Brute Force와 Password Spraying-like의 Baseline/Variant, Parser disposition, 실제 Replay, Comparison, 검증된 SafeFacts와 현행 Production Predicate다. 본 문서는 실험 프로토콜만 설계한다. 새 실행 코드와 Production 연결은 구현하지 않는다.

독립 검토가 없어도 설계·기존 자동 실험의 재현과 한계 기록은 가능하다. **S1 착수 HOLD**: 연구용 코드가 ER-1D 구현에 포함되는지 기존 문서가 예외를 정하지 않았으므로, 독립 검토를 대체하거나 HOLD를 암묵적으로 축소할 수 없다. 독립 검토·수동 승인 조건을 충족하거나, 권한 있는 별도 governance 결정으로 충돌을 명시적으로 해소하고 범위·격리 설계를 승인하기 전에는 프로토타입을 시작하지 않는다. 어느 경로도 이번 S0에서 승인하지 않는다.

## 2. Start Gate

기준 SHA `6ba524ebc5c958cbb2d65a6fca0f46b3e2f22cbb`, Exact CI `42209979702`: push / completed / success, head SHA 일치, Locked Python 3.12 regression 및 Linux·Restricted Report·Chromium/axe·tracked-file 단계 성공, Artifact 0. 시작 HEAD/local main/origin main/GitHub main 일치, tree clean, ahead/behind 0/0. `v0.4.0` tag 및 Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지. `AGENTS.md`와 security-analysis/security-testing 지침을 확인했다. `ER_1D_S0_START_GATE_GO`.

변경 전 로컬 macOS `uv run pytest -q`: 3884 passed, 2 warnings. CI는 GitHub Ubuntu 결과다. 기존 연구 근거는 [ER-0](evidence_research_er0.md), [ER-1A](counterfactual_corpus_er1a.md), [ER-1B](counterfactual_detector_replay_er1b.md), [ER-1C](counterfactual_holdout_validation_er1c.md), [ER-1C-R](counterfactual_independent_review_er1c_r.md), [ER-1D-P](counterfactual_sensitivity_explanation_design_er1d_p.md), [ER-1D-G0](counterfactual_explanation_readiness_audit_er1d_g0.md), [ER-2C](counterfactual_safe_evaluation_projection_er2c.md)를 따른다. 이전 문서의 단계별 상태는 작성 당시 시점으로 읽는다.

## 3. 1인 프로젝트 제약과 기존 Governance

| 활동 | S0의 판단 | 필요한 후속 결정 |
|---|---|---|
| A. 연구 설계와 기존 고정 합성 자동 실험 계획 | 허용된 문서 작업. 기존 실험을 독립 사람 검토라고 부르지 않는다. | 각 실행은 기존 계약 범위에서 명시적으로 기록 |
| B. 연구용 프로토타입 구현 | 후보만 설계. 기존 HOLD에 대한 적용 범위 충돌 미해결 | 별도 명시적 승인 및 기존 HOLD와의 관계를 기록한 governance 결정과 격리 검증 |
| C. Production 설명 기능 | 기존 독립 사람 검토와 수동 승인에 의해 차단 | ER-1C-R의 30건 검토, digest·독립성·누락/이견 처리 및 수동 승인, 별도 구현 Gate |

상태는 `INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`, `ER_1D_IMPLEMENTATION_HOLD`, `ER_2F_USER_ACCEPTANCE_PENDING`이며 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`다. 1인 개발과 자동 검사는 독립 검토의 대체 근거가 아니다.

## 4. Solo Research 목적과 허용 범위

설계의 목표는 탐지 발생·소멸뿐 아니라 해당 합성 실행에서 변한 입력 사실과 정책 조건을 검증 가능한 근거로 제한해 설명하는 것이다. 단일 원인, 모든 공격의 회피 원인, 침해, 독립 검증 완료, 운영 보증, 오픈소스 대비 독창성을 주장하지 않는다. 정책 임계값은 프로젝트 휴리스틱이며 외부 표준의 보편 기준이 아니다. 기존 [ER-0 연구 근거](evidence_research_er0.md)는 관측 가능성과 한계의 배경이지 수치 승인 근거가 아니다.

## 5. Production/Research 격리 설계

후속 승인 시 후보 위치는 `app/evaluation/research_er1d/`의 별도 evaluation 전용 모듈과 이에 대응하는 `tests/`다. 지금 디렉터리를 만들지 않는다. 고정 합성 Corpus만 읽고 사용자가 파일 경로·URL·Corpus root를 입력할 수 없게 한다. 명시적 오프라인 실행만 허용하고 네트워크·외부 LLM 호출은 0, 출력은 bounded closed schema와 fixed 오류로 제한한다. Production API/UI, Investigation registry, Risk, Correlation, Detector, Parser, 자동 대응 및 기존 Corpus/Label을 수정하거나 연결하지 않는다. raw log, IP/account, timestamp, private Evidence/context/owner, 내부 경로와 예외 원문을 출력하지 않는다.

기존 Replay는 이미 실제 Production 경로를 합성 입력으로 호출한다. 이는 읽기 전용 재사용 후보이지 새로운 신뢰 경계를 증명하지 않는다. 현재 공개 Replay DTO에는 owner-bound Brute 선택 window aggregate가 없다. 연구 코드가 이 결속을 얻으려 Production 모듈 또는 기존 Replay 계약 수정이 반드시 필요하면 해당 설계는 HOLD이며 별도 Gate로 회송한다. 임의 조립한 DTO나 private context를 공개 경계로 내보내지 않는다.

## 6. 네 계층 Evidence Contract

| 계층 | 현재 구현과 후속 계약 | 결측 시 |
|---|---|---|
| A Direct Input Mutation | 고정 manifest와 `apply_mutation()`이 7종 변형을 실행한다. scenario/mutation 종류는 연결되나 공개 가능한 변경 대상 참조와 bytes provenance는 설명 DTO에 없다. raw row는 출력하지 않는다. | 해당 직접 변경 Claim 보류 |
| B Observed Feature Delta | `SafeFacts`는 Parser facts와 target IP 집계를 제공한다. Baseline/Variant의 동일 scope/version 및 run 결속된 설명용 delta는 미구현이다. Brute selected-window는 동일 account의 선택 창이며 Spray whole-span은 같은 IP의 전체 실패다. target IP 집계를 Brute window로 대체하지 않는다. | 서로 다른 범위의 수치 비교 금지, delta 미평가 |
| C Policy Predicate | 기존 Production Brute 5회/60초 선택 창, Spray 4회/3계정/60초 전체 span을 그대로 관측한다. predicate별 `SATISFIED` / `NOT_SATISFIED` / `NOT_EVALUATED`와 같은 실행의 안전한 근거 결속은 설계뿐이다. | `NOT_EVALUATED`; 값이 없으면 0/False로 채우지 않는다 |
| D Detector Observation | 기존 Replay는 새 실행으로 실제 Detector 상태와 Comparison을 보존하고 owner/Evidence를 내부 검증한다. `INCOMPARABLE` / `UNDETERMINED`는 음성 탐지가 아니다. Parser `REJECTED`는 `NOT_DETECTED`가 아니다. | 원래 상태·fixed reason 유지, 전체 또는 해당 Claim 보류 |

네 계층 중 필요한 근거가 부족하거나 모순되면 그 Claim을 축소하거나 보류한다. Detector 결과를 설명기로 덮어쓰지 않는다. SafeFacts는 owner-bound selected-window evidence가 아니다. 자세한 현재 producer와 누락 근거는 [G0 감사](counterfactual_explanation_readiness_audit_er1d_g0.md)를 기준으로 한다.

## 7. 자기 검증과 독립 검증

각 향후 실험에서 실행 전 가설·예상 결과·반증 조건을 기록하고 Corpus/Fixture digest, 코드·정책 버전, 실행 명령과 환경을 고정한다. 기존 Replay 결과와 새 실험 결과를 별도로 보관하고 같은 입력의 결정적 재실행을 비교한다. 정상 사례와 주입 실패 사례를 구분하며 각 Claim에 안전한 Evidence 참조, scope, 한계와 반례를 붙인다. 자기 검토자는 작성자와 동일함을 명기하고 독립 사람 검토 미완료를 상시 표시한다. 자동 기대값을 사후에 맞춰 수정하지 않는다.

연구 기록의 후보 상태는 `AUTOMATED_VERIFIED`(명시된 자동 검사 범위만 통과), `SELF_REVIEWED`(작성자 자기 검토), `NOT_VERIFIED`(근거 미확보), `INDEPENDENT_REVIEW_PENDING`(독립 검토 미완료)이다. 서로 별개 차원이며 Production DTO나 승인 상태가 아니다. 자동 테스트와 자기 검토는 같은 작성자의 전제·누락을 공유할 수 있으므로 독립적으로 검증된 정확성을 뜻하지 않는다.

## 8. 실패·반증 테스트 매트릭스

아래는 구현된 테스트가 아닌 후속 승인 시 필수 설계다. 공통 실패 처리는 해당 Claim을 생성하지 않고 fixed status/reason을 남기며 부분 성공을 전체 승인으로 표시하지 않는 것이다. 각 행의 검증 근거는 명시한 기존 상태·scope·provenance 계약과 별도의 합성 주입 테스트다.

| 입력 조건 | 기대 상태 | 실패 처리 | 금지 출력 | 검증 근거 |
|---|---|---|---|---|
| Parser REJECTED | NOT_EVALUATED / INCOMPARABLE | 분석 Claim 보류 | NOT_DETECTED·안전 | ER-1B Parser/Comparison |
| Parser PARTIAL | 부분 scope 명시, 완전성 필요 Predicate NOT_EVALUATED | 원래 Replay 상태 유지 | 전체 입력에 대한 부재 단정 | Parser disposition |
| Execution Failure | EXECUTION_FAILED / UNDETERMINED 또는 기존 비교 결과 | fixed 오류, 원문 예외 제외 | false·0·음성 판정 | Replay 실행 상태 |
| Policy Version Mismatch | INCOMPARABLE | 상이한 정책 비교 중지 | 같은 정책으로 표현 | Comparison scope |
| Detector Version Mismatch | INCOMPARABLE | 비교 중지 | 동일 Detector Claim | Comparison provenance |
| 다른 Scope의 Feature | NOT_EVALUATED | delta 보류 | 범위를 합친 수치 | scope ID 및 단위 |
| Missing Evidence | NOT_EVALUATED 또는 UNDETERMINED | Claim 보류 | 추측한 count·False | Evidence provenance |
| Invalid Evidence Membership | UNDETERMINED | 결속 실패 거부 | 검증된 근거 Claim | Replay membership |
| 서로 다른 Run Owner의 Context 결합 | UNDETERMINED | cross-run 입력 거부 | owner가 일치한다는 주장 | owner identity 및 binding |
| 잘못된 Brute selected-window 집계 | NOT_EVALUATED | window 검증 실패 | IP 전체 count를 선택 창으로 표시 | Brute context membership |
| Spray whole-span을 window로 오해 | NOT_EVALUATED | 다른 scope 계산 거부 | prototype sliding 결과를 Production으로 표시 | Spray 전체 min/max span |
| 복수 특징 동시 변경 | 관측별 분리 또는 NOT_EVALUATED | 단일 attribution 보류 | 유일 원인 확정 | mutation 후 모든 facts 재계산 |
| Label Leakage | INVALID / Claim 보류 | 전체 출력 거부 | expected label·basis | closed allowlist 및 canary |
| Raw Log / Account / IP 유출 | INVALID / Claim 보류 | 전체 출력 거부 | 원문·식별자 | allowlist 및 privacy canary |
| Mutation provenance 불일치 | NOT_EVALUATED | scenario 결속 거부 | 변형 사실 확정 | fixture·variant digest |
| Missing Timestamp / Unknown Account | NOT_EVALUATED 또는 실제 Parser 상태 | 누락을 명시 | 0·False 대입 | Parser completeness와 정책 입력 |
| Comparison 상태와 설명 Claim 모순 | UNDETERMINED 또는 기존 상태 유지 | Claim 보류 | Comparison 재작성 | ER-2A-R1 outcome/reason |

## 9. 기존 ER-1D HOLD와의 충돌 분석

[ER-1D-P §14–15](counterfactual_sensitivity_explanation_design_er1d_p.md)는 별도 사람 검토, 실제 제출·누락/이견 처리, digest·독립성 근거 및 수동 승인 없이는 **구현을 시작하지 않는다**고 명시한다. [ER-1C-R §13](counterfactual_independent_review_er1c_r.md)도 ER-1D 기능 개발 전 같은 Gate를 요구하며, [G0](counterfactual_explanation_readiness_audit_er1d_g0.md)는 이후 개발을 사람 검토로 차단한다. 연구 전용 구현을 제외하는 문구는 확인되지 않았다. S1~S4는 같은 설명 기능의 연구 프로토타입 후보이므로 그 범위에 속하는지의 승인 문제가 해결되지 않았다.

S0는 예외를 창설하지 않는다. 별도 명시적 승인도 현행 Gate를 자동으로 취소하지 않으며, 권한 있는 governance 결정이 기존 조건의 충족 또는 적용 범위의 명시적 변경을 기록해야 한다. 그 결정이 없다면 S1 포함 구현 전체는 HOLD다. Production 구현은 연구 결과와 무관하게 기존 독립 검토·수동 승인을 요구한다.

## 10. S1~S4 단계별 연구 계획

모든 단계는 후보이며 각 시작 전 별도 명시적 승인, 정확한 기준 SHA/CI, 변경 범위 및 전 단계 성공 증거가 필요하다. 공통 금지 범위는 §5의 Production·Replay 계약·Corpus/Label·API/UI·의존성 변경이다. 모든 테스트는 합성 입력·오프라인 경계에서 실행하고 실패 시 HOLD한다.

| 단계 / 목표 | 선행조건과 허용 파일 후보 | 필요한 Evidence와 테스트·반증 | 보안 위험 및 완료·다음 Gate |
|---|---|---|---|
| S1 Safe Aggregate Research Prototype | §9 충돌 해소 및 격리·별도 명시적 승인; 후보 `app/evaluation/research_er1d/safe_aggregate.py`, 전용 tests/docs | 같은 실행의 owner/Evidence membership; Brute selected-window와 Spray whole-span, cross-run 주입, 누락·불일치·privacy canary | private context 누출 및 잘못된 집계. Production/Replay 변경이 필요하면 HOLD. 승인 범위의 자동 검사·자기 검토만 성공 기록 후 S2 별도 Gate |
| S2 Feature Delta Research | S1 승인된 산출·결과, provenance와 동일 scope 계약, S2 별도 승인; 후보 `feature_delta.py`와 전용 tests/docs | baseline/variant field·unit·scope·policy 및 owner binding, 범위 불일치·다중 변화·결정성 | IP 전체 feature를 선택 창으로 혼동. 증거 결측 시 delta 보류; 반증 포함 검증 후 S3 별도 Gate |
| S3 Predicate Explanation Research | S2 결과 및 정책 버전 계약, S3 별도 승인; 후보 `predicate.py`와 전용 tests/docs | 현행 Production 조건과 근거별 SATISFIED/NOT_SATISFIED/NOT_EVALUATED, 경계·누락·버전 차이 | 평가용 prototype을 Production으로 오인. 일치 검증과 범위 제한 후 S4 별도 Gate |
| S4 Bounded Explanation Research | S3 결과, closed Claim/uncertainty 및 privacy 계약, S4 별도 승인; 후보 `bounded_claims.py`와 전용 tests/docs | A–D 결속, 비교 상태·reason 정합성, 복수 변화, label leakage, 결정성 및 실패 주입 | 허위 인과·원문 유출. 반증과 실패 상태를 포함한 연구 평가 완료 후 별도 사람 검토 및 Production 진입 Gate; 자동 진급 금지 |

각 단계의 완료는 그 단계의 승인된 합성 자동 실험과 자기 검토에 국한한다. 허용 파일은 후보이지 생성 권한이 아니다. 새 경로가 고정 Source를 읽는 방식, 프로세스별 네트워크 차단, 임시 파일 수명과 closed output은 구현 승인 전 별도 검토한다.

## 11. 기술적·검증상 남은 차단 조건

- owner-bound Brute 선택 window safe aggregate와 Evidence membership을 공개 DTO 없이 동일 실행에서 검증하는 경계가 아직 없다.
- Direct mutation의 안전한 참조, 같은 scope의 delta, Predicate별 입력 provenance 및 불완전 Parser 처리 계약은 구현되지 않았다.
- 현재 공개 Replay에서 private owner를 사후 복원할 수 없다. Production 또는 기존 Replay 변경이 불가피하면 연구 후보는 HOLD다.
- S1을 포함한 연구 코드와 기존 ER-1D HOLD의 관계를 결정하는 별도 governance 기록이 없다.
- 독립 검토자 제출, 30건 완결성·의견 불일치 처리, 독립성 확인 및 수동 승인 근거가 없다.

ER-1C-R과 ER-1C-H0의 Label-Blind Packet·정책 요약·빈 양식·30건·digest·비교/이견 처리 절차를 유지한다. 외부 검토 전에는 기존 expected label, Replay 결과, 연구 예상값과 자기 검토 결과를 정답으로 제공하지 않는다. 공개 저장소에 정답이 있어 기술적 완전 blind는 보장되지 않는다. 사람 검토자의 열람 여부와 독립성은 별도 확인한다.

## 12. 위험과 한계

고정 합성 입력은 현실 환경이나 운영 정확도 평가가 아니다. Parser 성공은 로그 수집 완전성·원천 시계 정확성·실제 사용자 정체성을 증명하지 않는다. NAT·공유 계정 등은 해석에 영향을 줄 수 있다. 여러 파생 값이 동시에 바뀌므로 관측된 관계는 유일한 인과 설명이 아니다. 자동 검사와 자기 검토는 작성자 편향을 공유한다. Digest는 변경 탐지용이며 사람 검토·서명·출처 인증을 증명하지 않는다. 연구 output이나 Viewer는 독립 검토용 Blind Packet을 대체하지 않는다.

## 13. 최종 판정

`ER_1D_S0_SOLO_RESEARCH_DESIGN_LOCAL_CONDITIONAL_GO`는 본 설계와 문서 회귀에만 적용한다. S1 착수 HOLD 및 §9의 별도 governance·격리 검토·명시적 승인이 선행된다. 이 설계는 ER-1D 구현이나 Production 사용을 승인하지 않는다.

- `INDEPENDENT_HUMAN_REVIEW_PENDING`
- `MANUAL_APPROVAL_REQUIRED`
- `ER_1D_IMPLEMENTATION_HOLD`
- `ER_2F_USER_ACCEPTANCE_PENDING`
- 실제 사용자 자료·조직 운영·자동 대응: `NO_GO`

### 검증 기록

변경 전 전체 pytest 3884 passed, 2 warnings. 문서 계약 RED: 문서·색인 미존재로 3 failed. 문서 작성 후 S0와 ER-1D-P/G0 관련 문서 테스트 10 passed. 변경 후 전체 `uv run pytest -q`: 3887 passed, 2 warnings. `uv run python -m app.evaluation`: Synthetic Boundary 79/79, Risk 70/70, Case 70/70, Linux Process 합성 분류 21/21; 이는 운영 성능이 아니다. `uv lock --check`, `uv run python -m compileall -q app tests`, `git diff --check` 성공. 이 자동 결과는 독립 사람 검토가 아니다.
