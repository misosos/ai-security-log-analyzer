# Phase 36.10B-R4 — Password Spray Consumer Integration Design & Security Gate

## 1. Executive Summary

**판정 제안: `PHASE_36_10B_R4_CONSUMER_INTEGRATION_DESIGN_LOCAL_CONDITIONAL_GO`**. 이 문서는 현행 계약을 코드와 characterization으로 확인하고, 향후 통합의 내부 경계·순서·차단 Gate를 정의한다. Production Window 적용, Correlation anchor 승인, 운영상 정확도 승인은 포함하지 않는다.

현재 Production Password Spray는 IP 전체 실패 집계(whole-span)를 유지한다. R3 Prototype은 `app/evaluation/` 전용이며 Production과 연결되지 않았다. Window를 Detector에만 연결하면 whole-IP Features, Correlation, Risk, Case, Report의 의미가 달라질 수 있다. 따라서 Window Context와 검증된 downstream consumer를 한 단계씩 별도 승인해야 한다.

결정되지 않은 Correlation 시간 기준은 `CORRELATION_ANCHOR_UNRESOLVED`로 유지한다. 중복 전달, NAT·공유 Egress, Batch 허용 여부의 운영 근거도 부족하다. 정책 상태는 `MORE_EVIDENCE_REQUIRED`, Production Window는 `NO_GO`다.

## 2. 시작 SHA / CI Gate

- 저장소/브랜치: `ai-security-log-analyzer` / `main`
- 기준 SHA 및 시작 HEAD, local main, origin/main, GitHub main: `39be2cd179bcf159e6ea860ab795efa944b4c294`
- 시작 Working Tree: clean; ahead/behind `0/0`
- GitHub Actions [Run 41200349828](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41200349828): 정확한 SHA, `push`, `completed / success`; Artifact 0개
- Locked Python 3.12, 전체 pytest, Linux checkpoint/SSH, TCP Syslog/JSONL, Restricted Report, Chromium/axe, tracked-file 검사가 통과했다.
- v0.4.0 Tag/Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`은 변경하지 않았다.
- 이 CI는 시작 SHA의 Gate 근거다. 로컬 R4 문서 변경 뒤 실행된 CI를 뜻하지 않는다.

## 3. 36.10B~R3 결과

아래 결과는 독립 합성 Corpus의 분리된 분모다. 서로 합산하거나 운영 Precision/Recall로 해석하지 않는다.

| 기준 | 결과 | 해석 경계 |
|---|---|---|
| 36.10B, 36 scenario | Current whole-span TP15/FP1/FN4/TN10; Sliding TP17/FP1/FN2/TN10; Known-account TP16/FP1/FN3/TN10 | Sliding은 late-noise 두 합성 FN을 회복했지만 중복·NAT/Batch 경보 후보는 해결하지 않았다. |
| R2, 33 scenario | Current Pattern TP23/FP1/FN5/TN3; Known Benign 경보 후보 4/6; Current correlation 6, C1 5, C2 2 | 합성 관측만의 결과다. Window 외 failure endpoint 문제를 재현했다. |
| R3 Prototype | Prototype 신규 테스트 33개 통과; R3 전체 pytest `3442 passed, 2 warnings` | Evaluation 전용 Run/Context 검증이며 Production 구현이나 운영 보장은 아니다. |

현재 Gate 시작 기준은 `3442 passed, 2 warnings`다. R4 실행 결과는 최종 보고에 기입한다.

## 4. 현재 Production Architecture

현재 흐름은 아래와 같다. 이는 코드상 현재 동작이다.

```text
NormalizedEvent list
  → detect_attacks_with_context()
      ├─ group_logs_by_ip()
      ├─ summarize_ip_failures() → 전체 IP Features
      ├─ select_brute_window_contexts() → Brute 전용 Window
      ├─ brute_force_detection_from_context()
      └─ detect_password_spray(전체 IP Features, 해당 IP failures)
  → correlate_attacks()
      ├─ Brute: Detection + Run-owned Brute Context 검증
      └─ Spray: Detection gate + 전체 IP 로그의 closest authentication pair
  → assess_risk_with_metadata() → 현재 Features/Detection/Correlation
  → Case Adapter → Typed Incident Case Projection
  → Report Projection / Restricted Report / API
```

`AnalysisRunOwner`는 Detection mapping, Correlated Analysis, Risk 결과를 동일 객체 및 입력 mapping 상태에 결속한다. Brute Context는 Owner를 보유하고, Brute Correlation과 Case Adapter는 Detection Evidence·Context·Run 관계를 검증한다. Spray에는 현재 Brute와 같은 Window Context 경로가 없다. `detect_password_spray()`는 `failure_count >= 4`, `unique_target_count >= 3`, `within_window`를 검사하고 Evidence 세 항목을 반환한다. 입력 Feature는 IP 전체 실패 범위이며 60초 조건은 `summarize_ip_failures()`의 `within_window`에 반영된다.

`correlate_password_spray_to_success()`는 Detection이 참일 때 동일 IP 이벤트 전체에서 `_closest_authentication_pair()`를 호출한다. Spray Window membership 인자는 없다. 현재 코드가 실제로 이 함수를 호출하는 구조와 R1의 gate-open characterization을 함께 읽어야 한다. R1에서 0~15초 후보 Window 뒤 90초 failure/95초 success가 주어지면 함수가 90→95초 pair를 반환했다. 정상 Production whole-span Detector가 false인 입력에서는 Detection gate로 관계가 생성되지 않는다.

## 5. R3 Prototype Architecture와 분리

R3의 `PrototypeSprayRunOwner`, `PrototypeSprayWindowContext`, Evidence 발급·검증, C1/C2는 `app/evaluation/spray_trusted_context_prototype.py`에 있다. 강한 Event 참조, snapshot, Context 발급 identity 및 고정 오류 코드를 이용해 동일 프로세스 내 우발적인 cross-run misbinding을 검사한다. R3 Prototype은 Production `AnalysisRunOwner`, Pipeline, Correlation, Risk, Case, Report에서 import되지 않는다.

R3는 같은 프로세스의 악의적인 Python 코드, reflection, private 상태 조작, 프로세스 메모리 변조, OS 격리를 방어한다고 주장하지 않는다. Python 객체 identity는 로그 수집의 Event ID가 아니며, 같은 값의 이벤트가 독립 시도인지 delivery replay인지 결정하지 않는다. R3 테스트 통과를 Production 계약의 통과로 승격하지 않는다.

## 6. Future Integration Architecture (제안)

```text
NormalizedEvent
       ↓
Production Analysis Run / AnalysisRunOwner
       ↓
IP Grouping + Whole-IP Features ───────────────┐
       ├─ Brute Window Context (현행 유지)      │
       └─ Spray Window Context (미구현 후보)     │
                    ↓                            │
             Spray Detection + bound Evidence    │
                    ↓                            │
        Trusted, scope-aware Correlation         │
                    ↓                            │
       Risk with separate scope inputs  ←────────┘
                    ↓
         Case Adapter / Incident Case
                    ↓
      approved internal Report Projection
                    ↓
       restricted/public API, Checklist, UI
```

이는 미래 설계 후보이며 현재 구현으로 표현하지 않는다. 유효하지 않은 Window Context나 Evidence는 Consumer에 전달하지 않는다. Whole-span 사용을 명시적으로 선택한 경로는 기존 정책으로 동작할 수 있지만, Context 검증 실패를 조용히 Whole-span 성공으로 바꾸는 fallback은 허용하지 않는다.

## 7. AnalysisRunOwner 통합 설계

현재 `app/detector/brute_force.py:AnalysisRunOwner`는 한 분석 실행을 표현하는 내부 capability다. Pipeline은 Detection 이후 `_bind_detection_results()`, Correlation 이후 `_bind_correlated_analysis()`, Risk 이후 `_bind_risk_analysis()`를 호출한다. Case Adapter는 contextual analysis wrapper와 Owner가 같은 실행에 bound 됐는지 확인한다. 이것은 실제 Production 경계다.

| 대안 | 장점 | 위험/비용 | 판단 |
|---|---|---|---|
| A. 기존 AnalysisRunOwner 확장 | 단일 Run의 Brute/Spray Context와 단계 결속을 한곳에서 검증할 수 있다. | Owner의 내부 상태·전이와 기존 Brute 회귀 범위가 커진다. Spray 다중 계정 membership을 단일 target 가정에 섞으면 안 된다. | **권고 후보.** 별도 Spray 슬롯/검증기를 추가하고 Brute 계약은 그대로 유지하는 상세 설계가 필요하다. R4에서는 미구현. |
| B. 별도 Spray Owner + Production Owner 결속 | Spray 경계를 독립적으로 유지한다. | 두 Owner 간 원자적 결속, 수명, 순서, cross-run 검증을 추가로 증명해야 한다. | 단일 Run 경계를 복수 capability로 분할해 복잡성을 높이므로 기본안으로 권고하지 않는다. |
| C. 공통 내부 Context Registry | Context 종류별 발급/검증을 모을 수 있다. | registry 수명·정리·token 관리가 전역 상태가 되면 isolation과 누수 위험이 증가한다. R3는 전역 registry를 사용하지 않는다. | 필요성 입증 전 도입 보류. |

**잠정 방향:** A를 먼저 별도 설계/테스트 Phase에서 구체화한다. Owner가 이벤트 snapshot/reference, Context issuance, Detection identity, Correlation, Risk 및 final analysis를 한 번씩 순차 bind하는 구조를 검토하되 구현 승인은 아니다. 정상적인 새 분석은 새 Owner와 새 이벤트 참조 집합을 가져야 한다. 새 실행이 기존 Owner를 재사용해서는 안 된다.

## 8. Spray Context 및 Window Membership

Production 후보 내부 Context는 최소 다음 정보를 가진다. Public Schema나 `NormalizedEvent`에 새 필드를 추가한다는 뜻은 아니다.

- 동일 Production Run Owner binding과 발급 identity
- canonical Source IP, 승인된 Selection Policy ID, 실제 Source 집합
- 선택된 `login_failed` Event references 및 검증 snapshot
- UTC-aware start/end와 실제 member 수
- 알려진 target cardinality, missing-account 수
- Evidence binding과 Context 검증 상태
- ambiguity 상태; 모호하면 선택 실패로 표시하고 임의 tie-break하지 않음

검증 불변식: 모든 Member는 같은 Owner가 등록한 실제 normalized failure이고, 동일 IP에 속하며, start/end가 member timestamp의 UTC min/max와 같다. Count·known account·missing user·source set은 member에서 재계산해 일치해야 한다. Mutation, duplicate reference, 다른 Run, 다른 IP, success event, Brute Context, unissued/repackaged Context, 미승인 policy ID는 fail-closed한다.

R3에서 같은 selection key가 모호할 때 Context 생성을 거부했다. 이 방식은 근거 멤버 집합을 임의로 선택하지 않지만 독립된 반복 인증 행위까지 제외할 수 있다. 따라서 아래를 구분해야 한다.

| 상황 | 현재 데이터로 가능한 판단 | 제안 처리 |
|---|---|---|
| 서로 다른 정규화 필드로 구분되는 실제 Event | 해당 Event 객체와 관측 필드를 구분 가능 | membership은 실제 참조로 유지; 행위자/시도 ID로 과장하지 않음 |
| 동일 값의 별도 Event 객체 | 메모리 객체는 다르나 실제 시도 구분은 불가 | 자동 병합/삭제 금지; 의미상 동일 선택이 안전하게 증명되지 않으면 ambiguity와 평가 제외/제한을 기록 |
| 외부 원천이 보장하는 Event ID로 증명된 재전송 | 현재 Parser 공통 계약에는 확인되지 않음 | 신뢰 원천·정규화·재사용 범위를 별도 검증하기 전 dedup 금지 |
| 중복 의심만 있는 경우 | 확정 중복 아님 | 별도 limitation/operational uncertainty; detection 사실을 조용히 제거하지 않음 |
| 행위 pattern도 독립 라벨상 불확정 | 평가 정답으로 확정 불가 | `PATTERN_UNDETERMINED`; 혼동행렬에서 분리 |

따라서 모호한 **membership 확정**은 fail-closed하되 이것을 “pattern 부재”라고 해석하지 않는다. Pattern 후보 자체를 누락할지 별도 관찰로 남길지는 Contract Freeze에서 명시하고 추가 duplicate corpus로 검증해야 한다.

## 9. Detection / Evidence Binding

향후 순서는 `Run Owner가 Event set을 한 번 결속 → Context 선택/발급 → Context 재검증 → Context에서 private Evidence 발급 → DetectionResult와 Context identity를 같은 Run에 결속 → Correlation/Risk/Case boundary에서 재검증`이어야 한다.

Public `DetectionResult`와 `Evidence` 구조를 그대로 유지하며 private Context reference로 검증할 가능성은 있다. 단, 현재 Spray DetectionResult 자체에 Run identity가 없으므로 객체 identity와 Owner의 bind ledger를 검증하는 내부 연결이 필요하다. Public DetectionResult 복사·동일 값 재포장만으로 신뢰가 승계되면 안 된다. Evidence의 failure count, known target count, UTC range, Source IP 및 member set가 Context에서 유래하고 일치해야 한다. Unknown account는 미추정 값으로 유지한다.

기존 Brute 검증 구조를 참고하되 복제해서 끝내면 안 된다. Brute는 single account window이며 Spray는 multi-account pattern이다. 기존 Public Schema에 표현할 수 없는 member membership과 missing-account limitation은 private verification 범위로 제한한다. 외부 의미를 표현하기 위해 Public Schema 변경이 필요하다고 판명되면 별도 API/UI 승인 Phase를 요구한다.

## 10. Correlation Time Anchor — 결정 미해결

현재 Production `correlate_password_spray_to_success()`는 Detection gate 뒤 전체 IP 로그에서 closest same-account failure/success pair를 찾는다. Window member, Owner 또는 Window End를 전달받지 않는다. R1 characterization은 candidate detection을 주입했을 때 late failure 90초와 success 95초가 선택될 수 있음을 보였다.

| 대안 | 의미/장점 | 반례 및 잔여 위험 |
|---|---|---|
| C1 — Member Failure Anchor | 실제 member failure가 endpoint. same known account/IP, strict failure-before-success, member→success ≤60초. | Pattern이 완성되기 전(success가 Window end보다 빠른) 성공도 관계가 될 수 있다. 여러 계정 중 한 계정의 pair가 전체 multi-account pattern의 성공처럼 보일 위험. |
| C2 — Window End Anchor + Member Validation | member 검증 및 알려진 계정 완전성; Window end 뒤 성공만 허용하고 end→success 및 실제 member failure→success bound를 검증. Pattern 완료 이후 관측이라는 설명이 명확하다. | Window end 뒤 최대 60초 규칙은 project heuristic이며 Window 내/완료 전의 실제 인증 전이를 놓칠 수 있다. 서로 다른 member 계정의 관계를 하나로 표현하지 않도록 추가 규칙 필요. |
| C3 — 별도 Observation Relationship | 인증 failure→success 관찰을 Spray pattern과 별개로 유지; 같은 IP/account/time이 확인되는 범위만 표현. | 사용자에게 두 사실의 시간상 동시성을 직접 보여주더라도 관계 causal 의미가 혼동될 수 있다. Pattern과 observation을 같은 Incident/Risk로 결합할지는 별도 계약이 필요. |

**R4 결정:** Production anchor는 확정하지 않는다. `CORRELATION_ANCHOR_UNRESOLVED`로 기록하며 Production Window 적용 Gate를 차단한다. C3는 과장 방지 측면에서 가장 보수적인 *설계 탐색 후보*이나 승인된 최종 의미는 아니다. 먼저 R4A에서 다음을 정해야 한다: (a) Window completion 이전 success 허용 여부, (b) success의 기준 시계, (c) 여러 member 계정 중 관계 표시 범위, (d) missing username, tie, same timestamp, duplicate pair의 fail-closed 기준, (e) risk/case/report가 관계를 소비하는 방식.

상관은 인증 실패→성공 관찰 또는 제한된 시간상 관련성을 나타낼 수 있을 뿐이다. 동일 행위자, 동일 비밀번호, credential reuse, 실제 추측 성공, account compromise 또는 인과관계를 증명하지 않는다.

## 11. Risk Consumer Migration

`app/analyzer/risk.py`의 `build_risk_context()`는 subject `features`, `detections`, `correlation`을 합친다. `evaluate_likelihood()`는 Spray Detection 및 Spray→Success Correlation을 우선 분기에서 검사한다. Spray-only 분기에도 `target_scope >= 3`와 whole-IP `within_window`가 사용된다. `build_risk_factors()`의 volume/temporal/targeting rationale와 `likelihood.failure_count`, `target_scope`, `time_window`는 IP 전체 feature를 기록한다. `evaluate_impact()`는 Brute/Spray 중 하나가 탐지되면 현재 account privilege context에 따라 인증 영향 level을 정한다. `evaluate_confidence()`는 detection/correlation 상태별 의미를 제공하며 Risk Level과 별도다.

Window Detection을 연결하면서 기존 Whole-IP Feature를 Window 값으로 덮으면 전체 관측량과 선택된 증거 범위가 혼동된다. 미래 입력은 `whole_ip_aggregate`, `selected_spray_window`, `validated_correlation`의 scope를 명시적으로 구분하고, Risk 분기마다 필요한 scope를 검증해야 한다. Detection True인데 Window Evidence가 invalid이면 risk를 계산하지 않고 fail-closed해야 한다. Correlation이 Owner/Window 검증을 통과한 경우에만 해당 분기를 사용한다. Brute/Spray가 같은 Event를 공유하면 독립 관찰로 이중 계산할 근거가 별도로 필요하다. Known Benign Context는 현재 Runtime 입력이 아니므로 Risk 자동 감쇠에 쓸 수 없다.

Risk 산식·가중치·임계값은 이번 단계에서 바꾸지 않는다. Level은 확률이 아니다. Confidence와 Impact도 별도 dimension으로 유지한다.

## 12. Case Adapter / Incident Case Migration

`app/analyzer/incident_case_adapter.py`의 `_detections()`는 Spray Evidence의 정확한 세 type/source/value 구조와 IP Features 관계를 확인한다. Brute만 trusted Window Context를 받아 전용 matcher로 검증한다. R1 characterization에서 전체 feature 5 failures/4 accounts/90초와 candidate Window evidence 4/4/15초를 섞은 Spray는 `invalid_detection_contract`로 거부됐다. 이 검증을 약화해서는 안 된다.

미래 Adapter는 Owner, Context issuance, Detection identity, membership, count/target/time, whole-IP feature 분리, Correlation endpoint, Risk input의 같은 Run 결속을 검증한 뒤 내부 typed Case 입력을 생성해야 한다. invalid context는 Case projection을 거부한다. Window 밖 이벤트를 Window Evidence로 끼워 넣지 않는다. Brute/Spray가 같은 Event를 사용할 경우 두 개의 독립 관측으로 세지 않는다.

`app/analyzer/incident_case.py`는 Spray detection을 현재 관측/독립 항목으로 다루지만 Assembly가 `CASE-SPRAY-SUCCESS-01`을 `unsupported_case_rules`에 `CASE_SPRAY_SUCCESS_STATUS`와 함께 반환한다. R4는 이 상태를 승인·활성화하지 않는다. Case Rule 승격, Spray-success 자동 Incident Case 생성, Risk 재평가 모두 금지한다. Public Case Projection은 현재 닫힌 필드와 식별자 제한을 유지해야 한다.

## 13. Report Projection / Restricted Report

현재 `PasswordSprayingLikeEvidenceProjection`은 `failed_attempt_count`, `target_account_count`, `time_window_seconds` scalar 3개다. `report_projection._authentication_evidence()`는 Detection의 세 Evidence 항목에서 이 scalar를 만든다. Window membership, start/end, missing-account count, policy ID가 현재 public/report DTO에 직접 표현되지 않는다.

| 대안 | 범위 | 장점 | 제한 |
|---|---|---|---|
| A. 기존 public scalar 유지 | public 값은 기존 Whole-span 의미 유지 | API/UI/Report schema 호환 유지 | 내부 Window와 기존 scalar가 같은 탐지에 보이면 설명 충돌이 남는다. 의미가 명확한 renderer 설명과 data lineage가 필요하다. |
| B. Private Semantic Projection | 내부 projection에서 whole-IP와 selected-window를 구분한 뒤 현재 Public Projection에 승인된 필드만 허용 | 의미 검증을 외부 schema와 분리 가능 | 현재 public scalar가 어느 scope를 설명하는지 확정해야 하며 projection boundary 테스트 필수. |
| C. 향후 Public Schema Migration | 승인된 Window 전용 scope/range/limitations field를 versioned API/UI로 추가 | 사용자에게 선택 범위를 직접 설명 가능 | API, UI 19-field projection과 호환성, Restricted Report, CSP, checklist/guidance 전 경로 승인 필요. |

R4 권고는 B를 먼저 내부 검증 후보로 연구하고, public schema가 의미 표현에 불충분할 경우 C를 별도 승인받는 것이다. A를 무비판적으로 사용하거나 Window Count를 전체 count로 표기하지 않는다. 현재 schema 3개 scalar와 `investigation-workspace-ui/v1` 19-field projection은 변경하지 않는다.

Restricted HTML Report는 현재 trusted projection과 allowlist된 DTO에서 생성된다. Private Owner Token, Context, Event member, raw log, 계정 목록을 report/API/UI/Checklist/Guidance로 직렬화하지 않는다. Checklist v2와 Guidance는 현재 명시적 요청 계약, closed input, safe DTO, case isolation을 유지한다. R4는 자동 요청이나 신규 Case field를 허용하지 않는다. Renderer rollback `KEEP_LEGACY` 유지.

## 14. Static / Live Integration Gate

R3는 동일한 synthetic Owner Event set의 membership/determinism만 검증했다. 실제 Collector, live checkpoint/resume, file rotation, restart, replay 및 publication의 Spray Context parity는 검증되지 않았다. R2에서 기록한 `[false, true, false]`는 whole-span 정책의 합성 Prefix 특성이지 Live integration 증거가 아니다.

통합 전에는 Static 전체 입력 및 Live prefix를 구분해 다음 시나리오를 같은 fixture lineage에서 검증해야 한다: batch 분할·순서 변경, late arrival, duplicate delivery/replay, restart, checkpoint resume, rotation/truncate, mixed Source, UTC offset normalization, same Run 재계산과 새 Run 생성, Context expiry, backpressure/resource bound, event loss. 동일 Event set의 결정성 시험과 관측 시점이 다른 Prefix 간 결과 차이 시험은 별도 결과로 낸다.

결정이 필요한 것: Live Event 추가 시 기존 Context를 invalidate/reissue할지, 확정 Window의 membership을 언제 freeze할지, 새 분석/재시작에서 새 Owner를 발급할지, 기존 Correlation/Case/Report를 어떻게 stale 처리할지, Checkpoint 후 동일 Event reference를 어떻게 재결속할지. 실제 Live integration 전까지 Gate G8은 차단이다.

## 15. Duplicate / NAT / Operational Evidence Gate

현재 공통 Parser/Event 계약에서 신뢰 가능한 원천 delivery ID가 보장된다는 근거는 확인되지 않았다. R3의 Event object identity는 in-process reference이지 transport identity가 아니다. 따라서 동일 문자열, timestamp/IP/user 조합으로 deduplication하지 않는다. Retry, replay, collector redelivery, 실제 반복 시도는 현재 신뢰성 있게 구분되지 않는다.

현재 `src_ip`는 관측 필드지만 단일 사람·행위자 식별자는 아니다. Parser가 NAT/VPN/proxy 뒤 사용자나 승인 Batch 실행 context를 제공한다는 근거를 확인하지 못했다. R2의 `KNOWN_BENIGN`은 manifest의 평가 라벨이지 Runtime metadata가 아니다. 정상 맥락은 자동 suppression 또는 Risk 감쇠로 사용하지 않는다.

추가 근거가 필요하다: (1) source별 event/delivery ID의 issuer, uniqueness, retention, replay 보장, (2) 재전송과 독립 attempt를 구분하는 라벨 근거, (3) shared egress와 사용자 principal의 신뢰된 관계, (4) 승인 Batch metadata의 owner/source/signature/validity와 런타임 결속, (5) 여러 source의 account canonicalization. 현행 Parser에 해당 계약이 있는지는 `UNVERIFIED`. 이를 확보하기 전 운영 false-alert 평가 및 Production policy approval은 보류한다.

## 16. Consumer Compatibility Matrix

`CURRENT_VERIFIED`는 현재 코드/테스트에서 확인, `PROTOTYPE_ONLY`는 Evaluation 전용, `DESIGN_PROPOSED`는 미래 설계, `REQUIRES_EVIDENCE`는 운영 근거 필요, `BLOCKED`는 선행 Gate 미통과, `NOT_TESTED`는 해당 통합 시험 미실행을 뜻한다. 파일/함수는 현재 Repository의 실제 경로다.

| Consumer / 코드 경로 | 현재 입력 → 출력 계약 | Future Window에서 필요한 입력 / 신뢰 검증 | 실패 시 / Public 영향 | 필요한 테스트·Phase | 상태 |
|---|---|---|---|---|---|
| NormalizedEvent — `app/models/schemas.py` | Parser가 만든 event fields와 raw 내부값 | 기존 normalized fields를 Run owner가 등록·snapshot; mutation 재검증 | invalid event 거부; schema 변경 불필요 목표 | Parser/source coverage + mutation; R5 | CURRENT_VERIFIED / DESIGN_PROPOSED |
| AnalysisRunOwner — `app/detector/brute_force.py` | Detection mapping, correlation, risk, final analysis identity/state | 별도 Spray context slot을 same Owner에 결속; one-shot transition 검증 | 기존 Owner 거부 유지; API 비노출 | cross-run, copy/repack, stage-order regression; R5 | CURRENT_VERIFIED / DESIGN_PROPOSED |
| IP Grouping — `app/analyzer/pipeline.py:group_logs_by_ip` | non-null `src_ip`별 그룹 | canonical IP 정책을 기존 grouping과 합의; member IP 검증 | invalid/cross-IP 거부; public 영향 없음 | canonical IP/alias/source test; contract freeze | CURRENT_VERIFIED / DESIGN_PROPOSED |
| Shared Features — `summarize_ip_failures()` | 전체 IP failed count, targets, span/window/interval | 별도 보존; 절대 Window count로 덮지 않음 | feature mismatch면 downstream reject | late noise 5/4/90 vs 4/4/15 regression | CURRENT_VERIFIED |
| Brute Context — `BruteWindowContext`, `validate_brute_window_context()` | same IP/account selected failure window + AnalysisRunOwner | unchanged; Spray type과 exact-type 분리 | 잘못된 context는 no-correlation/Case rejection | Brute full regression; R5 | CURRENT_VERIFIED |
| Spray Context — 현재 없음; R3 `app/evaluation/spray_trusted_context_prototype.py` | Production: whole-span Feature only; R3: eval-only owner/context | Production same-Run owner, actual member refs, UTC/IP/count/target/missing/source/policy, ambiguity state | invalid → reject; private only | ownership/mutation/ambiguity; R5, then R6 | PROTOTYPE_ONLY / BLOCKED |
| Spray Detection — `app/detector/password_spray.py:detect_password_spray` | whole-IP features → `password_spraying_like` + 3 Evidence | verified Context before any Window detection; keep whole-IP feature separately | context/evidence mismatch fail-closed; no API change initially | production parity + scope tests; R6 | CURRENT_VERIFIED / BLOCKED |
| Detection Evidence — `app/models/schemas.py:Evidence`, adapter matchers | 3 scalar evidence values; failed count has whole observed range | Context-issued evidence reference, matching membership/count/range/IP/Owner | mismatch reject; Public model unchanged unless separate approval | scalar/member lineage, copy/repack tests; R6 | CURRENT_VERIFIED / DESIGN_PROPOSED |
| Authentication Correlation — `app/correlation/attack_chain.py` | same-IP auth pair observation | do not let generic auth relation imply spray causation; identity/time scope separate | ambiguous pair no relation; existing contract preserved | auth pair isolation/tie; R4A/R6 | CURRENT_VERIFIED / DESIGN_PROPOSED |
| Spray→Success Correlation — `correlate_password_spray_to_success()` | Spray bool gates whole-IP `_closest_authentication_pair()` | explicit verified Context and approved C1/C2/C3 time/account rules | invalid context/no unique endpoint → no relation; relation wording remains noncausal | out-of-window, multi-account, pre-end, tie/missing, wrong-run; R4A then R6 | CURRENT_VERIFIED / BLOCKED |
| Risk — `app/analyzer/risk.py` | features+detections+correlation; whole-IP count/scope/span signals | separate whole-IP, Window Evidence, validated relation inputs and scope-specific branches | invalid/mixed scope stops analysis; no silent fallback | late-noise branch, double-count, all level/confidence tests; R7 | CURRENT_VERIFIED / DESIGN_PROPOSED |
| Case Adapter — `app/analyzer/incident_case_adapter.py` | exact shape/source/evidence/features and Brute trusted context | Owner + Spray Context + Detection/Risk/Correlation same-run verifier | preserve `invalid_detection_contract`; no projection | mismatch and cross-run rejection; R8 | CURRENT_VERIFIED / BLOCKED |
| Incident Case — `app/analyzer/incident_case.py` | typed observations, correlations; unsupported Spray-success rule status | only approved evidence semantics; independent observation vs relation distinction | unsupported Spray-success remains unsupported; no new auto case | assembly, overlap, unsupported rule unchanged; R8 | CURRENT_VERIFIED |
| Case Projection — `app/analyzer/incident_case_projection.py` | closed DTO / alias and limited safe values | only verified internal projection, no member list/private token | reject extra fields; public schema migration separate | privacy canary/schema negative; R8/R9 | CURRENT_VERIFIED / DESIGN_PROPOSED |
| Report Projection — `app/analyzer/report_projection.py` | three Spray scalar fields | internal semantic scope lineage; public fields only after explicit mapping | reject unverified scope; no raw evidence | scope mismatch, safe text and schema compatibility; R9 | CURRENT_VERIFIED / DESIGN_PROPOSED |
| Restricted Report — `app/local_investigation_api.py`, `app/analyzer/report.py` | restricted typed projection and controlled render | verified Projection only, no token/member/raw/account list | fail closed on invalid projection; schema/version approval | private canary, HTML escaping, report regression; R9 | CURRENT_VERIFIED / DESIGN_PROPOSED |
| Checklist — `app/investigation_checklist_36_2.py`, `app/investigation_checklist_api_36_3.py` | explicit safe case DTO request → checklist/v2 | only already-approved public case semantics; no private Context | preserve opt-in, stale ref refusal, case isolation | explicit POST only and privacy; R9 | CURRENT_VERIFIED |
| Guidance — `app/local_guidance_33_4.py` | explicit closed public-case DTO → lexical guidance | no Window private data; guidance corpus boundary unchanged | refusal on invalid/stale/corpus mismatch | no implicit request, case isolation; R9 | CURRENT_VERIFIED |
| Investigation Workspace — `frontend` + 19-field projection | existing closed `investigation-workspace-ui/v1` projection | public scope only after approved semantic mapping | validator rejects added fields; Legacy renderer remains | UI projection/privacy/rollback; R9 | CURRENT_VERIFIED |
| Static Analysis — `app/analyzer/pipeline.py`, loader/parser | complete normalized input batch | owner per analysis; deterministic context from exact set | fail closed or explicit whole-span selection, never context-error fallback | order/batch/source/time regression; R10 | CURRENT_VERIFIED / DESIGN_PROPOSED |
| Live Monitoring — `app/live_monitoring/*` | Prefix/accumulator/checkpoint-specific state | define reissue, stale invalidation, replay/rotation lifecycle | uncertain state cannot publish trusted Window result | real checkpoint/restart/late/replay integration; R10 | NOT_TESTED / BLOCKED |
| Trusted Analysis Provenance — `AnalysisRunOwner`, source-role wrapper | current Brute/analysis-stage ownership and source-role binding | Spray Context and final public projection same Run; no unowned handoff | exact owner mismatch reject | cross-run matrix end-to-end; R5–R9 | CURRENT_VERIFIED / DESIGN_PROPOSED |

## 17. Security Gate Matrix G1–G12

| Gate | 조건 / 현재 근거 | 미검증 및 통과 테스트 | 변경 계층 / 상태 |
|---|---|---|---|
| G1 Run Ownership | Production `AnalysisRunOwner`는 Brute/analysis 단계 binding을 검증; Spray Window slot 없음 | same Owner Brute/Spray, cross-run, copy/repack, mutation 및 정상 새 Run; R5 | Detector/Owner; **BLOCKED** |
| G2 Window Membership | R3 Evaluation Prototype에서 member/UTC/IP/count 검증 | Production normalized parser event에 같은 검사와 ambiguity semantics; R5 | Context; **PROTOTYPE_ONLY** |
| G3 Detection Evidence | Production Spray evidence는 whole-span; R3 private Evidence는 Context issued | Detection identity + context + scope exact binding, production parity; R6 | Detector/Evidence; **BLOCKED** |
| G4 Correlation | 현 Spray는 전체 IP pair를 선택; C1/C2 비교 Prototype은 존재 | anchor, completion timing, account scope, ties, wording decision; R4A + R6 | Correlation; **BLOCKED — CORRELATION_ANCHOR_UNRESOLVED** |
| G5 Risk | whole-IP features 및 correlation 분기를 실제 사용 | scope-separated risk characterization, overlap/double count, evidence consistency; R7 | Risk; **DESIGN_PROPOSED** |
| G6 Case Adapter | 범위 불일치 Spray Evidence는 현재 거부; Brute owner context 검증 | new context same-run accepted path + invalid rejection without weakening; R8 | Adapter; **BLOCKED** |
| G7 Report/Public Projection | 3 scalar Spray fields; 19-field workspace schema closed | scope-aware internal projection, no private serialization; schema migration approval if needed; R9 | Report/API/UI; **DESIGN_PROPOSED** |
| G8 Static/Live | batch prototype only; real live parity unverified | prefix, late, checkpoint, restart, rotation, replay, stale output integration; R10 | Live/accumulator; **BLOCKED / NOT_TESTED** |
| G9 Duplicate/Shared Egress | R2 benign candidates; common trusted delivery ID/NAT principal not verified | duplicate identity and shared egress corpus + product/source contract; R5 evidence stage | Parser/ops context; **REQUIRES_EVIDENCE** |
| G10 Privacy/Security | current APIs/projections closed; R3 prototype redacts repr/CLI | production Context ingress, serialization, logs, reports privacy canary; R5/R9 | all boundaries; **DESIGN_PROPOSED** |
| G11 Regression | Start CI exact SHA success; R1/R2/R3 characterization recorded | all existing CLI/tests + new consumer path regression, no Brute/API/UI drift | all; **CURRENT_VERIFIED baseline, future BLOCKED** |
| G12 Operational Acceptance | no production corpus/user/organization authorization in these phases | separate data/operations approval and evaluation; no auto response; independent sign-off | operations; **BLOCKED / NO_GO** |

R3 통과만으로 G1, G3–G12를 통과 처리하지 않는다. G9/G12가 해소되지 않는 한 `MORE_EVIDENCE_REQUIRED`를 유지한다.

## 18. 마이그레이션 Stage 및 별도 승인

아래는 설계 순서 제안이며 R4에서 실행한 Production 변경은 없다. 각 Stage는 별도 Phase, 시작 조건, 종료 Gate, 회귀 및 검토를 요구한다.

| Stage | 범위 | 완료 전 차단 조건 |
|---|---|---|
| 1 — Contract Freeze | Whole-IP vs Window, policy ID, ambiguous membership, dedup/missing-user, C1/C2/C3 semantics 확정 | Correlation anchor unresolved면 다음 단계 금지 |
| 2 — Trusted Context Internal | 기존 Whole-span 선택 유지하며 Production Owner와 별도 Spray Context lifecycle 검증 | G1/G2 실패면 Detection 이식 금지 |
| 3 — Detector/Evidence Binding | Context에서 private Evidence 발급 및 Detection identity 결속 | G3 및 existing Production parity 실패면 Correlation 금지 |
| 4 — Correlation Integration | 승인된 endpoint/time/account contract만 추가 | G4 미통과면 Risk 연동 금지 |
| 5 — Risk Compatibility | Whole-IP, Window, relation 입력을 scope별로 전달·검증 | G5/기존 Risk regression 실패면 Case 금지 |
| 6 — Case/Report Compatibility | Adapter fail-closed 유지, 내부/public 의미 mapping 검증 | G6/G7 미통과면 API/UI/public report 금지 |
| 7 — Static/Live Integration | real prefix/checkpoint/replay/rotation/expiry path 검증 | G8 미통과면 Live Window 금지 |
| 8 — Policy Decision | duplicate/NAT/Batch 포함 추가 evidence를 검토해 정책 재평가 | G9/G12 미통과면 Production Window 계속 NO_GO |

단계 건너뛰기, 통합 대량 PR, 실패를 기존 whole-span으로 숨기는 방식은 허용하지 않는다.

## 19. Rollback / Compatibility

향후 마이그레이션은 현재 whole-span 경로를 명시적으로 선택할 수 있어야 하며 Brute 경로와 기존 API/Report schema를 보존해야 한다. 새 Spray Context가 없는 기존 분석도 기존 path에서 동작해야 한다. 그러나 Window path에서 Context 검증 실패를 자동으로 Whole-span detection으로 변환하는 silent fallback은 금지한다. 실패는 명시적 non-result/error boundary로 기록해 신뢰 실패를 감추지 않아야 한다. 부분 이관에서 검증되지 않은 Correlation/Risk/Case/Report는 공개하지 않는다.

Public schema/문구가 바뀌면 호환성/versioning 및 API/UI 승인 검토가 별도 필요하다. `KEEP_LEGACY` renderer rollback은 유지한다. Rollback 기준은 Owner/context mismatch, wrong member/endpoint, scope 혼합, Risk/Case/Report 왜곡, privacy leak, Static/Live stale 결과, Brute 회귀 중 하나라도 관찰되는 경우다.

## 20. Characterization Tests / 현재 근거

R1 `tests/test_spray_consumer_contract_design_36_10b_r1.py`가 현재 동작을 read-only로 확인한다.

1. late-noise 입력에서 whole IP `5 failures / 4 accounts / 90 seconds`, `within_window=False`, current Spray detection false, evaluation Sliding candidate true.
2. Candidate detection을 correlation boundary에 주입했을 때 90s failure→95s success pair가 선택될 수 있다. 이는 Production pipeline wiring이 아니라 Consumer 함수 동작 characterization이다.
3. risk boundary에서 candidate detection을 주입하면 current correlation의 90→95 pair와 함께 whole-IP `5/4/90` signal이 유지된다.
4. Whole-IP Features와 candidate Window Evidence가 다른 Spray contract는 Case Adapter가 `invalid_detection_contract`로 거부한다.
5. Report Projection의 Spray Evidence는 scalar `failed_attempt_count`, `target_account_count`, `time_window_seconds`만 갖는다.

R3 `tests/test_spray_trusted_context_prototype_36_10b_r3.py`는 Evaluation-only Owner, copy/repack, mutation, UTC/60초, count/target/missing-user, ambiguity, Evidence binding, C1/C2, out-of-window endpoint 등을 검증한다. Prototype import 경계와 CLI redaction도 확인한다. 이는 production Consumer integration 테스트가 아니다.

R4는 문서 전용 변경으로 진행한다. 기존 검증이 이미 의도한 경계를 덮으므로 characterization assertions를 중복 추가하지 않는다. Runtime UI/Checklist/Guidance 계약은 기존 UI3 Navigation E2E 및 Checklist/Guidance privacy 테스트를 regression으로 재실행한다.

## 21. Research Basis / Observable Evidence Mapping / Limitations

이번 R4는 새 Detection threshold나 로그 해석을 만들지 않는다. 4 failures / 3 known targets / 60 seconds는 앞선 평가의 **project heuristic**으로, 권위 있는 보안 표준값이 아니다.

- MITRE ATT&CK, [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/), Last Modified 2025-10-24. Password spray 행위 설명은 동일 비밀번호 재사용을 요구하는 공격 개념과 current telemetry의 차이를 이해하는 데 사용했다. 실제 코드의 조건으로 복사하지 않았고, 현재 parser가 credential value를 제공한다고 보지 않는다.
- Microsoft Learn, [Learn about the sign-in log activity details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details), Entra ID 전용 product documentation (조회 2026-10-31; 페이지에 별도 갱신 일자는 검색 결과에서 확인 불가). Entra 제품에 Request/Correlation ID 및 event time와 ingestion time 차이가 있다는 점은 source-specific stable event identity의 중요성을 보여주지만, 이 ID가 Repository의 Application/SSH event에 제공된다는 근거는 아니다.

**Observable Evidence Mapping:** 실패/성공 관계는 repository normalized `event_type`, `timestamp`, `src_ip`, `user`가 실제로 존재할 때 same-IP/account 및 시간 순서라는 관측 관계를 계산한다. Window 후보는 같은 Run의 `login_failed` members와 known `user` 집합에 제한된다. 비밀번호, 실제 attempt ID, delivery replay identity, NAT 뒤 사용자, Batch 승인, actor sameness는 사용할 telemetry에 없다.

**Limitations:** 합성 Corpus는 운영 분포나 실제 오류율을 추정하지 않는다. Correlation이 같은 account/IP/time을 연결해도 인과·같은 actor·credential reuse·침해를 입증하지 않는다. 공통 Event ID, trusted Batch approval, NAT principal mapping은 미확인이다. 실제 Live Collector parity, production Spray Owner, Consumer integration, Safari/운영 acceptance는 미검증이다. Prototype Python identity는 process 내부의 우발적 misbinding 위협 모델에 한정된다.

## 22. Privacy / Security 및 Production Non-change

R4에서 Raw Log, password, real account, user data를 사용하거나 출력하지 않는다. 외부 Network/LLM 호출은 없었다. Public Schema, CSP, Checklist/Guidance opt-in, Case isolation, Trusted Analysis Provenance, Brute Context, Static Asset limit, Legacy Renderer 정책은 변경하지 않는다. R3 Prototype 및 36.10B Ground Truth도 수정하지 않는다.

금지된 Production 파일은 수정하지 않는다. 본 단계는 whole-span detector, correlation, risk, Case, report, API, frontend, Live 동작을 바꾸지 않는다. Private Context를 외부 직렬화하지 않는 미래 설계 원칙을 명시했지만 이는 아직 production serialization path에서 검증된 구현이 아니다.

## 23. Open Decisions / Residual Risks

1. Correlation C1/C2/C3 및 time anchor: unresolved; `CORRELATION_ANCHOR_UNRESOLVED`.
2. 동일 값 distinct Event와 ambiguous membership 사이에서 pattern을 어떻게 별도 기록할지: Contract Freeze 필요.
3. Source-specific trusted Event/Delivery ID 존재·보장: `UNVERIFIED`.
4. NAT/VPN/Proxy principal mapping 및 승인 Batch context: `UNVERIFIED`.
5. Cross-source username canonicalization: `UNVERIFIED`.
6. Spray Context 수명, Live reissue/invalidation 및 stale Case/Report 처리: 미구현·미검증.
7. Public scalar 3개로 Window scope를 설명할지 versioned schema가 필요한지: 별도 API/UI 승인 판단.
8. Production `AnalysisRunOwner` 확장에 따른 기존 Brute 회귀 범위: Prototype 통과가 대체하지 않는다.

## 24. Rollback

R4 문서만 되돌릴 경우 신규 설계 문서와 `docs/index.md`의 링크를 제거하면 된다. Production 코드와 기존 평가 파일에는 변경이 없다. 로컬 commit 이전에는 해당 두 파일만 대상으로 변경을 검토하며, 과거 Phase 문서나 Ground Truth를 수정하지 않는다.

## 25. 최종 Decision 및 다음 Phase

문서·필수 회귀가 통과하면 R4 판정은 `PHASE_36_10B_R4_CONSUMER_INTEGRATION_DESIGN_LOCAL_CONDITIONAL_GO`로 한다. 아래는 별도로 계속 차단된다.

- Production Password Spray: `WHOLE_SPAN`
- Policy Recommendation: `MORE_EVIDENCE_REQUIRED`
- Production Window: `NO_GO`
- `CORRELATION_ANCHOR_UNRESOLVED`
- G1/G3/G4/G6/G8/G12: Production 진입 전 차단
- G9: `REQUIRES_EVIDENCE`
- `PRODUCTION_GO`, `POLICY_CHANGE_APPROVED`, `LIVE_PARITY_VERIFIED`, `OPERATIONAL_ACCURACY_VERIFIED`, `PUBLIC_SCHEMA_MIGRATION_APPROVED`: 부여하지 않음

**다음 Phase 권고: `Phase 36.10B-R4A — Spray Correlation Semantic Decision`.** Anchor와 관계 의미가 unresolved인 상태에서 Owner/Consumer 통합을 먼저 진행하면 테스트 계약이 흔들릴 수 있다. R4A는 C1/C2/C3 시간 기준, multi-account attribution, missing account, tie/same-time, pre-window-end success, 관계 표현과 consumer 의미만 별도 합성 평가로 결정한다. 별도로 중복/NAT/Batch 근거 확보가 계속 필요하므로 `MORE_EVIDENCE_REQUIRED`는 유지한다. R4A 통과가 Production 적용을 자동 승인하지 않는다.

### 최종 경계

- 실제 사용자 자료: `NO_GO`; 조직 운영: `NO_GO`; 자동 대응: `NO_GO`
- 실환경 탐지 정확도: `UNVERIFIED`; 모델 기반 AI: `NOT_TESTED`
- Safari 사용자 수용: `SAFARI_USER_ACCEPTANCE_PENDING`; VoiceOver/실제 모바일: `NOT_TESTED`
- Vector/VM: `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`
- OS-level hard CPU/memory cap: 미보장; secure erase: 미보장
- Renderer: `KEEP_LEGACY`
