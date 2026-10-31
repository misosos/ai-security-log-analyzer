# Phase 36.10B-R2 — Spray Window Consumer Boundary Independent Validation

## 1. Executive Summary

**판정: `PHASE_36_10B_R2_INDEPENDENT_VALIDATION_LOCAL_CONDITIONAL_GO`** — 33개 신규 합성 시나리오와 평가 전용 Window/Correlation 경계 검증을 통과했다. 이 판정은 합성 평가·테스트에만 해당한다. Production Password Spray는 기존 whole-span 정책이며 정책 권고 `MORE_EVIDENCE_REQUIRED`를 유지한다.

새 Corpus의 150개 입력 행은 모두 현재 Parser에서 정규화됐고, 그중 3개 시나리오는 계정 정보가 일부 빠져 `PARTIAL`로 분류됐다. 현재 Production Detector는 이 Corpus에서 TP 23 / FP 1 / FN 5 / TN 3이었다(판정 가능한 라벨만 분모). 알려진 정상 맥락 6개 중 4개에서 관측 패턴이 탐지됐다. 이는 Pattern FP와 분리한 합성 운영상 경보 후보이며 실환경 경보율이 아니다.

late-noise 사례에서는 whole-span Detection이 닫혀 실제 Production Correlation은 없었다. Detection gate를 후보로 열어 현재 Correlation 함수를 별도 특성화하자 전체 입력에서 90초 실패와 95초 성공을 골랐다. Window member-bound 후보는 해당 실패가 Window member가 아니므로 관계를 만들지 않았다. 후보 방식은 이 특정 경계 문제를 줄였지만, 계정 누락·중복·실행 provenance와 Live 수집 범위의 운영 근거는 해결하지 않는다.

## 2. 시작 Gate / CI

- Repository: `ai-security-log-analyzer`, `main`
- 기준 SHA / local HEAD / local main / origin main / GitHub main: `8fe908c07c9a766d2b3116b890ad61b143384ace`
- 시작 Working Tree: clean; ahead/behind `0/0`
- GitHub Actions [Run 41193800999](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41193800999): exact SHA, `push`, `completed / success`; 필수 Linux/Python/Chromium/axe/Tracked-file 단계 성공, Artifact 0개
- 시작 전체 pytest 기준선: `3388 passed, 2 warnings`
- v0.4.0 tag/release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 불변

## 3. R1 설계 기준 및 구현 경계

R1은 Whole-IP Aggregate와 Selected Spray Window를 다른 관측 단위로 정의했다. R2에서 만든 `SprayWindowContext`와 `EvaluationRun`은 `app/evaluation/spray_consumer_boundary.py` 안에서만 쓰이는 평가 객체다. Context는 실제 `NormalizedEvent` 참조, 동일 평가 owner, 실패 타입, 동일 IP, UTC 시작/끝, member 수, 알려진 계정 수, 누락 계정 수를 검증한다. 생성된 Context 객체 자체를 owner에 결속해 같은 값의 새 Context 재포장도 거부한다.

이는 Production `AnalysisRunOwner` 또는 신뢰 경계 구현이 아니다. 악의적인 같은 프로세스 Python 코드의 내부 상태 변조 방지 주장도 하지 않는다. Brute의 `BruteWindowContext`는 Spray Context로 받지 않는다.

## 4. Corpus 및 독립 라벨

`sample_logs/spray_consumer_boundary_evaluation/manifest.json`은 33개 독립 합성 시나리오를 닫힌 필드로 정의한다. 각 행에는 Pattern, 운영 맥락, Parser 상태, Correlation eligibility, fixture 작성 시 알고 있는 underlying attempt 수, 중복 전달 oracle 여부, 라벨 근거가 별도 기록된다. 운영 승인·재전송 oracle 정보는 Parser/Detector 입력으로 전달하지 않는다.

| 축 | 분포 |
|---|---|
| Behavioral Pattern | PRESENT 28, ABSENT 4, UNDETERMINED 1 |
| Operational Context | CONTEXT_UNKNOWN 22, KNOWN_BENIGN 6, NOT_LABELED 3, SIMULATED_ATTACK 2 |
| Parser Observation | VERIFIED 30, PARTIAL 3 |
| Correlation eligibility | PAIR_ELIGIBLE 2, PAIR_NOT_ELIGIBLE 5, PAIR_AMBIGUOUS 7, NOT_APPLICABLE 19 |

Corpus는 32개 Application 입력과 2개 SSH 입력을 33개 시나리오에서 사용한다. `mixed_source_lookalike`는 두 Parser의 이벤트를 같은 documentation IP 집계로 결합해 이 합성 Pipeline 경계를 확인한다. 이는 실제 혼합 Collector/Live 경로를 검증한 것은 아니다. 모든 주소는 RFC 문서용 범위이며 계정명은 합성 `spray_*`다.

### Parser 관측

| 입력 행 | Parsed | Ignored | Rejected | PARTIAL Scenario |
|---:|---:|---:|---:|---:|
| 150 | 150 | 0 | 0 | 3 |

상태는 실제 parser 출력으로 산출하며 manifest 기대값과 불일치하면 실행을 실패시킨다. 지원하지 않는/거부 형식은 이번 코퍼스에 포함하지 않아 REJECTED/IGNORED 경계의 런타임 수치는 없다.

## 5. Duplicate / Replay 및 운영 맥락

`replay_three_attempts_four_rows`는 underlying attempt 3과 observed failure rows 4를 별도로 가진다. 현재 Detector는 4개 행을 계산해 탐지한다. oracle상 중복 전달 1개를 뺀 반사실 결과는 탐지 기준 미달이다. 반면 `genuine_four_attempts_identical_rows`도 동일한 4행이지만 한 계정만 있어 다중 계정 Spray 조건을 충족하지 않는다. 따라서 동일 내용 반복만으로 “4회/3계정” 조건을 자동 충족한다고 해석하지 않는다.

현재 로그에 공통 신뢰 Event ID가 없는 경우 완전히 같은 문자열이 재전송인지 독립 재시도인지 구분할 수 없다. oracle counterfactual은 fixture metadata로만 계산되며 Runtime dedup 정책 근거가 아니다. 현행은 관측 행을 각각 세며, R2는 자동 dedup을 구현하지 않았다.

KNOWN_BENIGN 6개 중 Production에서 4개가 탐지되어 operational false-alert candidate로 별도 기록됐다. Shared NAT, VPN, proxy, 승인 batch, 혼합 맥락은 fixture 설명일 뿐 Runtime 입력이 아니다. IP 하나가 같은 사용자·행위자를 뜻하지 않으며, 승인 여부를 현재 인증 이벤트만으로 판단할 수 없다.

## 6. Current Detection 및 Pattern 결과

Current Detection은 실제 `app.main.analyze()` / Production pipeline을 호출했다. Window 후보는 별도 평가 함수로 유지했다.

| Corpus / 지표 | 결과 |
|---|---:|
| Current Pattern TP | 23 |
| Current Pattern FP | 1 |
| Current Pattern FN | 5 |
| Current Pattern TN | 3 |
| Excluded undetermined | 1 |
| Excluded parser rejected | 0 |
| Known benign operational candidate | 4 / 6 |

이 작은 평가용 R2 집합은 Phase 36.10B의 36개 집합(15/1/4/10), 기존 Detector Accuracy의 46-scenario 집합(TP2/FP0/FN0/TN5)과 다른 분모다. 수치를 합산하거나 운영 precision/recall로 해석하지 않는다. Pattern label은 fixture 관측 조건으로 독립 작성했고, `KNOWN_BENIGN`은 별도 축이다.

## 7. Correlation: C0 / C1 / C2

- **C0 Current**: Production `correlate_password_spray_to_success()`를 실제 호출했다. 전체 Pipeline에서 Detection이 거짓이면 관계도 생성되지 않는다.
- **C0 gate-open characterization**: Window 후보가 있다고 가정해 기존 함수에 Detection gate만 열었을 때의 별도 특성화다. Production wiring을 의미하지 않는다.
- **C1 member-bound**: 평가 Window의 실제 member 실패만 대상으로, 같은 IP·알려진 계정·엄격한 failure < success·최대 60초 조건을 적용한다. Success가 Window end 뒤인지 강제하지 않는 시간 기준 후보다.
- **C2 conservative**: C1에 더해 member 내 누락 계정이 있으면 거부하고 Success가 Window end 이후인 경우만 허용한다. 이 조건은 보수적 후보일 뿐 승인된 정책이 아니다.

| 계량 항목 | C0 actual | C1 | C2 |
|---|---:|---:|---:|
| Correlated scenarios | 6 | 5 | 2 |

`window_outside_late_failure_success`에서 실제 Current Detection은 whole-span 90초로 false이고 actual C0 관계는 없다. gate-open 특성화에서는 90→95초 endpoint가 선택된다. 90초 실패는 0–15초 선택 Window member가 아니며 C1/C2는 관계를 만들지 않는다. 따라서 후보가 이 예시의 out-of-window endpoint를 막는 것은 확인됐다.

C1은 Window 안에서 패턴이 완성되기 전의 Success도 과거 member 실패와 시간 조건을 만족하면 연결할 수 있다. C2는 이를 Window end 전이라는 이유로 제외한다. 어느 시간 anchor가 적절한지는 아직 설계 선택이다. 계정 없는 실패·다중 계정 Window는 행위자 귀속 또는 credential reuse를 의미하지 않는다. 관계는 공격 성공·침해·인과를 증명하지 않는다.

| 경계 | 평가 결과 |
|---|---|
| Cross-account / Cross-IP | member-bound 후보에서 matching member pair가 없어 no relation |
| Missing username | C2가 member account 불확실성에서 fail-closed; C1은 확인된 동일 계정 member만 후보 |
| Equal-delta / duplicate pair | R2 `equal_delta_pair`에서 C1/C2 모두 `ambiguous_pair`로 거부; 각각 1건 |
| Success before failure | 엄격한 시간 순서 때문에 no relation |
| Same timestamp | 동일 timestamp pair는 순서가 없어 후보가 아님; 더 이른 동일 계정 member가 있으면 별도 합법 후보가 될 수 있음 |
| Different Run / copied event | evaluation owner, context identity, member object identity로 거부 |
| Brute/Spray | 별도 Context type 유지, 교차 전달 거부 |

상관관계 eligibility는 관계 쌍의 적격성만 라벨링한다. 동일 사용자 계정 필드가 일치해도 동일 인간·행위자나 인과를 증명하지 않는다.

## 8. Window Membership 및 Provenance

평가 validator는 다음을 검사한다: exact evaluation Context type, owner identity 및 owner 발급 객체 identity, 모든 member가 현재 event list의 동일 객체인지, 중복 참조 없음, 실제 `login_failed`, 같은 documentation IP, UTC-aware timestamp, 실제 member min/max와 정확한 endpoint, member 수, 알려진 계정 cardinality, missing count, 평가 정책 ID. 단위 테스트는 다른 IP, 성공 Event member, count/target/time 변조, duplicate reference, empty member, 다른 Run, 값이 같게 복제된 Event/Context 및 Brute Context를 거부한다.

이는 테스트용 검증기의 효력이다. Production Run Ownership, hidden context, immutable member evidence가 구현됐다는 뜻은 아니다. 내부 API를 호출하는 악성 Python 코드가 private state를 공격하는 위협 모델은 다루지 않는다.

## 9. Risk / Case / Report Consumer 호환성

Production 경로는 수정하지 않았다. R1 Characterization test `tests/test_spray_consumer_contract_design_36_10b_r1.py`가 실제 Risk의 whole-IP `failure_count`, `target_scope`, `time_window` 및 현재 Correlation 조합을 확인하고, Case Adapter가 candidate Window evidence와 Whole-span feature의 불일치를 거부하는 경계를 확인한다. R2는 해당 테스트를 그대로 regression으로 실행한다.

현재 Report Spray projection은 세 scalar(실패 수, target account 수, time window seconds)만 표현하며 membership/start-end/중복 신뢰/누락 계정 제한을 직접 나타내지 못한다. 따라서 Window metric을 기존 scalar에 대입하면 의미가 섞일 수 있다. Checklist/Guidance 및 Investigation UI는 닫힌 projection을 소비하므로 Window 적용 시 공개 schema 영향 검토와 별도 승인 필요하다. 이 R2에서 실제 Case/Report 소비자에 후보를 연결하지 않았다.

| Consumer | 현행 계약 | Window 적용 전 필요한 검증 | 실패 시 경계 |
|---|---|---|---|
| Detector | `detect_password_spray()` whole-span threshold와 3 Evidence | Selected member evidence 별도 identity 및 range | Detection-Evidence mismatch 거부 |
| Shared Features | IP 전체 failure/target/span | Whole-IP aggregate와 Window metric 동시 보존 | 한 범위 값을 다른 범위에 대입 금지 |
| Correlation | Detection gate 뒤 same-IP 전체-event nearest pair | Window member·account·time anchor·tie·success timing | endpoint 모호하면 no relation |
| Risk | Detection/Correlation 및 whole-IP count/target/span | Detection scope와 rationale scope 일치, Brute 중복 가산 분석 | 범위 불일치 Context 거부/제한 |
| Case Adapter | 전체 feature와 exact Spray evidence 계약 | Window member 및 같은 Run evidence validation | 기존 Adapter의 `invalid_detection_contract` 유지 |
| Incident Case | 검증된 observation/relationship adapter input | 중복 관찰과 독립 관찰 분리, 성공·침해 표현 금지 | 미지원/불완전 contract reject |
| Case Projection | 닫힌 Case projection | 승인된 Window 제한/uncertainty projection 여부 확인 | 새 Public field 이번 Phase 불가 |
| Report Projection | Spray scalar 3개 | membership/start-end/context 한계를 표현하는 승인 계약 | 기존 scalar 의미 보존 |
| Restricted Report | 현재 projection 기반 restricted output | 신규 internal evidence 승인·privacy review | raw event/member 노출 금지 |
| Checklist | 기존 projection의 명시 요청 상태 | 새 Window 의미를 action count로 오해하지 않는 검증 | 현재 Checklist contract 유지 |
| Guidance | 명시적 요청·Case 격리 | Window member가 guidance input/corpus key에 누출되지 않는지 검증 | 자동 요청/Private Context 노출 금지 |
| Investigation Workspace | 19-field `investigation-workspace-ui/v1` | 별도 승인된 projection migration 및 Renderer 회귀 | 기존 19-field/KEEP_LEGACY 유지 |
| Static Analysis | 현재 제공된 batch 입력 전체 | 동일 event-set selection deterministic 검증 | 분석 Run 내부 불일치 시 fail closed |
| Live Monitoring | prefix/checkpoint/rotation 단위 관측 | replay/late arrival/rotation/restart/backpressure E2E | parity 검증 전 promotion 금지 |
| Trusted Provenance | 기존 AnalysisRunOwner 및 Brute Context 경계 | Spray 전용 type, owner binding, member identity 검증 | 다른 Run 또는 Brute Context reject |

## 10. Static Prefix 결과

`late_noise_changes_full_input_result`의 동일 입력 prefix에서 실제 `detect_password_spray()` 호출 결과는 1행 `False`, 첫 4개 실패 `True`, 5번째 late-noise 실패 포함 `False`였다. 이는 동일 synthetic fixture의 정적 prefix 시뮬레이션이다. 실제 Live Monitoring, collector replay, checkpoint, rotation 또는 운영 시간 경과를 실행하지 않았으므로 Static/Live parity로 부르지 않는다. 늦게 도착한 이벤트에 따른 재분석·기존 Correlation 변경 가능성은 추가 통합 검증이 필요하다.

## 11. Manifest / Privacy / Performance 경계

Loader는 strict UTF-8, duplicate JSON key/NaN 상수 거부, closed schema, 중복 ID/fixture, 경로 traversal/symlink, manifest 128 KiB, fixture 8 KiB, scenario 128개, fixture당 128 line, 총 4096 line 경계를 검사한다. Fixture는 문서용 IP와 `spray_*` 계정만 허용한다. Raw line, 원문, 계정, IP는 CLI 결과에 출력하지 않는다. 외부 네트워크/LLM 호출은 없다.

이번 실행의 집계는 33 scenario / 150 line이다. CLI는 의미상 결정적인 JSON과 text를 생성한다. 별도 benchmark로 해석할 안정적인 CPU/메모리 보장은 주장하지 않는다.

## 12. Research Basis / Observable Evidence Mapping / Limitations

MITRE ATT&CK T1110.003은 Password Spraying을 여러 계정에 소수의 password를 시도하는 행위로 분류하며, 느리거나 낮은 빈도 시도는 임계값 기반 탐지를 회피할 수 있음을 설명한다. MITRE DET0487도 password pattern과 source/target telemetry 및 tuning이 필요함을 보인다. 이 자료는 프로젝트의 4 failures / 3 accounts / 60 seconds를 표준화하거나 검증하지 않는다. 해당 값은 기존 프로젝트 휴리스틱이다. [MITRE T1110.003](https://attack.mitre.org/techniques/T1110/003/), [MITRE DET0487](https://attack.mitre.org/detectionstrategies/DET0487/)

Microsoft Entra 문서는 해당 제품의 Sign-in Activity Details가 Request ID, 사용자, IP 등 필드를 가질 수 있고 일부 Correlation ID 정확성이 제한됨을 설명한다. Entra FAQ는 batch/retry/MFA 집계 또는 수집 시각 차이로 중복처럼 보이는 기록이 생길 수 있음을 언급한다. 이들은 특정 제품의 문서이므로 이 프로젝트 Parser에 동일 필드가 존재한다는 근거가 아니다. 오히려 현재 프로젝트의 공통 Event ID 부족과 IP 귀속 한계를 일반화하지 말아야 하는 참고다. [Entra sign-in activity details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details), [Entra reporting FAQ](https://learn.microsoft.com/sr-latn-rs/entra/identity/monitoring-health/reports-faq)

**Observable mapping:** 현재 Application/SSH Parser는 normalized timestamp, source, user(누락 가능), source IP, event type, authentication outcome을 제공한다. 이를 통해 관측 행 수, source IP 집계, 알려진 계정의 분포, 시간 간격 및 동일 계정 failure→success 후보를 계산할 수 있다. 현재 입력에서 실제 underlying attempt, Collector delivery identity, NAT 뒤 인간 사용자, batch 승인, password 값은 확정할 수 없다. Correlation은 시간·계정·IP가 일치하는 로그 관계이지 행위자 동일성/인과/credential reuse/침해 증거가 아니다.

**Limitations:** 33개 합성 corpus는 실제 조직의 발생 빈도·운영 오탐률·정확도를 추정할 수 없다. Known Benign, replay oracle은 fixture metadata에만 존재한다. mixed-source event grouping, rejected/ignored source fixture, 실제 collector replay, checkpoint/rotation, Safari 사용자 수용은 미검증이다. 이번 판정으로 사용자 로그 사용, 조직 운영, 자동 대응 또는 Production 정책 변경을 승인하지 않는다.

## 13. 테스트 / Regression

- 신규 독립 테스트: `tests/test_spray_consumer_boundary_36_10b_r2.py` — 21 passed
- R2 CLI text/JSON: 실행 성공
- 기존 36.10B scope CLI, detector accuracy, brute window CLI: 전체 regression 실행 시 기록
- R1 Characterization tests: 전체 pytest 포함. 이 테스트들은 Risk의 5/4/90 whole-span 특성, Window candidate에 대한 Case Adapter `invalid_detection_contract` 거부, Report 3-scalar 한계를 직접 호출해 검증한다.
- `npm run test:a11y --silent`: 별도 Chromium/axe 실행
- UI3 Navigation E2E의 구형 DOM selector 실패는 기존 알려진 stale 테스트 공백으로 별도 기록; 현행 별도 E2E 절차와 결과를 보고
- 최종 전체 `uv run pytest -q`: `3409 passed, 2 warnings`
- `python3 -m compileall -q app tests`, `uv lock --check`, `git diff --check`: PASS
- `npm run test:a11y --silent`: 25 states PASS, external requests 0
- `node tests/ui_navigation_closure_36_10a_ui3.mjs`: PASS; sample POST 1, guidance POST 1, checklist POST 0, Case A/B 늦은 응답 격리 true, stale route 만료 true, 외부 요청 0, CSP 확인

## 14. Production Non-change / Rollback

Production Detector, Parser, Pipeline, Correlation, Risk, Case/Report/API, Frontend, Live Monitoring, 기존 Ground Truth 및 CI/Dependency는 변경하지 않았다. 신규 모듈은 `app/evaluation/` 전용이고 Production Pipeline에서 import되지 않는다. Rollback은 신규 evaluator, corpus, tests, 문서 및 색인 링크만 제거하면 된다. 기존 평가 corpus와 과거 Phase 문서는 건드리지 않는다.

## 15. 남은 위험 및 권장 다음 Phase

Window-bound 후보는 특정 out-of-window endpoint 연결 문제를 제한했지만 shared egress, real duplicate provenance, success time anchor, member selection tie semantics, mixed source, live checkpoint/replay 및 Consumer 전체의 같은-Run binding을 해결하지 않는다. Production Window Context 및 Consumer 적용은 아직 준비되지 않았다.

권장: **`Phase 36.10B-R3 — Trusted Spray Window Context Prototype`**를 격리된 Prototype/검증 범위로 진행하되, 먼저 duplicate/shared-egress와 Correlation time-anchor 추가 Corpus를 포함한다. Production pipeline, Risk, Case, Report 연결은 별도 승인·Acceptance Gate 이전까지 금지한다. 정책 권고는 계속 `MORE_EVIDENCE_REQUIRED`다.

## 16. 최종 판정

`PHASE_36_10B_R2_INDEPENDENT_VALIDATION_LOCAL_CONDITIONAL_GO`

이는 독립 합성 평가와 evaluation-only boundary validator 통과 판정이다. **Production 정책 적용 GO가 아니다.** 실제 사용자 자료 `NO_GO`, 조직 운영 `NO_GO`, 자동 대응 `NO_GO`, 실환경 정확도 `UNVERIFIED`, 모델 기반 AI `NOT_TESTED`, Safari 수용 `SAFARI_USER_ACCEPTANCE_PENDING`, VoiceOver/실제 모바일 `NOT_TESTED`, Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`, OS hard CPU/memory cap 미보장, secure erase 미보장, Legacy Renderer `KEEP_LEGACY`를 유지한다.
