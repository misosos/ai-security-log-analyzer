# Phase 36.10B-R4A — Spray Correlation Semantic Decision

## 1. Executive Summary

이 Phase는 28개의 독립 합성 시나리오로 현재 Spray→Success correlation(C0), R3의 Member Failure 기준(C1), Window End 기준(C2), 그리고 패턴과 일반 인증 전이를 따로 보존하는 C3를 비교했다. 각 시나리오의 관측 라벨은 정책 결과와 분리했다.

권고는 **`C3_SEPARATE_OBSERVATION_RECOMMENDED`**다. 현재 자료는 특정 계정의 실패→성공 관찰과 다중 계정 Spray-like 패턴을 각각 보여줄 수 있지만, 두 관찰을 특수한 “Spray 이후 성공” 관계로 묶으면 패턴 완성 시점, 다중 계정 귀속 및 동일 행위자 여부를 과장할 수 있다. 이 권고는 내부 설계 권고이며 `PRODUCTION_CORRELATION_APPROVED`가 아니다. Production의 `WHOLE_SPAN`, `MORE_EVIDENCE_REQUIRED`, `CORRELATION_ANCHOR_UNRESOLVED`, Window 적용 `NO_GO`를 유지한다.

C1은 Window의 실제 Member Failure를 endpoint로 사용해 late-noise 뒤의 Window 밖 실패를 배제하지만, Window 완성 전 또는 Window 종료 시각의 Success도 그 계정의 더 이른 member failure가 있으면 연결한다. C2는 완성 뒤의 Success만 남겨 의미가 더 좁지만, 정상적인 pre-completion 인증 전이 관찰을 제외하고 missing account가 하나라도 있으면 전체 후보를 거부한다. C3는 이 두 사실을 서로 다른 관찰로 보존하고 Spray 특수 관계를 만들지 않는다.

## 2. 시작 SHA / CI

- 시작 기준 SHA: `cfec6cd124b81b1fa3e8777db322ad606499740d`
- GitHub Actions Run: [41202733240](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41202733240)
- Gate: 동일 SHA의 `push / completed / success`; Locked Python 3.12, 전체 pytest, Linux·SSH·TCP Syslog·JSONL, Restricted Report, Chromium/axe, tracked-file 검사 성공; Artifact 0개
- 시작 branch: `main`; HEAD/local main/origin/main/GitHub main 일치, ahead/behind `0/0`, clean
- v0.4.0 target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 변경 없음

## 3. Current Production Correlation

`app/correlation/attack_chain.py:correlate_password_spray_to_success()`는 전달된 Spray Detection Boolean이 True이면 IP 전체 로그를 `_closest_authentication_pair()`에 넘긴다. Pair 선택은 non-empty 동일 계정, 동일 Source IP, failure timestamp < success timestamp, delta ≤ 60초를 요구하고 최소 delta가 유일해야 한다. Spray Window membership은 입력되지 않는다. 그래서 향후 Window Detector를 별도로 연결해도 Consumer를 바꾸지 않으면 Window 밖 endpoint가 선택될 수 있다.

이 평가에서 C0 Actual은 Production `detect_attacks()`의 실제 Spray 결과와 Production correlation 함수를 호출했다. C0 Gate-open은 같은 Production correlation 함수에 탐지 결과만 강제로 True로 주입한 **진단용 characterization**이다. 이는 실제 Production 탐지 결과가 아니며 후보 Window 정책의 성능도 아니다.

## 4. R1~R4 검증 결과

- 36.10B: Current whole-span TP15/FP1/FN4/TN10; Sliding TP17/FP1/FN2/TN10; Known-account TP16/FP1/FN3/TN10
- R2: 33개 별도 corpus, Current TP23/FP1/FN5/TN3; Current correlation 6, C1 5, C2 2
- R3: 격리된 Prototype의 Owner/Event/Context/Evidence 검증 및 C1/C2 구현; Production 연결 없음
- R4: Consumer·Security Gate 설계, 당시 anchor unresolved

위 분모들은 서로 다르며 이 문서의 28개 시나리오와 합산하지 않는다.

## 5. Semantic Threat Model

보호할 의미 경계는 관찰된 인증 이벤트와 그 사이의 제한된 시간 관계다. 평가기는 같은 IP·알려진 동일 계정에서 failure와 success가 순서대로 관찰되었는지, failure가 선택 Window member인지, success가 Window 완료 전/후인지 구분한다. 동일 IP가 행위자라는 주장, 같은 비밀번호 사용, 공격 의도, Credential Reuse, 계정 침해 또는 인과관계는 추론하지 않는다.

## 6. Observation vs Association vs Compromise

- **Authentication Transition Observation (A):** 동일 IP 및 알려진 계정에서 failure 후 success가 관찰됨.
- **Spray Window Association (B):** success가 검증된 선택 Window의 해당 계정 member failure와 시간 조건상 연결됨.
- **Post-pattern Success Observation (C):** Window가 완성된 뒤 해당 Window의 알려진 대상 계정에서 success가 관찰됨.
- **Credential Compromise (D):** 현재 로그로 입증되지 않으며 평가 결과로 주장할 수 없음.

A, B, C 중 어떤 것이 성립해도 D를 뜻하지 않는다. C3는 A와 Spray-like Detection을 함께 보존하되 B/C 특수 relation은 만들지 않는다.

## 7. 신규 Corpus 설계

신규 독립 corpus는 `sample_logs/spray_correlation_semantics/manifest.json`과 28개의 독립 Scenario, 29개 source fixture (혼합 Source 시나리오는 fixture 2개), 총 150개 Parser Event로 구성된다. 기본 타이밍, pre/post completion, end 동시 시각, 60초/60초+1µs, 계정 scope, multi-success, tie, missing account, late noise, cross-IP, Brute overlap 및 혼합 Application/SSH Source를 포함한다.

모든 IP는 RFC 5737 문서용 범위, 계정은 합성 이름이다. 60초는 프로젝트 후보 평가 휴리스틱이지 보편 표준이나 벤더 권고가 아니다. 60초+1µs 시나리오는 Parser의 정밀도를 주장하지 않는다. Manifest의 명시적 `timestamp_adjustment`로 Parser 후 합성 datetime에 1µs를 더해 계산 경계만 시험한다.

## 8. Ground Truth / Label

Manifest는 `behavioral_pattern`, `operational_context`, `parser_status`, `success_timing`, `success_account_relation`, `relationship_interpretation`, `ambiguity`를 별도 보유한다. 라벨 근거는 이벤트 종류·정규화 시간 순서·계정 필드 존재·Source/IP 관측이라는 정책 독립 사실이다. 평가기는 manifest 라벨을 읽은 뒤 정책 결과를 계산하며, 결과를 이용해 라벨을 바꾸지 않는다.

28개 분포:

| 축 | 분포 |
|---|---|
| Behavioral Pattern | PRESENT 26, UNDETERMINED 2 |
| Operational Context | SIMULATED_ATTACK 21, CONTEXT_UNKNOWN 7 |
| Parser | VERIFIED 25, PARTIAL 3, REJECTED 0, IGNORED 0 |
| Success Timing | NO_SUCCESS 8, PRE_COMPLETION 2, AT_WINDOW_END 1, POST_COMPLETION 5, LATE_NOISE 2, BEFORE_ALL_FAILURES 1, END_PLUS_60S 2, END_PLUS_60S_PLUS_1US 1, END_PLUS_61S 1, MULTIPLE_SUCCESS 4, SAME_TIMESTAMP 1 |

Timing 분류는 corpus의 다중-success 시나리오 특성상 중복 의미를 일부 표현하며 합계가 scenario 수와 같도록 상호배타적으로 설계된 축은 아니다. 주요 관계 라벨과 ambiguity의 정확한 카운트는 CLI JSON의 `label_counts`가 기준이다.

## 9. Parser Observability

28개 Scenario에서 150개 줄이 Parsed되고 Rejected 0이다. 3개 Scenario는 username 누락으로 `PARTIAL`이다. Application/SSH Parser가 내놓은 `NormalizedEvent`의 timestamp를 기존 timezone 정규화 함수로 UTC-aware로 바꾸고 후보 평가에 사용했다. 혼합 Source에서는 문자열 계정명이 같더라도 동일 Principal이라는 보장이 없으므로 `cross_source_identity_unverified`로 표시한다.

지원되지 않는 Source는 closed Manifest에서 거부한다. 이 corpus는 Parser coverage의 일반적인 완결성이나 실환경 입력의 정상 처리율을 측정하지 않는다.

## 10. C0 Current

28개 시나리오 중 13개에서 Production Detector 실제 결과로 Spray correlation이 성립했다. 이는 합성 Scenario 수에서 산출한 관찰 건수이지 Precision/Recall 또는 운영률이 아니다. Production의 기존 whole-span 탐지 조건과 전체 IP pair selector를 그대로 사용했다.

## 11. C0 Gate-open

탐지 Gate만 진단 목적으로 열었을 때 16개 Scenario에서 Production pair selector가 relation을 반환했다. `late_noise_window_outside_pair`에서 실패 offset 90초와 성공 95초가 선택되었다. 둘 다 선택 Window member가 아니므로 향후 Window 탐지와 현행 Consumer를 혼합하면 부적절한 endpoint가 선택될 수 있음을 재현한다. Gate-open 결과를 실제 탐지 성공으로 세지 않는다.

## 12. C1 Member Failure

R3 Prototype의 실제 `correlate_c1()`를 호출했다. 조건은 Window member failure와 success의 실제 동일 계정·동일 IP, 엄격한 failure-before-success, member→success ≤60초, 최소 delta Pair의 유일성이다. 12개 Scenario에서 Candidate Pair가 나왔다.

C1은 window 종료 시각과 success timestamp가 같아도 연결될 수 있다. 그 이유는 Window 안에 같은 계정의 더 이른 Failure가 있을 수 있기 때문이다. 이는 “Window 종료 이후 success”가 아니라 “Window member failure 이후 success”라는 뜻이다. R3 코드와 일치한다.

## 13. C2 Window End

R3 Prototype의 실제 `correlate_c2()`를 호출했다. C1 조건 외에 Window의 모든 member 계정이 알려져 있어야 하고, success가 Window 종료보다 엄격히 뒤에 있으며 end→success ≤60초여야 한다. 실제 member failure→success ≤60초도 별도로 요구한다. 7개 Scenario에서 Candidate Pair가 나왔다.

따라서 C2는 Window 완료 이후 관찰이라는 의미를 더 잘 보존하지만, pre-completion/종료 동시 success와 username이 누락된 Window를 제외한다. 성공이 Window 끝과 같으면 실패→성공 순서가 성립해도 C2는 거부한다.

## 14. C3 Separate Observation

C3는 새 Production relation이나 Case Rule이 아니다. 기존 generic `correlate_authentication_transition()`의 A 관찰과 Spray-like 패턴을 각각 유지하고 `pattern_success_association=false`로 기록하는 Evaluation 모델이다. Generic transition은 16개 Scenario에서 관찰됐으며 이는 C1/C2와 다른 의미·분모다. C3는 어느 관찰도 숨기지 않지만 둘 사이에 특수 인과 관계를 만들지 않는다.

## 15. Time Anchor 수학적 정의

표기: `t_f`는 동일 계정 Window member Failure, `t_s`는 Window Start, `t_e`는 Window End, `t_success`는 해당 계정 Success. 유효 member는 `t_s ≤ t_f ≤ t_e`를 만족한다.

- C1: `t_f < t_success` 및 `0 < t_success - t_f ≤ 60s`.
- C2: 위 C1 member 조건에 더해 `t_e < t_success`, `0 < t_success - t_e ≤ 60s`, 모든 member의 username 알려짐.

`d_f = t_success - t_f`, `d_e = t_success - t_e`라 두면, `t_f ≤ t_e`이므로 `d_f ≥ d_e`다.

- **End delta는 통과하지만 account-specific member delta가 실패:** 가능. 계정 A의 member가 0초, 다른 계정들로 Window가 15초에 완성되고 A의 success가 75초이면 end delta=60초지만 A failure delta=75초다. C2의 end 요건은 맞지만 추가 C1 member 제한 때문에 거부된다.
- **Member delta는 통과하지만 end delta가 실패:** Success가 Window 종료 후라는 조건을 둔 C2에서는 불가능하다. `t_s < t_success`이고 `t_f ≤ t_e`이므로 `d_e ≤ d_f`; 따라서 member delta ≤60이면 end delta도 ≤60이다. Success가 end 이전/동시라면 C1은 통과하고 C2는 엄격한 end 조건 때문에 제외될 수 있다.
- **Window End와 같은 시각의 Success:** 같은 시각인 failure와 success는 strict ordering을 만족하지 않는다. 다만 더 이른 동일 계정 member failure가 있으면 C1은 그 failure를 endpoint로 선택할 수 있다. C2는 `t_e < t_success`가 거짓이므로 제외한다.
- 60초 경계는 inclusive이며 +1µs는 배제된다. 이는 평가용 수학 경계다.

## 16. Pre-completion Success

3개 Scenario에서 C1이 선택한 success는 Window End 이전이었다. 별도 1개는 success가 Window End와 같은 시각이었다. C1은 다중 계정 Window가 완성되기 전에 이미 발생한 계정별 failure→success를 허용한다. 관계를 “Spray-like pattern completion 후 성공”이라고 부르면 시간 의미가 틀린다. C2는 이런 association을 만들지 않는다.

## 17. Post-completion Success

C2의 실제 Candidate Pair는 7개였다. 이는 “Window가 완성된 후 알려진 Window 계정에 성공 이벤트가 관찰됨”을 말할 뿐, 해당 성공이 앞선 다중 계정 패턴 때문에 발생했다고 말하지 않는다. 더구나 Candidate Pair가 없더라도 공격이 없다는 의미는 아니다.

## 18. Multiple Accounts

Window는 최소 여러 계정의 실패로 구성되지만 C1/C2의 성공 relation은 특정 한 계정의 실제 Failure endpoint에만 귀속된다. 다른 Window 계정 성공은 각각 독립 Pair일 수 있으며, 이들을 전체 Spray Pattern의 “성공”으로 합쳐 표현하면 안 된다. 같은 IP는 같은 행위자를 증명하지 않는다. 서로 다른 Source의 username 문자열 동일성도 Principal 동일성을 증명하지 않는다.

## 19. Missing Account

C1은 known member failure와 success의 Pair가 명확하면 Window에 다른 missing-username failure가 있어도 그 Pair를 허용한다. C2는 Window 전체의 member account 완전성을 요구해 거부한다. C2는 계정 귀속 불확실성을 넓게 제한하지만, 알려진 계정의 분명한 관찰까지 제외할 수 있다. 누락 계정을 success 계정으로 추정하지 않는다.

## 20. Equal-delta / Duplicate

동일 최소 delta의 서로 다른 계정 Pair는 R3 C1/C2에서 `ambiguous_pair`로 거부된다. 같은 시각의 failure/success는 strict ordering을 통과하지 않는다. `duplicate_looking_window_member`는 동일-looking 로그를 fixture에서 반복 관측한 상황을 나타낼 뿐 실제 collector redelivery임을 입증하지 않는다. 공통 원천 Event ID가 없으므로 이를 무조건 deduplicate하거나 독립 인증 시도라고 확정하지 않는다.

## 21. Out-of-window Endpoint

C0 Gate-open은 late-noise 시나리오에서 90→95초 pair를 선택했다. C1/C2는 선택 Window member만 failure 후보로 사용하므로 그 두 endpoint로 relation을 만들지 않았다. 다만 C1/C2도 운영자의 동일 행위자·동일 비밀번호 추측을 입증하는 것은 아니다.

## 22. Wrong-run / Provenance

이번 의미 Corpus는 R3 Prototype의 Owner/Context를 사용하며 R3의 별도 negative tests는 wrong-run Event, copied Event, context repackaging, mutation, Brute/Spray type mix 및 cross-run success 거부를 검증한다(`tests/test_spray_trusted_context_prototype_36_10b_r3.py`). R4A는 그 trusted-context 구현을 다시 만들지 않았다. R3 객체는 Evaluation-only이며 Production `AnalysisRunOwner` 확장이 아니다.

## 23. Brute/Spray Overlap

`brute_overlap_auth_transition`은 Brute 반복 실패와 다중 계정 패턴이 같은 IP 관측에 겹치는 합성 사례다. 두 패턴이 같은 이벤트 일부를 공유할 수 있으므로 두 개의 독립 관측으로 중복 가산해서는 안 된다. R4A는 Production Risk를 바꾸지 않았다.

## 24. Mixed Source

Application과 SSH에서 같은 문서용 IP/username으로 합성된 이벤트를 관찰해도 서로 다른 Source의 계정 namespace가 동일 Principal이라는 신뢰 계약은 없다. 혼합 Source 여부만 표식하며 별도 Principal 연결은 하지 않는다.

## 25. Semantic Evaluation Results

| 결과 | Scenario 수 |
|---|---:|
| C0 Production actual correlation | 13 |
| C0 gate-open characterization | 16 |
| C1 Member Failure candidate | 12 |
| C2 Window End candidate | 7 |
| C3 generic auth transition observation | 16 |
| C1 pre-completion association | 3 |
| C1 success at Window completion | 1 |
| C2 post-completion association | 7 |
| C0 gate-open out-of-window endpoint 재현 | 2 |
| C1 equal-minimum ambiguity 거부 | 2 |

이는 독립 합성 corpus의 집계이며 각 수치의 eligibility denominator가 동일하지 않다. Precision, Recall, F1, 운영 오탐률은 산출하지 않는다. `success_60_seconds_plus_one_microsecond`는 후보 둘 다 생성하지 않았다.

## 26. Consumer Impact

| Consumer | C1 의미/위험 | C2 의미/위험 | C3 설계 영향 |
|---|---|---|---|
| Production correlation | Window member만 쓴다는 보장이 없어 그대로 연결 불가 | Window End 계약과 trusted context가 없어 그대로 연결 불가 | Generic transition과 패턴 별도 유지; 특수 relation 없음 |
| Risk (`app/analyzer/risk.py`) | 현행 Spray→Success 분기가 HIGH likelihood를 만들 수 있어 pre-completion을 “after spray”로 과장할 위험 | completion 이후 제한 관찰이지만 관계만으로 인과·침해 입증 안 됨 | 현행 Risk가 독립 observation 조합을 의미적으로 처리하는지 미검증; 자동 결합 금지 |
| Case Adapter (`app/analyzer/incident_case_adapter.py`) | 후보 context가 없어 기존 evidence/features 일치 검증 불충족 | 같은 제한; fail-closed 유지 | 기존 Case 규칙을 그대로 유지 |
| Incident Case (`app/analyzer/incident_case.py`) | Spray-success Case 활성화 불가 | 동일 | `CASE-SPRAY-SUCCESS-01` NO_GO 그대로 |
| Report (`app/analyzer/report_projection.py`) | “패턴 완성 후” 문구는 부정확할 수 있음 | 문구는 제한적으로 가능하나 근거·membership projection 필요 | 두 독립 관찰의 공존만 설명; 원인/공격 성공 금지 |

현재 Report public evidence는 scalar 세 값뿐이며 Context membership을 전달하지 않는다. C1/C2를 Public Projection에 쓰려면 별도 승인·통합 검증이 필요하다.

## 27. Risk Meaning

현재 Risk의 likelihood 경로가 Spray Detection과 Spray→Success correlation 조합에서 높은 likelihood를 선택할 수 있다는 사실은 R1/R4 characterization에서 확인됐다. C1/C2가 달라지면 현재 boolean input 및 likelihood rationale도 달라질 수 있지만 이 Phase는 산식/분기 변경을 하지 않았다. Whole-IP features와 selected Window metrics를 섞거나 같은 이벤트를 Brute/Spray 독립 신호로 이중 집계해서는 안 된다. Risk level은 공격 확률이 아니다.

## 28. Case / Report Meaning

Case Adapter의 범위 불일치 rejection은 보존한다. C1/C2 relation을 소비하려면 trusted Window Context, Detection Evidence와 동일 Run 결속, endpoint membership, count/time/IP consistency가 선행돼야 한다. Spray Case 정책은 NO_GO다. Report 문구 후보는 “선택 Window에 포함된 특정 계정의 인증 실패 이후 해당 계정의 성공이 관찰됨(C1)” 또는 “Window 완성 이후 해당 Window의 알려진 계정에서 성공이 관찰됨(C2)” 정도의 제한 의미여야 한다. C3 문구는 두 관찰을 별도로 설명해야 한다. “Spray 공격 성공”, “Credential Reuse”, “계정 침해”는 허용하지 않는다.

## 29. Security Gate G4

**설계상 의미 차이는 구체화했지만 Production G4는 `BLOCKED`다.** relation name, 실제 Failure/Success endpoint, Window membership, time anchor, account scope, missing account, equal-delta rejection을 비교했다. 하지만 실제 Production Owner/Context·Detection binding·Consumer integration 테스트가 없고 운영상 identity 및 duplicate 근거도 부족하다. R4의 G1/G3/G5/G6/G7/G8/G9/G10/G11/G12도 자동 통과하지 않는다.

## 30. Decision Matrix

| 대안 | 시간 의미 | 계정 귀속 | 정보 보존/누락 | 소비자 오해 위험 | 결론 |
|---|---|---|---|---|---|
| C1 | 실제 member failure 이후; completion 전도 가능 | 동일 IP의 알려진 계정 Pair | member endpoint 보존, 동률 거부 | “Spray 이후 성공”으로 이름 붙이면 pre-completion 왜곡 | semantic 후보로는 명확하나 채택 보류 |
| C2 | Window End 이후 strictly | 모든 member 계정이 알려진 경우, 특정 Pair | 더 엄격하지만 missing account 및 pre-end pair 제외 | completion 시점은 명확, 원인 관계는 여전히 미입증 | 제한된 후보, 운영 효과 불명 |
| C3 | 특수 Spray anchor 없음 | generic transition 자체의 동일 IP/account 조건 | Pattern과 transition을 둘 다 보존 | 결합/인과 오해 최소화; consumer의 별도 조합 설계 필요 | 권고 |

## 31. Final Semantic Recommendation

**`C3_SEPARATE_OBSERVATION_RECOMMENDED` / `SEMANTIC_DESIGN_RECOMMENDED`**. C3가 가장 정확하게 현재 로그가 증명하는 바를 보존한다. “로그에 없는 관계를 만들지 않음”은 관찰을 버리는 의미가 아니다. Generic 실패→성공 관찰과 Spray-like 패턴은 각자 보존할 수 있다. 다만 후속 Risk/Case/Report가 두 관찰을 자동으로 하나의 사건/원인으로 묶어서는 안 된다.

현재 Production Correlation Anchor는 `CORRELATION_ANCHOR_UNRESOLVED`로 유지한다. C1 또는 C2를 향후 검토한다면 relation display name, 정확한 endpoint, consumer rationale 및 운영 중복·NAT evidence를 독립 검증해야 한다. 이번 평가만으로 Production Correlation 승인을 하지 않는다.

## 32. Remaining Uncertainty

- Collector delivery/event identity가 없음: retry/replay와 독립 시도를 안정적으로 구분할 수 없음.
- NAT/VPN/Proxy Egress 뒤 사용자 principal은 미확인.
- Application/SSH account namespace 정규화 미확인.
- 승인된 Batch 업무는 Manifest의 synthetic context일 뿐 Runtime에는 없음.
- 실시간 prefix 도착, ingestion 지연, Live checkpoint/restart 동작은 시험하지 않음.
- 합성 평가 분포는 실환경 base rate를 나타내지 않음.

## 33. Research Basis

MITRE ATT&CK T1110.003은 Password Spraying을 여러 계정에 낮은 횟수의 비밀번호 시도로 분산하는 행위로 분류하고, 실패 횟수·시간 간격은 관찰 규칙의 예시 맥락으로 다룬다. 이 분류는 프로젝트 로그에서 동일 비밀번호가 사용됐다는 증거가 아니다. [MITRE ATT&CK T1110.003](https://attack.mitre.org/techniques/T1110/003/)

Microsoft Entra sign-in telemetry는 서비스 자체가 제공하는 식별자와 이벤트 시간 필드를 설명한다. 이는 제품 전용 관측임을 보여주는 참고 자료이며, 이 Repository의 Application/SSH parser가 동일 ID나 delivery identity를 제공한다는 뜻은 아니다. [Microsoft Entra sign-in logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)

## 34. Observable Evidence Mapping

| 주장 가능한 관찰 | Repository 입력 필드 | 허용 결론 |
|---|---|---|
| failure/success 및 timestamp | `NormalizedEvent.event_type`, `.timestamp` | 이벤트 순서와 차이 관찰 |
| source IP | `.src_ip` | 동일 기록 IP 내 pair 후보; 동일 사용자/행위자는 아님 |
| 계정 문자열 | `.user` | 알려진 문자열 일치; cross-source principal 동일성은 보장 안 됨 |
| window membership | R3 evaluation context의 실제 object reference | Prototype에서 member binding 검증; Production 계약 아님 |
| 같은 credential/actor/compromise | 사용 가능한 field 없음 | `UNVERIFIED`, 주장 불가 |

## 35. Privacy / Security

Manifest/fixture는 bounded, strict UTF-8, closed schema, duplicate JSON key/NaN 거부, path traversal/symlink 방지, RFC 5737 문서 IP와 합성 사용자만 허용한다. CLI 출력은 raw log, 계정, IP, context token을 출력하지 않는다. 외부 network와 LLM 호출은 없다. 60초+1µs 보정은 평가 코드 안에서만 수행한다.

## 36. Production Non-change

`app/detector/`, Production Analyzer/Correlation/Risk/Case/Report, API, UI, Parser, Live Monitoring, 기존 corpus/ground truth, CI 및 Dependency는 변경하지 않는다. Evaluation 코드에서 기존 Production 함수 및 R3 evaluation prototype을 호출해 characterization만 수행한다. 신규 모듈이 Production pipeline에서 import되지 않는지 source boundary를 회귀 확인한다.

## 37. Regression

실행 결과:

- 시작 baseline: `3442 passed, 2 warnings`; 변경 후 전체: `3461 passed, 2 warnings`.
- R4A 신규 테스트: `19 passed`.
- `uv sync --locked --dev`, `uv lock --check`, `python3 -m compileall -q app tests`, `git diff --check`: 통과.
- 기존 boundary Evaluation: `79/79`; Parser `195/200`; Risk `70/70`; Case `70/70`; Linux Process `21/21`.
- 기존 Detector Accuracy corpus: 46 scenarios; Spray TP2/FP0/FN0/TN5. 기존 Brute Window corpus: 24 scenarios. 기존 36.10B CLI 결과는 Current 15/1/4/10, Sliding 17/1/2/10, Known-account 16/1/3/10.
- R2 Consumer Boundary CLI 및 R3 Trusted Context Prototype CLI의 text/JSON 실행 통과. 각 CLI 결과는 기존 별도 corpus/prototype 분모를 유지했다.
- 신규 R4A CLI text/JSON 실행과 JSON parsing 통과; 28 scenario, 150 parsed event.
- `npm run test:a11y --silent`: 성공, Chromium/axe 25 state, `external_requests=0`.
- `node tests/ui_navigation_closure_36_10a_ui3.mjs`: 성공, `externalRequests=0`, CSP 확인, delayed Case response isolation 확인.

기존 36.10B/R2/R3/R4 문서와 Ground Truth는 소급 수정하지 않는다. `MORE_EVIDENCE_REQUIRED` 유지. 구형 stale DOM Navigation 스크립트는 별도로 실행하지 않았고 이 Phase의 증거에 포함하지 않는다. Safari 사용자 수용은 자동화 검증으로 대체하지 않는다.

## 38. Rollback

신규 산출물은 추가 Evaluation module, CLI, synthetic corpus, test, document 및 index link뿐이다. 이를 제거하더라도 Production whole-span 경로에 영향이 없어야 한다. 이 단계에서는 정책 fallback이나 consumer migration 자체가 없다.

## 39. Next Phase

다음은 **`Phase 36.10B-R5 — Independent Observation Consumer Compatibility`**를 권고한다. C3 권고를 실제 consumer에서 안전하게 유지할 수 있는지 Risk·Case·Report가 별도 generic transition과 Spray pattern을 어떻게 표시/조합하는지 평가 전용 contract test로 분석한다. Production 연결은 계속 금지한다. Duplicate/Event ID 및 shared egress 운영 근거는 별도 차단 항목으로 유지한다.

## 40. Final Decision

평가 설계·실행은 로컬 검증 조건을 충족하면 `PHASE_36_10B_R4A_SEMANTIC_DECISION_LOCAL_CONDITIONAL_GO`로 판정한다. 이는 Semantic Design만 의미하며 Production Correlation 승인, Window 활성화, 실환경 정확도 또는 Live parity를 의미하지 않는다. Correlation Anchor Production 상태는 `CORRELATION_ANCHOR_UNRESOLVED`; Policy Recommendation은 `MORE_EVIDENCE_REQUIRED`다.
