# ER-1D-S1-P — Restricted Adapter 사전 기술·보안 감사

## 1. Executive Summary

기술 분류는 `FEASIBLE_ONLY_WITH_RESTRICTED_ADAPTER`다. 공개 Replay 결과만으로 실제 Brute 선택 Window를 복원할 수는 없다. 그러나 기존 Production Loader가 만든 이벤트 목록을 연구 호출자가 보유한 채 기존 `_analyze_normalized_logs_with_context(logs)`를 호출하는 내부 경계는 있다. 이 경계에서 실제 반환된 analysis/context/owner와 같은 실행 이벤트의 membership을 검증한 뒤 count/span만 복사하는 제한된 adapter를 설계할 수 있다. 새 callback/hook이나 Production·Replay 공개 계약 변경이 구조적으로 필수인 것은 아니다.

이 결론은 코드 추적과 기존 테스트에 근거한 설계 가능성이다. 안전한 추출기를 구현·실증한 결과가 아니다. 같은 프로세스의 임의 악성 코드나 외부에서 조립한 private 객체를 인증하는 기능도 아니다. 정책 효력과 S1 구현 승인은 여전히 대기 상태이며, 이번 변경은 문서·문서 계약 테스트뿐이다. 신규 보안 테스트는 구현하지 않았다.

## 2. Start SHA / Exact CI

기준 SHA `c76e5735c50c4c88fa469d30bc535974a07269f6`; Exact [CI 42320298483](https://github.com/misosos/ai-security-log-analyzer/actions/runs/42320298483)는 push / completed / success, head 일치. Locked Python 3.12 회귀·필수 Linux·Restricted Report·Chromium/axe·tracked-file 단계 성공, Artifact 0개를 직접 확인했다. 시작 HEAD/local main/origin main/GitHub main 일치, working tree clean, ahead/behind 0/0. `v0.4.0` tag와 Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 불변. `ER_1D_S1_P_START_GATE_GO`.

`AGENTS.md`와 관련 security-testing/security-analysis 지침 및 기존 [ER-1D-P](counterfactual_sensitivity_explanation_design_er1d_p.md), [G0](counterfactual_explanation_readiness_audit_er1d_g0.md), [S0](counterfactual_solo_research_track_er1d_s0.md), [G1](counterfactual_solo_research_governance_er1d_s0_g1.md), [G2](counterfactual_research_input_scope_governance_er1d_s0_g2.md), [G3](counterfactual_solo_research_policy_decision_er1d_s0_g3.md), [ER-1B](counterfactual_detector_replay_er1b.md), [ER-0](evidence_research_er0.md)를 대조했다. 새 탐지 의미나 정책 임계값을 제안하지 않고 현재 코드를 감사한다. GitHub Ubuntu CI와 아래 로컬 macOS 실행 결과를 구분한다.

## 3. 실제 분석 실행 데이터 흐름

다음은 현재 함수명·위치이며 이 단계에서 수정하지 않았다.

| Producer/검증 위치 | 실제 역할과 반환 |
|---|---|
| `app/evaluation/counterfactual_corpus.py:255 load_fixture(fixture_id)`, `:371 _parse_fixture(source, fixture_bytes)`, `:428 prepare_scenario(scenario)` | 고정 Development bytes, 별도 Parser 사전 검증, 제한된 PreparedScenario. PreparedScenario는 실제 Detector 실행의 이벤트/owner를 보유하지 않음 |
| `app/evaluation/counterfactual_replay.py:432 run_scenario(scenario)`, `:453 _replay_prevalidated_scenario(...)` | 고정 bytes와 변형 bytes 각각 새 Production 실행. `:238 _execute_production(...)`은 private bundle을 검증하고 내부 execution/observation으로 축소 |
| `app/analyzer/pipeline.py:40 load_normalized_logs(log_sources)` | 기존 Loader/등록 Parser를 호출하고 timestamp를 UTC로 정규화해 실제 이벤트 list 반환. Parser disposition 전체를 반환하는 함수는 아님 |
| `app/main.py:227 analyze_with_source_role_snapshot(log_sources=None)` | 위 Loader 이후 동일 내부 core 실행, source-role snapshot과 private context/owner를 bundle로 반환 |
| `app/main.py:203 _analyze_normalized_logs_with_context(logs)` | 새 owner 생성 → 실제 Detection → Correlation → Risk → owner-bound analysis 생성 → `(result, brute_window_contexts, run_owner)` 반환 |
| `app/detector/brute_force.py:43 AnalysisRunOwner` | Detection·Correlation·Risk 입력/결과 참조를 결속. `:257 is_bound_to(analysis)`는 analysis 및 내부 참조·값을 검사 |
| `app/analyzer/pipeline.py:139 detect_attacks_with_context(logs, run_owner)` | IP별 features와 선택 contexts 생성, 실제 DetectionResult를 owner에 결속하고 결과/context 반환 |
| `app/detector/brute_force.py:284 BruteWindowContext`, `:380 select_brute_window_contexts(logs, run_owner=None)` | 같은 IP·known account의 실제 선택 창, count·UTC endpoints·멤버 이벤트 참조 및 owner 보유 |
| `app/detector/brute_force.py:472 brute_force_detection_from_context(context)` | 선택 context를 검증한 후 count·span·계정 수 1의 실제 Detection Evidence 생성 |
| `app/detector/brute_force.py:330 validate_brute_window_context(context, *, subject_ip=None)` | context 타입·owner 타입·subject·count·계정·timestamp·멤버 내부 정합성 검사 |
| `app/detector/brute_force.py:496 brute_evidence_matches_context(detection, context, *, subject_ip=None)` | 위 검증과 정확한 Brute Evidence 종류/source/count/시간 범위/span 검증 |
| `app/detector/brute_force.py:463 brute_window_context_owner(context)` | context의 owner 참조 확인용. 단독으로 실제 실행 전체를 인증하지 않음 |
| `app/investigation_role_snapshot_36_4.py:106 AnalysisWithSourceRoleSnapshot` | source-role/analysis 결속, context owner 일치·타입·정합성 검사 및 context mapping의 read-only copy. 실행 보안 근거를 보완하는 실제 관련 consumer |

현재 전체 진입점의 순서는 Fixed bytes → Loader/Parser → 정규화 이벤트 → 새 owner → features/선택 context → 실제 Detection Evidence → Correlation/Risk → owner-bound result/bundle → Replay의 private 검증 → public Replay result다. Evidence Membership 검증은 selector/context/Evidence/consumer와 Replay 경계에 나뉘어 있다. 모든 원문 membership을 보증하는 단일 공개 API는 없다.

후속 연구 후보는 **고정 bytes의 기존 검증 → 기존 Loader의 실제 list를 보유 → 기존 내부 core 호출 → 반환 triple와 보유 list를 함께 검증 → 안전 scalar를 복사**하는 경계다. 이 부분이 Restricted Safe Aggregate Candidate이며 현재 구현돼 있지 않다. Correlation/Risk는 core가 이미 실행하는 단계다. 이를 연구 코드가 바꾸거나 registry/API/UI 상태로 연결해서는 안 된다. 특히 `app/analyzer/pipeline.py:339 assess_risk()`는 `app/analyzer/risk.py:45 load_account_metadata()`를 통해 고정 `data/account_metadata.json`도 읽는다. core가 Corpus 파일만 읽는다고 주장하지 않으며, 이 고정 의존성의 허용 여부·버전/digest·합성 연구 적합성과 출력 제외를 S1 파일 접근 Gate에 포함해야 한다. 허용할 수 없다면 Risk 경로를 임의 우회하지 않고 HOLD한다.

## 4. Run Owner 및 Context Lifetime

| 객체 | 생성/보유 경계 | 실제 수명과 검증 한계 |
|---|---|---|
| 원본 합성 bytes/임시 파일 | 기존 Corpus·Mutation 및 private temporary copy | 기존 Replay는 temp scope 종료 뒤 bundle 검증을 계속한다. 파일 삭제가 이벤트/owner 참조 폐기를 뜻하지 않음 |
| NormalizedEvent list와 각 event | Production Loader, 이후 core 인수 | `analyze_with_source_role_snapshot()`은 전체 list를 외부로 반환하지 않는다. 선택 context는 member event 참조를 보유. 내부 core의 직접 연구 호출자는 같은 list를 보유 가능 |
| owner | core 안의 `AnalysisRunOwner()` | 반환 result와 owner 사이 강한 참조가 있으며 함수 반환 즉시 만료되지 않음. 참조가 사라지고 회수될 때까지 객체는 존재할 수 있음. 별도 TTL·폐기 증명·재발급 인증 없음 |
| 선택 context | selector가 해당 실행 owner와 member tuple로 생성 | mapping과 context가 frozen/read-only여도 member events와 Detection/Evidence는 중첩 mutable 객체다. 얕은 불변성만으로 내용 불변을 보증하지 않음 |
| DetectionResult/Evidence | 실제 detector, owner의 결과 참조와 analysis가 보유 | owner는 DetectionResult 참조를 결속하며 임의 다른 detector 객체를 그 값만 같다고 승인하지 않는다. Evidence의 모든 내부 내용은 별도 재검증 필요 |
| `_Execution.owner`와 public Replay | Replay private local 객체 → 공개 DTO로 축소 | 공개 DTO에 owner/context/member가 남지 않는다. 직렬화·다른 프로세스·폐기 이후 같은 실행의 identity를 복원할 수 없음 |

따라서 살아 있는 같은 실행의 참조를 보유한 동안에만 object identity 검증이 가능하다. 공개 결과의 count/span 또는 같은 필드값으로 이전 owner를 재구성할 수 없다. 검증된 scalar를 나중에 읽을 수 있다는 것과 나중에 private membership을 다시 인증할 수 있다는 것을 구분한다. Python 객체 identity와 `id()`는 출력·영구 식별자로 사용하지 않는다.

## 5. Evidence Membership 검증 경로

검증해야 할 사실은 세 가지다.

1. **같은 실행 결과:** 실제 core가 반환한 owner에 대해 `is_bound_to(result)`가 참이고 subject의 Detection 객체가 그 result의 실제 slot에 있어야 한다. owner의 `_has_brute_detection()`와 `_matches_detection_results()` 같은 기존 내부 검증점은 결과 참조를 보조 확인하지만 public 인증 API가 아니다. 외부에서 받아온 analysis/context/owner 조합은 연구 입력으로 받지 않는다.
2. **context/Evidence 정합성:** context owner가 같은 owner인지, subject가 같은지 검사하고 `validate_brute_window_context()` 및 `brute_evidence_matches_context()`가 확인하는 count·known account·시간·Evidence 종류/source를 유지한다. `brute_evidence_matches_context()`만은 다른 실행에서 만든 동등한 값의 Detection 객체까지 provenance로 구별하는 함수가 아니다.
3. **실제 분석 event membership:** selector가 사용한 **동일 list의 event 객체**에 모든 context member가 속하고 개수/중복도를 초과하지 않아야 한다. `app/correlation/attack_chain.py:167 correlate_brute_force_to_success()`에도 IP 이벤트의 identity 집합과 멤버를 대조하는 기존 invariant가 있다. 그 함수의 false는 성공 로그인 부재 등 다른 이유일 수도 있으므로 correlation 결과 자체를 membership 증명으로 사용하지 않는다. 후속 adapter는 보유한 실제 list에서 멤버 identity·중복도·subject/account·시각 불변을 직접 검증해야 한다.

`validate_brute_window_context()`의 단독 성공은 제공된 context 안의 멤버 정합성만 입증한다. 원래 전체 event list, 선택 정책 최적성, 모든 원본 행의 수집 완전성이나 같은 권한의 악성 Python 코드로부터의 보호를 보증하지 않는다. 선택 정책 자체는 신뢰한 현재 Production selector의 실제 반환을 사용하고, 새 Window를 독립 재계산해 선택 결과를 교체하지 않는다.

권고 경계에서는 입력 bytes/digest·Parser 사전 검증과 실제 Loader 입력의 동일성을 유지하고, list를 복사·다른 run과 공유하거나 중간 callback에 넘기지 않는다. mutable fields와 result가 분석 전후·검증 전후에 변하지 않았는지 안전한 내부 snapshot과 기존 검증으로 확인하고 동기적으로 scalar를 복사한다. 이 강화 경계는 설계 요구이며 아직 S1에서 검증되지 않았다.

## 6. Adapter 방식 A/B/C 비교

| 방식 | 가능한 것 | 불가능/부족한 것 | 기술 판단 |
|---|---|---|---|
| A 공개 `ReplayScenarioResult`/`SafeFacts`만 사용 | Parser-level target IP 집계와 실제 관측 상태 읽기 | selected-window count/span·owner·member identity 없음. target 집계로 대체 불가 | 목표한 선택 Window 추출에는 불가능 |
| B1 기존 `analyze_with_source_role_snapshot()`의 반환 bundle 사용 | 실제 analysis·owner·선택 context·Evidence를 같은 호출에서 읽고 기존 결속 검사 가능 | bundle은 full parsed list를 반환하지 않아 사후에 모든 source event와의 독립 identity 비교 불가. source-role snapshot도 완전한 원문 membership 증명 아님 | 제한된 실행 provenance 확인에 유용하나 이번 membership 요구를 충분히 증명하는 단독 경계로 선택하지 않음 |
| B2 기존 Loader + `_analyze_normalized_logs_with_context(logs)` | 연구 호출자가 같은 실제 parsed list와 반환 triple를 함께 보유. 실제 선택 결과와 Evidence 대조 및 full-list membership 검사 설계 가능 | private 인터페이스에 결속; 입력/실행/출력 보안 wrapper가 아직 없음 | 권고 내부 경계. Production 함수 수정·새 hook/callback이 구조적으로 필요하지 않음 |
| C 연구 전용 제한 adapter | B2를 고정 Tier 0 입력·closed scalar 출력·실패 처리로 감싸는 별도 연구 모듈 후보 | Production 알고리즘을 별도 실행·복제해 값만 비교하면 실제 실행의 owner/선택 동일성이 증명되지 않음 | B2 위의 Restricted Adapter일 때만 조건부 실현 가능 |

B2를 선택한다고 `_execute_production()`에 callback을 넣거나 공개 Replay DTO를 확장하지 않는다. 기존 Replay 검증 로직의 사본을 더 느슨하게 만들어 우회하지 않으며, 연구 경계에서 무엇을 재사용하고 무엇을 별도 검증할지는 S1 승인 파일·테스트 계약에서 고정해야 한다. private core의 사용 자체가 허용되지 않거나 S1이 공개 Replay 결과에서만 추출해야 한다면 현재 요구로는 BLOCKED다.

별도로 실행한 기존 Replay와 새 adapter는 같은 bytes를 사용해도 다른 run이다. 새 aggregate와 실제 Detection 관측은 **같은 adapter 호출의 반환 triple**에서 함께 검증해야 하며, scenario ID나 count가 같다는 이유로 이전 Replay 실행에 대한 같은-owner 증명처럼 붙이면 안 된다. 기존 Replay는 별도 회귀 기준으로 유지한다. 공개 `analyze()`도 일반 dict만 반환하므로 private 결속 복원 경계로 삼지 않는다.

## 7. Brute selected-window 계약

현재 Production은 같은 source IP와 알려진 동일 account의 실패를 UTC 순서로 정렬해 실패 5회 이상, span 60초 이하인 후보를 선택한다. 계정별 가장 빠른 qualifying 종료를 후보로 만들고 `(end, start, span, -count)` 우선순위로 선택하며 동률 계정이 모호하면 선택하지 않는다. 같은 시각의 행은 실세계 중복임을 알 수 없어 유지된다. 따라서 선택 count가 항상 5인 것은 아니다. 이는 프로젝트의 현 정책이며 외부 표준 임계값이 아니다.

집계는 그 실행에서 실제 반환된 context의 `failure_count`와 `end_utc-start_utc`만 후보로 한다. DETECTED여도 owner/Evidence/member 검증이 실패하면 두 필드는 null 또는 미출력, 검증 상태는 INVALID/NOT_EVALUATED 후보로 둔다. 실제 NOT_DETECTED에는 선택 창이 없으므로 count=0, span=0의 가상 창을 생성하지 않는다. 실제 Detection 상태와 선택 집계 평가 상태는 별개다.

## 8. Spray whole-span 계약

`app/detector/brute_force.py:601 summarize_ip_failures(logs)`는 같은 IP의 전체 실패 집계를 만들고 `app/detector/password_spray.py:4 detect_password_spray(features, failures)`는 실패 4회 이상·known account 3개 이상·전체 min/max span 60초 이하를 확인한다. Brute 창과 달리 Production whole-span이다.

음성 Spray 결과에도 실제 전체 실패 집계는 존재할 수 있다. count/account/span은 같은 실제 list의 해당 IP 실패와 Production features를 대조한 경우에만 후보이며 Evidence가 비어 있다는 사실을 Evidence 검증 성공으로 표현하지 않는다. whole-span이 60초를 넘는 사실은 그대로 유지하고 60초로 절단하지 않는다. Parser/subject/시각 근거가 없으면 0을 채우지 않는다. 이 표의 Spray 필드 설계가 S1에서 그 범위의 구현까지 승인한 것은 아니다.

## 9. Safe Aggregate 후보 DTO

아래는 연구 전용 field 후보다. 기존 Replay/DTO를 변경하지 않으며 모두 상시 출력할 의무는 없다. 이름·closed enum·출력 상한은 후속 S1 범위 승인 때 확정한다. `null`은 수치 부재이며 0과 다르다. 개인 식별값·원시 참조는 어떤 필드에도 넣지 않는다.

| 필드/타입 후보 | 실제 Producer | 필요한 검증점 | 내부 객체 / 같은 실행 결속 | 연구 출력 허용 | 지원 Scope | 누락 시 | 부정 테스트 |
|---|---|---|---|---|---|---|---|
| `detector_id`: closed string | 고정 scenario와 실제 DetectionResult slot/type | owner.is_bound_to + slot/type 확인 | 실제 result/detection / 필수 | 코드만 | Brute/Spray 지정 scope | claim 미평가 | N02/N11/N12 |
| `policy_version`: closed string | 고정 scenario.policy_id + 승인된 현재 Production 코드 매핑 | `compare_runs()` metadata 규칙과 exact SHA/파일 digest pin 계획 | 실행 설정/동일 코드 버전 / 필수 | 정책 코드만 | `brute_force_production_v1`, `password_spray_whole_span_production_v1` 후보 | 미평가 | N10/N11 |
| `scope_type`: closed string | selector 또는 IP 전체 feature의 실제 scope | context/subject 및 list scope 검사 | 동일 list/context / 필수 | 정해진 범위 코드만 | selected-window / whole-span | 미평가 | N15 |
| `parser_disposition`: closed string | Corpus `_parse_fixture()`/`prepare_scenario()`와 실제 Loader 입력 | 같은 bytes/digest, 입력 품질·수집 행/필수 field 확인 | 사전 검증은 별도 실행; 실제 bytes 일치 확인 필요 | 상태만 | 입력/parsed subset | NOT_EVALUATED | N06–N09/N12 |
| `evidence_validation_status`: closed string | 아직 없는 제한 validator의 판정 후보 | owner + context + Evidence + 전체 list membership | 같은 실제 실행 / 필수 | VERIFIED/INVALID/NOT_EVALUATED 후보만 | 검출 근거에 한정 | NOT_EVALUATED | N01–N05/N13/N16 |
| `selected_window_failure_count`: int 또는 null | 실제 Brute context.failure_count | validate_brute_window_context + brute_evidence_matches_context + list membership | context/Detection/owner/list / 필수 | 검증 후 수치만 | Brute 선택 account 창 | null/미출력 | N03–N05/N14/N15 |
| `selected_window_span_seconds`: finite number 또는 null | 실제 context UTC endpoint 차이 | 위 검사와 Evidence span 일치 | 동일 context/Detection / 필수 | 상대 시간 폭만 | Brute 선택 창 | null/미출력 | N07/N14/N15 |
| `whole_span_failure_count`: int 또는 null | Production features.failure_count | owner result binding + 실제 같은 IP 전체 failures 대조 | 동일 list/features / 필수 | 검증 후 수치만 | IP 전체 실패 | null/미출력 | N04/N14/N15 |
| `whole_span_account_count`: int 또는 null | Production features.unique_target_count | 실제 실패의 non-empty known account 집합 대조, `_verify_spray_evidence()`의 기존 계약 참조 | 동일 list/features/해당 Detection / 필수 | 이름 없이 cardinality만 | Spray 전체 IP | null/미출력 | N05/N06/N15 |
| `whole_span_seconds`: finite number 또는 null | Production features.window_seconds | 실제 전체 failures min/max 및 검출 시 Spray Evidence 대조 | 동일 list/features/Detection / 필수 | 원본 시각 없이 span만 | Spray 전체 IP | null/미출력 | N07/N14/N15 |
| `evaluation_status`: closed string | 아직 없는 연구 평가 validator | 모든 필요한 근거 및 parser/실행 상태 검사 | 같은 run의 제한 기록 / 필수 | 상태만; 독립 승인 의미 없음 | 후보 record | NOT_EVALUATED | N08/N09/N20/N22 |
| `reason_codes`: closed tuple | 현재 Replay/Comparison의 고정 사유와 연구 scope별 판정 | `validate_reason_codes()` 참조; 새 사유 추가는 별도 schema 승인 | 검증 실패 차원에만 결속 | 고정 code만 | 해당 평가 차원 | 성공 추측 금지 | N10–N13/N17/N22 |

Detection 함수가 실제 policy 버전 stamp를 반환하는 것은 아니다. `policy_id`는 scenario metadata라 같은 문자열 아래 알고리즘이 바뀌면 문자열 비교만으로 감지되지 않는다. approved exact SHA·실행 code의 고정 매핑/변경 탐지와 설정 결속을 후속 Gate에서 정해야 한다. 없으면 정책 검증 완료라고 출력하지 않는다.

정수는 bool과 구별하고 0 이상이며 승인된 고정 입력 크기보다 클 수 없다. 현재 mutation은 최대 8192 bytes/64행이다. 검증된 selected count는 5 이상, span은 유한한 0–60초다. whole-span은 60초를 초과할 수 있으므로 별도 고정 입력/자원 상한을 정하되 정책 threshold로 절단하지 않는다. 출력 수·bytes·숫자/정밀도·중첩 및 시간 한도는 구현 전에 확정해야 한다. 선택된 count/span의 조건부 후보 외의 새 기능을 이 표로 자동 승인하지 않는다.

## 10. Privacy 및 Security Boundary

Raw Log/Event, Source IP, Account Name, 원본 Timestamp, 내부 파일 경로, exception 원문, owner/context/Evidence 객체, private context ID 및 원본 row를 복원하는 참조는 출력 금지다. 고정 합성 값도 같은 경계를 적용한다. 고정 detector/policy/scope 코드와 검증된 bounded 수치·상태만 explicit allowlist로 복사한다.

`AnalysisRunOwner`, `BruteWindowContext`, bundle의 repr은 redacted지만 그 사실이 모든 직렬화를 막지 않는다. `dataclasses.asdict()`, `__dict__`, 필드 나열, 재귀 JSON default=str, 자동 직렬화는 Evidence/NormalizedEvent의 원문·식별자와 context의 fields를 노출할 수 있다. slots로 __dict__가 없어도 `asdict`와 속성 접근은 별개다. raw 분석 dict의 일반 JSON 변환도 IP 키와 내부 값을 내보낸다. repr/str/자동 logging에 의존하지 않고 allowlist encoder만 제안하며 stdout/stderr·로그·예외·출력 bytes를 함께 검증해야 한다.

frozen context/mapping은 깊은 불변성이나 프로세스 격리가 아니다. 같은 권한의 악성 Python이 private field를 임의 조작하는 공격까지 방어했다고 주장하지 않는다. 제한 adapter는 신뢰한 고정 입력과 코드가 만든 실제 객체만 내부에서 다루고, 외부가 제공한 bundle/context/owner를 검증 대상으로 수용하지 않는 경계를 요구한다. 임시 파일·입력 사본·메모리의 최소 수명, 네트워크/LLM 호출 0, 비정상 종료 잔존 및 bounded 오류 처리도 별도 S1 검증 대상이다.

## 11. Negative Test Matrix

기존 근거 표기: E1=`tests/test_brute_window_production_36_9f.py`의 실제 context/Evidence, 60초·동률·whole-IP 회귀; E2=`tests/test_brute_window_run_ownership_36_9g_r1.py`의 cross-run·same-event/new-owner·repr; E3=ownership closure/analysis unique binding/analysis closure 테스트들의 재포장·재결속 거부; E4=`tests/test_counterfactual_replay_er1b.py`의 상태·scope·동일 bytes·owner·network·privacy·결정성·exception; E5=`tests/test_counterfactual_holdout_er1c.py`의 고정 digest·fresh owner·same bytes·결정성. 이들은 **기존 consumer/Replay**의 근거다. 아래의 신규 adapter 동작을 이미 검증했다고 뜻하지 않는다.

| 번호 | 입력 조건 | 기대 처리·금지 출력 | 재현 방법 / 기존 범위와 새로 필요한 범위 |
|---|---|---|---|
| N01 | 다른 Run Owner의 context 결합 | owner 불일치 거부, Claim 없음 | E2/E3의 두 실행 교차 참조; 새 adapter가 같은 값을 가진 foreign context도 거부하는 회귀 필요 |
| N02 | 다른 Detector 실행의 Evidence 주입 | bound Detection object identity 불일치 또는 검증 실패; 값만 같다고 승인 금지 | E3는 결과 참조 재포장 거부, 새 adapter에 동등값 다른 Detection 주입 계획 |
| N03 | Evidence Membership 불일치 | context/Evidence 또는 실제 member identity 검사 실패 | E1의 count 변조·다른 이벤트 소비 실패; 새 adapter에 멤버 삭제/대체 주입 필요 |
| N04 | 선택 Window와 실제 Raw Event 유래 집합 불일치 | 같은 Loader list에 없는 member 또는 초과 중복도 거부 | 같은 필드값의 별도 event clone 주입; E1/E2 consumer 범위 외 adapter 자체 검사 필요 |
| N05 | 같은 IP의 다른 account event 혼입 | context account/membership 불일치; IP 전체 count 대체 금지 | E1의 계정별 선택·동률 근거, 새 context member 변조 계획 |
| N06 | Missing Account | policy 필수 입력 누락/부분 scope, 선택 count 추측 금지 | E1의 known account 정책 및 E4 부분 범위; 새 필드별 null/보류 검사 필요 |
| N07 | Missing Timestamp | Parser/실행 실패 차원 보존, span=0 추측 금지 | E1의 naive timestamp 거부, E4 실행 실패; missing 값 adapter 경계 계획 |
| N08 | Parser PARTIAL | parsed subset 한계, 완전성 필요한 Claim NOT_EVALUATED | E4의 PARTIAL 비교 불확정/불가; 새 numeric 출력 보류 검사 필요 |
| N09 | Parser REJECTED | Detector NOT_EVALUATED, 비교 INCOMPARABLE | E4/E5 상태 보호; 새 aggregate null/미출력 확인 필요 |
| N10 | Policy Version Mismatch | policy mismatch/미평가, 다른 정책으로 보정 금지 | E4 metadata mismatch는 검증됨; 실제 code pin과 metadata 불일치 시험은 새로 필요 |
| N11 | Detector Version Mismatch | version/source code 결속 실패, 결과 보류 | E4 detector ID mismatch는 검증됨; 동일 ID의 코드 변경 감지는 별도 계획 필요 |
| N12 | Unsupported Source | allowlist/scope 거부; 다른 Parser fallback 금지 | 기존 Corpus의 application/ssh allowlist, 새 연구 진입점의 부정 source 입력 필요 |
| N13 | Null/Empty Evidence | DETECTED이면 invalid; 실제 음성의 빈 근거는 검증 성공으로 격상 금지 | 기존 E1 Evidence shape 및 E4 음성 계약, 새 null·empty 출력 행 검사 필요 |
| N14 | 잘못된 Count/Span | 타입·유한성·멤버 수·endpoint/Evidence 불일치 거부 | E1 count 변경·시간 경계. 새 bool/NaN/과도한 숫자·serializer 검증 필요 |
| N15 | Brute/Spray Scope 혼동 | selected-window와 whole-span을 각각 보존 | E1은 실제 전체 count 6/span 70과 선택 count 5/span 20 구분; 새 DTO field mapping 검사 필요 |
| N16 | Baseline/Variant owner 교차 주입 | owner와 context/result 조합 거부 | E2/E4/E5는 fresh owner 보호; 새 adapter pair 조합 검사 필요 |
| N17 | Raw Log/IP/Account Canary | 출력·로그·오류 어디에도 원문 없음 | E4/E5의 기존 직렬화 privacy, 새 scalar allowlist/stdout/stderr canary 필요 |
| N18 | Private 객체 직렬화 시도 | schema/type reject; repr redaction만으로 성공 선언 금지 | E2 repr과 E3 공개 mapping 보존은 기존 범위; 새 asdict/자동 직렬화 방지 계획 필요 |
| N19 | 외부 네트워크 호출 | socket/API/LLM 시도 0, 발견 시 HOLD | E4/E5 network 차단 fixture는 기존 실행 보호; 새 entrypoint 전체 검증 필요 |
| N20 | Production 결과 또는 Replay DTO 변화 | 기존 결과·공개 schema·정책·Corpus 불변 | E1/E3/E4/E5 관련 회귀, 새 adapter 호출 전후 깊은 값 비교·변경 범위 검사 필요 |
| N21 | 반복 실행 비결정적 출력 | 동일 bytes/정책의 scalar canonical bytes 동일 | E4/E5 Replay 결정성은 기존 근거; 새 DTO에 시각·random ID·주소가 없도록 검사 필요 |
| N22 | 오류 시 원문 Exception | fixed code, partial Claim·traceback·입력 반사 없음 | E4의 private exception canary, 새 adapter의 모든 실패 경계 검사 필요 |

실제 주입은 향후 승인된 테스트의 메모리 사본·합성 canary에서만 수행하고 원본 Corpus/fixture bytes를 수정하지 않는다. 이 S1-P에서는 신규 보안 테스트를 만들거나 임의 private 객체 공격 실험을 실행하지 않았다.

## 12. Production/Replay 수정 필요 여부

권고 B2/C 구조는 기존 Loader와 내부 core를 호출하므로 현재 코드의 구조상 Production 함수·Parser·Detector·Risk/Correlation을 수정하거나 새 callback/hook을 넣을 필요가 없다. 실제 결과에서 선택 context를 반환하는 인터페이스가 이미 존재한다. 기존 Replay는 회귀 관측 기준으로 별도 유지하고 새 aggregate를 그 DTO에 추가하지 않는다.

다만 기존 public Replay만 사용할 수 있다는 제약, private core 사용 불허, 또는 새로운 공용 provenance/검증 API가 필수라는 후속 판단이 나오면 현재 범위를 넓히지 않는다. 이 경우 별도 변경 제안과 Gate가 필요하고 `BLOCKED_BY_PRODUCTION_OR_REPLAY_CHANGE`로 재분류한다. same-run list identity 검사를 완성하려면 제한 adapter의 신규 검증은 필요하며 현재 구현 승인 전이다.

## 13. Tier 0과 Tier 1 적용 차이

초기 후보는 Tier 0 고정 Development 16 + Holdout 14의 불변 manifest/fixture/digest와 제한 mutation이다. 기존 준비/Replay API는 이를 검증하지만 owner-bound 집계를 주는 새 인터페이스가 아니다. 각 Corpus의 기존 검증 경로와 실제 분석 bytes 동일성을 재사용 계획에서 확정해야 하며 label/basis는 집계 출력에서 제외한다.

Tier 1은 별도 S5 입력 보안 Gate 전 미승인이다. Tier 0 prevalidation은 임의 사용자 입력의 Parser 품질·민감정보·자원 한도나 Label provenance를 보증하지 않는다. 사용자 정의 합성 로그의 실용적 확장은 후속 후보로 남고 영구적으로 30건만 지원한다는 뜻은 아니다. Tier 2는 권한·Privacy/Security·보관/삭제 Gate 이전 미승인, Tier 3는 NO_GO다. 신규 입력에 고정 Label을 상속하거나 Tier 0의 성공을 적용하지 않는다.

## 14. 기술적 Feasibility 판정

| 분류 | 이번 근거에 따른 적용 |
|---|---|
| FEASIBLE_WITH_EXISTING_BOUNDARY | 현재 제한 scalar API가 완성돼 있다는 뜻으로는 선택하지 않음. 내부 호출 경계는 존재하지만 출력·보안 wrapper는 미구현 |
| FEASIBLE_ONLY_WITH_RESTRICTED_ADAPTER | **선택**. B2에서 실제 parsed list와 core 반환 triple를 연구 호출자가 함께 보유하고, 실시간 결속·membership·한도·출력 검증을 구현하는 경우의 조건부 설계 가능성 |
| BLOCKED_BY_PRODUCTION_OR_REPLAY_CHANGE | 공개 Replay만 사용해야 하거나 현 private 경계를 허용할 수 없어 hook/API 변경이 필수라면 적용; 현재 권고 구조에 그 변경이 필수라는 근거는 없음 |
| UNDETERMINED | 새 adapter의 실제 보안 성공·모든 실패 처리·자원/출력 한도는 아직 실증되지 않음. 설계 가능성과 구분 |

실제 Detection은 core가 반환한 원래 result slot을 owner 검증 후 사용하고 선택 context도 같은 반환값에서 가져와야 한다. Source/Account와 원본 timestamp는 내부 확인만 하고 finite count/span만 복사한다. owner가 폐기되거나 public DTO로만 남은 뒤에는 소급 검증할 수 없다. 같은 필드값과 별도 재계산은 동일 실행의 증거가 아니다. 설계상 추출 가능성을 확인했지만, 현재 안전한 Adapter 구현 성공을 선언하지 않는다.

## 15. 정책 효력 및 S1 승인 조건

G3의 Option B **방향 승인**은 기록돼 있다. 실제 정책 권한·적용 의무 확인, R1–R6의 채택·효력·기간과 개별 S1 범위/허용 파일 승인은 아직 없다. 본 감사는 이를 대체하지 않는다.

`SOLO_RESEARCH_POLICY_EFFECTIVENESS_PENDING`, `ER_1D_S1_IMPLEMENTATION_HOLD`, `INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`, `ER_1D_IMPLEMENTATION_HOLD`, `ER_2F_USER_ACCEPTANCE_PENDING` 및 실제 운영 NO_GO를 유지한다. 새 코드 착수 전에 정확한 SHA/성공 CI, B2/C private core 사용 범위, 고정 입력/provenance 경로, §9 schema/수치·출력·실행 한도, §11 부정 테스트 및 privacy/network 차단·Production 불변 계획을 승인된 목록으로 확정해야 한다.

## 16. 구현 전 해결할 차단 조건

- 정책 효력과 실제 S1 구현 승인 및 허용 파일 목록.
- B2/C 호출자 소유 이벤트 목록의 전후 불변·identity/중복도, owner/result/Evidence 검증 순서와 private 인터페이스 사용 계약.
- core가 읽는 고정 account metadata를 포함한 전체 파일 접근 의존성의 allowlist·버전/digest 및 합성 연구 적합성. 임의 사용자 경로를 허용하거나 Risk 경로를 생략해 맞추지 않는다.
- 현재 코드의 버전 pin과 scenario policy metadata 결속; 문자열만으로 정책 검증했다고 표시하지 않는 기준.
- 필요한 입력만 처리하는 fixed Corpus 경로, Parser 완전성·REJECTED/PARTIAL/음성/exception 처리, 두 실행 분리.
- nullable 집계·fixed reason/enum·숫자·bytes·시간·collection 상한과 깊은 불변 DTO/allowlist 직렬화.
- §11의 기존 근거와 신규 adapter 회귀 사이의 공백 해소 계획. 하나라도 실제 구현에서 실패하면 Claim 보류 및 HOLD, Production/Replay 변경으로 우회하지 않음.

## 17. Final Decision

`ER_1D_S1_P_RESTRICTED_ADAPTER_PREFLIGHT_LOCAL_CONDITIONAL_GO`: 현재 경계의 기술·보안 준비도 감사를 완료했다. 이는 조건부 설계 가능성 및 추가 검증 계획에 한정하며 정책 효력 또는 S1 구현 승인·성공이 아니다. 핵심 경계가 후속 구현에서 성립하지 않으면 구체적 근거와 함께 `ER_1D_S1_P_TECHNICAL_HOLD` 및 관련 기술 분류를 재평가한다.

### 검증 증거와 한계

변경 전 전체 pytest는 기존 `test_linux_browser_memory_behavior_with_node`의 15초 subprocess timeout으로 **1 failed, 3896 passed, 2 warnings**였다. 당시 파일 변경 전이었고, 동일 테스트를 수정 없이 단독 재실행했을 때 **1 passed in 0.43s**로 재현되지 않았다. 환경 원인을 확정하지 않으며 최초 실패를 보존한다.

기존 Replay/Brute/owner 8개 테스트 파일 focused 회귀는 **73 passed, 2 warnings**다. §11 E1–E5는 해당 기존 검증 범위이며 adapter의 실행 증거가 아니다. 문서 계약 TDD RED는 문서·색인 부재로 4 failed. S1-P와 기존 P/G0/S0/G1/G2/G3 문서 계약 GREEN은 **24 passed**다. 변경 후 전체 `uv run pytest -q`는 **3901 passed, 2 warnings**로 통과했고 최초 Node timeout도 이 전체 실행에서 재현되지 않았다. 두 warning은 기존 FastAPI/Starlette 및 AnyIO deprecation 경고다.

`uv run python -m app.evaluation`은 Synthetic Boundary 79/79, Risk 70/70, Case 70/70, Linux Process 합성 분류 21/21로 성공했다. `uv lock --check`, `uv run python -m compileall -q app tests`, `git diff --check`도 성공했다. 이 수치는 기존 합성 평가이며 운영 탐지 성능이 아니다. 새 연구 코드 및 신규 보안 테스트는 구현하지 않았다. 변경은 이 신규 감사 문서·docs/index.md·문서 계약 테스트로 한정하며 Production/Replay/Corpus/Snapshot/정책 구현 계약은 변경하지 않았다.
