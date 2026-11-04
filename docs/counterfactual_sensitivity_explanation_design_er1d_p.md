# ER-1D-P — 탐지 민감도 설명 설계 및 계약

## 1. Executive Summary

**설계 판정:** `ER_1D_P_EXPLANATION_DESIGN_LOCAL_CONDITIONAL_GO` — 합성 입력에서 관찰된 입력 변화, 재계산 특징, 현재 정책 조건, 실제 replay 관측을 서로 다른 근거 계층으로 설명하기 위한 계약을 제안한다. 이 문서는 설계 전용이며 Production 설명 코드·API·UI·기존 Corpus·Label·Replay를 변경하지 않는다.

ER-1D가 답할 질문은 다음으로 한정한다.

> 동일한 탐지 정책에서 Baseline과 Variant의 관측 결과가 달라졌을 때, 어떤 입력 사실과 파생 특징이 달라졌으며 그 차이가 정책 조건과 어떤 관계가 있는가?

가능한 결론은 해당 합성 입력과 실행에서 검증한 사실과 정책 predicate의 관계뿐이다. Mutation 하나가 결과 변화의 유일한 원인이라는 주장, 공격자의 의도, 실제 공격·침해, 탐지 회피 성공, 또는 미탐지의 안전 의미를 만들지 않는다.

현재 Production 임계값은 프로젝트 평가 휴리스틱이다. Brute Force는 같은 IP 및 알려진 같은 계정의 선택 Sliding Window에서 실패 5회 이상·60초 이하이고, Password Spraying-like는 같은 IP 전체 실패 4회 이상·알려진 계정 3개 이상·전체 span 60초 이하이다. 두 범위는 서로 대체할 수 없다.

## 2. Start SHA / CI Gate

- 저장소: `misosos/ai-security-log-analyzer`
- 시작 SHA: `d04d0d882391e0becdd18e249a322359802d8951`
- Exact CI: [41828620405](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41828620405), `push / completed / success`, head SHA 일치
- 필수 Linux regression/smoke, Restricted Report, Chromium·axe, tracked-file 검사: 성공
- Artifact: 0
- 시작 시 branch `main`, working tree clean; HEAD/local main/origin main/GitHub main 동일, behind/ahead 0/0
- `v0.4.0` Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지
- 변경 전 순차 기준선 `uv run pytest -q`: 3,752 passed, 기존 deprecation warning 2개
- `AGENTS.md`, `.agents/skills/security-analysis/SKILL.md`, `.agents/skills/security-testing/SKILL.md`를 확인했다.

## 3. Existing System Analysis

### 3.1 입력에서 replay 결과까지

`app/evaluation/counterfactual_corpus.py::load_corpus()`는 고정 `sample_logs/counterfactual/`의 manifest와 fixture allowlist를 검증한다. `prepare_scenario()`는 baseline과 변형 bytes를 기존 source parser에 각각 전달하고, 관측 event facts와 사전 작성된 독립 입력-pattern label을 검증한다. `app/evaluation/counterfactual_mutation.py::apply_mutation()`은 허용된 mutation을 normalized event가 아니라 입력 bytes에 적용한다.

`app/evaluation/counterfactual_replay.py::_replay_prevalidated_scenario()`는 검증한 동일 bytes를 각각 새 temporary input으로 쓰고, 각각 `app.main::analyze_with_source_role_snapshot()`으로 실행한다. `app.main::_analyze_normalized_logs_with_context()`는 실행마다 새 `AnalysisRunOwner`를 만들며, 결과·source-role snapshot·private Brute context를 한 실행에 묶는다. replay는 Baseline과 Variant owner가 서로 다른지 검사한다.

Replay는 Brute 검출 시 context owner와 `brute_evidence_matches_context()`의 Evidence membership을 확인한다. 이 private context는 공개 replay 결과에 직렬화되지 않는다. 현재 `ReplayScenarioResult`의 공개 facts는 `SafeFacts`의 제한된 집계(count, source count, target scope count/span)뿐이다. 이 구조는 Brute 선택 window 내부의 별도 baseline/variant 집계나 모든 정책 predicate의 항목별 판정을 제공하지 않는다. 그 값은 ER-1D가 기존 공개 결과에 있다고 가정해서는 안 된다.

### 3.2 비교 상태와 현재 출력

`app/evaluation/counterfactual_comparison.py`는 Parser, Detection, Comparison을 별도 enum으로 두고, detector/policy/source/parser profile/input scope/subject가 일치하지 않으면 `INCOMPARABLE`을 반환한다. Parser `REJECTED` 또는 미실행은 탐지 음성이 아니다. 실행 실패는 `EXECUTION_FAILED`이고 `NOT_DETECTED`로 바뀌지 않는다. provenance 또는 evidence binding 부족은 `UNDETERMINED`로 fail-closed 처리한다.

Replay output에는 scenario/detector/policy/profile, parser·detection·comparison 상태, 기존 fixed reason code, 사전 작성된 pattern label 검증 상태 및 제한 facts가 포함된다. 실행 시각, raw event, account/IP, timestamp, path, private context, exception 원문은 포함되지 않는다. 이 output은 설명 근거의 일부이지, 그 자체가 사람 검토나 독립 라벨이 아니다.

### 3.3 Production predicate 범위

| 정책 ID | 현재 Producer | 입력 scope 및 predicate |
|---|---|---|
| `brute_force_production_v1` | `app/detector/brute_force.py::select_brute_window_contexts()` 및 `brute_force_detection_from_context()`; pipeline consumer는 `app/analyzer/pipeline.py::detect_attacks_with_context()` | 동일 source IP와 알려진 동일 계정의 선택 window, 실패 5회 이상, window span 60초 이하. 후보는 UTC 시각으로 정렬하고 선택 context는 실행 owner에 결속된다. |
| `password_spray_whole_span_production_v1` | `app/detector/brute_force.py::summarize_ip_failures()`와 `app/detector/password_spray.py::detect_password_spray()` | 동일 IP의 전체 실패 집계, 실패 4회 이상, 알려진 계정 3개 이상, 전체 실패 span 60초 이하. Production은 Sliding Window가 아니다. |

Brute 선택 account window와 동일 IP의 전체 feature는 서로 다른 scope다. Spray 평가용 Sliding Window prototype은 Production 정책에 포함하지 않는다. 이 문서는 두 정책의 임계값을 바꾸거나 외부 기준으로 승인하지 않는다.

## 4. Explanation Purpose

설명은 사람이 재현할 수 있도록 “무엇이 바뀌었는가”, “무엇을 parser/replay가 실제로 확인했는가”, “어떤 현재 predicate와 관계가 있는가”, “무엇은 아직 알 수 없는가”를 함께 제시한다.

기본 불변식:

- `Detection ≠ Confirmed Compromise`
- `Correlation ≠ Causation`
- `No Detection ≠ Safe`
- `Login Success ≠ Account Compromise`
- `Parser Failure ≠ Detector False Negative`
- `Counterfactual Change ≠ Real-world Evasion Success`
- 합성 행은 실제 운영 로그의 진실성·수집 완전성·공격 의도를 보증하지 않는다.

## 5. Four-Layer Evidence Model

각 실행측(Baseline, Variant)은 다음 네 계층을 각각 표현한다. 계층을 합쳐 단일 “원인” 설명을 만들지 않는다.

### A. Direct Input Mutation

Mutation engine이 synthetic bytes에 직접 적용한 닫힌 유형: `remove_failure_row`, `add_failure_row`, `change_timestamp`, `change_account`, `change_source_ip`, `reorder_rows`, `damage_format`. 직접 변경된 항목의 식별은 line text가 아닌 제한된 scenario 내 mutation target/순번 참조로 한다. 원문 bytes나 row를 설명 출력에 싣지 않는다.

### B. Observed Feature Delta

동일한 입력 bytes의 Loader→Parser 출력과 안전한 Production replay 결과에서 다시 계산·검증된 값의 차이다. 후보 필드는 전체 event/failure 수, target IP 실패 수, known account 수, source IP group 수, target 전체 실패 span, Brute 선택 account window의 실패 수·시간 폭, Parser completeness다.

각 값은 필드 provenance와 scope를 붙인다. 예: `parser.login_failed`, `production.features.ip_scope`, `owner_bound.brute_selected_window`. `null`은 관찰 불가/계산 불가를 뜻하며 0으로 대체하지 않는다. Brute 선택 window의 수치 출력은 별도 내부 검증이 동일 run owner·Evidence membership을 확인한 경우에만 safe aggregate로 내보낸다. raw `BruteWindowContext`, account, event, timestamp는 출력하지 않는다. 현재 Replay `SafeFacts`만으로 이 window delta가 제공된다고 주장할 수 없으며, ER-1D 구현 전에 명시적인 safe projection이 필요하다.

### C. Policy Predicate Evaluation

predicate별로 scope, observed value, 연산자, policy threshold/version, 상태를 표현한다. 상태는 `SATISFIED`, `NOT_SATISFIED`, `NOT_EVALUATED`의 closed set이다. 필수 field가 빠지거나 Parser completeness가 불충분하면 `NOT_EVALUATED`; unknown을 false로 처리하지 않는다. 정책 predicate는 해당 입력의 관측 사실에 대한 기계적 계산이며 별도 독립 Label이 아니다.

Brute predicate: same IP, known same account, selected-window failure count ≥5, selected-window span ≤60 sec.

Spray predicate: same IP full failure count ≥4, known-account cardinality ≥3, full failure span ≤60 sec.

### D. Detector Observation

실제 Production replay에서 얻은 `DETECTED`, `NOT_DETECTED`, `NOT_EVALUATED`, `EXECUTION_FAILED` 및 scenario 비교의 `PRESERVED`, `LOST`, `GAINED`, `UNCHANGED_ABSENT`, `INCOMPARABLE`, `UNDETERMINED`를 원래 상태 그대로 결속한다. Observation은 C의 입력/predicate 해석이나 독립 Label 생성 근거로 역이용하지 않는다. Replay 결과가 predicate 설명과 충돌하면 상태를 덮어쓰지 않고 `INCONSISTENT_EVIDENCE`에 해당하는 기존 fixed reason/status로 fail-closed하여 설명 claim을 보류한다. 기존 reason code에 이 이름이 없다면 ER-1D 구현 전에 코드 집합 변경 별도 승인이 필요하다.

## 6. Direct Mutation vs Feature Delta

한 direct input mutation은 복수 파생 사실을 바꿀 수 있다. 예컨대 실패 행 제거는 total failure count, 계정 cardinality, 전체 span, Brute 선택 후보 window를 함께 바꿀 수 있다. 따라서 출력 분류는 다음 closed categories로 각 항목을 나눈다.

- `DIRECT_INPUT_CHANGE`
- `DERIVED_FEATURE_CHANGE`
- `POLICY_CONDITION_CHANGE`
- `DETECTOR_OBSERVATION_CHANGE`
- `INSUFFICIENT_EVIDENCE`

각 claim은 근거 참조와 범위가 있어야 한다. 보이는 feature delta가 여럿이면 전부 기록하거나 출력 상한에 맞춰 생략된 개수와 `INSUFFICIENT_EVIDENCE`를 표시한다. 하나를 골라 “유일 원인”이라고 하지 않는다. Input change, derived delta, predicate transition, detector transition은 각각 독립된 관찰이다. counterfactual replay가 개입 효과의 현실적 인과 증명을 제공하지 않는다는 제한을 함께 표시한다.

## 7. Production Policy Predicates

predicate 값은 API나 replay에서 받은 숫자를 그대로 믿지 않는다. 입력 bytes→정확한 parser profile→정규화된 지원 event facts→정책 scope의 동일성이 검증되어야 한다. Baseline/Variant 각각에서 동일한 버전의 Production 정책을 평가한다.

| Predicate 그룹 | 입력 근거 | scope 및 경계 | 값이 없거나 incomplete일 때 |
|---|---|---|---|
| Brute same IP/account | parser의 `src_ip`, 알려진 `user`, `login_failed` event | 각 source IP와 account 그룹; 선택 window | IP/user 또는 completeness 미확인 시 `NOT_EVALUATED` |
| Brute count/span | owner-bound selected window와 membership 검증 | 선택된 계정 window; ≥5, ≤60초 | 안전한 owner-bound aggregate 없으면 선택-window claim 금지 |
| Spray count/accounts/span | 같은 IP에 대한 모든 Parser 실패 event와 Production `features`/Evidence 일치 | IP 전체 실패집합; ≥4, ≥3 known accounts, 전체 min/max ≤60초 | PARTIAL/누락 필드면 whole-input predicate `NOT_EVALUATED` |

60초 조건은 현재 코드에서 inclusive (`<=`)다. 정확히 60초는 통과하고 60초 초과는 통과하지 않는다. 이 값은 project heuristic이지 NIST/MITRE 기준이 아니다. 시간 계산은 parser가 정규화한 timezone-aware timestamp의 실제 scope를 따른다. 원본 로그 시계 정확도는 보증하지 않는다.

## 8. Detector Observation Binding

ER-1B의 bound run 규칙을 그대로 요구한다. Baseline/Variant는 독립 Production 실행 및 서로 다른 `AnalysisRunOwner`여야 한다. Brute의 DETECTED는 해당 owner의 `BruteWindowContext`와 Evidence membership 검증을 통과해야 한다. Spray evidence는 Production full-IP features와 일치해야 한다. Explanation DTO에는 owner/context, private event identity, `Evidence` object 자체를 싣지 않고 검증 결과와 허용된 집계만 싣는다.

Binding status는 closed enum `VERIFIED`, `FAILED`, `NOT_EVALUATED`로 제안한다. `FAILED`이면 수치·predicate로 결과를 정당화하는 claim을 내지 않고, 현재 fixed `EVIDENCE_BINDING_FAILED` reason code를 사용한다. Label provenance가 부족하면 `LABEL_PROVENANCE_MISSING`; 그러나 설명은 Label을 필요로 하지 않아야 하며, Label 상태는 비교 결과의 별도 메타데이터다. 비교/설명에서 사전 작성된 `PATTERN_*` 기대 Label을 사실처럼 표현하지 않는다.

## 9. Allowed and Disallowed Claims

| 허용되는 bounded claim | 필요한 근거 | 남겨야 하는 제한 |
|---|---|---|
| “검증된 실패 이벤트 수가 5에서 4로 바뀌었고, 현재 선택-window 최소 횟수 조건은 Variant에서 충족되지 않았습니다.” | 양쪽 parser VERIFIED, 같은 scope, owner-bound selected-window aggregate 및 predicate 결과 | 이 synthetic run에 한정; 실제 공격/회피 원인 아님 |
| “전체 실패 span이 60초를 초과해 현재 Spray 시간 조건을 충족하지 않았습니다.” | same-IP whole-span Parser facts, completeness VERIFIED | 개별 sliding window로 바꿔 해석하지 않음 |
| “일부 입력 행을 parser가 해석하지 못했습니다.” | Parser PARTIAL과 bounded rejection/missing count | 전체 입력에 대한 음성 결론 금지 |
| “대상 source 범위가 달라 동일 subject 비교가 성립하지 않습니다.” | `SUBJECT_MISMATCH` / scope provenance | LOST/GAINED로 축약 금지 |

금지 주장 예: “공격자가 탐지를 성공적으로 우회함”, “보안 통제를 무력화함”, “실제 Brute Force 공격임이 확인됨”, “로그 변형이 결과 변화의 유일한 원인임”, “탐지되지 않았으므로 안전함”, “로그가 일부 거부됐지만 탐지는 없었음”. 자연어 생성은 fixed template/claim code와 검증된 값으로 제한하며, 임의 LLM 생성은 이 계약의 일부가 아니다.

## 10. INCOMPARABLE / UNDETERMINED Handling

- **INCOMPARABLE**: known comparison identity/scope가 달라 같은 proposition 비교가 성립하지 않음. 예: detector/policy/source/parser profile/scope mismatch, target subject 변경, Parser `REJECTED`, 또는 VERIFIED와 PARTIAL 사이의 completeness mismatch.
- **UNDETERMINED**: 비교 proposition은 같을 수 있으나 결과를 정할 근거·정상 실행·binding이 부족함. 예: `EVIDENCE_BINDING_FAILED`, `LABEL_PROVENANCE_MISSING`, 양측 PARTIAL로 outcome의 completeness equivalence를 확인할 수 없음, execution incomplete.

기존 코드에서는 PARTIAL 양쪽의 경우 `AMBIGUOUS_OUTCOME`로 UNDETERMINED; 상태 차이가 있으면 `INPUT_SCOPE_MISMATCH`로 INCOMPARABLE이다. ER-1D 설명은 이 distinction을 보존해야 한다.

| 상황 | 상태 연결 | 허용 안내의 요지 | 금지 해석 |
|---|---|---|---|
| Parser REJECTED | Detection NOT_EVALUATED, Comparison INCOMPARABLE (`PARSER_REJECTED`) | 지정 Parser가 입력을 해석하지 못해 Detector를 실행하지 않음 | false negative |
| Parser PARTIAL | Detection은 실제 scope 값 유지, 전체 비교는 보류 가능 (`REQUIRED_FIELD_MISSING`, `AMBIGUOUS_OUTCOME` 등) | 일부만 해석되어 전체 입력 결론은 제한됨 | 미검출 또는 전체 입력의 정상 결과 |
| Subject scope changed | INCOMPARABLE (`SUBJECT_MISMATCH`) | 비교 대상 IP 범위가 달라 직접 비교 불가 | 결과 key 부재 = LOST |
| Evidence binding failure | UNDETERMINED (`EVIDENCE_BINDING_FAILED`) | 실행과 근거의 결속을 확인할 수 없어 claim 보류 | 검증된 detection claim |
| Label provenance missing | UNDETERMINED (`LABEL_PROVENANCE_MISSING`) | 기대 Label과의 일치 판정을 할 provenance 없음 | 설명 기준으로 Label을 채택 |
| Detector execution failure | Detection EXECUTION_FAILED; 대개 UNDETERMINED (`EXECUTION_INCOMPLETE` 또는 `ANALYSIS_EXECUTION_FAILED`) | 실행이 완료되지 않아 detector 관측이 없음 | NOT_DETECTED |

알 수 없는 상태·reason·조합은 직렬화하지 않는다. Runtime exception 문자열 대신 ER-0/ER-1B의 fixed reason code만 허용한다. 현재 closed set에는 예상치 못한 조합을 별도로 표현하는 범용 `INCONSISTENT_EVIDENCE`가 없으므로, 이를 임의로 추가하지 않는다. 기존 `INVALID_INTERNAL_CONTRACT`/`EVIDENCE_BINDING_FAILED` 중 어느 것을 적용할지 ER-1D 구현 전 계약 시험으로 확정한다.

## 11. Proposed Closed Explanation Schema

아래는 ER-1D-P 제안 DTO이며 구현/공개 API 계약이 아니다. UTF-8 canonical JSON의 제안 상한은 전체 report 64 KiB, 시나리오 30건, claim/delta/predicate 각 배열 항목 32개, string 96 ASCII 문자(고정 code/ID allowlist), string list 16개다. 제한 초과는 잘라내지 않고 안전한 오류 상태로 전체 설명 생성을 거부한다.

| Field | Type / allowlist | Null | Producer / provenance | Privacy 및 검증 |
|---|---|---|---|---|
| `schema_version` | integer literal `1` | 금지 | Explanation builder | exact integer, bool 거부 |
| `scenario_id` | 고정 Corpus manifest ID 중 하나 | 금지 | corpus registry | 외부 입력 경로 아님; bounded allowlist |
| `detector_id` | `brute_force`, `password_spraying_like` | 금지 | manifest + replay | pair policy allowlist 검증 |
| `policy_id` | 위 두 fixed Production policy ID | 금지 | Production policy registry/manifest 일치 | 정책 추정/변형 금지 |
| `mutation_type` | 7종 ER-1A mutation enum | 금지 | 실제 `apply_mutation` input record | direct input type만; 원문 미포함 |
| `parser_states` | `{baseline, variant}` × ParserState 4종 | 금지 | prevalidation의 동일 bytes | bytes identity 및 parser profile 결속 |
| `detection_states` | `{baseline, variant}` × DetectionState 4종 | 금지 | fresh Production replay | run owner/evidence binding 확인 |
| `comparison_state` | ComparisonState 6종 | 금지 | `compare_runs` | replay state와 동일해야 함 |
| `direct_input_changes` | ≤32 closed object `{kind, target_ref, before_digest?, after_digest?}` | `digest`는 선택 | mutation executor | line/raw byte 미포함; ref는 scenario-local; digest는 input bytes digest로 원문 대체 아님 |
| `observed_feature_deltas` | ≤32 `{feature_id, scope_id, before, after, unit, provenance}` | 수치 before/after는 관측 불가 시 null | parser facts 또는 검증된 production aggregate | known feature/scope/unit/provenance allowlist; null을 0으로 대체 금지 |
| `policy_predicates` | ≤16 `{predicate_id, scope_id, operator, observed_value?, threshold, state, provenance}` | observed value만 null 허용 | fixed policy evaluator + source observations | threshold는 policy ID에 고정; 임의 값/문자열 없음 |
| `evidence_binding_status` | `VERIFIED`, `FAILED`, `NOT_EVALUATED` | 금지 | replay verifier | private object 자체 대신 결과만 |
| `explanation_claims` | ≤32 `{claim_code, evidence_refs[]}`; fixed template catalog | 금지, 빈 배열 허용 | deterministic renderer | free text/LLM/raw data 없음; 모든 ref가 같은 DTO 근거를 지시 |
| `uncertainty_codes` | 정렬된 중복 없는 기존 ER-1B `reason_codes` allowlist | 금지, 빈 배열 허용 | parser/comparison/replay validators | unknown reason 거부; 원문 예외 없음 |

`feature_id` allowlist는 `event_count`, `login_failed_count`, `known_account_count`, `source_ip_count`, `target_failure_count`, `target_known_account_count`, `target_failure_span_seconds`, `brute_selected_failure_count`, `brute_selected_span_seconds`, `parser_completeness`다. `scope_id`는 `input`, `source_ip_group`, `target_subject`, `brute_selected_window` 중 producer가 실제 증명한 값만 허용한다. `provenance`는 parser fact, production feature, owner-bound context/evidence, parser disposition의 fixed identifier다. SHA-256 digest는 소문자 64자리 hex 형식만 허용하며 선택적이고 raw row를 대신하지 않는다. `predicate_id`, `claim_code`, `unit`, `operator`도 versioned allowlist여야 하며 자연어를 받아들이지 않는다. Predicate 상태는 위에서 정의한 세 값뿐이고, claim은 현재 검증 가능한 제한 문구용 catalog가 마련되지 않은 항목이면 생성하지 않는다.

모든 object는 closed key set이며 duplicate key, NaN/Infinity, unknown enum, bool-as-int, 초과 크기, 불일치 provenance는 reject한다. `direct_input_changes`와 derived delta는 before/after를 같은 field identity 및 scope에서 비교한다. scope가 달라지면 numeric delta를 만들지 않고 uncertainty/reference만 반환한다. Label/label basis는 schema에 넣지 않는다. 값이 필요한 경우 comparison result는 별도 trusted producer가 전달하며 expected label을 설명에서 숨기거나 다시 산출한다.

기존 Reason Code set을 우선 재사용한다: `DETECTOR_MATCH`, `NO_MATCH_IN_EVALUATED_SCOPE`, `DETECTOR_NOT_RUN`, `PARSER_REJECTED`, `REQUIRED_FIELD_MISSING`, `SUBJECT_MISMATCH`, `INPUT_SCOPE_MISMATCH`, `SOURCE_SCOPE_MISMATCH`, `PARSER_PROFILE_MISMATCH`, `POLICY_MISMATCH`, `EVIDENCE_BINDING_FAILED`, `LABEL_PROVENANCE_MISSING`, `AMBIGUOUS_OUTCOME`, `EXECUTION_INCOMPLETE`, `ANALYSIS_EXECUTION_FAILED`, `OUTCOME_*`, `INVALID_INTERNAL_CONTRACT`, `RESOURCE_LIMIT` 등 실제 `counterfactual_comparison.py` closed set에 이미 있는 값만 쓴다. 새 public reason code는 이 설계에서 추가하지 않는다.

## 12. Scenario-Based Validation Matrix

기준 인벤토리는 Development 16건 + Holdout 14건이다. 아래 “존재”는 manifest와 fixture 수준에서 검토 가능한 후보가 있다는 뜻이며 ER-1D 설명 검증을 이미 했다는 뜻이 아니다. Replay/Packet의 별도 assertions 없이는 설명 상태를 `NOT_TESTED`로 남긴다.

| 검증 항목 | 현재 사례 및 관찰 근거 | 필요한 상태/허용 설명 | 남길 불확실성·안전하지 않은 주장 | 구현 시험 조건 |
|---|---|---|---|---|
| 실패 1회 감소 | `bf_app_remove_failure`, `er1c_spray_app_remove_boundary` | VERIFIED facts와 각 정책 scope에서 count/predicate delta | “행 제거가 유일 원인” 금지 | direct remove와 모든 파생 facts를 양쪽 재계산 |
| 실패 1회 증가 | `bf_app_add_failure`, `spray_app_add_failure`, `er1c_spray_ssh_fourth_failure_at60` | count 변화와 Brute window / Spray whole-span predicate 분리 | 공격 강도/성공 주장 금지 | baseline/variant parser bytes 동일성, policy-specific scope 검증 |
| 계정 수 변경 | `bf_app_change_account`, `spray_app_change_account`, `er1c_bf_ssh_two_qualifying_accounts`, `er1c_spray_app_third_account_added` | known-account count와 Brute same-account scope를 각각 계산 | 사용자 실재/동일 주체 의도 불명 | source Parser에서 account group relationship 검증 |
| Source IP 변경 | `bf_app_change_ip`, `spray_app_change_ip`, `er1c_bf_app_subject_membership_change` | subject scope 변경, 필요 시 INCOMPARABLE | result key 부재를 LOST로 표시 금지 | 이전/새 그룹 membership을 독립 추적 |
| 정확히 60초 | `bf_app_exact60_reorder`, `bf_ssh_exact60_reorder`, `spray_ssh_exact60_reorder`, `er1c_bf_app_61_to_60`, `er1c_spray_app_exact60_permutation` | 코드의 inclusive `<=60` predicate 만족 여부 | 원시 clock 정확성 미보증 | UTC normalized span 정확히 60 확인 |
| 60초 초과 | `bf_app_late_timestamp`, `er1c_bf_ssh_61_second_crossing`, `er1c_spray_ssh_span_61` | scope별 실제 span과 predicate 미충족 | 단일 mutation 인과 단정 금지 | 60초 초과 값을 각 correct scope에서 검증 |
| Brute 선택 Window | `bf_app_window_with_late_ip_noise` (ER-1C), `er1c_bf_app_window_with_late_ip_noise`, `er1c_bf_ssh_two_qualifying_accounts` | owner-bound selected window count/span 및 Evidence membership | 전체 IP features와 window를 혼용 금지 | context private 유지, 공개 safe projection과 owner/evidence 결속 확인 |
| Spray Whole-span | `spray_app_late_timestamp`, `er1c_spray_ssh_span_61`, `er1c_spray_app_exact60_permutation` | 같은 IP의 모든 failure min/max span | sliding sub-window 설명 금지 | 전체 실패 scope가 Production feature/Evidence와 일치 |
| 입력 행 순서 | `bf_app_exact60_reorder`, `bf_ssh_exact60_reorder`, `spray_ssh_exact60_reorder`, `er1c_spray_app_absent_permutation` | 입력 순서 delta와 timestamp-order facts 분리 | 순서가 시간 변경을 뜻한다고 하지 않음 | bytes order changed, parsed event multiset/times invariant |
| Parser PARTIAL | `bf_app_partial_account`, `spray_app_partial_account`, `er1c_bf_app_partial_missing_user`, `er1c_spray_app_partial_account` | PARTIAL, 누락 field/count, 제한된 scope claim | 전체 입력 NOT_DETECTED 금지 | partial input에 대해 partial-only claim 및 comparison 보류 |
| Parser REJECTED | `spray_ssh_rejected_timestamp`, `er1c_bf_ssh_rejected_timestamp` | Detection NOT_EVALUATED, Comparison INCOMPARABLE | False Negative 금지 | no usable normalized event; reason `PARSER_REJECTED` |
| Evidence Binding Failure | Corpus에 자연 발생 사례 없음 | UNDETERMINED 및 claim 보류 | detector output을 verified evidence라 단정 금지 | 분리된 failure-injection test, 고정 reason, no raw exception |
| Label Provenance Missing | Corpus에 자연 발생 사례 없음 | Comparison UNDETERMINED; 설명은 input/policy facts와 별도 | Label로 설명 생성 금지 | replay observation provenance false를 주입하고 fail-closed 확인 |
| Detector Execution Failure | Corpus에 자연 발생 사례 없음 | EXECUTION_FAILED, 보통 UNDETERMINED | NOT_DETECTED/안전으로 표현 금지 | isolated exception injection; 정상 replay 결과와 별도 test group |
| Scope incomparable | `er1c_bf_app_subject_membership_change`; source IP mutation cases | INCOMPARABLE + subject/scope reason | LOST/GAINED 금지 | target subject/source scope mismatch로 comparator 테스트 |

나머지 inventory도 label-blindness 및 change coverage의 regression matrix에 포함한다. Development: `bf_app_exact60_reorder`, `bf_app_remove_failure`, `bf_app_add_failure`, `bf_app_late_timestamp`, `bf_app_change_account`, `bf_app_change_ip`, `bf_app_partial_account`, `bf_ssh_exact60_reorder`, `spray_ssh_exact60_reorder`, `spray_app_remove_failure`, `spray_app_add_failure`, `spray_app_late_timestamp`, `spray_app_change_account`, `spray_app_change_ip`, `spray_app_partial_account`, `spray_ssh_rejected_timestamp`. Holdout: `er1c_bf_app_window_with_late_ip_noise`, `er1c_bf_ssh_61_second_crossing`, `er1c_bf_app_61_to_60`, `er1c_bf_ssh_two_qualifying_accounts`, `er1c_bf_app_partial_missing_user`, `er1c_bf_ssh_rejected_timestamp`, `er1c_bf_app_subject_membership_change`, `er1c_spray_app_exact60_permutation`, `er1c_spray_ssh_span_61`, `er1c_spray_app_third_account_added`, `er1c_spray_ssh_fourth_failure_at60`, `er1c_spray_app_absent_permutation`, `er1c_spray_app_partial_account`, `er1c_spray_app_remove_boundary`.

Natural corpus does **not** supply evidence binding failure, missing label provenance, or detector execution failure. Those are future injected unit-contract tests, not corpus coverage. Existing Corpus has parser incomplete and subject-scope cases. No current fixture demonstrates a verified Brute selected-window count changing exactly 5→4 while preserving same subject/parser completeness; that precise explanatory example requires a separately reviewed new synthetic case after ER-1D gate, if needed.

## 13. Privacy and Security Constraints

- 합성 고정 Corpus만 사용한다. 실제 user logs, account, IP, secrets, hostnames는 입력·출력에 포함하지 않는다.
- 공개 DTO에는 raw event/log, account/IP, raw timestamp, temporary path, `AnalysisRunOwner`, `BruteWindowContext`, private event membership, exception repr, expected label basis를 금지한다.
- 관계가 필요한 진단 참조는 packet 계약처럼 scenario-local opaque group/ref만 쓴다. 원본 식별자와 되돌릴 수 있는 alias map은 보관하지 않는다.
- 외부 API, LLM, telemetry, arbitrary path, 사용자의 임의 로그 처리 기능을 추가하지 않는다.
- UTF-8 strict, closed schema, duplicate-key·non-finite 거부, allowlist enum, 크기 상한, canonical ordering, provenance binding, output canary test를 요구한다.
- failed validation은 해당 claim/report를 거부하거나 상태를 보류한다. 그럴듯한 fallback 설명을 만들지 않는다.
- `Evidence` 모델의 구조화 값은 해당 source의 관측/검출 근거다. 그 이름만으로 독립 Label provenance, 원본 진실성 또는 custody가 증명되는 것은 아니다.

## 14. Independent Human Review Gate

현재 상태를 변경하지 않는다.

- 대상: ER-1A Development 16 + ER-1C Holdout 14 = 30 scenarios
- Packet digest: `12988ec065c66901eb4036454fb24e52ef52c2bc435e65ea73b42d9846957c92`
- Human Review: `INDEPENDENT_HUMAN_REVIEW_PENDING`
- Manual Approval: `REQUIRED`
- ER-1D Implementation: `HOLD`

ER-1C-R/H의 별도 reviewer 검토와 실제 제출/누락·이견 처리, digest 확인, 독립성 근거 및 수동 승인 없이는 구현을 시작하지 않는다. Packet을 준비했거나 자동 계약 검증에 성공한 사실은 사람 검토가 아니다. 여기서 문서를 작성한 Codex는 reviewer가 아니다. 기존 corpus, label, replay 결과는 변경하지 않는다.

## 15. ER-1D Implementation Readiness

다음 구현을 별도 승인 후에만 시작한다.

1. 승인된 human review 및 immutable corpus/packet provenance gate 확인.
2. ER-1D-P의 schema·claim catalog를 closed DTO/test로 동결.
3. 기존 replay가 가진 facts의 provenance/scope를 사용하고, 부족한 Brute selected-window safe aggregate를 private context 밖으로 유출하지 않는 trusted projection으로 확보.
4. 입력 bytes, Parser facts, production policy predicate, owner-bound detector observation을 분리 생성하는 deterministic explanation builder.
5. 30건 matrix에 없는 failure-binding/provenance/exception 상태를 주입 테스트로 검증하고 natural corpus와 injection 결과를 별도 집계.
6. Canonical output, privacy canary, no network/LLM, deterministic repeat, error redaction 및 전체 회귀.
7. 설명 문구 수용성·오해 검토를 독립 사람에게 별도로 받기 전까지 UI/Production 경로에 연결하지 않음.

검증 실패, unsupported scope, multi-feature attribution의 유일 원인화, private context 노출, label leakage 또는 human approval 부재는 구현 HOLD 조건이다.

## 16. Limitations

### Research Basis

자료는 2026-11-04 확인했다.

- NIST SP 800-86, [Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final), 최종 2006년 8월. NIST의 수집→조사→분석→보고 흐름과 자료 무결성을 기록하는 원칙은 네 계층을 분리하고 근거 참조·제한을 report에 남기도록 하는 데 사용했다. NIST 자료는 본 프로젝트 임계값, parser 정확도 또는 이 synthetic replay의 forensic chain of custody를 인증하지 않는다.
- MITRE ATT&CK, [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/), [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/), [DET0551](https://attack.mitre.org/detectionstrategies/DET0551/), [DET0487](https://attack.mitre.org/detectionstrategies/DET0487/). ATT&CK의 행동 설명과 탐지 전략은 서로 다른 로그 source·계정/IP aggregation·시간 scope가 있을 수 있음을 확인하는 taxonomy context다. 저장소의 application/제한 OpenSSH parser가 제공하는 실패 event/user/IP/time으로 설명 가능한 범위만 사용한다. ATT&CK technique/analytic을 프로젝트 정책이나 탐지 proof로 복사하지 않으며 5/60 또는 4/3/60의 공식성 근거로 쓰지 않는다. ATT&CK의 탐지 설명에 성공 이벤트나 다중 플랫폼 로그가 포함된 경우에도 현재 프로젝트 입력은 그 사실을 제공하지 않을 수 있다.
- Repository evidence: `app/detector/brute_force.py`, `app/detector/password_spray.py`, `app/analyzer/pipeline.py`, `app/main.py`, `app/evaluation/counterfactual_{corpus,mutation,replay,comparison,holdout}.py`, `docs/evidence_research_er0.md`, ER-1A/B/C/R docs 및 고정 manifests. 실제로 사용 가능한 fields와 scope는 이 구현이 결정한다.

### Observable Evidence Mapping

`research의 기록·범위 원칙 → synthetic baseline/variant bytes 및 digest → fixed Application/SSH Parser → timezone-aware NormalizedEvent(event_type/src_ip/user/timestamp) → bounded per-scope facts → (Brute) owner-bound selected context와 Evidence membership / (Spray) whole-IP feature와 detector evidence → closed predicate status → actual Detection/Comparison observation → claim + uncertainty`.

ATT&CK의 행동 맥락은 필요한 telemetry가 무엇인지 생각하는 데만 보조한다. 입력 사실이 해당 telemetry를 포함하지 않으면 그 행동을 설명하지 않는다. 5회·60초, 4회·3계정·60초는 external research threshold가 아니라 repository policy다.

### Limitations

- 현재 Corpus 30건은 소규모 synthetic set이며 운영 일반화·통계적 정확도·공격 회피율을 뒷받침하지 않는다.
- parser의 성공은 원본 출처 진실성, 수집 완전성, 누락되지 않은 행, 정확한 host clock을 증명하지 않는다.
- 입력 재실행은 실제 환경의 인증 결과·계정 상태·잠금 정책·NAT/proxy/공유 egress를 모사하지 않는다.
- 여러 derived features가 동시에 달라질 수 있어 단일 인과 설명은 할 수 없다.
- Brute selected-window numeric delta를 안전하게 공개하는 현재 `SafeFacts` 필드는 없다. owner-bound aggregate projection은 후속 설계/구현 승인과 테스트가 필요하다.
- evidence binding failure, label provenance missing, detector exception은 현재 Corpus에서 자연 발생하지 않고 별도 injected tests가 필요하다.
- independent human review, reviewer independence 근거 및 manual approval이 미완료다.

### Test Results

- 변경 전 전체 기준선 `uv run pytest -q`: **3,752 passed, 2 warnings**.
- TDD RED: 구현 전 문서 계약 테스트 **3 failed** — 설계 문서 및 index link 부재로 실패 확인.
- ER-0/1A/1B/1C/1C-R 및 신규 문서 focused 회귀: **100 passed**.
- 변경 후 전체 `uv run pytest -q`: **3,755 passed, 2 warnings**. 두 경고는 기존 Starlette/httpx 및 AnyIO deprecation이다.
- `uv run python -m app.evaluation`: 성공; synthetic boundary 79/79, Brute Force 11 TP/0 FP/0 FN/58 TN, Spray 2 TP/0 FP/0 FN/67 TN, Parser 195/200, risk/case 각 70/70, Linux process synthetic classification 21/21. 이는 별도 기존 평가이며 ER 설명 성능이나 실운영 정확도는 아니다.
- `uv lock --check`, `git diff --check` 통과. Python/Production 코드·Corpus·dependency/lockfile·workflow 변경 없음.

## 17. Final Decision

`ER_1D_P_EXPLANATION_DESIGN_LOCAL_CONDITIONAL_GO`

이는 네 계층 근거 모델, bounded closed schema, 비교 불가·불확실성, 30건 corpus matrix 및 향후 검증 기준을 문서로 고정했다는 의미에 한정한다. 구현 또는 운영 설명 승인으로 해석하지 않는다.

- `INDEPENDENT_HUMAN_REVIEW_PENDING`
- `MANUAL_APPROVAL_REQUIRED`
- `ER_1D_IMPLEMENTATION_HOLD`
- 실제 사용자 자료: `NO_GO`
- 조직 운영: `NO_GO`
- 자동 대응: `NO_GO`
