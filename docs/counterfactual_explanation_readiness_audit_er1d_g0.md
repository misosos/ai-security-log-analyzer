# ER-1D-G0 — 탐지 설명 구현 준비도 감사

## 1. Start Gate

- 저장소: `misosos/ai-security-log-analyzer`
- 기준 SHA: `b04f93b2429a5a951f73d6d472b7a07079364d5f`
- Exact CI: `42203712571`, `push / completed / success`, head SHA 일치
- 필수 Locked Python 3.12 전체 회귀, Linux 검사, Restricted Report, Chromium/axe, tracked-file 검사: 성공
- Artifact: 0개
- 시작 local HEAD/main/origin/main/GitHub main: 동일 SHA; working tree clean; ahead/behind `0/0`
- `v0.4.0` tag 유지, Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`
- 로컬 기준선 `uv run pytest -q`: `3881 passed, 2 warnings`
- `AGENTS.md`, `security-analysis`, `security-testing` 지침 확인

시작 판정: `ER_1D_G0_START_GATE_GO`. 이번 감사는 문서와 코드의 현행 근거를 비교하며 ER-1D 실행 코드나 Production 분석 동작을 추가하지 않는다.

## 2. 기존 ER-1D-P 계약

ER-1D-P는 같은 고정 합성 시나리오의 Baseline/Variant에 대해 다음 사실을 분리해 표현하도록 설계했다.

1. 입력 bytes에 실제 적용된 Direct Input Mutation
2. 동일 Parser/Production 경로에서 검증된 Observed Feature Delta
3. Brute selected-window 또는 Spray whole-span에 맞춘 Production Policy Predicate
4. 실제 Production Replay의 Detector Observation과 Comparison 상태

그 설계는 설명을 제한된 사실과 정책 조건의 관계로 한정한다. 입력 변경이 결과 변화의 유일 원인이라는 주장, 공격 의도·침해·회피 성공, `NOT_DETECTED`의 안전 의미를 금지한다. 구현 후에도 `INCOMPARABLE`, `UNDETERMINED`, `PARTIAL`, `REJECTED`, `EXECUTION_FAILED`를 보존하고 Explanation이 Detector 결과를 덮어쓰지 않도록 요구한다.

G0 감사 결론은 이 구조 중 일부 기반만 존재하며, 네 계층을 묶어 안전한 Explanation DTO와 Claim을 만드는 기능은 아직 설계에 머문다는 것이다.

## 3. 4계층 Evidence Matrix

분류 기준:

- `IMPLEMENTED_AND_VERIFIED`: 구현 경로와 해당 범위의 회귀 근거를 코드·테스트에서 확인
- `IMPLEMENTED_NOT_VERIFIED`: 관련 코드가 있으나 이 설명 사용의 전제나 투영 계약을 검증하는 테스트가 없음
- `DESIGN_ONLY`: ER-1D-P에 요구/구조가 있으나 실행 가능한 Explanation 생산자가 없음
- `MISSING_EVIDENCE`: 필요한 값이나 provenance가 현재 결과 계약에 없음
- `BLOCKED_BY_HUMAN_REVIEW`: 독립 검토·수동 승인 없이는 다음 개발 단계가 열리지 않음

| 계층 / 근거 | 상태 | 현재 확인한 근거 | 준비도와 경계 |
|---|---|---|---|
| A. 고정 Corpus의 mutation 종류와 scenario 연결 | `IMPLEMENTED_AND_VERIFIED` | `counterfactual_corpus.py`는 고정 manifest의 scenario ID, detector, source, fixture 및 mutation 계약을 검증한다. `counterfactual_mutation.py::apply_mutation()`은 허용된 7종 mutation을 입력 bytes에 적용한다. ER-1A 검증은 Parser 입력 단계에서 baseline/variant facts를 확인한다. | `mutation_type`과 scenario는 기존 생산 경로에서 연결된다. 원문 로그를 출력하지 않고 유형과 고정 ID를 설명 재료로 사용할 수 있다. |
| A. 실제 변경 범위의 안전한 공개 참조 | `MISSING_EVIDENCE` | `ReplayScenarioResult`는 mutation 자체나 before/after byte digest·변경 row reference를 보유하지 않는다. ER-2A report projection에는 mutation type이 있지만 바이트 차이의 안전한 target reference는 없다. | mutation metadata만으로 특정 row의 직접 변경 범위를 주장할 수 없다. 원문 row·line offset을 노출하지 않는 검증된 scenario-local reference와 baseline/variant byte provenance가 필요하다. |
| B. SafeFacts에 이미 있는 parser facts | `IMPLEMENTED_AND_VERIFIED` | `SafeFacts`는 `event_count`, `login_failed_count`, `known_account_count`, `source_ip_count`, `target_failure_count`, `target_known_account_count`, `target_failure_span_seconds`를 제한된 수치로 보유한다. 이는 `PreparedScenario`의 고정 입력 Parser facts에서 생성되고 Replay 결과로 직렬화된다. | 해당 scope와 provenance를 그대로 표시하는 제한 요약은 만들 수 있다. `target_*`는 Target IP 범위이며 Brute 선택 계정 Window 수치로 해석할 수 없다. |
| B. Baseline/Variant의 안전한 특징 차이와 provenance 검증 | `DESIGN_ONLY` | ER-1D-P는 `feature_id`, `scope_id`, 단위·provenance를 가진 delta 계약을 제안한다. 현재 Replay는 SafeFacts 양쪽을 제공하지만 `ObservedFeatureDelta` 계산·scope 동일성 확인·누락 시 null 처리 API가 없다. | feature delta 계산과 설명용 allowlist projection을 별도로 구현·검증해야 한다. 여러 수치가 함께 변해도 하나를 원인으로 선정할 근거는 없다. |
| B. Brute selected-window count/span | `MISSING_EVIDENCE` | `BruteWindowContext`는 private `target_account`, UTC start/end, count, member events와 `_run_owner`를 가진다. Production Evidence는 context와 membership에 대조되지만 `SafeFacts`에는 selected-window 수치가 없다. `ReplayScenarioResult`는 context/owner를 내보내지 않는다. | 5→4 경계 시나리오의 parser-level 사실은 존재하지만, Explanation DTO에 안전하게 투영할 owner-bound Production selected-window aggregate는 없다. 현재 가장 구체적인 구현 차단 근거다. |
| B. Spray whole-span facts | `IMPLEMENTED_NOT_VERIFIED` | `summarize_ip_failures()`는 같은 IP의 모든 실패를 세고 알려진 account cardinality와 전체 min/max span을 만든다. `detect_password_spray()`는 해당 feature의 count `>=4`, account count `>=3`, `within_window`를 사용한다. Replay는 탐지 시 Evidence 세 값과 feature 및 time range가 일치하는지 `_verify_spray_evidence()`로 확인한다. | Production scope는 whole-IP span이다. SafeFacts의 target count/span은 parser facts이며 Production feature와 각각 다시 일치시키는 Explanation용 validator는 없다. Safe delta로 사용하기 전 비교 바인딩 테스트가 필요하다. |
| C. Production Brute predicate | `IMPLEMENTED_AND_VERIFIED` | `select_brute_window_contexts()`는 동일 IP·known account별 UTC 정렬 후보를 살펴 선택된 qualifying window를 고른다. 기준은 실패 5회 이상, 60초 이하이며 모호한 동률/해석 오류는 선택하지 않는다. `brute_evidence_matches_context()`는 결과 근거와 private context를 재검증한다. | 현재 Production 판정은 실행 가능하고 Replay가 실제 결과를 검증한다. Predicate별 Explanation 상태·관측값·고정 policy version으로 내보내는 projection은 없다. 5/60은 프로젝트 heuristic이며 외부 표준 임계값이 아니다. |
| C. Production Spray predicate | `IMPLEMENTED_AND_VERIFIED` | `summarize_ip_failures()`와 `detect_password_spray()`의 whole-span 조건 및 Replay Evidence 대조가 구현되어 있다. | 실패 수/계정 수/span의 scope를 유지한 실제 Detector 결과는 검증된다. 별도 Predicate DTO/상태는 아직 없다. 4/3/60도 프로젝트 heuristic이다. |
| C. Baseline/Variant predicate 평가의 독립 설명 출력 | `DESIGN_ONLY` | ER-1A의 `_independent_pattern()` 및 ER-1C 입력 oracle은 기대 패턴을 Detector와 분리해 계산하고 audit한다. 그러나 이는 scenario label 검증 경로이며 Replay의 Production feature 결과와 연결된 정책별 predicate DTO가 아니다. | 기대 Label이나 label validation을 Claim으로 재사용해서는 안 된다. 같은 replay 실행에 결속된 재계산 evaluator가 필요하다. 평가용 prototype과 현 Production 정책을 혼합하지 않아야 한다. |
| D. 실제 Production Replay 상태 | `IMPLEMENTED_AND_VERIFIED` | `run_scenario()`는 검증한 고정 bytes를 각기 새 temporary input으로 `analyze_with_source_role_snapshot()`에 전달한다. Replay DTO에 Parser/Detection/Comparison state와 기존 reason codes가 들어간다. | 실제 탐지 상태를 기존 결과 그대로 설명 근거로 읽을 수 있다. 새로운 Explanation이 탐지를 생성하거나 수정해서는 안 된다. |
| D. Owner와 Evidence membership의 내부 검증 | `IMPLEMENTED_AND_VERIFIED` | 각 Production 실행에서 새 `AnalysisRunOwner`가 만들어지고 analysis에 결속된다. Brute는 context owner와 Evidence membership을 확인한다. Spray는 detected Evidence의 count/account/span을 feature에 대조한다. Baseline/Variant owner 동일성은 거부한다. | 현재 Replay 내부 실행 중 결속은 확인된다. `AnalysisRunOwner` 객체는 private이며 결과 DTO에서 제외되는 것이 올바른 privacy 경계다. |
| D. 공개 Replay 이후의 재검증 가능한 owner provenance | `MISSING_EVIDENCE` | `ReplayScenarioResult`에는 run ID/owner handle이 없다. `SafeFacts`는 parser prevalidation facts이며 owner-bound context 자체가 아니다. | 이 상태는 의도된 공개 경계일 수 있으나, 이후 설명 builder도 같은 검증 호출 내에서 결과와 safe aggregate를 함께 만들어야 한다. 분리된 임의 DTO를 나중에 합치는 형태는 신뢰되지 않는다. |
| D. Parser/Detection/Comparison 예외 상태 보존 | `IMPLEMENTED_AND_VERIFIED` | `counterfactual_comparison.py`는 상태 enum과 scope/provenance 검사를 수행한다. REJECTED는 NOT_EVALUATED/INCOMPARABLE, incomplete binding은 UNDETERMINED, execution failure는 EXECUTION_FAILED로 유지한다. ER-2A-R1은 outcome/reason 모순을 막는다. | 상태와 reason code를 그대로 보존 가능하다. UI/Explanation 해석이나 수치 predicate로 이를 음성 탐지로 바꾸면 안 된다. |
| 전체 네 계층을 잇는 검증된 Claim/Uncertainty 출력 | `DESIGN_ONLY` | ER-1D-P에 closed schema, 허용/금지 claim, fail-closed 규칙은 문서화되어 있다. 실행 가능한 ER-1D builder는 없다. | 현재 증거만으로 “설명 기능 구현 준비 완료”라고 볼 수 없다. owner-bound Brute aggregate와 정책 평가·입력 변형 참조가 선행되어야 한다. |

## 4. 현재 코드 근거와 실제 데이터 경로

현재 검증 흐름은 고정 Corpus manifest와 fixture bytes → 입력 mutation 및 Parser fact oracle → 각 bytes의 별도 Production Replay → owner/context 및 detector Evidence 내부 검증 → `compare_runs()` → 제한된 Replay/ER-2A/ER-2C 결과다. ER-2C Snapshot은 사람이 볼 수 있는 상태와 Reason Code를 표현하지만 Feature Delta나 Policy Predicate를 추가하지 않는다.

`run_corpus()`/`run_holdout()` 결과가 실제 Production 관측을 제공하더라도, `ReplayScenarioResult`의 `baseline_facts`와 `variant_facts`는 prevalidation Parser facts다. 이들은 raw log가 아니지만 Detection Evidence나 private context와 같은 종류의 객체가 아니다. 따라서 이 값이 production aggregate와 동일하다고 전제하려면 별도의 scope·membership 일치 확인이 필요하다.

### Scope를 혼동하지 않을 정책 경계

| 탐지기 | Production 집계 범위 | 현 조건 | 설명에서 구별할 점 |
|---|---|---|---|
| Brute Force | 같은 source IP와 known account에서 선택한 sliding window | 5회 이상, 선택 span 60초 이하; 선택 동률이 모호하면 미선택 | 선택 Window count/span은 전체 IP SafeFacts가 아니다. `target_failure_count`나 `target_failure_span_seconds`를 selected-window 근거로 쓸 수 없다. |
| Password Spraying-like | 같은 IP의 전체 실패 집합 | 4회 이상, 알려진 계정 3개 이상, 전체 min/max span 60초 이하 | Production은 whole-span이다. Brute의 선택 창이나 ER-0/ER-1C 연구용 prototype window로 설명하지 않는다. |

두 정책의 숫자는 저장소의 현재 코드에 있는 평가 휴리스틱이며 NIST/MITRE가 정한 보편 기준이 아니다. 60초 경계는 코드상 inclusive다. Parser timestamp는 정규화된 입력 값이지 원천 시스템 시계 정확성의 증거가 아니다.

## 5. Implementation Blockers — Missing Evidence와 구현 전제조건

| Gap | 현재 코드 근거 | 빠진 증거와 구현 위험 | 필요한 테스트 | 선행 Gate / 권장 단계 |
|---|---|---|---|---|
| Brute selected-window safe aggregate | Private context는 owner·subject·account·member events·UTC span·count를 검증하고 Replay에서 Evidence membership을 대조한다. 공개 SafeFacts는 이 선택 window를 표현하지 않는다. | safe aggregate를 owner와 membership 검사보다 먼저 만들면 다른 run의 count/time을 설명에 붙이거나 계정/시각/이벤트를 유출할 수 있다. | 같은 owner/context/evidence 성공·교차 owner 실패·membership 변경 실패·raw account/IP/time 미직렬화·불일치 시 전체 Claim 보류. | 독립 사람 검토 및 수동 승인 후 ER-1D 설계 이행 하위 단계에서 내부 검증 API 설계. |
| Run Owner 결과 결속 | owner는 Production 결과 mapping 및 Brute context를 runtime에 보호하지만 Replay DTO로 나오지 않는다. | 설명 빌더가 별도 전달된 facts, detection, context를 단순 조합하면 객체 재포장/결과 교체를 통해 잘못된 설명이 가능하다. | baseline/variant 별도 owner, 같은 owner 재사용 거부, 결과 mapping mutation 및 cross-run context 주입 거부. | 동일 trusted replay 실행에서 결과 관측과 bounded projection을 함께 생산하도록 승인된 내부 API 필요. |
| Evidence membership의 설명용 증명 | Brute와 Spray의 검출 Evidence는 해당 Production 결과와 내부적으로 비교된다. | 현재 성공한 검증 사실이 추후 설명 consumer에 전달되지 않는다. Evidence 객체 자체를 공개하면 식별 timestamp 등 개인정보 범위가 넓어진다. | 내부 validator 결과만 DTO에 허용, 원 Evidence/owner/context는 schema reject, 실패 코드만 안전 출력. | ER-1D builder 승인 후 owner-bound verifier와 함께 구현. |
| Predicate별 계산 provenance 및 completeness | Replay는 ParserState, 일부 `SafeFacts`, detection state를 보유하며 PARTIAL에 fixed reason을 추가한다. | PARTIAL에서 어떤 전체 범위 조건이 미평가인지와 null/0 차이를 predicate별로 표현하는 공개 구조가 없다. 이를 false로 처리하면 오해를 만든다. | VERIFIED/PARTIAL/REJECTED/NOT_EVALUATED 각 케이스에서 SATISFIED/NOT_SATISFIED/NOT_EVALUATED 경계, 누락 계정 및 잘못된 timestamp test. | closed predicate schema 확정 후 ER-1D builder 검증. |
| Direct mutation의 공개 가능한 target reference | manifest에 mutation type/target/parameters가 있고 bytes 변형을 수행한다. Public report는 mutation type만 projection한다. | target을 raw line 번호/문자열로 공개하면 원문 재식별·입력 노출 가능. 유형만으로 “어느 입력 사실이 바뀌었나”라는 전체 claim을 증명할 수 없다. | 같은 fixture→mutation bytes golden 검사, scenario-local opaque reference, Canary·원문 비노출, multi-feature delta 전체 계산. | privacy 검토가 포함된 closed direct-change schema 필요. |
| Multi-feature delta와 단일 원인 제한 | 하나의 row/account/IP/time mutation이 여러 집계를 동시에 바꿀 수 있다. 현재 result에는 delta와 원인 attribution이 없다. | 하나의 변화를 유일 원인으로 요약하면 검증되지 않은 인과 주장을 하게 된다. | 다중 delta 입력에서 각 관측 변화 병렬 출력, unsupported attribution에서 claim 없음, template의 bounded wording 검토. | deterministic multi-claim 규칙을 독립 검토에 제출. |
| Unsupported scope와 정책 식별 | 현재 평가 corpus/parser/detector 조합은 고정 allowlist이며 Comparison은 detector/policy/source/profile/scope/subject mismatch를 처리한다. | unknown/new policy를 현재 정책으로 가장하거나 다른 scope끼리 수치를 비교할 수 있다. | unknown policy/source, Detector mismatch, Subject mismatch에서 `NOT_EVALUATED` 또는 기존 INCOMPARABLE/UNDETERMINED와 fixed reason 보존. | 지원 scope를 closed allowlist로 유지하고 추가 scope는 별도 승인. |
| 독립 검토 및 승인 | ER-1C-R packet과 제출 비교 흐름은 준비되어 있으나 status는 PENDING으로 고정된다. | 사람 검토 없이 Claim 문구/label correctness가 안전하다고 가정할 수 없다. | 외부 제출 근거, packet/source digests, 30건 completeness, disagreement/missing 처리 및 수동 승인에 대한 별도 governance 확인. | 사람 검토와 manual approval이 먼저 완료되어야 구현 Gate 재평가 가능. |

## 6. Privacy Boundary

설명 결과에 필요한 것은 고정 scenario ID, 허용된 mutation/policy/detector/status code, 검증된 bounded aggregate와 provenance code뿐이다. 다음 값은 설명 DTO에 복사하지 않는다.

- Raw Log/Event 및 원문 mutation row
- 실제 또는 원문 IP, account, hostname
- 원본 timestamp와 source path
- `BruteWindowContext`, member event, `AnalysisRunOwner`
- 원문 `Evidence` 객체와 private event identity
- 원문 exception/stack, temporary/local path
- `PATTERN_*` Expected Label 및 label basis를 사실 claim으로 사용
- 사람 reviewer 신원·의견·서명

현재 Corpus IP/account는 합성 자료지만 이 경계를 느슨하게 해도 된다는 뜻은 아니다. Replay/ER-2A/ER-2C의 safe field allowlist를 그대로 Explanation DTO로 확장하지 않고, 새 필드마다 scope와 provenance를 검증해야 한다. 오류는 fixed reason code로만 표현하고, partial report를 반환하지 않는다.

## 7. Human Review Gate

ER-1C-R 문서는 16 development + 14 holdout의 label-blind review packet을 준비하고 digest를 `12988ec065c66901eb4036454fb24e52ef52c2bc435e65ea73b42d9846957c92`로 기록했다. packet 생성과 자동 제출 비교는 review 자체가 아니다. 문서는 공개된 expected label 때문에 기술적 blind를 보장할 수 없고, 독립성은 reviewer 자기선언만으로 기계 확인할 수 없다고 명시한다.

이번 저장소 자료에서 실제 독립 reviewer의 완료 제출, 30건 전체 누락/불일치 adjudication 기록, 외부 독립성 확인, manual approval을 증명하는 근거는 확인되지 않았다. 따라서 상태는 계속 다음과 같다.

- Human Review: `INDEPENDENT_HUMAN_REVIEW_PENDING`
- Manual Approval: `MANUAL_APPROVAL_REQUIRED`
- ER-1D Implementation: `ER_1D_IMPLEMENTATION_HOLD`

자동 생성 packet, CI 성공, Viewer의 ER-2F 수용 피드백은 독립 label 검토를 대체하지 않는다. ER-2F는 Desktop Safari UI에 대한 제한된 사용자 수용이며 탐지 조건의 검토가 아니다.

## 8. 차별화 가능성 평가

주장 “탐지 결과가 변했을 때 입력·파생 특징·정책 조건·실제 탐지 결과를 분리하여 검증 가능한 설명을 제공한다”는 **목표 계약으로는 구체적이고 시험 가능한 구조**다. 현재 증거는 그 중 일부를 뒷받침한다.

현재 검증 가능한 부분:

- 실제 synthetic input bytes의 고정 mutation 종류와 Parser-level 사실 재계산
- 현재 Production Parser/Detector를 거친 Baseline/Variant 관측
- Replay 당시 owner/context/evidence 내부 binding 검사
- scope/provenance 차이를 보존하는 Comparison과 fixed reasons
- Brute와 Spray의 Production scope 차이를 코드에서 재현

아직 증명되지 않은 부분:

- 안전한 direct-change reference와 설명용 feature delta
- Brute selected-window 집계의 외부 safe projection
- production predicate별 독립 claim/status와 replay 결과의 안전한 합성
- 30건에서 독립 사람이 label-blind 절차로 판단하고 의견을 adjudicate했다는 사실
- 사용자에게 제시된 설명이 독립 검토자에게 오해를 주지 않는다는 수용 증거

따라서 이 방식은 project 내부에서 검증 가능한 transparency contract가 될 가능성은 있으나, 이 감사는 기술적 독창성, 운영 탐지 정확도, 산업적 차별성 또는 공격 회피 성능을 입증하지 않는다.

## 9. 권장 최소 구현 순서

아래 단계는 권고 순서이며 이번 판정으로 승인되지 않는다.

1. ER-1C-R packet/manifest/fixture digest와 30건 제출 완결성, 독립성 근거, 불일치·누락 처리 및 수동 승인 기록을 별도 governance gate에서 확인한다.
2. 승인된 이후 ER-1D schema와 claim/reason vocabulary를 closed contract/test로 확정한다. Expected Label을 Explanation source로 사용하지 않는다.
3. 기존 Production replay 안에서 owner-bound Brute selected-window aggregate와 Spray whole-span feature consistency를 검증하는 내부 경계를 설계한다. 공개 DTO에는 안전한 count/span과 scope/provenance code만 projection한다.
4. Baseline/Variant direct mutation reference와 Parser/feature facts를 각각 생성하고 같은 field/scope/version인지 검증한다. 비교가 불가능하면 숫자 delta를 내지 않는다.
5. 현재 Production 정책을 별도 predicate evaluator로 동일 scope에서 계산해 `SATISFIED`, `NOT_SATISFIED`, `NOT_EVALUATED`를 만들되 실제 Detector Observation을 수정하지 않는다.
6. 이미 검증된 Detection/Comparison과 predicate 결과를 closed Claim catalog로 결합한다. multi-feature 변화는 병렬로 표현하고 유일 원인을 주장하지 않는다.
7. 자연 Corpus 30건과 별도 injected failure cases를 분리해 검증한다: evidence binding failure, label provenance missing, execution failure, unsupported scope, Parser completeness, private-context 교차 주입.
8. Privacy canary, deterministic serialization, fixed error, no network/LLM, full pytest와 Evaluation Runner를 통과시킨 뒤에도 실제 UI/Production 연결 전 별도 승인과 설명 문구 사람 수용 검토를 요구한다.

## 10. 승인 전 금지사항

- 이번 G0 문서 판정을 ER-1D 구현 승인으로 해석하지 않는다.
- Production Parser/Detector, policy threshold/window, Replay/Comparison, Corpus/Label 또는 Snapshot을 변경하지 않는다.
- ER-1C-R 사람 검토 상태를 자동으로 완료/승인으로 바꾸지 않는다.
- `PATTERN_ABSENT`, `NOT_DETECTED`, `LOST`를 안전·공격 회피 성공으로 표시하지 않는다.
- Brute selected-window 사실을 Spray whole-span 또는 Target-IP SafeFacts로 대체하지 않는다.
- private owner/context/evidence/raw values를 public DTO·API·UI로 직렬화하지 않는다.
- predicate/feature 자료가 없을 때 0, false, NOT_DETECTED로 채우지 않는다.
- LLM으로 설명 근거나 인과·의도·침해 결론을 생성하지 않는다.

## 11. Test Results

- 변경 전 전체 기준선: `uv run pytest -q` — `3881 passed, 2 warnings`.
- TDD RED: 신규 G0 문서 테스트 `3 failed` — audit 문서와 index link가 없어 실패.
- 문서 완성 후 focused 문서 계약 테스트: `3 passed`.
- ER-1D-P/ER-0 회귀와 G0 문서 계약 테스트: `9 passed`.
- 전체 회귀: `uv run pytest -q` — `3884 passed, 2 warnings`.
- Evaluation Runner: `uv run python -m app.evaluation` — 성공. Synthetic Boundary `79/79`; Risk `70/70`; Case `70/70`; Linux Process 합성 분류 `21/21` (하위 분류 `4/4`, `4/4`, `3/3`, `4/4`).
- 추가 정적 검사: `uv lock --check`, `uv run python -m compileall -q app tests`, `git diff --check` 모두 성공.
- 이번 단계는 문서/테스트만 변경한다. 자동 테스트는 문서 사실과 gate를 검사하며 사람 검토의 진위를 자동 증명하지 않는다.

## 12. 최종 판정

G0의 목적은 ER-1D-P를 다시 설계하거나 구현을 승인하는 것이 아니라, 현재 코드가 설명 근거를 어느 경계까지 제공하는지 감사하는 것이다. 네 계층의 실제 producer와 missing evidence, 사람 검토 선행 조건을 기록했다.

완료 판정: `ER_1D_G0_READINESS_AUDIT_LOCAL_CONDITIONAL_GO` — readiness audit 문서 및 회귀 계약 완료에만 적용한다.

- `INDEPENDENT_HUMAN_REVIEW_PENDING`
- `MANUAL_APPROVAL_REQUIRED`
- `ER_1D_IMPLEMENTATION_HOLD`
- `ER_2F_USER_ACCEPTANCE_PENDING`
- 실제 사용자 자료·조직 운영·자동 대응: `NO_GO`
