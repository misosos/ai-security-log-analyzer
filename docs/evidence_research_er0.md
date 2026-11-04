# ER-0 — Evidence Research Contract Design Gate

## 1. Executive Summary

**결정: `ER_0_EVIDENCE_CONTRACT_LOCAL_CONDITIONAL_GO`**. 이 단계는 기존 Brute Force와 Password Spraying-like 결과를 근거·관찰·판단·불확실성으로 분리해 검토하고, ER-1A 합성 반사실 실험의 구현 계약을 정한다. Production Parser, Detector, Correlation, Risk, API, DTO, 평가 corpus는 변경하지 않았다.

ER-1A의 결과는 “입력 변형에서 이 프로젝트의 특정 parser와 detector가 어떻게 반응했는가”에 한정한다. 이는 실제 공격자의 회피 성공, 침해, 계정 탈취, 또는 운영 정확도에 대한 증거가 아니다.

## 2. Start Gate

- 저장소/branch: `misosos/ai-security-log-analyzer` / `main`
- 기준 SHA 및 local HEAD, local main, origin/main, GitHub main: `adc6bdde1e08a30d53ab6aef93cc13b6c9fcc49f`; ahead/behind `0/0`; 시작 working tree clean
- GitHub Actions [Run 41791113403](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41791113403): 정확한 SHA의 `push`, `completed / success`
- Locked Python regression 및 전체 pytest, Linux TCP Syslog 기본/reliability/management, JSONL Linux acceptance, Restricted Report Linux smoke, Restricted Report benchmark, Chromium·axe, tracked-file 검사가 실제 실행되어 성공했다. Artifact 0개.
- `v0.4.0` tag와 GitHub Release는 모두 기존 target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`을 가리킨다.
- Phase 36.15B의 로컬 onedir feasibility 기록은 독립 근거로 유지한다. ER-0는 bundle, launcher, runtime, release를 변경하지 않는다.

위 CI는 변경 전 시작 gate다. 이 문서 변경 이후의 원격 CI 결과를 뜻하지 않는다.

## 3. Current Production Architecture

실제 batch 경로는 다음과 같다.

```text
source config → load_normalized_logs() → NormalizedEvent[]
  → detect_attacks_with_context()
      → group_logs_by_ip()
      → summarize_ip_failures()                 [IP 전체 실패 feature]
      → select_brute_window_contexts()          [Brute 전용 선택 창]
      → brute_force_detection_from_context()
      → detect_password_spray()                 [IP 전체 feature]
  → correlate_attacks()
  → assess_risk_with_metadata()
  → case/report/API projections
```

코드 근거:

- `app/main.py:analyze()`, `_analyze_normalized_logs_with_context()`는 Parser output을 받아 새 `AnalysisRunOwner`로 Detection → Correlation → Risk를 순차 수행한다. 공개 분석 반환값과 private context는 분리되어 있다.
- `app/analyzer/pipeline.py:load_normalized_logs()`는 `app/parser/registry.py`의 source별 Parser를 호출하고 UTC로 normalize한다. 지원 source는 application, ssh, access이며 Linux Audit은 별도 경로다. 실패 줄은 현재 loader에서 이벤트 목록에 포함되지 않으므로 입력 품질 평가와 detector 실행 결과는 별도 축이어야 한다.
- `detect_attacks_with_context()`는 IP별 전체 Features와 Brute 선택 context를 별도로 만들고, Spray에는 전체 IP Features와 해당 IP의 실패들을 넘긴다. `correlate_attacks()`는 Brute evidence/context/owner를 검증하며, Spray correlation은 별도 기존 consumer를 사용한다.
- `app/detector/brute_force.py:AnalysisRunOwner`, `BruteWindowContext`, `validate_brute_window_context()`, `select_brute_window_contexts()`는 현재 Brute context의 private run binding·event membership·시간·계정 조건을 검증한다. `repr`은 redacted이며 이 객체를 ER output 또는 공개 DTO에 노출하지 않는다.
- `app/models/schemas.py:NormalizedEvent`는 내부 raw event를 포함한다. `Evidence`는 `type`, scalar `value`, `source`, 선택적 timestamp/time_range를 가진 내부 dataclass다.
- `app/evaluation/detector_accuracy.py`는 corpus를 먼저 Parser disposition으로 분류하고, `PARSER_VERIFIED`일 때에만 실제 `app.main.analyze()`를 실행한다. `PARSER_PARTIAL`과 `PARSER_REJECTED`는 detector FN/FP가 아니라 parser contribution으로 분리한다.
- `app/evaluation/runner.py:evaluate()`는 기존 합성 evaluation 경로다. 평가 label을 입력으로 받아 생산 detector가 label을 생성하지 않는다.
- `docs/architecture.md`는 현재 비어 있다. ER-0에서는 이를 임의로 고쳐 현재 아키텍처 문서인 것처럼 만들지 않는다. 실무 계약은 코드와 다음 문서에서 대조했다: `docs/detector_accuracy_evaluation_36_9c.md`, `docs/brute_force_sliding_window_production_remediation_36_9f.md`, `docs/password_spray_consumer_integration_security_gate_36_10b_r4.md`, `docs/public_analysis_privacy.md`.

### 현재 detector 정책 — 코드 기준

| 규칙 | 현재 관측·계산 | 설계상 한계 |
|---|---|---|
| Brute Force | `select_brute_window_contexts()`가 같은 source IP와 알려진 동일 user의 `login_failed`를 정렬하고, 최소 5개·UTC-aware timestamp·경과시간 60초 이하의 선택 후보를 만든다. 모호한 동률 및 해당 주체의 timestamp 해석 오류는 fail-closed한다. Detection Evidence는 선택된 context와 재검증된다. | `summarize_ip_failures()`의 count/target/window 등 IP 전체 Feature와 Brute 선택 Evidence는 범위가 다르다. “Brute 전체 IP feature가 5회/60초 sliding window”라고 표현하면 틀린다. 중복 Event의 실세계 중복 여부를 알아내는 stable source event ID는 확인되지 않았다. |
| Password Spraying-like | `summarize_ip_failures()`의 동일 IP 전체 실패 집계에서 실패 4개 이상, 알려진 고유 user 3개 이상, 전체 실패의 min/max span 60초 이하이면 `app/detector/password_spray.py:detect_password_spray()`가 탐지한다. | Production은 sliding window가 아닌 whole-span 정책이다. password 값은 관찰하지 않으므로 동일 password 재사용·공격 의도는 증명하지 않는다. Window prototype은 평가 전용이며 Production 정책에 적용하지 않는다. Correlation anchor는 R4에서 `CORRELATION_ANCHOR_UNRESOLVED`로 남았다. |

`docs/detector_accuracy_evaluation_36_9c.md`의 당시 Brute whole-span 설명은 현재 Brute Production과 다르다. 현재 selector는 36.9F에서 도입한 계정별 선택 window이고, 그 문서의 Brute 평가 서술은 과거 시점 기록이다. 반면 Production Password Spraying-like는 현재도 전체 span이다. 36.10B-R4의 Window/consumer 제안은 `PROTOTYPE_ONLY` 또는 `DESIGN_PROPOSED`이며 현행 Production 조건이 아니다.

## 4. Existing Evidence Model

기존 `app.models.schemas.Evidence`는 Detector가 반환하는 구조화된 **탐지 설명 값**이다. 예를 들어 실패 수, 선택 시간 범위, detector source 이름을 보유한다. 이것은 자체적으로 원본 로그 출처의 무결성, parser가 입력 전부를 받아들였는지, event ID membership, chain of custody, 독립 검증 또는 악의성 라벨을 보증하는 provenance record가 아니다.

ER의 Evidence는 별도의 **연구용 근거 계약**이다. 최소한 특정 run의 Observation ID, source/parser profile 및 버전, 검증된 field allowlist, 적용 범위, parser disposition, Detection output binding, 독립 기대 label의 출처를 추적할 수 있어야 한다. 원본 행이나 raw event를 그 Evidence 객체에 복사하지 않는다. 생산 `Evidence`를 ER Evidence로 격상하거나 공개 DTO에 새 필드를 넣는 일은 별도 승인 없이는 금지한다. 내부 Brute context 및 `AnalysisRunOwner`도 공개하지 않는다.

## 5. Observation / Evidence / Claim / Uncertainty Contract

| 개념 | 의미·생성 주체 | 필수 근거 | 허용되는 판단 | 금지되는 해석 / 기존 연결 |
|---|---|---|---|---|
| **Observation** | Parser가 정규화한 event, detector 결과, 평가기가 관찰한 Parser disposition처럼 실행에서 직접 얻은 값. 생성 주체는 명시된 Loader/Parser/Detector/evaluator다. | 입력 run 식별, 고정 실행 설정, source profile/version, 관찰 단계와 범위. 직접 관찰과 파생 Feature를 구분한다. | “이 실행에서 이 지원 profile로 N개 실패 event가 정규화됨”, “해당 detector가 true/false를 반환함”. | Observation 하나를 사건의 원인·공격자·침해 사실로 넓히지 않는다. `NormalizedEvent.raw`는 내부 관측물이지 공개 표시 근거가 아니다. |
| **Evidence** | Observation의 출처·검증·귀속을 설명하는 연구용 연결 자료. ER-1 평가 harness가 생성하며 정규화된 참조와 안전한 scalar만 갖는다. | run/observation 참조, Parser disposition과 필드 검증, source·parser profile, 대상 detection proposition 및 scope. 참조가 없거나 서로 불일치하면 invalid. | 특정 제한된 Claim이 어떤 관찰에서 나왔는지 재검증 가능하게 연결한다. | 기존 `Evidence` scalar만으로 원문 membership·원천 무결성·credential sameness를 주장하지 않는다. Evidence는 로그 진실성 자체를 자동 보장하지 않는다. |
| **Claim** | 검증된 Evidence에서 허용된 범위로 도출한 명시적 판단. ER 연구 평가기가 생성하며 detector output과 독립적으로 명세한다. | 닫힌 proposition, 적용 detector/policy ID·버전, Evidence 참조, 판정 scope, 반례/limitation 및 label provenance. | “이 합성 입력의 verified event 집합이 이 프로젝트 Brute 규칙의 조건을 만족했다/못했다.” | “공격이 성공했다”, “실제 계정이 탈취됐다”, “원인/동일 행위자/동일 비밀번호” 금지. |
| **Uncertainty / Evidence Gap** | 관찰할 수 없거나 근거가 부족하거나 실행이 완결되지 않은 영역. 평가기가 고정 reason code로 표시한다. | 무엇이 누락·거부·불일치인지 나타내는 closed code와 관련 차원. 자유형 원문·예외는 금지. | 비교가 보류되었거나 해당 claim이 미확정임을 설명한다. | gap을 부재 사실·탐지 음성·안전 증거로 바꾸지 않는다. Parser 실패는 Detector false negative가 아니다. |

필수 경계:

- **Detection ≠ Confirmed Compromise**
- **Correlation ≠ Causation**
- **No Detection ≠ Safe**
- **Login Success ≠ Account Compromise**
- **Parser Failure ≠ Detector False Negative**
- **Counterfactual Change ≠ Real-world Evasion Success**

## 6. Parser / Detection / Comparison State Model

세 차원은 독립 closed enum으로 표현한다. ER-1A에서 unknown 값, boolean 뭉개기, 예외 문자열 기반 판정을 허용하지 않는다.

### Parser Dimension

| 상태 | 진입 조건 및 필수 근거 | 배타성·전이 | reason code / 금지 해석 |
|---|---|---|---|
| `VERIFIED` | 지원 source의 전체 입력 line disposition을 계산했고, 기대 event count/type/필수 fields/source subject가 fixture 계약과 일치한다. | 한 Parser run에서 `PARTIAL` 또는 `REJECTED`와 동시 불가. 최초 `NOT_EVALUATED`에서 판정하며, 완료 후 수정은 새 run. | 통상 reason 없음. “입력 로그가 사실이다” 또는 “분석이 정확/안전하다”가 아니다. |
| `PARTIAL` | 유효 이벤트가 일부 있으나 line/event 수, type, source subject, required field 중 하나 이상 불일치하거나 일부 line 거부/무시 근거가 있어 전체 범위를 검증할 수 없음. | `VERIFIED`와 동시 불가. Detector 실행은 가능할 수 있으나 그 입력 범위는 parsed subset으로 기록한다. | `EVENT_COUNT_MISMATCH`, `EVENT_TYPE_MISMATCH`, `SUBJECT_MISMATCH`, `REQUIRED_FIELD_MISSING`, `LINE_REJECTED`, `LINE_IGNORED`. “완전한 원 입력에 대한 음성” 금지. |
| `REJECTED` | 지원 profile이 입력을 해석하지 못해 실행 가능한 정규화 입력을 제공하지 않거나 고정된 Parser 거부가 발생함. | Detection은 반드시 `NOT_EVALUATED`; parser rejection 뒤 detector false로 바꾸지 않는다. 새 run 없이 상태 승격 금지. | `PARSER_REJECTED`, `UNSUPPORTED_SOURCE`, `INPUT_LIMIT_EXCEEDED`. “탐지되지 않음” 또는 “안전” 금지. |
| `NOT_EVALUATED` | Parser 미실행, 해당 source/profile 범위 밖, 사전 검증이 시작되지 않음. | 초기 상태. 실행을 시작하면 결과에 따라 terminal Parser status로 한 번만 확정한다. | `PARSER_NOT_RUN`, `SOURCE_OUT_OF_SCOPE`. 부재 증거가 아니다. |

`VERIFIED`는 해당 **fixture가 정의한 대상 행과 필드**의 Parser 적합성을 의미한다. real-world log completeness, 수집 무손실, source authenticity를 인증하지 않는다. Blank/ignored line은 별도 disposition count로 남겨야 하며 기대 입력 계약이 이를 정하지 않으면 VERIFIED로 추정하지 않는다.

### Detection Dimension

| 상태 | 진입 조건 및 필수 근거 | 배타성·전이 | reason code / 금지 해석 |
|---|---|---|---|
| `DETECTED` | Parser가 결과를 제공하고 해당 detector가 지정 scope에서 `is_detected is True`; detector ID/version, 입력 scope, 결과 binding이 있음. `PARTIAL` 입력이면 parsed subset에 한정됨을 함께 표시. | 같은 run/detector/scope에서 `NOT_DETECTED`와 동시 불가. 실행 중 `NOT_EVALUATED` 뒤 결과 확정. | 성공 사유는 fixed `DETECTOR_MATCH`. 침해·의도·공격 성공 확정 금지. |
| `NOT_DETECTED` | 대상 detector가 예외 없이 실제 실행되어 지정된 parsed event scope에서 false를 반환. Parser가 `REJECTED`이면 불가. | `DETECTED`와 상호 배타적. 실행 완료 결과만 terminal. | `NO_MATCH_IN_EVALUATED_SCOPE`. “없음/안전”을 전체 원자료나 실제 환경에 일반화 금지. |
| `NOT_EVALUATED` | 입력/parser 결과가 없거나 source/policy 범위 밖이라 실행하지 않음. Parser `REJECTED`의 필수 companion 상태. | 초기/미실행 상태. 분석 실패로부터 재해석해 false를 만들지 않는다. | `PARSER_REJECTED`, `SOURCE_OUT_OF_SCOPE`, `DETECTOR_NOT_RUN`. |
| `EXECUTION_FAILED` | Detector 실행을 시작했으나 제한된 처리 오류 때문에 결과를 완료하지 못함. 예외는 보존/출력하지 않고 category만 기록. | `DETECTED`·`NOT_DETECTED`와 동시 불가. 재시도는 별도 run. | `ANALYSIS_EXECUTION_FAILED`, `RESOURCE_LIMIT`, `INVALID_INTERNAL_CONTRACT`. 실행 실패를 `NOT_DETECTED`로 환산 금지. |

### Comparison Dimension

| 상태 | 진입 조건 | 비교 가능성·전이 | reason code / 금지 해석 |
|---|---|---|---|
| `PRESERVED` | 독립 baseline/variant 실행이 비교 가능하고 양쪽 동일 proposition이 `DETECTED`. | 양쪽 evidence binding, detector/policy/parser 설정 및 판정 scope가 같아야 한다. 비교 terminal. | `OUTCOME_PRESERVED`. 동일한 행·경로·증거가 보존됐다거나 공격이 계속 성공했다는 의미가 아니다. |
| `LOST` | 비교 가능한 baseline `DETECTED`, variant `NOT_DETECTED`. 변형 Parser 및 detector가 필요한 범위에서 검증·완료됨. | 원본/변형 실행 실패, input completeness 차이 등 결과의 의미를 바꾸는 불일치가 없어야 한다. | `OUTCOME_LOST`. 실제 회피 성공, 침해 방지 또는 보안 통제 효과가 아니다. |
| `GAINED` | 비교 가능한 baseline `NOT_DETECTED`, variant `DETECTED`. | `LOST`와 같은 비교 가능 조건. | `OUTCOME_GAINED`. 공격 발생/성공 증거가 아니다. |
| `UNCHANGED_ABSENT` | 양쪽 모두 완전 실행된 `NOT_DETECTED`; 독립 label과 scope가 비교 가능함. | 둘 다 음성 결과여야 하며 실패·미평가를 음성으로 대입하지 않는다. | `OUTCOME_ABSENT_BOTH`. 안전을 의미하지 않는다. |
| `INCOMPARABLE` | 의미 있는 직접 비교를 깨는 차이가 알려짐: parser profile/schema, detector/policy version, source scope, label proposition, normalized input scope의 불일치 또는 필요한 Parser 거부. | 비교를 시작하지 않거나 중간에서 불일치 확인 시 terminal. 값 억지 정규화/재매핑 금지. | `PARSER_PROFILE_MISMATCH`, `DETECTOR_VERSION_MISMATCH`, `POLICY_MISMATCH`, `SOURCE_SCOPE_MISMATCH`, `INPUT_SCOPE_MISMATCH`, `PARSER_REJECTED`. |
| `UNDETERMINED` | 실행은 비교 후보이나 evidence binding, 독립 label provenance 또는 disposition가 모호/불충분하여 관계를 정할 수 없음. | 알려진 비교 불가 사유는 `INCOMPARABLE`; 알려진 불일치 없이 근거 부족이면 `UNDETERMINED`. terminal이며 재해석 대신 새 run/label이 필요하다. | `EVIDENCE_BINDING_FAILED`, `LABEL_PROVENANCE_MISSING`, `AMBIGUOUS_OUTCOME`, `EXECUTION_INCOMPLETE`. “unchanged”나 성공/실패로 추측 금지. |

**Dimension 간 fail-closed 규칙:** `Parser=REJECTED`는 `Detection=NOT_EVALUATED`와 `Comparison=INCOMPARABLE`을 요구한다. `Detection=EXECUTION_FAILED`는 `Comparison=UNDETERMINED` 또는 비교 불가 사유가 명확할 때 `INCOMPARABLE`만 허용한다. `Parser=PARTIAL`인 두 run은 결손 범위와 disposition이 동등하다고 명시적으로 증명되지 않으면 `LOST/GAINED/PRESERVED` 판정을 금지한다. 상태 충돌·알 수 없는 enum·누락된 근거는 run 결과를 거부하고 고정 category만 반환한다.

각 run 결과는 immutable record로 취급한다. `NOT_EVALUATED → terminal` 이외의 자동 재작성은 없다. correction/retry는 새 run ID에서 수행한다. 비교 결과는 두 immutable run에 대한 별도 record다.

초기 closed reason code 집합은 다음과 같다(ER-1 구현 시 추가가 필요하면 schema version 승인 필요): `EVENT_COUNT_MISMATCH`, `EVENT_TYPE_MISMATCH`, `SUBJECT_MISMATCH`, `REQUIRED_FIELD_MISSING`, `LINE_REJECTED`, `LINE_IGNORED`, `PARSER_REJECTED`, `UNSUPPORTED_SOURCE`, `INPUT_LIMIT_EXCEEDED`, `PARSER_NOT_RUN`, `SOURCE_OUT_OF_SCOPE`, `DETECTOR_MATCH`, `NO_MATCH_IN_EVALUATED_SCOPE`, `DETECTOR_NOT_RUN`, `ANALYSIS_EXECUTION_FAILED`, `RESOURCE_LIMIT`, `INVALID_INTERNAL_CONTRACT`, `OUTCOME_PRESERVED`, `OUTCOME_LOST`, `OUTCOME_GAINED`, `OUTCOME_ABSENT_BOTH`, `PARSER_PROFILE_MISMATCH`, `DETECTOR_VERSION_MISMATCH`, `POLICY_MISMATCH`, `SOURCE_SCOPE_MISMATCH`, `INPUT_SCOPE_MISMATCH`, `EVIDENCE_BINDING_FAILED`, `LABEL_PROVENANCE_MISSING`, `AMBIGUOUS_OUTCOME`, `EXECUTION_INCOMPLETE`.

## 7. Brute Force and Password Spray Policy Boundary

ER-1A는 두 현재 Production detector를 **변경 없이 재실행**해 현재 동작을 조사한다. detector heuristic이나 36.10B evaluation-only Sliding/known-account policy를 candidate Production policy로 바꿔 넣지 않는다.

| 검토 항목 | Brute Force — 현 Production | Password Spraying-like — 현 Production |
|---|---|---|
| 집계 범위 | IP별 public Feature는 전체 실패 집합. Detection은 같은 IP·같은 알려진 계정의 선택 window context. | 같은 IP의 전체 `login_failed` 집합 및 전체 집합 시간 span. |
| 조건 | 선택 window에서 실패 5개 이상, known user 정확히 1개, UTC timestamp, span ≤60초. | 전체 IP 실패 4개 이상, known user 3개 이상, 전체 min/max span ≤60초. |
| 변형 해석 | 실패 하나 삭제/추가, timestamp 이동, 대상·IP 변경은 실제 합성 입력을 바꾸고 Parser부터 다시 실행한다. 선택 window membership과 IP-wide feature를 함께 다시 계산하고 각각 기록한다. | 동일 mutation이 전체 실패 수·대상 수·전체 span을 바꾸므로 세 조건을 함께 재계산한다. Sliding candidate를 Production expectation으로 사용하지 않는다. |
| 별도 경계 | private `BruteWindowContext`와 `AnalysisRunOwner`는 내부 run 검증용이며 ER/public output에 노출하지 않는다. | Window implementation 및 correlation anchor는 Production 미승인/미구현 상태를 그대로 둔다. |

기존 `Evidence.time_range`는 detector별 선택 scope가 다를 수 있다. ER 결과는 count/span을 한 의미로 합치지 말고 “전체 IP feature”와 “선택 Brute window”를 구별한다. `single_target_user=1`은 detector가 선택한 known user 수이며 실제 사람/공격자 identity가 아니다.

## 8. Counterfactual Input Transformation Contract

ER-1A MVP는 지원되는 **application authentication** 및 **SSH authentication** 입력의 합성 fixture에 한정한다. Access 로그는 인증 Brute/Spray 실험에서 제외한다. 현재 registry와 parser 계약에서 지원하지 않는 문법은 format damage 변형으로만 테스트하며, 성공적으로 인식될 것이라는 label을 주지 않는다. RFC 5424 OpenSSH는 제한된 profile이며 자동 RFC3164 추측을 추가하지 않는다.

모든 변형은 불변 synthetic source bytes의 새 복사본에 직접 적용한다. 각 baseline과 변형을 독립적으로 Loader → Parser → `app.main.analyze()`/동일 현재 production path로 실행한다. 기존 `NormalizedEvent`, Feature dictionary, Brute Context, Detection Evidence를 변형하거나 직접 수정하는 금지. 파생값은 전부 재계산한다.

| 변형 | 입력 변경 및 사전 조건 | Parser 기대 | 독립 기대 label 및 허용 의미 | 비교 불가 조건 |
|---|---|---|---|---|
| 인증 실패 행 1개 제거 | known synthetic failure row 하나만 source bytes에서 삭제. 원본이 가진 event identity/order는 유지하고 새 복사본 생성. | 남은 모든 지원 형식 행은 개별 profile에 따라 검증. | baseline와 달라진 실패 수, 계정 set, Brute membership, whole-span 등을 독립적으로 수계산. detector 결과와 무관하게 패턴 label을 사전 작성. | 변형 행 구분이 모호, baseline Parser 불완전, 제거가 여러 물리 행을 바꾸거나 라벨이 detector 결과를 보고 작성됨. |
| 실패 행 1개 추가 | 문법·필수 필드가 유효한 합성 `login_failed` 레코드 하나 추가. reserved IP 및 synthetic account 사용. | 추가 행도 기대 type/source/time/user/IP로 parse되는지 별도 assert. | 추가로 바뀌는 aggregate, unique target, min/max와 선택 window를 계산. 여러 조건이 연쇄 변경될 수 있어 “실패 수만이 원인”이라고 단정하지 않음. | 추가 line의 source profile 미지원, 필수 field 누락 또는 parser disposition 불일치. |
| 이벤트 시각 변경 | 하나의 합성 행 timestamp만 바꾸고 timezone 포함 의미를 고정. Brute 선택 window 및 Spray whole-span에 미치는 값 계산. | 지원 Parser가 해당 시각을 동일 timezone 의미로 normalize해야 함. | 이전/새 전체 span 및 Brute 후보 창을 계산하고 현재 policy의 outcome을 기대 label과 비교. 60초 경계는 inclusive인지 코드에서 검증한다. | 잘못된/ambiguous timestamp, 서로 다른 timezone/profile 또는 parser가 거부. |
| 대상 계정 변경 | 하나의 `user` 입력 필드를 합성 계정으로 수정. | Parser의 `user`와 `login_failed` 결과를 재검증. | Brute known target cardinality 및 Spray unique-target cardinality를 다시 세고, 한 변형이 두 detector 조건에 모두 영향 가능함을 기록. | `user` 추출이 없거나 값이 unknown/invalid하여 독립 대상 label을 지정할 수 없음. |
| Source IP 변경 | 한 행의 source IP 입력만 문서용 범위(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)의 synthetic IP로 변경. | Parser output subject가 기대 문서용 IP와 일치해야 함. | IP grouping 변화, 이전 그룹에서 제거/새 그룹에 추가되는 aggregate를 계산. 다른 IP의 기존 aggregate가 함께 영향을 받을 수 있어 전체 입력의 결과를 비교. | malformed IP, Parser가 source IP를 다르게 정규화하거나 row membership을 증명할 수 없음. |
| 입력 행 순서 변경 | bytes에서 기존 행의 순서만 순열 변경; timestamp와 모든 필드는 유지. | 같은 줄별 Parser disposition과 event set을 얻어야 함. | detector의 permutation invariance를 시험하고 독립 label은 규칙상 order-independent 여부로 사전 결정. 결과가 다르면 관측된 구현 특성이지 새 policy 승인이 아님. | parser/profile이 line order semantics를 갖거나 행이 stateful framing에 의존. |
| 이벤트 형식 손상 | 허용된 synthetic row의 header/형식 토큰을 손상하여 한 변형만 추가. | 해당 행 `REJECTED`/`PARTIAL` disposition과 다른 행 처리 결과를 별도 확인. | Parser 실패는 Detector negative/FN 아님. 손상 후 정규화 입력 subset에서 detector 실행했다면 그 subset 범위의 상태만 기록하고 whole-input comparison은 보통 incomparable. | 손상 위치가 의도한 문법 필드 외에도 입력을 여러 방식으로 변경하거나 expected parser disposition이 정의되지 않음. |

변형 ID는 closed enum이며, 임의 사용자 파일 경로나 로그 line 기반으로 생성하지 않는다. 한 번의 variant에는 한 가지 직접 입력 조작만 허용한다. 이 조작으로 여러 파생 Feature가 변하는 것은 별도 observable effect다. 통제된 fixture에서도 “direct change가 탐지 차이의 유일한 인과 원인”이라고 자동 주장하지 않는다.

## 9. Independent Labeling and Evaluation

- Label은 immutable synthetic fixture에서 evaluation runner 실행 전에 작성·검토한다. Label basis는 expected input facts, source/parser contract와 policy predicate를 기반으로 하며 detector output에서 자동 생성하지 않는다.
- 각 variant의 기대값에는 direct input mutation, 예상 parser disposition, 독립적으로 계산한 normalized event facts, 각 policy predicate, uncertainty/ambiguity, context label을 별도 필드로 둔다. Pattern label과 operational context는 계속 분리한다.
- 같은 detector 구현으로 라벨을 생성하고 같은 fixture에 맞춰 policy를 조정한 뒤 그 수치를 독립 정확도로 부르지 않는다. Corpus는 평가 후 holdout/independent review가 없으면 characterization에 한정한다.
- Parser 검증과 Detector 실행은 분리한다. Parser rejected/partial을 detector FP/FN이나 `NOT_DETECTED`로 채우지 않는다. `PARSER_PARTIAL`에서 true detection이 실제로 발생할 수 있으면 parsed subset claim으로 제한하고, negative comparison은 completeness evidence 없이는 undetermined/incomparable이다.
- Baseline과 variant는 매번 새 run owner/context를 사용한다. 같은 `NormalizedEvent` 객체나 private context를 재사용하지 않는다. 각 run의 input/config identity와 allowed hash는 합성 fixture에 한해 저장할 수 있지만 원문이나 원문 유래 사용자 정보를 출력하지 않는다.
- 반복 실행은 동일 fixture bytes·parser profile/version·detector policy/version·timezone/config에서 closed result가 결정적으로 같아야 한다. 바뀐 환경 버전은 같은 실행으로 뭉개지 않고 별도 run으로 기록한다.
- 비교 단위와 분모를 고정하고 `VERIFIED`, `PARTIAL`, `REJECTED`, unknown label, execution failure를 별도 집계한다. 제한된 corpus metric을 실환경 정확도 추정치로 일반화하지 않는다.

## 10. Privacy and Security Boundary

ER-1A 구현 요구사항:

1. 합성 입력만 허용한다. 계정명은 `synthetic-user-01` 형태의 가짜 label, source IP는 IANA 문서용 주소만 쓴다. 실제 password, token, credential, 사용자 계정은 어떤 fixture에도 쓰지 않는다.
2. 원문 로그 또는 일부, account, IP, hostname, path, command, timestamp, environment value를 console, exception, JSON/HTML/report/metric에 표시하지 않는다. 합성 privacy canary를 모든 출력 경계에서 검사한다.
3. 테스트 fixture만 root-confined allowlist에서 읽는다. 임의 파일/디렉터리 경로, symlink escape, network, subprocess arbitrary command, glob-all 입력은 금지한다. 크기/line/scenario 수를 bounded 한다.
4. Source/parser rejection, invalid expected label, detector exception은 서로 다른 fixed reason code로 구분한다. 예외 repr/traceback/input echo를 평가 output에 사용하지 않는다.
5. Baseline/variant 실행은 input, mutable event, Feature, owner/context를 공유하지 않는다. 실험은 원본 합성 fixture를 수정하지 않고 별도 byte copy에 mutation을 적용한다.
6. 원본, IP 전체 feature, 선택 Brute context, Detection Evidence, Owner binding 및 result mutation을 공개 DTO로 serialize하지 않는다. `AnalysisRunOwner`와 `BruteWindowContext`는 private implementation detail이다.
7. 외부 API, network, LLM, 모델 다운로드/embedding은 호출하지 않는다. 평가기는 기존 local pipeline만 호출한다.
8. `PARSER_REJECTED`, detector execution error, evidence binding mismatch를 결과 부재/정상으로 바꾸지 않는다. 미지 값, 충돌, incomplete run이면 fail-closed한다.
9. 결과에는 closed status, fixed reason, scenario ID, bounded counts/Boolean outcomes만 허용한다. Fixture ID 자체도 개인 식별 정보로 오해될 수 있는 값이나 실제 path를 포함하지 않는다.

이 계약은 합성 평가 도구 경계다. 악성 Python 내부 코드, 디버거/memory dump, 운영체제 침해, 실제 입력 source authenticity, secure erase 또는 실제 조직 보안 통제를 보장하지 않는다.

## 11. Research Basis

자료 확인일: **2026-11-04**. 외부 자료의 기술을 탐지 조건으로 복사하지 않고, 이 설계가 보존할 근거관리 원칙과 관측 한계를 점검하는 데만 사용했다.

| 자료 및 외부에서 확인한 원칙 | 현재 코드에서 실제로 관찰 가능한 것 | ER-0 제안 정책 / 적용하지 않은 것 |
|---|---|---|
| NIST [SP 800-92, Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final) (2006 Final)는 로그 관리, 분석 및 로그 무결성·보존 프로세스를 다룬다. NIST [SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final)는 분석의 신뢰성과 반복 가능한 방법, 데이터 출처 보존을 강조한다. | Loader→Parser→normalized event→detector 순서는 코드로 확인되나 input collection completeness, 실제 원본 무결성, custody metadata는 batch 분석 contract에서 증명되지 않는다. | observation provenance와 parser disposition을 비교 판단의 전제에 둔다. 이 local 합성 평가를 포렌식 chain-of-custody라고 부르지 않고 NIST 문서가 detector threshold를 승인한다고 주장하지 않는다. |
| MITRE ATT&CK [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/)와 [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)는 기술 행위를 서술한다. MITRE [DET0551](https://attack.mitre.org/detectionstrategies/DET0551/) 및 [DET0487](https://attack.mitre.org/detectionstrategies/DET0487/)는 데이터 source와 mutable analytic parameters의 예를 제시한다. | 현재 Application/SSH parser가 `login_failed`, timestamp, source IP, user를 일부 지원 profile에서 만들고 두 detector가 해당 값과 aggregate를 사용한다. password 자체/동일 비밀번호 여부는 event schema에서 사용되지 않는다. | MITRE 명칭은 label 의미를 이해하는 taxonomy로만 참고한다. 5회/60초, 4회/3 user/60초는 기존 프로젝트 heuristic이지 ATT&CK/NIST 표준 임계값이 아니다. 같은 credential/악의성은 claim하지 않는다. |
| IETF [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424)는 syslog header와 RFC3339 기반 timestamp syntax, time-quality metadata 가능성을 정의한다. 문법상 timestamp 존재가 해당 원천 시계의 정확성/신뢰성을 자동 보증하지 않는다. | Phase 36.11B는 RFC5424 OpenSSH 제한 profile을 지원한다. `NormalizedEvent.timestamp`는 Parser가 parse/normalize한 값이다. source clock accuracy, delivery lag 또는 independent event identity는 일반적으로 검증되지 않는다. | timestamp 변형은 문법 파싱과 정규화 결과를 따로 확인한다. timestamp가 바뀌면 event ordering/window feature도 재계산하고, “실제 시스템에서 시간 조작됐다”고 해석하지 않는다. |

**Observable Evidence Mapping**

| 입력 근거 | 코드 관측 | 가능한 claim | 불가능한 claim |
|---|---|---|---|
| 지원 문법의 synthetic authentication line | `load_normalized_logs()` → source Parser → UTC-normalized `NormalizedEvent` | 해당 run에서 Parser가 정해진 fields/event type을 생성했음 | 원천 로그 진실성, 원본 누락 없음, 실제 user identity |
| 동일 IP·known user `login_failed` event members | Brute selector가 검증한 private `BruteWindowContext`; count/time/member exactness 재검사 | 현재 Brute Production policy의 선택 창 predicate 결과 | 같은 password, 한 사람/공격자, 시도 중복 제거의 정확성 |
| 동일 IP failures·known target set·min/max time | `summarize_ip_failures()` 전체 IP feature; Spray detector predicate | 현재 whole-span rule이 합성 normalized scope에서 만족/미만족했는지 | password spraying 행위 확정, credential reuse, 운영상 benign/malicious |
| AnalysisRunOwner 및 같은 실행의 Detection/Correlation/Risk binding | Private stage binding and consumer verification | 내부 pipeline stages가 같은 owned run result를 사용했는지 | 영구·공개 identity, 다른 process 간 trusted provenance |

**Limitations:** 외부 연구는 프로젝트의 60초를 정당화하지 않는다. synthetic samples는 실제 데이터 분포, source clock, forwarding/replay, NAT, shared egress, username canonicalization, service policy, rate limits, omitted logs를 모델링하지 못한다. ATT&CK taxonomy는 특정 관측 row가 악의적이거나 compromise를 의미한다고 인증하지 않는다. RFC timestamp parsing은 clock correctness를 인증하지 않는다. NIST log handling 원칙을 채택해도 이 prototype이 포렌식 인증을 획득하는 것은 아니다. 현재 Production Password Spray correlation anchor와 Window consumer는 미해결이며 ER-1A는 이를 해결하거나 변경하지 않는다.

## 12. ER-1A Implementation Requirements

ER-1A 구현 전/수행 조건:

1. `app/evaluation/` 아래 Production import 방향을 지키는 별도 harness로 구현한다. API/UI/public DTO에는 연결하지 않는다.
2. 작은 closed manifest schema/version을 두고 변형 enum, source, fixture ID, independent label basis, expected parser disposition, detector/policy ID를 allowlist 검증한다. Duplicate JSON key, NaN/Infinity, unknown field/enum, symlink, traversal, oversized input 거부.
3. loader가 임의 path를 받지 않게 고정 synthetic fixture registry에서만 resolve한다. 각 실행에 fresh run/context/event objects를 제공한다.
4. 실행 결과는 Parser, Detection, Comparison 3축 closed state, fixed reason codes, safe counts만 기록한다. 상태간 불일치·실패시 fail-closed.
5. 기존 Brute Production path가 선택 window와 IP-wide feature를 보존하는지, Spray Production path가 whole-span임을 경계 fixture로 고정한다. Evaluation-only Window prototype은 다른 별도 정책 결과로 명확히 분리하고 Production 결과와 합산하지 않는다.
6. 7가지 입력 변형(행 제거/추가, timestamp, target, IP, 순서, 문법 손상)을 실제 bytes에 적용하고 전체 pipeline을 매번 재실행한다. 파생 feature는 직접 수정 금지.
7. 각 변형에 independent positive/negative/undetermined behavioral label을 미리 정의하고 label checker가 detector output에 의존하지 않도록 테스트한다. operational context는 pattern label과 분리한다.
8. RED contract tests는 parser reject vs detector negative, execution failure vs no match, known Brute window vs IP-wide features, whole-span Spray, cross-run/context mix, invalid comparison, incomplete label/provenance를 포함한다.
9. 결정성 테스트는 baseline/variant를 반복 실행해 canonical redacted JSON bytes가 같음을 검증한다. stdout/stderr, exception, repr, privacy canary, filesystem/network access를 별도 검사한다.
10. 입출력 byte/line/scenario cap 및 실행 시간은 작은 fixture 기반으로 고정한다. limit 초과는 partial success가 아니라 fixed failure category.
11. ER-1 결과는 분석 정확도·회피·보안 보증을 주장하지 않는다. 새 rule/threshold나 Detector semantics 변경은 별도 evidence research와 승인 phase를 요구한다.

## 13. Unresolved Questions / HOLD Conditions

- Application parser에서 로그 timestamp timezone이 실제 source timezone과 일치하는지: source-specific 운영 검증 없음.
- 중복된 동일 내용의 line이 별도 인증 시도인지 delivery replay인지: stable event/delivery ID 없음; deduplicate/중복 제거 불가.
- NAT, proxy, shared egress와 실제 계정 owner 간 mapping 및 합성 benign/attack operational context: 근거 미확보.
- source clock skew, log ingestion delay, out-of-order collection이 real event order를 얼마나 보존하는지: 현재 evidence 부족.
- missing user/account가 Spray pattern의 account cardinality에 어떤 systematic bias를 주는지: 운영 data 없음.
- 독립 label reviewer/holdout process가 마련되지 않으면 평가가 같은 정책을 자기 평가하는 위험이 남는다.
- Parser partial status의 “동등한 입력 범위” comparison rule, state schema version, exact output caps는 ER-1A TDD에서 구체화해야 한다.
- ER-1A 실행이 실제 user file, arbitrary path/network/LLM, raw input echo에 접근하려 하거나 output과 dimension이 충돌하면 HOLD.
- ER-1A를 Production detector, risk, case, checklist, report에 연결하거나 36.10B evaluation-only Window를 Production으로 승격하려는 요구는 별도 Gate 전까지 NO_GO.

## 14. Test Results

### 변경 전 TDD RED 및 baseline

- 문서 계약 테스트를 먼저 추가하고 문서를 만들기 전에 실행: **2 failed**. 하나는 `docs/evidence_research_er0.md` 부재, 하나는 `docs/index.md` link 부재. assertion/deadline을 완화하지 않았다.
- 시작 baseline, 순차 실행: `uv run pytest -q` — **3655 passed, 2 warnings** (기존 Starlette/httpx/AnyIO deprecation warnings, Python 3.12/macOS).
- 그 다음 `uv run python -m app.evaluation` — 성공: synthetic boundary 79/79; Brute 11 TP/0 FP/FN/58 TN; Password Spraying-like 2 TP/0 FP/FN/67 TN; parser 195/200 (ignored 2, rejected 3, unexpected parse/rejection 0); Risk 70/70; Case 70/70; Linux process synthetic classification 21/21. 이는 합성 결과이며 운영 탐지 보장이 아니다.

### 문서 변경 후

- Documentation contract test: `uv run pytest -q tests/test_evidence_research_er0_documentation.py` — **2 passed**. 처음 문서 작성 직후 1개 문서 phrase assertion이 너무 구체적이어서 실패했고, 실제 한국어 계약 문구와 맞게 테스트 기대 문자열만 조정한 뒤 통과했다. 의미 검증을 완화한 변경은 아니다.
- 전체 `uv run pytest -q` (evaluation과 순차): **3657 passed, 2 warnings, 151.49s** (macOS, Python 3.12). Warning은 baseline과 같은 Starlette/httpx/AnyIO deprecation 2개다.
- 이어서 `uv run python -m app.evaluation`: 성공. synthetic boundary **79/79**; Brute Force **TP 11 / FP 0 / FN 0 / TN 58**; Password Spraying-like **TP 2 / FP 0 / FN 0 / TN 67**; parser **195/200** (ignored 2, rejected 3, unexpected parse/rejection 0); correlation 6/6, 3/3, 1/1; Risk **70/70**; Case **70/70**; Linux process synthetic classification **21/21**. 기존 evaluation 결과이며 ER 반사실 분석기가 추가되었다는 뜻이 아니다.
- `git diff --check`: **PASS**.
- 범위 검사: 신규 설계 문서, `docs/index.md`, 신규 문서 계약 테스트만 변경. Production/evaluation/corpus/dependency/lockfile/workflow 변경 없음.

macOS는 local host다. 새 commit의 Ubuntu CI는 push하지 않아 `NOT_TESTED`; 새 설계의 Safari/실제 mobile 검증은 해당 없음/미실행.

## 15. Final Decision

**`ER_0_EVIDENCE_CONTRACT_LOCAL_CONDITIONAL_GO`** — 시작 exact-SHA CI gate 통과, 현재 Brute/Spray Production 차이 코드 기준 확인, 각 근거 개념과 세 개의 independent state dimensions, 입력 변형 및 privacy/fail-closed 계약 정의, 문서 RED 테스트 재현, 문서 계약·전체 pytest·기존 evaluation 통과를 확인했다. 이 판정은 문서/합성 평가 harness의 로컬 설계 Gate일 뿐이다.

- ER-1A 구현 진입: 문서 계약·전체 회귀·평가·scope 검사 최종 통과 후 가능.
- 기존 Detection/Correlation/Risk 및 public schema: 변경 승인 없음.
- 실제 사용자 자료: `NO_GO`; 조직 운영: `NO_GO`; 자동 대응: `NO_GO`.
- 실환경 탐지 정확도: `UNVERIFIED`; 모델 기반 AI 사용: 없음.
