# ER-1D-S1-G — Solo Research 정책 효력 및 S1 구현 승인 패키지

## 1. Executive Summary

이 문서는 S1 구현 **착수 명세**를 고정한다. S1은 Tier 0 중 Brute 15개 시나리오의 Baseline/Variant를 대상으로, 같은 Production 실행에서 선택된 Window와 실제 Evidence를 검증하고 count/span만 복사하는 연구 전용 Restricted Adapter다. 새 실행 코드는 이번 단계에서 작성하지 않았다.

설계 수준의 준비 상태는 `S1_TECHNICAL_READY`, 구현 방식은 `FEASIBLE_ONLY_WITH_RESTRICTED_ADAPTER`다. 아직 Adapter 보안성을 실증한 판정은 아니다. 정책 효력은 `S1_POLICY_EFFECTIVENESS_PENDING`, 구현 승인은 `S1_IMPLEMENTATION_APPROVAL_PENDING`이며 종합 구현 착수는 HOLD다. 이미 승인된 Option B 방향을 재선택하도록 요구하지 않는다. §18의 미채택 승인문으로 남은 권한·의무 확인, R1–R6 채택, S1 범위를 함께 결정할 수 있다.

## 2. Exact Start Gate

기준 SHA: `1cf1b1c49eb6696136b52695117038201a0d1b36`. Exact [CI 42330174168](https://github.com/misosos/ai-security-log-analyzer/actions/runs/42330174168): push / completed / success, head 정확히 일치. `Locked Python 3.12 regression` Job과 Linux checkpoint/SSH/unified app/OpenAPI/full regression/TCP Syslog/collector/Restricted Report/Chromium accessibility/tracked-file 검사를 포함한 모든 Step 성공, Artifact 0개를 직접 확인했다.

HEAD/local main/origin/main/GitHub main 동일, working tree clean, ahead/behind 0/0. `v0.4.0` tag의 dereferenced SHA 및 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`로 불변이다. `AGENTS.md` 및 관련 보안 지침을 확인했다. `ER_1D_S1_G_START_GATE_GO`. 이 GitHub Ubuntu 증거는 기준 커밋에 한정하며 아래 로컬 macOS 검증과 구별한다.

## 3. Previous Phase Evidence

| 근거 | 이번 단계에서 사용하는 결론 |
|---|---|
| [ER-1D-P §14–15](counterfactual_sensitivity_explanation_design_er1d_p.md) | 기존 독립 검토·구현 HOLD의 역사적 근거. 네 계층 설명 설계는 유지하되 S1은 설명을 생성하지 않음 |
| [G0](counterfactual_explanation_readiness_audit_er1d_g0.md) | Target IP SafeFacts는 Brute selected-window의 근거가 아님 |
| [S0](counterfactual_solo_research_track_er1d_s0.md) / [G1](counterfactual_solo_research_governance_er1d_s0_g1.md) | 연구/Production 분리 및 권한 있는 명시적 정책 예외 필요 |
| [G2](counterfactual_research_input_scope_governance_er1d_s0_g2.md) | Tier 0 회귀 불변, Tier 1/S5와 Tier 2/S6 별도 Gate |
| [G3 §6–7](counterfactual_solo_research_policy_decision_er1d_s0_g3.md) | 방향 승인 존재, R1–R6와 정책 효력·S1 승인 구분 |
| [S1-P §3–6·11](counterfactual_restricted_adapter_preflight_er1d_s1_p.md) | B2/C 내부 경계, 수명·membership 제한 및 22개 반증 계획 |

최신 코드를 다시 대조했다. `app/main.py::_analyze_normalized_logs_with_context()`는 새 `AnalysisRunOwner`를 만들고 Detection/Correlation/Risk 후 `(result, contexts, owner)`를 반환한다. `app/analyzer/pipeline.py::load_normalized_logs()`의 실제 list를 호출자가 유지할 수 있다. `app/detector/brute_force.py::validate_brute_window_context()`, `brute_window_context_owner()`, `brute_evidence_matches_context()` 및 owner의 `is_bound_to(result)`를 함께 써야 한다. 어느 함수 하나도 전체 원천 membership을 단독 인증하지 않는다.

## 4. Option B Decision Scope

실제 사용자 결정: “내가 결정 권한을 가진 내부 개발 정책이라는 전제하에 Option B 연구 전용 정책 개정 방향을 승인해. 단, S1 구현 자체는 별도 Gate 통과 후 승인하고 독립 검토 및 운영 HOLD는 유지해.”

| 항목 | 현재 증거 상태 |
|---|---|
| Option B 방향 | APPROVED_IN_CONVERSATION |
| 내부 정책 결정권 | CONDITIONAL_USER_STATEMENT |
| 외부 의무 검증 | NOT_INDEPENDENTLY_VERIFIED |
| R1–R6 구체적 채택 | NOT_ADOPTED |
| S1 구현 승인 | NOT_GRANTED |
| 실제 승인 날짜/서명 | NOT_PROVIDED |

이 문서 작성 요청은 채택·구현 승인으로 해석하지 않는다. 승인 날짜·서명은 생성하지 않는다. 소유자가 적용되는 의무와 자신의 결정 범위를 직접 확인할 수 있으며, 존재하지 않는 외부 검토자나 임의 신원 인증을 새 조건으로 요구하지 않는다. 그 확인도 독립적인 법적 검증이나 독립 사람 검토를 뜻하지 않는다.

## 5. R1–R6 Policy Adoption Preconditions

[G3 §6](counterfactual_solo_research_policy_decision_er1d_s0_g3.md)의 문구를 채택 대상으로 유지하며 아래 표는 이번 S1에 적용할 구체적 해석이다. 현재 모두 채택 확인 대기다.

| 조항 | 이미 승인된 방향 / 구체적 채택 내용 | 적용 시작 조건 |
|---|---|---|
| R1 | 별도 오프라인 연구 트랙 방향 승인. 효력 있는 좁은 연구 예외를 Tier 0 S1에만 적용 | 내부 결정권·적용 의무 충돌 확인, 실제 R1–R6 채택 기록 |
| R2 | 신규 합성 입력 확장 방향만 인정. Tier 1은 S5 전 금지, Tier 2는 S6 및 별도 승인 전 금지, Tier 3 NO_GO | S1에는 새로운 입력 권한 없음 |
| R3 | §7 파일만 변경하고 §8–9 호출만 허용. Production/Replay DTO/Corpus/Label/Snapshot/Pin/API/UI 불변 | 별도 S1 구현 승인과 exact SHA/CI Gate |
| R4 | same-run 검증·closed scalar 출력·privacy/network/LLM 차단 | §9–13을 구현 수용 기준으로 채택, 실제 성공은 구현 후 확인 |
| R5 | 자동 검증/자기 검토/미검증/독립 검토 대기 구별 | 연구 문서에 AUTOMATED_VERIFIED, SELF_REVIEWED, NOT_VERIFIED, INDEPENDENT_REVIEW_PENDING을 사실에 맞게 기록; Public DTO에 추가 금지 |
| R6 | 방향·정책 효력·구현 승인·후속 단계 분리, 위반 시 중단 | §14 재검토·롤백과 실제 승인 시점 기록 |

효력은 실제 결정이 기록된 시점 이후, 승인된 기준 SHA의 변경 범위에만 적용한다. 과거 구현을 소급 승인하지 않는다. ER-1D-P §14–15, ER-1C-R §13, G0 §5·9–10, S0 §3·9·13의 역사적 HOLD를 삭제하지 않는다. 권한 있는 채택이 있으면 그 이후의 명시적 Tier 0 연구 예외만 구분하고 기존 Production HOLD와 독립 검토 Gate는 계속 우선한다. 상위 지침·외부 의무와 충돌하면 정책 효력을 부여하지 않고 HOLD한다. 현재 적용 시작·유효기간은 UNDECIDED다.

## 6. S1 Minimal Implementation Scope

향후 공개 연구 callable은 `evaluate_fixed_brute_aggregate(corpus_id, scenario_id, run_role)` 하나와 `canonical_safe_aggregate_json(record)` encoder로 고정한다. 이것은 **후속 구현 명세이며 현재 존재하는 API가 아니다**. 입력 세 개는 exact str이며, corpus_id는 `development`/`holdout`, scenario_id는 해당 고정 Manifest의 Brute inventory, run_role은 `baseline`/`variant`만 허용한다. Scenario/Owner/Context/Event/bytes/path/URL/config 객체를 외부 인수로 받지 않는다.

고정 30건 중 Development Brute 8건·Holdout Brute 7건, 각각 두 run role이 후보이므로 최대 30개의 개별 호출이다. 나머지 Spray 15건은 회귀 기준이며 S1 집계 대상이 아니다. 한 호출은 **한 scalar record**만 반환한다. 자동 batch/CLI/웹 route/기본 runner 등록은 만들지 않는다. 테스트가 명시적으로 호출하고, 승인된 사용자는 고정 ID의 Python callable을 명시적으로 실행할 수 있다. baseline/variant는 각각 새 실행이며 반환 객체를 서로 공유하지 않는다.

Feature Delta, Policy Predicate Explanation, 자연어 원인 설명, 사용자 정의 입력, 파일 업로드·텍스트 입력 UI, 실제 로컬 로그, Production API/UI, LLM 및 자동 대응은 구현하지 않는다. S2–S6은 모두 별도 승인이다.

## 7. File Change Allowlist

후속 S1에서 **생성만 허용하는 네 파일**이다. 기존 파일 변경 권한과 혼동하지 않는다.

| 정확한 경로 | 허용 내용 |
|---|---|
| `app/evaluation/research_er1d/__init__.py` | 부작용 없는 package 초기화; 자동 실행·다른 패키지 등록 없음 |
| `app/evaluation/research_er1d/safe_aggregate.py` | 고정 입력 선택·private core wrapper·같은 실행 검증·closed record/encoder/fixed 오류; 단일 모듈 |
| `tests/test_counterfactual_research_safe_aggregate.py` | 정상 경계와 §13 모든 수용 기준, 오프라인·파일·privacy 감시 |
| `docs/counterfactual_research_safe_aggregate_er1d_s1.md` | 실제 RED/GREEN·명령·결과·한계·승인 참조 기록 |

S1은 이 승인 명세에서 결과 문서 경로를 미리 연결했으므로 별도 `docs/index.md` 수정이 필요하지 않다. 이번 S1-G 변경은 신규 Gate 문서·문서 계약 테스트·색인뿐이다. S1 구현 중 다른 파일 수정, helper 분리, 의존성 추가가 필요하면 목록을 임의로 확대하지 않고 HOLD 및 범위 재승인을 요구한다.

## 8. Runtime Dependency Allowlist

읽기·실행 재사용은 변경 허용이 아니다. 기준 SHA의 코드/자료를 신뢰 근거로 고정한다. 파일명만이 아니라 기준 Git blob과 SHA-256를 비교한다. 후속 S1 테스트는 아래 집합의 기준 digest 목록을 전용 테스트 파일에 고정하고, runtime 모듈에도 입력/정책/Detector/Parser/metadata의 신뢰 pin을 별도 상수로 둔다. 검사 대상 파일에서 읽은 현재 digest를 expected pin으로 자동 채택하지 않는다. 코드 pin은 프로세스 시작의 신뢰한 checkout을 검증하는 보조 경계이며 동일 권한의 악성 Python/OS 변경에 대한 서명 인증이 아니다.

| 분류 | 정확한 허용 집합과 호출 |
|---|---|
| Development 데이터 | `sample_logs/counterfactual/manifest.json` 및 그 Manifest의 baseline_fixture_id로 열거된 정확한 16개 `.log`; `load_corpus()`, `prepare_scenario()`, `load_fixture()`, `_thaw()`, `apply_mutation()` 재사용. glob으로 새 파일을 자동 승인하지 않음 |
| Holdout 데이터 | `sample_logs/counterfactual_holdout/manifest.json`, `hashes.json` 및 Manifest에 고정된 14개 `.log`; `load_holdout()`가 검증한 fixture_bytes/variant_bytes와 audit 사용. 기존 함수가 Development도 읽는 점 포함 |
| Parser/실행 | `app/analyzer/pipeline.py::load_normalized_logs`, `app/main.py::_analyze_normalized_logs_with_context`, `app/detector/brute_force.py`의 owner/context 검증 함수. source는 application/ssh만 |
| 간접 metadata | `data/account_metadata.json`만. `assess_risk()` → `app/analyzer/risk.py::load_account_metadata()`가 실제 읽는 고정 의존성; 합성 연구에 적합한 현재 버전만 pin, 내용·계정명 출력 금지 |
| Python 코드 | 아래 34개 모듈과 해당 경로의 package `__init__.py` 중 기준 SHA에 존재하는 파일; import closure는 아래에 열거. 실제 동작 추적과 대조해 새 runtime dependency가 나오면 HOLD |
| 환경 코드/시간대 | locked Python 3.12/uv.lock의 설치 라이브러리, 표준 라이브러리, ZoneInfo Asia/Seoul·UTC 데이터. 코드 import/bytecode와 timezone 읽기는 로그 입력 접근과 구분하며 테스트 환경을 고정 |
| 임시 I/O | 호출 내부가 생성한 private temp directory의 `synthetic.log`만. 디렉터리 0700/파일 0600, bounded bytes 동일성 확인, 정상·예외 종료 삭제. 사용자 경로 인수 없음. 기존 사전 Parser도 내부 임시 사본을 쓰므로 이를 포함 |

기준 Manifest 파일 SHA-256는 Development `a0d81f404b99e19acb15458fe80fada677dab846db79cb3682b1f7359b70d062`, Holdout `392127d5ad7fb61cfca361d0b9c21a6c349d94313c14bd3c1f4ead48f9393739`, Holdout hashes 파일 `0280690f3d86ab41725bc9004e3d43ab956505eab206a56bc2d5194a4f2a50f1`, account metadata `39959034cc82c3eef0db2cb587c5721127951b0bbf94fe799fb94139f0a4c2f5`다. Development fixture pin도 기준 Git blob에서 별도 고정해야 하며 Manifest 자체가 fixture bytes를 암호학적으로 결속한다고 가정하지 않는다.

코드 import closure(기준 정적 추적 34개, 호출 허용은 위 표와 §9에 한정):

```text
app.analyzer.html_report
app.analyzer.html_report_file
app.analyzer.pipeline
app.analyzer.process_execution
app.analyzer.process_execution_classification
app.analyzer.report
app.analyzer.report_projection
app.analyzer.risk
app.analyzer.web_observation_projection
app.correlation.attack_chain
app.correlation.linux_audit_login_session
app.correlation.linux_audit_session
app.correlation.session_process
app.detector.brute_force
app.detector.password_spray
app.detector.shared_memory_execution
app.detector.web_attack
app.evaluation.counterfactual_comparison
app.evaluation.counterfactual_corpus
app.evaluation.counterfactual_holdout
app.evaluation.counterfactual_mutation
app.evaluation.counterfactual_replay
app.investigation_role_snapshot_36_4
app.loader.file_loader
app.loader.linux_audit_loader
app.main
app.models.schemas
app.parser.access_log
app.parser.auth_log
app.parser.linux_audit
app.parser.registry
app.parser.ssh_auth
app.parser.time_utils
app.public_identifiers
```

위 목록은 현재 import의 읽기 의존성이다. report 저장, Linux/Access 입력, 다른 Detector의 연구 출력을 허용하는 목록이 아니다. `app.main.main()`, 기본 `LOG_SOURCES`, Report 출력, API/UI/Live/LLM 호출은 금지한다. 신규 연구 모듈을 기존 `app.evaluation` 기본 runner나 API/UI에서 import하지 않는다. Python import 시 bytecode 영구 쓰기를 억제한 격리 프로세스를 사용한다. 이 프로세스는 준비 함수 호출 전 umask 077을 설정해 기존 사전 Parser가 만드는 임시 파일도 0600으로 제한한다. 명시적으로 요청한 safe JSON 외 stdout/stderr 출력과 결과 영구 저장은 0이다. 임시 사본은 정상·포착 가능한 실패에서 삭제하며 강제 kill/OS crash 후 삭제를 보증하지 않는다. 잔존 자료는 재사용하지 않고 비공개로 조사·삭제한다.

## 9. Restricted Adapter Execution Contract

채택할 방식은 S1-P의 **B2를 감싸는 C**다. 공개 Replay DTO만 사용하는 A와 full parsed list가 없는 bundle만 사용하는 B1은 사용하지 않는다.

1. closed 인수·고정 inventory·버전·자료 pin을 검증한다. Development는 기존 prepare 경로, Holdout은 기존 load/audit가 확인한 baseline/variant bytes를 사용한다. Label/Expected Facts는 기존 Corpus 정합성 검증에만 쓰고 Detector 관측이나 출력값을 Label에서 만들지 않는다.
2. UTF-8 strict, 8192 bytes 이하·64행 이하·빈 입력 금지다. core용 private 임시 사본을 만들고 읽기 전후 bytes/digest 동일성, 일반 파일·비symlink·부모 디렉터리를 확인한다. 원본 Corpus를 변경하지 않는다.
3. 기존 `load_normalized_logs()`의 **실제 list와 각 event 객체**를 유지한다. 기존 `_parser_disposition()`의 엄격한 완전성 조건을 이 list에도 적용해 행 수·source·account·UTC timestamp 및 사전 검증과의 일치를 확인한다. PARTIAL/REJECTED이면 이 S1 호출에서는 core를 실행하지 않고 §10에 따라 보류한다. 기존 Replay가 PARTIAL subset을 실행하는 계약은 변경하지 않는다.
4. 이 list를 복사하거나 다시 parse하지 않고 `_analyze_normalized_logs_with_context(logs)`에 전달한다. 그 호출이 만든 owner와 반환한 원래 result/context mapping을 같은 동기 실행에서 보유한다. callback이나 외부 제공 bundle을 사용하지 않는다.
5. `type(owner) is AnalysisRunOwner`, `owner.is_bound_to(result)`, 실제 subject/Detection slot/type을 검증한다. 대상 subject가 없으면 대상 부재로 보류하고 NOT_DETECTED를 발명하지 않는다.
6. 검출 시 실제 mapping의 context에 대해 owner identity·subject·`validate_brute_window_context()`·`brute_evidence_matches_context()`를 검증한다. 다른 실행의 값이 같은 Detection/context도 거부한다. 비검출 시에도 owner와 실제 결과 slot 결속, context 부재 및 검출 Evidence 부재의 정합성을 확인한다.
7. 원래 list의 **object identity** 다중집합을 만들고 context member의 **multiplicity**가 이를 초과하지 않는지 확인한다. source/IP/account/실패 이벤트/UTC 범위도 검사한다. 값이 같은 clone은 허용하지 않는다. 각 event의 필드 및 list 순서·내용을 core 전후와 사영 전후의 내부 snapshot으로 확인한다. result/Evidence도 검증 전후 불변인지 확인하고 owner binding을 다시 검사한다.
8. 신뢰한 기존 selector가 실제 반환한 context의 count와 end-start만 복사한다. 별도 선택기 재계산, IP 전체 SafeFacts 대입, 다른 Replay 실행과 Owner 결합은 하지 않는다. core를 재실행하면 다른 owner이므로 기존 Replay는 별도 회귀 관측으로 비교한다.
9. §10 전체를 검증한 뒤 불변 scalar record를 한 번에 반환한다. result/context/member/owner와 내부 snapshot은 외부 반환하지 않는다. 임시 사본을 삭제하고 참조를 해제한다. Python 메모리 완전 소거는 보증하지 않는다. Owner는 함수 반환 시 자동 만료되지 않으며 참조를 유지한 동안의 검증에 한정한다. 직렬화·참조 폐기 후 결속 복원은 금지한다.

같은 실행의 선택 결과를 신뢰하는 근거는 고정 코드의 실제 core 반환값·소유 관계·Evidence·원래 event list를 결합한 검증이다. 같은 권한의 악성 Python이 임의 메모리를 바꾸는 공격까지 막았다고 주장하지 않는다. private interface 변경 시 자동 적응하지 않고 HOLD한다.

## 10. Safe Aggregate DTO

연구 전용 단층 closed schema다. 아래 14개 키만 항상 존재하며 기존 Public Replay DTO에는 추가하지 않는다. 입력 ID 검증에 실패하면 record를 만들지 않는다.

<!-- S1_SCHEMA_START -->
| 필드 | 정확한 타입·허용값 | Producer / 검증 |
|---|---|---|
| `schema_version` | int, 1만 허용, bool 금지 | 연구 schema 상수 |
| `corpus_id` | str, development / holdout | 검증된 closed 인수 |
| `scenario_id` | str, 고정 Brute inventory ID, ASCII 3–64자 | 검증된 Manifest, 원본 행 참조가 아님 |
| `run_role` | str, baseline / variant | closed 인수 |
| `detector_id` | str, brute_force | 실제 Detection slot/type과 고정 scenario |
| `policy_version` | str, brute_force_production_v1 | policy metadata와 코드 pin, 이름만으로 검증 성공 금지 |
| `scope_type` | str, BRUTE_SELECTED_ACCOUNT_WINDOW | 실제 선택 context에 한정 |
| `parser_disposition` | str, VERIFIED / PARTIAL / REJECTED / NOT_EVALUATED | 실제 bytes와 parsed list |
| `detection_state` | str, DETECTED / NOT_DETECTED / NOT_EVALUATED / EXECUTION_FAILED | 같은 실행의 검증된 관측만 |
| `evaluation_status` | str, VERIFIED / NOT_EVALUATED / INVALID / EXECUTION_FAILED | 연구 사영 평가 상태 |
| `evidence_validation_status` | str, VERIFIED / NOT_EVALUATED / INVALID | 같은 실행 결속 검증 |
| `failure_count` | exact int 5–64 또는 null | 실제 context.failure_count, member 수 일치 |
| `window_span_seconds` | 유한 int/float 0–60 또는 null, bool 금지 | 실제 UTC end-start, Evidence 일치 |
| `reason_code` | str, 아래 closed set 중 하나 | 고정 분기 선택만 |
<!-- S1_SCHEMA_END -->

소수 span은 datetime 유래 최대 microsecond 정밀도다. 음의 zero·NaN·Infinity·추가 키·private 객체를 금지한다. 상한 64는 기존 64행 입력의 연구 자원 제한이며, 5와 60은 기존 Production 조건이지 새로운 탐지 임계값이 아니다.

| 조건(위에서부터 우선) | parser / detection | evaluation / evidence | 수치 / reason_code |
|---|---|---|---|
| Owner/member/Evidence/type 모순 | 확인된 parser 또는 NOT_EVALUATED / NOT_EVALUATED | INVALID / INVALID | 둘 다 null / EVIDENCE_BINDING_FAILED(결속) 또는 INVALID_INTERNAL_CONTRACT(타입·schema) |
| Policy/code/source/provenance 불일치 | 확인된 parser 또는 NOT_EVALUATED / NOT_EVALUATED | INVALID / NOT_EVALUATED | 둘 다 null / POLICY_MISMATCH, DETECTOR_VERSION_MISMATCH, UNSUPPORTED_SOURCE, INPUT_SCOPE_MISMATCH 중 해당 첫 조건 |
| Parser/실행의 예상 밖 예외 | 확인된 parser 또는 NOT_EVALUATED / EXECUTION_FAILED | EXECUTION_FAILED / NOT_EVALUATED | 둘 다 null / ANALYSIS_EXECUTION_FAILED |
| Parser REJECTED | REJECTED / NOT_EVALUATED | NOT_EVALUATED / NOT_EVALUATED | 둘 다 null / PARSER_REJECTED |
| Parser PARTIAL(Account/시각 누락 포함) | PARTIAL / NOT_EVALUATED | NOT_EVALUATED / NOT_EVALUATED | 둘 다 null / REQUIRED_FIELD_MISSING |
| Parser 미실행 | NOT_EVALUATED / NOT_EVALUATED | NOT_EVALUATED / NOT_EVALUATED | 둘 다 null / PARSER_NOT_RUN |
| 완전한 입력이나 대상 subject 부재 | VERIFIED / NOT_EVALUATED | NOT_EVALUATED / NOT_EVALUATED | 둘 다 null / SUBJECT_MISMATCH |
| 완전한 입력·정상 결속된 실제 음성 | VERIFIED / NOT_DETECTED | NOT_EVALUATED / NOT_EVALUATED | 둘 다 null / NO_MATCH_IN_EVALUATED_SCOPE |
| 전체 검증 성공·실제 검출 | VERIFIED / DETECTED | VERIFIED / VERIFIED | count/span 유효 / DETECTOR_MATCH |

`reason_code`는 위 표에 열거한 13개만 허용한다. 복수 모순일 때 표의 순서, 같은 행에서는 열거 순서로 하나를 고른다. 연구 출력의 제한된 subset이며 기존 reason enum은 수정하지 않는다. 결속 실패 시 검증하지 못한 Detection 값을 실제 관측이라고 반사하지 않는다. 실패 record는 보류 상태이지 기존 Replay의 결과를 덮어쓰는 DTO가 아니다.

잘못된 인수·알 수 없는 ID·자원 초과·Serializer 불정합은 신뢰할 ID조차 없을 수 있으므로 연구 전용 `ResearchAggregateError` 고정 code로 전체 거부하고 record를 반환하지 않는다. 허용 code는 INVALID_INTERNAL_CONTRACT, CORPUS_INVALID, RESOURCE_LIMIT, INPUT_SCOPE_MISMATCH다. str/repr에는 code만 두고 하위 exception chain을 억제한다. 기존 함수의 예상 밖 stdout/stderr/log는 최대 4096 bytes까지 제한해 내부 포착한다. 내용이 한 글자라도 있으면 성공을 거부하고 고정 오류만 반환하며 내용을 공개하지 않는다. 무제한 StringIO 포착은 금지한다.

수치는 VERIFIED 검출 행에서만 둘 다 존재하고 그 밖에는 둘 다 null이다. 누락을 0/False로 보충하지 않는다. 한 record, 배열·중첩 객체 없음, canonical 출력은 LF 포함 4096 bytes 이하. `json.dumps(ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)`와 마지막 LF 하나를 UTF-8 bytes로 만든다. 명시적 allowlist encoder만 사용하며 `asdict`/`__dict__`/`default=str`·private dataclass 자동 직렬화는 금지한다. encoder도 타입·enum·상호 정합성을 다시 검증한다. 정상 ID record에 HTML 형태의 문자열·추가 필드·private 객체를 주입해도 거부한다.

## 11. Brute/Spray Scope Preservation

Brute는 같은 source IP·알려진 동일 account, 실패 5회 이상, 선택 Sliding Window의 span 60초 이하다. 기존 selector의 우선순위·같은 시각 중복·account 동률 보류를 그대로 사용한다. 비검출의 가상 Window를 만들지 않는다.

Spray는 같은 IP 전체 실패 4회 이상·알려진 account 3개 이상·전체 span 60초 이하의 Production whole-span이며 S1은 출력하지 않는다. 전체 count6/span70에서도 Brute 선택 count5/span20이 성립하는 기존 회귀를 필수로 한다. Target IP SafeFacts를 Brute count로 대체하거나 Spray를 Sliding Window로 만들지 않는다. Parser REJECTED/PARTIAL·EXECUTION_FAILED를 NOT_DETECTED로 바꾸지 않는다. 기존 Comparison의 INCOMPARABLE/UNDETERMINED는 그대로 유지하고 S1 record는 Comparison을 생성하지 않는다.

## 12. Privacy and Isolation Requirements

Raw Log/Event, IP Address, Account Name, 원본 Timestamp, 내부 경로, Owner/Context/Private Evidence, private ID, 재식별 가능한 행 참조, exception 원문은 record·canonical bytes·stdout/stderr·log·예외 전체에 금지한다. Scenario ID는 고정 공개 ID이며 실제 event 참조가 아니다. Canary는 메모리와 분리된 fixture에서 시험하고 고정 Corpus는 변경하지 않는다.

외부 네트워크/LLM, Production API/UI, Investigation Registry/Count/Risk/Checklist/Guidance/Timeline/Report/Live/SSE/Checkpoint/Publication 연결·변경, 임의 파일 읽기, 결과 영구 저장, 기본 import 시 자동 실행은 0이다. core 내부의 정상 Risk 계산은 기존 그대로 메모리에서 수행하되 Investigation에 등록하지 않는다. runtime에서 전역 socket monkeypatch를 제품에 추가하지 않는다. 격리 테스트 프로세스에서 socket/DNS/HTTP/LLM/파일 open/write를 감시·차단하고 실행 코드에 외부 접근 경로가 없는지 검사한다. 사전 import를 이유로 이후 불허 접근을 면제하지 않는다.

코드·자료 pin과 실제 파일 접근은 §8에 일치해야 한다. 고정 account metadata를 허용할 수 없다면 Risk 경로를 임의 우회하지 않고 HOLD한다. 한 입력 실행은 격리 process에서 10초 이내를 수용 기준으로 한다. public 연구 callable은 spawn 방식의 내부 worker를 감독하며, worker의 연구 입력은 검증된 고정 ID 세 개뿐이다. §9의 Loader/core/Owner 검증은 모두 worker 안에서 끝내고 부모에는 검증된 bounded scalar 또는 고정 오류만 전달한다. private 객체를 IPC로 보내지 않는다. 부모가 만든 private temp root는 외부 연구 입력이 아닌 내부 실행 자원으로만 worker에 전달하고, worker의 tempfile 사본은 모두 그 아래에 둔다. 제한 시간 초과 시 부모가 worker 종료·join 후 사본을 정리하고 출력 없이 RESOURCE_LIMIT로 거부한다. 이 제한은 연구 실행의 자원 상한이며 기존 CI/Node timeout 변경 제안이 아니다. worker·IPC도 같은 단일 연구 모듈에 한정하고 기본 import에서는 시작하지 않는다. §13의 I/O 감시는 부모뿐 아니라 실제 worker에도 적용해 검증하며, IPC는 부모에서도 길이·schema를 확인한 canonical bytes와 고정 오류 code에 한정한다.

## 13. Negative Test Acceptance Matrix

아래는 **후속 S1에 구현할 필수 테스트**이며 이번에 신규 security test를 실행해 PASS한 기록이 아니다. 전용 단일 테스트 파일에서 고정 입력의 메모리 사본, 내부 함수의 제한적 monkeypatch와 실제 별도 run으로 모두 구현 가능하다고 판단한다. 공개 callable에 주입용 인수를 추가하지 않는다. 실제 정상 core 경로를 mock으로 대체하지 않는다. 기존 E1–E5의 테스트 범위는 [S1-P §11](counterfactual_restricted_adapter_preflight_er1d_s1_p.md)에 연결하며 기존 성공을 신규 adapter 성공으로 간주하지 않는다.

공통 출력 금지 P는 §12의 모든 private 자료와 원문 예외다. 기대한 거부가 발생하는 부정 테스트는 정상 GREEN이다. 부정 수용·P 유출·미검증 수치·호환성 차이가 한 건이라도 있으면 S1 완료 HOLD다. 아래 INVALID 등은 §10 record를, 전체 거부는 record 없는 고정 오류를 뜻한다.

| 번호 | Group / 대상·입력과 준비 조건 | 기대 결과·실패 상태 | 금지 출력 / HOLD 기준·기존 범위와의 차이 |
|---|---|---|---|
| N01 | A Owner: 같은 bytes의 두 실행에서 foreign owner/context를 triple에 주입. 참조 폐기 후 재구성 시도 | INVALID/EVIDENCE_BINDING_FAILED, 둘 다 null. 외부 private 인수는 전체 거부 | P. 값 일치·잘못된 수명 수용 시 HOLD. E2/E3와 신규 adapter |
| N02 | A Detection: 같은 값의 다른 실행 Detection/Evidence로 실제 slot 교체 | INVALID/EVIDENCE_BINDING_FAILED, owner binding 재검사 | P. 다른 실행을 값만으로 승인하면 HOLD. E3와 신규 검사 |
| N03 | A Evidence: member 삭제/대체, Evidence 종류/source/count와 context 불일치 | INVALID/EVIDENCE_BINDING_FAILED | P. context 단독 검사만으로 통과하면 HOLD. E1과 신규 검사 |
| N04 | A Event: 원래 list에 없는 값 일치 clone, member 중복도 초과, 실행 중 event/list 변경 | INVALID/EVIDENCE_BINDING_FAILED, identity/multiplicity·전후 snapshot 거부 | P. identity 집합만으로 초과 중복을 허용하면 HOLD. 신규 adapter 전용 |
| N05 | A/B Account: 같은 IP의 다른 account를 member에 혼입 | INVALID/EVIDENCE_BINDING_FAILED | P. IP 전체 count 대체 시 HOLD. E1과 신규 검사 |
| N06 | C Missing Account: 기존 partial variant와 메모리 canary의 미상 account | PARTIAL/NOT_EVALUATED, REQUIRED_FIELD_MISSING, core 미실행·둘 다 null | P. 알려진 account로 가정하면 HOLD. E1/E4와 보류 구현 |
| N07 | C Missing Timestamp: 기존 rejected 입력과 별도 누락/naive 시각 주입 | parse 거부면 REJECTED/PARSER_REJECTED, subset이면 PARTIAL/REQUIRED_FIELD_MISSING, 예상 밖 예외면 EXECUTION_FAILED | P. span0 보충 시 HOLD. E1/E4와 신규 경계 |
| N08 | C PARTIAL: 부분 입력 variant, 행 수/필드 completeness 불일치 | NOT_EVALUATED/REQUIRED_FIELD_MISSING, core 미실행·둘 다 null | P. subset을 완전 입력으로 출력하면 HOLD. 기존 Replay partial 동작 불변 |
| N09 | C REJECTED: 기존 rejected variant/빈 parse 결과 | NOT_EVALUATED/PARSER_REJECTED, Detector 미실행·둘 다 null | P. 음성으로 바꾸면 HOLD. E4/E5와 신규 record |
| N10 | B Policy: metadata와 고정 code pin의 정책 불일치 주입 | INVALID/POLICY_MISMATCH, 둘 다 null | P. 정책명만으로 통과하면 HOLD. 신규 code pin 검사 |
| N11 | B Detector: 같은 ID지만 코드 digest 변경을 모사 | INVALID/DETECTOR_VERSION_MISMATCH. 코드 로드 전 pin 실패는 전체 거부 INPUT_SCOPE_MISMATCH | P. 변경 묵인 시 HOLD. 기존 ID 검사에 추가 |
| N12 | C Source/Input: access/미상 source, path/URL/bytes/미상 ID/불정확 타입, 8193 bytes/65행 | 내부 source 불일치는 INVALID/UNSUPPORTED_SOURCE. 외부 불정확 인수는 전체 거부 INVALID_INTERNAL_CONTRACT/CORPUS_INVALID, 초과 RESOURCE_LIMIT | P. fallback/임의 입력 수용 시 HOLD. 신규 entrypoint |
| N13 | C Evidence: 검출됐는데 null/빈 Evidence, 음성에 context/검출 Evidence 존재 | INVALID/EVIDENCE_BINDING_FAILED. 정상 음성만 NOT_EVALUATED/NO_MATCH_IN_EVALUATED_SCOPE | P. 빈 Evidence를 VERIFIED로 만들면 HOLD. E1/E4와 신규 record |
| N14 | B/C Count/Span: bool·음수·NaN/Infinity·count5미만/64초과·span60초과·member/Evidence 모순·과대/추가 schema | 결속 모순은 INVALID/EVIDENCE_BINDING_FAILED, 타입은 INVALID_INTERNAL_CONTRACT. encoder 전체 거부, 초과 RESOURCE_LIMIT | P. 절단/반올림/0 보충 시 HOLD. 신규 encoder 포함 |
| N15 | B Scope: 전체6/70과 선택5/20, Spray scenario 지정, whole-span scope 주입 | 정상 Brute는5/20. Spray 인수 전체 거부 CORPUS_INVALID, 내부 scope 불일치 INVALID/INPUT_SCOPE_MISMATCH | P. Spray 창 전환·전체값 대체 시 HOLD. E1과 신규 schema |
| N16 | A Baseline/Variant: 같은 scenario 두 role의 owner/context/result 상호 주입 | INVALID/EVIDENCE_BINDING_FAILED. 매 호출 owner 별도 참조 | P. 별도 Replay와 same-run 주장 시 HOLD. E2/E4/E5와 신규 adapter |
| N17 | D Privacy: Raw/IP/Account/시각/path/row canary를 내부 자료·exception·logger에 주입 | 정상 allowlist에 P 없음. 출력 시도 발견 시 고정 오류/record 없음, 포착 원문 폐기 | P. bytes/stdout/stderr/log/exception 어느 면의 유출도 HOLD. 신규 감시 |
| N18 | D Serialization: Owner/Context/Evidence를 record/encoder에 전달, asdict/default=str 경로 검사 | 전체 거부 INVALID_INTERNAL_CONTRACT, private 자동 encoder 없음 | P. repr redaction만으로 승인하면 HOLD. 신규 encoder |
| N19 | D Network/File: socket/DNS/HTTP/LLM 감시·강제 실패, 불허 open/symlink/교체·결과 저장 시도 | 정상 외부/임의 file/영구 write 시도0. 경계 위반을 발견하면 전체 거부 INVALID_INTERNAL_CONTRACT, record 없음·temp cleanup | P. 구현 경로에 외부 I/O 시도 있으면 HOLD. 환경 코드/zone/temp만 §8대로 |
| N20 | E Compatibility: 호출 전후 events/result·기존 Production/Replay 깊은 값, Corpus/Label/Snapshot/Pin/metadata digest 대조 | 차이0, 관련 기존73건·전체pytest·Evaluation Runner 성공 | P. DTO 추가/자동 import/API 활성화·값 차이면 HOLD. 기대값 수정 금지 |
| N21 | E Determinism: 같은ID/role의 별도 process 반복, 호출 순서 역전, 다른 role 삽입 | canonical bytes 동일, 1record/4096 bytes 이내, time/random/privateID 없음 | P. 순서 의존·지연 private 참조면 HOLD. E4/E5와 신규 encoder |
| N22 | D Exception/Resource: Loader/core/validator/encoder 각 단계에 private 예외, 출력4097 bytes, 10초 초과 주입 | 고정 code만, 부분 record 없음 또는 §10 EXECUTION_FAILED, 원문 chain 없음, bounded 포착·cleanup | P. traceback/원문/무제한 보유 시 HOLD. E4와 모든 단계 신규 회귀 |

입력64행/8192 bytes의 정확한 경계, Count5/64, Span0/60 및 60초+1microsecond, 정상 중복 유지, 음성null, core 전후 불변도 정상/부정 쌍으로 검증한다. Production에 전역 비활성화 hook을 추가하지 않는다. OS 강제kill 후 메모리 소거, 같은 권한의 공격 코드에 대한 암호학적 인증, 임의 syscall 완전 차단을 검증했다고 주장하지 않는다. 테스트로 확인할 수 없는 추가 의존성이나 함수 변경 필요성이 발견되면 테스트를 삭제하지 않고 S1_TECHNICAL_BLOCKED로 되돌린다.

## 14. Stop/Rollback Contract

Production/Replay 공개 계약 변경 필요, private 유출, Owner/Evidence 불정합 수용, 잘못된 Window·다른 run 혼합, Parser 오해, scope/policy 불일치, Corpus/Label 변경, network/LLM, Tier 1/2 처리, 무제한 출력, 기존 Detector 결과 변경이면 즉시 실행 중단·S1 HOLD다. 잘못된 입력을 기대대로 거부한 것은 정상 동작이며, 부정 수용을 수정하지 않은 채 합격 처리하는 것을 금지한다.

연구 entrypoint 중단 후 생성물을 비공개로 격리하고 §7 연구 변경만 식별한다. 원문을 공개 report에 붙이지 않고 검토 가능한 patch/역commit으로 연구 변경을 되돌린다. reset/clean/stash/강제checkout으로 사용자 작업을 삭제하지 않는다. 기존 계약·고정 digest·network0을 재확인하고 원인 RED/GREEN과 필요한 범위 재승인 후에만 재개를 검토한다. Production/Replay 변경이 필요한 해결책은 별도 Gate로 회송한다.

## 15. Node Timeout Observation

S1-P 변경 전 `tests/test_linux_audit_web_ui.py::test_linux_browser_memory_behavior_with_node`에서 Node 자식 process의 15초 timeout이 한 번 발생했다. 변경 없는 단독 재실행과 S1-P 종료 전체 회귀에서는 재현되지 않았다. 원인 미확정이며 기존 제품 결함이나 S1 결함으로 확정하지 않는다. 이번 변경 전 기준선 3901 passed에서는 재발하지 않았다. CI/Node timeout 확대, skip, 테스트 삭제는 하지 않는다. 반복되면 별도 안정성 문제로 재현 증거를 수집한다.

## 16. Technical Readiness

| 판정 대상 | 상태와 근거 |
|---|---|
| Owner/Context/full parsed list 경계 | 설계 확인, §9의 실제 B2/C 함수, 새 hook 불필요 |
| Production/Replay 변경 | 불필요하다고 판단, §7 밖 수정 필요 시 HOLD |
| Scalar/입력/의존성/출력 한계 | §6–12에서 고정 |
| 22개 부정 테스트·추가 자원/호환성 | §13에 주입 방법·실제 정상 core 대조 정의 |
| 현재 기술 준비 | S1_TECHNICAL_READY, 구현 전 명세 준비만 의미 |
| 향후 부정 조건 | private 경계·의존성·필수 테스트가 성립하지 않으면 S1_TECHNICAL_BLOCKED |

기술 분류는 FEASIBLE_ONLY_WITH_RESTRICTED_ADAPTER이며 미구현 Adapter의 안전 추출에 PASS를 준 것이 아니다. 연구 자기검증으로 운영 수집 완전성이나 독립 정확성을 보증하지 않는다.

## 17. Governance Readiness

Option B 방향 승인은 존재한다. 남은 것은 실제 내부 결정권·적용 의무 확인, 구체적 R1–R6 채택과 효력 시작, S1 최소 범위 구현 승인, 시작 시점의 정확한 SHA/CI다. `S1_POLICY_EFFECTIVENESS_PENDING` / `S1_IMPLEMENTATION_APPROVAL_PENDING`이며 현재 `SOLO_RESEARCH_POLICY_EFFECTIVENESS_PENDING` / `ER_1D_S1_IMPLEMENTATION_HOLD`는 유지한다.

`INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`, `ER_1D_IMPLEMENTATION_HOLD`, `ER_2F_USER_ACCEPTANCE_PENDING`, 실제 사용자 자료·조직 운영·자동 대응 `NO_GO`는 향후 정책 효력이 인정돼도 계속된다. ER-1C-R/H0의 Label-Blind Packet/Response/독립성/의견 불일치 절차를 보존하며 자기검증 결과를 독립 검토자에게 정답으로 제공하지 않는다.

## 18. Owner Approval Decision Text

아래는 **미채택 승인문**이다. 현재 approval은 NOT_GRANTED다. Option B 방향 승인은 재요청하지 않는다. 채택하는 경우 소유자의 실제 응답과 대상 SHA를 기록하고, 확인할 수 없는 조건은 미확인으로 남겨 HOLD한다.

> 나는 이 저장소의 내부 연구개발 정책 결정권을 보유하며, 이 제한 연구에 적용되는 상위 지침·외부 계약·조직상 의무와 충돌하지 않는다는 점을 내 적용 범위에서 확인했다. G3 §6의 R1–R6를 이 S1-G §5–14의 구체적 조건과 함께 채택한다. 대상은 고정 Tier 0 Brute 15개 시나리오의 오프라인 연구뿐이며, §7의 4개 파일·§8의 읽기 의존성·§9의 기존 private core·§10의 closed DTO·§13의 모든 부정 테스트를 조건으로 S1 구현을 승인한다. Production/Replay 계약·Corpus/Label/Snapshot/Pin은 변경하지 않고 privacy·network/LLM 차단·중단/롤백 조건을 준수한다. Tier 1은 별도 S5 승인 전, Tier 2는 별도 Privacy/Security 승인 전 처리하지 않으며 Tier 3는 NO_GO다. 기준은 내가 지정하는 S1-G 확정 커밋 SHA와 성공한 Exact Push CI로 하고, 실제 결정 기록 후 시작 Gate를 재확인한 뒤 적용한다. 독립 검토·Production/운영 HOLD는 유지한다. 범위·입력 Tier·Policy/Detector/의존성 버전·적용 의무 변경, 사고, 독립 검토자 확보, Release/운영 요청 시 재심사하며 S2–S6은 자동 승인하지 않는다. 효력 범위는 이 S1 작업에 한정한다.

이 문구는 채택 가능한 초안이지 사용자가 실제로 이 전문을 채택했다는 증거가 아니다. 부분 채택·거부도 기록할 수 있으나 필수 조건이 미확인이면 코드를 시작하지 않는다. 임의의 날짜·서명·외부 검토자·법적 보증을 부가하지 않는다.

## 19. Remaining Blockers

1. §18의 실제 권한/의무 확인과 구체적 채택·효력 기록이 없다.
2. §7–14를 대상으로 하는 실제 S1 구현 승인이 없다.
3. 시작 기준 SHA와 Exact Push CI는 소유자의 다음 결정·Push 후 고정한다. 이번 성공 CI를 향후 미Push 커밋에 재사용하지 않는다.
4. Adapter 구현·실증은 미실시다. 승인 후 §13의 TDD RED/GREEN을 수행하며 해결되지 않은 필수 실패가 있으면 S1 완료 HOLD다.

첫 두 항목은 같은 실제 결정으로 해소할 수 있어 Option 비교나 같은 설계 감사를 반복할 필요가 없다. 승인과 시작 Gate 후 §7 범위에서 바로 S1을 구현할 수 있는 명세다. 고정 30건의 성공으로 Tier 1 입력의 privacy·완전성·권한이나 미지 환경의 안전성을 증명하지 않는다.

## 20. Final Decision

`ER_1D_S1_G_AUTHORIZATION_PACKET_LOCAL_CONDITIONAL_GO`는 승인 준비 자료의 완료만 뜻한다. 기술 명세는 S1_TECHNICAL_READY, 정책 효력·구현 승인은 PENDING이며 종합 S1 착수는 HOLD다. 구현·정책 효력·독립 검증·사용자 수용·운영 승인을 선언하지 않는다.

### 검증 기록

로컬 macOS 실측 결과이며 기준 SHA의 GitHub Ubuntu 결과(§2)와 구별한다.

| 검증 | 결과 |
|---|---|
| 변경 전 `uv run pytest -q` | 3901 passed, 2 warnings, 140.10초 |
| 신규 문서 계약 TDD RED | 문서 부재로 4 failed |
| 신규 S1-G 및 P/G0/S0/G1/G2/G3/S1-P 문서 계약 GREEN | 28 passed |
| 기존 Owner/Brute/Replay/Holdout 관련 회귀 | 73 passed, 2 warnings |
| 변경 후 전체 `uv run pytest -q` | 3905 passed, 2 warnings, 121.60초 |
| `uv run python -m app.evaluation` | Synthetic Boundary 79/79, Risk 70/70, Case 70/70, Linux Process 합성 21/21 |
| `uv lock --check` | 성공, 기존 58 packages |
| `uv run python -m compileall -q app tests` | 성공 |
| `git diff --check` | 성공 |

경고 2개는 기존 Starlette/httpx 및 anyio deprecated API 사용으로 동일하다. 기존 Node timeout은 변경 전후 모두 재발하지 않았다. 문서 회귀는 이 신규 테스트 파일과 기존 7개 문서 테스트 파일, 분석 회귀는 S1-P의 E1–E5에 해당하는 기존 8개 테스트 파일로 실행했다. 이번 추가는 이 문서·색인·문서 계약 테스트뿐이며 연구 실행 코드는 추가하지 않았다. 기존 Production/Replay/Corpus/Label/Snapshot/Pin/Dependency/CI/Release 경로의 Git 변경은 없다. 이 문서 테스트는 미래 Adapter의 22개 부정 테스트를 실제 실행한 결과가 아니며, 합성 평가 수치는 운영 정확도·정책 권한·독립 검토·S1 승인의 증거가 아니다.

### 소유자 확인용 짧은 미채택 승인문

“내부 연구 정책 결정권과 적용 의무 충돌 없음을 확인하고 G3 R1–R6 및 이 S1-G §5–14를 채택한다. 내가 지정하는 S1-G 커밋 SHA/성공 Exact CI를 기준으로 §7의 4개 파일만 변경하는 Tier 0 Brute Restricted Adapter 구현을 승인한다. Production/Replay 불변, privacy/network 차단, 모든 부정 테스트와 중단 조건, 독립 검토·운영 HOLD는 유지한다. Tier 1/2/3 및 S2 이후는 승인하지 않는다. 실제 결정 기록과 시작 Gate 확인 후 적용한다.”
