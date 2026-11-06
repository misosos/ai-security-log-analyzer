# ER-1D-S0-G3 — Solo Research 정책 방향 결정 및 적용 계약

## 1. Executive Summary

사용자의 Option B 연구 정책 개정 **방향 승인**을 실제 대화 근거로 기록한다. 사용자는 내부 정책에 대한 결정권을 가진다는 전제를 붙였으며, S1 구현은 별도 Gate와 승인 후에만 시작하고 독립 검토·운영 HOLD를 유지하도록 결정했다. G1/G2에서 제안한 내용을 좁은 연구 정책 조항으로 정리했지만 권한·외부 의무·구체적 문구 채택 등 효력 요건은 아직 미확인이다.

`SOLO_RESEARCH_POLICY_EFFECTIVENESS_PENDING`과 `ER_1D_S1_IMPLEMENTATION_HOLD`를 유지한다. 방향 승인 여부를 다시 묻는 단계는 완료됐다. 남은 것은 그 방향에 따른 적용 계약의 효력 확인과 개별 구현 Gate다. 이번 문서와 문서 계약 테스트는 S1 코드·Adapter·입력 기능을 구현하지 않는다.

## 2. Start Gate

- 기준 SHA: `1f8d1d32f35d63e34f69110d670f9c6422753110`.
- Exact CI: [42246247734](https://github.com/misosos/ai-security-log-analyzer/actions/runs/42246247734), push, head SHA 일치.
- 최초 조회는 `in_progress`여서 `ER_1D_S0_G3_START_GATE_HOLD`로 종료했고 당시 파일은 변경하지 않았다.
- 이후 사용자의 실제 지시 “ci가 오래걸려서 일단 진행해”에 따라 **CI 완료 전 문서·테스트 작업 진행**을 허용받아 재개했다. 이는 연구 정책 효력이나 S1 구현 승인을 추가한 지시가 아니다. 재개 조회에서도 CI가 진행 중이었으므로 필수 CI 완료를 추정해 기록하지 않는다.
- 재개 시 HEAD/local main/origin main 및 원격 main이 위 SHA에 일치, tree clean, ahead/behind 0/0. Artifact 조회는 0개. `v0.4.0` tag의 dereferenced target과 GitHub Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`로 불변이었다.
- 작업 중 후속 재조회에서 동일 Exact CI가 `push / completed / success`로 완료됐다. Head SHA 및 Locked Python 3.12·필수 Linux·Restricted Report·Chromium/axe·tracked-file 전체 성공, Artifact 0개를 직접 확인했다. 완료 후 재확인 판정은 `ER_1D_S0_G3_START_GATE_GO`다. 이는 최초 대기 상태나 사용자 지시로 먼저 진행한 이력을 소급 변경하지 않는다.
- `AGENTS.md` 및 security-analysis/security-testing 지침을 확인했다. 현행 정책·근거·코드의 계약 감사로 한정하며 새 탐지 의미·임계값을 제안하지 않는다.
- 로컬 macOS 변경 전 `uv run pytest -q`: `3893 passed, 2 warnings`. GitHub Ubuntu 결과와 구분한다. 종료 시 CI 재확인 및 로컬 결과는 §17에 기록한다.

## 3. User Decision Record

근거는 이 G3 요청에 포함된 실제 사용자 문구다.

> 내가 결정 권한을 가진 내부 개발 정책이라는 전제하에 Option B 연구 전용 정책 개정 방향을 승인해. 단, S1 구현 자체는 별도 Gate 통과 후 승인하고 독립 검토 및 운영 HOLD는 유지해.

아래는 문서 기록 필드이며 실행 DTO·자동 승인 토큰이 아니다.

| 기록 필드 | 확인된 값 | 의미 |
|---|---|---|
| decision_source | USER_MESSAGE_ER_1D_S0_G3 | 현재 대화의 실제 승인 의사 |
| direction_approval | APPROVED_IN_CONVERSATION | Option B의 연구 전용 정책 개정 방향 승인 |
| authority_verification | CONDITIONAL_USER_STATEMENT | 사용자가 내부 정책 결정권을 가진다는 조건부 진술; 권한 자체의 독립 검증 아님 |
| external_obligations_verification | NOT_INDEPENDENTLY_VERIFIED | 외부 계약·조직 의무 부재는 확인되지 않음 |
| approval_date | NOT_PROVIDED | 사용자 승인 날짜가 별도로 제시되지 않아 생성하지 않음 |
| signature | NOT_PROVIDED | 서명을 받거나 생성하지 않음 |
| policy_text_adoption | PENDING_CONFIRMATION | 아래 조항의 구체적 채택·적용 조건 확인은 미완료 |
| policy_effectiveness | SOLO_RESEARCH_POLICY_EFFECTIVENESS_PENDING | 실제 시행으로 표시하지 않음 |
| research_track_operation | BLOCKED_PENDING_EFFECTIVENESS_AND_PHASE_GATE | 방향 승인만으로 새 연구 코드 실행·개발 권한이 생기지 않음 |
| s1_implementation_approval | NOT_GRANTED | S1 구현 별도 승인 전 |
| independent_review_completion | NOT_ESTABLISHED | 기존 INDEPENDENT_HUMAN_REVIEW_PENDING 유지 |
| production_operation_approval | NOT_GRANTED | Production 및 운영 승인 없음 |
| policy_validity_period | UNDECIDED | 승인권자가 정할 유효기간·적용 시점 미확정 |

사용자의 방향 승인 사실을 이전의 단순 제안·승인 미확인 상태로 되돌리지 않는다. 동시에 방향 승인으로 법적 권한, 의무 부재, 독립 검토 또는 각 Tier 실행 허가를 증명하지 않는다. 검토자·법적 근거·날짜·서명을 만들어 빈칸을 채우지 않는다.

## 4. Authorization Authority and Conditions

이 기록의 적용 대상은 본 저장소 내부 연구 개발 정책이다. 실제 결정권이 해당 내부 정책에 미치는 범위, 적용되는 프로젝트 상위 지침, 외부 계약·조직 의무와의 충돌 유무를 실제 결정권자가 확인하고 근거를 남겨야 한다. 현재의 조건부 진술만으로 이 확인이 끝났다고 볼 수 없다. 상위 지침 또는 변경할 수 없는 의무와 충돌하면 본 연구 예외는 효력을 갖지 않는다.

방향 승인은 기록할 수 있으며 권한·효력 확인은 별도다. 이는 법률 판단이나 소유권 인증이 아니다. 별도 외부 승인 제도가 있다고 추정하지도 않는다. 확인되지 않은 의무의 부재를 자동으로 참으로 처리하지 않는다. 구체적 문구와 적용 조건을 채택하는 후속 기록에서 실제 승인자가 효력의 시작·범위·유효기간을 결정해야 하며, Codex나 CI가 그 결정을 대신하지 않는다.

## 5. Governance Conflict Resolution

| 이전 근거와 정확한 절 | 당시 요구 | 본 계약이 효력을 가질 경우의 좁은 적용 관계 |
|---|---|---|
| [ER-1D-P §14–15](counterfactual_sensitivity_explanation_design_er1d_p.md) | “별도 reviewer 검토와 실제 제출/누락·이견 처리, digest 확인, 독립성 근거 및 수동 승인 없이는 구현을 시작하지 않는다.” | Production ER-1D 및 연구 예외 밖 구현에 계속 적용. 명시적 채택 후 개별 Gate를 통과한 Tier 0 오프라인 연구 범위에만 §6을 추가 적용 |
| [ER-1C-R §13](counterfactual_independent_review_er1c_r.md) | “ER-1D 기능 개발 전 반드시 별도 사람 검토”와 30건 완결·이견·digest·독립성·승인 요구 | 독립 검토 결과·자료와 Production 진입 Gate 유지. 연구 예외가 사람 검토 완료를 의미하지 않음 |
| [G0 §5·9–10](counterfactual_explanation_readiness_audit_er1d_g0.md) | missing evidence 및 사람 검토 선행 조건 | owner-bound aggregate 등 기술적 결측은 정책 결정으로 해결되지 않음. 별도 연구 Gate에서도 검증 필요 |
| [S0 §3·9·13](counterfactual_solo_research_track_er1d_s0.md) | 연구 예외 없음, S1 착수 HOLD | G3는 실제 방향 승인을 추가 기록. 효력과 개별 구현 승인 전에는 같은 HOLD |
| [G1 §3·9–11](counterfactual_solo_research_governance_er1d_s0_g1.md) | Option B 제안·권한 미확인·별도 승인 | 방향 승인 의사는 G3가 최신 기록이며 정책 효력·기술 경계는 여전히 조건부 |
| [G2 §13–16](counterfactual_research_input_scope_governance_er1d_s0_g2.md) | Tier 1/2 확장 제안, G3/S1–S6 개별 Gate | Tier별 확장 방향을 계승하되 현재 처리는 비활성, 특히 S5/S6 Gate를 유지 |

기존 문서는 당시의 역사적 결정으로 보존하며 소급 승인하지 않는다. 향후 본 계약의 권한·의무·문구 채택과 효력 요건을 충족한 결정 기록이 존재할 때만, 적용 시점 이후 명시된 연구 범위에서 충돌하는 포괄 HOLD에 대해 §6의 제한된 예외를 우선 적용한다. Production·독립 검토·보안 의미·개인정보에 대한 요구는 우선순위를 바꾸지 않는다. 효력 조건이 없거나 범위를 벗어나면 기존 HOLD가 적용된다. 역사적 문서 자체를 지우거나 당시 판단을 덮어쓰지 않는다.

## 6. Revised Solo Research Policy

다음 조항은 실제 사용자 승인 방향에 따라 정리한 **효력 확인 대기 계약 문구**다. 조항 작성만으로 시행되지 않는다.

| 조항 | 적용 계약 |
|---|---|
| R1 제한적 연구 범위 | AI Security Log Analyzer는 독립 사람 검토가 완료되지 않았더라도, 권한이 확인된 소유자의 명시적 연구 정책 결정이 효력을 갖고 개별 기술·보안 Gate 및 구현 승인을 충족한 경우, 고정 합성 데이터에 대한 격리된 오프라인 연구용 프로토타입 개발을 별도 범위에서 검토할 수 있다. |
| R2 신규 입력 | 사용자 정의 합성 로그는 별도 입력 보안 Gate와 명시적 구현 승인, S5 범위를 받은 경우에만 추가 검토한다. 실제 로컬 로그는 별도 Tier 2/S6 권한·Privacy/Security·보관·삭제 Gate 이전에 처리하지 않는다. 운영 Live는 NO_GO다. |
| R3 변경 한계 | 허용된 연구 파일·고정 입력 및 명시적 실행만 다룬다. Production 정책/코드, 기존 Replay 공개 DTO, Corpus/Label, Snapshot/Pin, API/UI 및 Investigation 상태 변경을 허용하지 않는다. 이를 수정해야만 연구가 가능하면 범위를 넓히지 않고 HOLD한다. |
| R4 검증·출력 | 같은 실행의 owner/Evidence·scope·Parser completeness를 확인한 안전 집계만 내보낸다. raw log, Source IP, Account, 원본 시각, private context/owner/Evidence, 내부 경로·예외를 출력하지 않는다. fixed 오류, closed bounded output, no network/LLM, 결정성·불변성 검사를 요구한다. |
| R5 결과 의미 | 연구 기록의 자동 검증·자기 검토·미검증·독립 검토 대기를 구분한다. 공격 의도·침해·회피 성공·유일 원인·운영 정확도나 독창성 보증으로 일반화하지 않는다. 연구 결과를 Production 승인 또는 독립 검토 완료로 사용하지 않는다. |
| R6 단계별 효력 | 방향 승인, 정책 효력, 개별 구현 승인을 별도 기록한다. S1 이후 단계와 Tier 1/2, Release·운영은 자동 진급하지 않는다. 위반 시 §13에 따라 중단·격리·검토한다. |

연구 방향 승인 = S1 구현 승인, 자체 테스트 통과 = 독립 검토 완료, 연구용 코드 = Production 배포 가능, Tier 1 승인 = Tier 2 승인, 합성 처리 성공 = 실제 로그 안전성 입증이라는 해석을 금지한다.

## 7. Effective Scope and Pending Preconditions

| 항목 | 현재 기록 | 효력 또는 실행 전 필요한 근거 |
|---|---|---|
| Option B 방향 | 승인됨 | 다시 방향 승인 여부를 묻지 않고 기록을 사용 |
| 권한과 적용 의무 | 조건부 진술 / 미확인 | 실제 내부 결정권 범위·적용 지침 및 의무 충돌 검토 기록 |
| 구체적 정책 조항 | R1–R6 작성, 적용 대기 | 정확한 문서 버전·채택 대상 조항·우선순위·시작 시점과 재검토 조건 확인 |
| 정책 효력 | SOLO_RESEARCH_POLICY_EFFECTIVENESS_PENDING | 위 조건의 확인을 담은 실제 후속 결정 기록 |
| 연구 트랙 구현 운영 | 대기 | 정책 효력과 해당 단계 기술·보안 Gate 및 명시적 구현 승인 |
| S1 | ER_1D_S1_IMPLEMENTATION_HOLD | §11 전체 및 별도 실제 S1 승인 |

개별 승인 기록은 기준 Commit SHA, 허용 파일·실행·import/파일 읽기 범위, 적용 Corpus/정책 버전, 금지 변경, 검증 결과·한계, 중단·롤백, 유효기간을 명시해야 한다. 기준 SHA에서 승인된 변경 범위 안의 구현만 허용하는 계약이며, 문서 작성이나 일상 커밋이 자동 승인·자동 만료를 결정하는 시스템을 만들지 않는다. 효력 시작과 기간은 확인 전 `UNDECIDED`다.

## 8. Tier 0–3 Input Authorization Matrix

| Tier | 인정된 방향 | 현재 새 실행 권한 | 다음 조건 |
|---|---|---|---|
| Tier 0 — Fixed Synthetic Corpus | Development 16 + Holdout 14를 불변 회귀 기준으로 보존하고 연구에 사용하는 후보 | 기존 승인된 Replay/평가 계약의 실행은 유지. 새로운 S1 구현은 승인되지 않음 | Manifest/Fixture/Label/Digest 및 독립 검토 자료 불변, 정책 효력·S1 Gate |
| Tier 1 — User-Defined Synthetic Logs | G2의 확장 방향 인정 | 새 입력 기능 구현·활성화 없음 | 별도 S5 Security Gate와 명시적 구현 승인. 비신뢰 입력, strict UTF-8·크기·Source allowlist·Parser disposition·수명·기본 영구 저장 금지·provenance·privacy·네트워크 차단·Label 격리 |
| Tier 2 — User-Authorized Local Logs | 권한 있는 실제 로컬 로그의 후속 가능성 검토 | 구현·처리 승인 없음, 실제 사용자 자료 NO_GO | 별도 권한·Privacy/Security·보관·삭제·명시적 사용자 승인 및 S6 검토 |
| Tier 3 — Operational Live Logs | 현재 범위 밖 | NO_GO | 실시간 수집·SIEM·원격 수집·지속 감시·운영 변경·자동 대응 금지 |

사용자의 합성 선언은 민감정보가 없다는 증거가 아니다. Tier 1 결과에 정답 Label을 자동 부여하거나 Tier 0 회귀 점수에 합산하지 않는다. 사용자 정의 입력의 Label provenance 공백과 비교 semantics는 [G2 §10–11](counterfactual_research_input_scope_governance_er1d_s0_g2.md)의 별도 미해결 Gate로 유지한다.

## 9. Research/Production Isolation Contract

후속 연구 후보 위치는 `app/evaluation/research_er1d/`다. 이번 단계에 디렉터리나 실행 코드를 만들지 않는다. 폴더명만으로 격리를 증명할 수 없으므로 명시적 로컬 evaluation-only 진입점, 기본 실행 경로에서 비활성, import 그래프, 고정 파일 읽기 allowlist, 임시 자료 수명, 외부 네트워크·LLM 차단, 출력 schema와 bytes 한도를 검증해야 한다.

Production API/UI와 Feature Flag, Investigation registry/Checklist/Report/Live/SSE 등에 연결하지 않는다. Parser/Detector 정책, Risk/Correlation, 기존 Replay 공개 DTO, Corpus/Label, Snapshot/Trusted Pin을 변경하지 않는다. Tier 0의 고정 소스 읽기와 검증된 bytes의 내부 임시 사본만 후보이며 임의 파일 경로·사용자 실제 로그 접근을 받지 않는다. private 객체는 같은 실행의 검증 수명 안에 머물게 하고, 안전 집계는 검증 후 별도 불변 객체로 복사한다. 실패 시 Claim을 보류하고 입력이나 예외 원문을 fixed 오류에 반사하지 않는다.

## 10. Restricted Adapter Constraints

기술 분류는 G1/G2의 **`FEASIBLE_ONLY_WITH_RESTRICTED_ADAPTER`**를 유지한다. 이는 코드 독해상의 조건부 후보이며 안전한 adapter가 구현·검증됐다는 판정이 아니다.

| 코드 근거 | 현재 확인한 구조 | S1에서 반드시 검증할 경계 |
|---|---|---|
| `app/main.py::_analyze_normalized_logs_with_context()` / `analyze_with_source_role_snapshot()` | 실행마다 새 `AnalysisRunOwner`를 생성하고 analysis·source roles·Brute contexts·owner를 같은 bundle로 반환 | 실제 고정 bytes 및 Parser profile과 bundle의 결속, Baseline/Variant owner 분리, 동일 실행 객체의 수명 안에서 검증 |
| `app/analyzer/pipeline.py::detect_attacks_with_context()` | 선택된 `BruteWindowContext`로 Detection을 만들고 owner에 결과를 결속 | 같은 subject의 실제 Detection과 context 및 owner가 일치하는지 확인. 재포장·교체된 결과나 사후 계산만으로 성공 처리하지 않음 |
| `app/detector/brute_force.py::validate_brute_window_context()` / `brute_evidence_matches_context()` / `brute_window_context_owner()` | member event의 IP/account/실패·시각·count와 context, Detection Evidence를 대조 | Evidence Membership와 owner identity를 함께 검사. 함수 하나의 성공을 모든 provenance의 보증으로 확대하지 않음 |
| `app/evaluation/counterfactual_replay.py::_execute_production()` 및 `_replay_prevalidated_scenario()` | 합성 bytes의 별도 Production 실행·bundle binding·context/Evidence·서로 다른 owner를 검사한 뒤 공개 결과를 생성 | 기존 검증을 완화·우회하거나 공개 DTO에 private 필드를 추가하지 않는 재사용 계획. 기존 Replay 계약 수정이 불가피하면 HOLD |
| `app/detector/password_spray.py::detect_password_spray()` / `summarize_ip_failures()` | 같은 IP의 전체 실패 feature와 whole-span 조건 | Brute selected-window와 다른 scope임을 보존하고 window prototype과 혼합하지 않음 |
| `counterfactual_comparison.py::compare_runs()` | version·source/profile·scope·Parser·label provenance·binding·실행 상태를 구분 | 기존 INCOMPARABLE/UNDETERMINED 및 reason 의미 유지. 버전·근거 부족을 출력 편의를 위해 보정하지 않음 |

Brute는 같은 IP와 알려진 동일 계정의 selected-window이며 Spray는 같은 IP 전체 실패의 whole-span이다. `SafeFacts.target_failure_count`와 target span은 Parser-level IP 집계로서 선택 Window의 count/span이 아니다. 검증한 Brute context가 없는 음성 결과에서 선택 Window 값을 0으로 발명하지 않는다. PARTIAL의 집계는 subset 한계를 지니며 REJECTED는 Detector NOT_EVALUATED다.

owner는 같은 프로세스의 실행 capability이며 디지털 서명·외부 출처 인증이 아니다. membership/context 내부 정합성은 원천 로그 수집의 완전성까지 증명하지 않는다. 객체가 반환된 뒤 참조가 존재하는 수명과 그 객체의 정보가 공개적으로 신뢰 가능하다는 것은 다르다. 사후 SafeFacts와 다른 실행의 context를 조합하지 않고 검증 시점의 실제 bundle을 사용해야 한다.

## 11. S1 Separate Implementation Gate

아래 조건은 새 S1 구현 착수 **이전**에 모두 확인한다. 계획과 구현 후 검증을 구별한다. 초기 착수에는 실행 구조·허용 범위와 필수 반증 계획을 고정하고, 구현 중 TDD에서 그 계획을 검증한다. 아직 없는 S1 코드의 테스트 PASS를 착수 근거로 만들어내지 않는다.

| Gate | 착수 전 필요한 자료 | 미충족 시 |
|---|---|---|
| Governance | §4·7의 실제 권한/의무 확인, R1–R6의 채택·효력 및 기존 HOLD와의 적용 관계 기록 | 정책 효력 PENDING, S1 HOLD |
| Scope 승인 | 실제 별도 S1 구현 승인, 기준 Commit SHA, Tier 0 한정과 허용 파일·금지 변경 목록 | 방향 승인으로 대체 불가 |
| Git/CI | S1의 정확한 기준 SHA·성공한 Exact Push CI, artifact·Git·Release Gate | 다음 단계 시작 HOLD; 이번 문서 진행 지시는 S1 CI 예외가 아님 |
| 격리 설계 | 명시적 evaluation 진입점·기본 비활성·import/파일 읽기/임시 수명·network/LLM 차단 경계 | Research 폴더명만으로 통과 불가 |
| 동일 실행 근거 | Production 호출 경로를 읽기 전용으로 재사용하는 계획, Baseline/Variant owner·subject·Evidence Membership 및 scope/policy/detector/profile version 검증 | Production/Replay 계약 변경이 필요하면 HOLD |
| 최소화 | 안전 count/span·closed status만 출력하는 allowlist, private 객체·Source IP/Account·원문/원시 Timestamp 제외, fixed 오류와 bounded bytes 한도 | 출력 schema 확정 전 착수 불가 |
| 반증 계획 | §12의 Cross-run Injection Test, Privacy Canary Test, Deterministic Output Test 및 기존 Production 불변·실패 보류 검증 계획 | 임의 skip/완화 금지 |

후속 파일 후보는 해당 경로의 필요한 초기화 파일·단일 제한 aggregate/adapter 모듈, 전용 테스트 및 S1 문서다. 정확한 파일명·개수·출력 한도·실행 명령은 별도 S1 Gate에서 확정하며 이 후보 목록은 생성 승인이 아니다. 안전한 내부 재사용 경로가 확정되지 않으면 기존 Production 또는 Replay 코드를 수정해 우회하지 않는다.

## 12. Security Negative Tests

아래는 S1 이후 필요한 테스트 **계획**이다. 이번 G3에서 실행하거나 PASS로 인정한 연구 실험이 아니다. 기존 상태와 오류 의미를 유지하며, 실패 입력은 원본 Corpus bytes가 아닌 분리된 합성 객체·사본에 주입한다.

| 입력/주입 조건 | 기대 동작과 금지 출력 | 검증 또는 HOLD 기준 |
|---|---|---|
| Cross-run owner 또는 context 교체 | owner identity/binding 거부, Claim 없음 | 같은 값이라도 다른 실행 객체를 허용하면 HOLD |
| Evidence Membership·subject·member count/time 불일치 | context/Evidence 검증 실패, 해당 결과 보류 | 선택 Window 값을 믿거나 원문 예외를 내보내면 HOLD |
| 검출됐지만 Empty Evidence / 음성인데 context 존재 | 기존 Replay 정합성 검사대로 거부 | 검출/음성 보정이나 가짜 선택 창 금지 |
| Target IP SafeFacts를 Brute count/span으로 주입 | scope mismatch, 선택 집계 Claim 보류 | 전체 IP 집계를 선택 Window로 출력하면 HOLD |
| Spray whole-span을 sliding으로 교체 | Production scope 일치 실패 | 다른 정책 값을 같은 근거로 사용하면 HOLD |
| Parser PARTIAL/REJECTED·missing Account/Timestamp | subset/NOT_EVALUATED와 기존 비교 불가·불확정 보존 | 거부·미실행을 NOT_DETECTED나 0/False로 만들면 HOLD |
| Policy/Detector Version·source/profile/provenance 불일치 | 비교 보류, INCOMPARABLE 또는 기존 fixed reason | 버전·출처를 추정해 맞추면 HOLD |
| Private Context, Raw Log, Source IP/Account, 시각·경로·exception canary | allowlist/bytes/stdout/stderr/log 검사에서 0 | 한 항목이라도 노출 시 즉시 HOLD |
| 비정상 타입·collection·입력 또는 출력 bytes 초과 | 명시적 resource bound에서 전체 거부 | 절단 성공·원문 반사·unbounded 처리 금지 |
| 임의 경로·사용자 입력·Tier 1/2 호출 | 승인된 Tier 0 외 입력 거부 | 연구 범위를 자동 확장하면 HOLD |
| 네트워크/LLM 호출·Production API/UI import 활성화 | 연결 시도·자동 호출 0 | 시도 또는 기존 실행에 연구 기능 활성화 시 HOLD |
| Production 결과, Corpus/Label·Snapshot/Pin 또는 Replay 공개 계약 변조 | 기존 regression·digest·변경 파일 검사로 불변 확인 | 차이가 생기면 HOLD; 기대값 수정으로 통과 금지 |
| 같은 입력 반복·순서 변경·Claim/Replay 모순 | 반복 canonical bytes 동일, 기존 scope/reason/결과 보존 | 결과 충돌을 Detector 재작성으로 숨기면 HOLD |

S1 구현 중 안전상 실패가 나면 먼저 회귀 RED를 기록하고 원인을 수정·검증한다. 해결되지 않은 필수 실패를 성공으로 표시하지 않으며 승인 범위를 바꾸는 수정을 자동 수행하지 않는다.

## 13. Stop/Rollback Conditions

private context·Raw Log/IP/Account 유출, owner 교차 결합·membership 실패 수용, 잘못된 Window 집계, Production 결과 변경, Corpus/Label·Replay 공개 계약 변조, 네트워크 호출, 입력 한도 실패, 승인되지 않은 입력, policy scope 불일치, Parser 실패의 NOT_DETECTED 처리 또는 Claim/Replay 모순이 발생하면 즉시 해당 연구 실행과 구현 진급을 HOLD한다.

롤백은 연구 전용 실행을 중단·비활성화하고 해당 phase의 변경과 생성물만 식별하는 절차다. 필요한 증거는 비공개로 보존하고 오류·원문을 공개 기록에 붙이지 않는다. 명시적 범위의 변경을 검토 가능한 역커밋 또는 patch로 되돌리며 사용자 작업물을 삭제하거나 reset/clean/stash/강제 checkout으로 정리하지 않는다. 기존 Production 결과·고정 입력·Replay 공개 계약 및 network 0을 다시 확인한 후 승인권자의 범위 재확인과 실패 회귀 GREEN이 있어야 재개를 검토한다. 이번 G3는 실행 모듈을 만들지 않아 비활성화할 연구 기능이 없다.

## 14. Independent Human Review Preservation

- `INDEPENDENT_HUMAN_REVIEW_PENDING`
- `MANUAL_APPROVAL_REQUIRED`
- `ER_1D_IMPLEMENTATION_HOLD`
- `ER_2F_USER_ACCEPTANCE_PENDING`
- 실제 사용자 자료·조직 운영·자동 대응: `NO_GO`

`MANUAL_APPROVAL_REQUIRED`는 기존 독립 검토·Production 진입 수동 승인의 미완료 상태다. 이미 확인된 연구 방향 승인과 혼동하지 않는다. `ER_1D_IMPLEMENTATION_HOLD`도 전반적 구현 자동 승인으로 바꾸지 않는다. 향후 효력 있는 좁은 연구 예외 및 개별 phase 승인만 따로 기록하며 Production HOLD는 유지한다.

ER-1C-R/H0의 30건 Label-Blind Packet·정책·빈 양식·digest·제출/이견 처리와 실제 검토자 독립성 근거 요구를 보존한다. `counterfactual_review_packet.py`는 비교를 해도 review status를 PENDING, independence를 SELF_REPORTED_NOT_VERIFIED, approval을 MANUAL_APPROVAL_REQUIRED로 출력한다. 실제 제출·서명·완료 기록은 생성하지 않는다. 연구 예상값·자기 검토와 기존 Label을 독립 검토자에게 정답으로 제공하지 않는다.

## 15. Policy Reassessment Conditions

Production 코드 또는 Replay 계약 수정 필요, Tier 1 활성화·실제 로컬 로그 요청, Detector 범위 확대, 개인정보/보안 사고, 독립 검토자 확보, Corpus/Policy Version 변경, Release·운영 배포 요청이 있으면 즉시 현재 scope를 재검토한다. 범위 밖 확장은 재승인 전 HOLD다. 새로운 근거가 확인되면 보안·개인정보 제약과 독립 검토 경로에 대한 영향도 함께 평가한다.

정책의 적용 시작 시점·기간은 `UNDECIDED`다. 정해진 만료일이나 실제 승인 날짜를 만들어내지 않는다. 기간을 정하더라도 위 조건은 별도의 재검토 trigger로 유지하고, 유효기간 종료 시 연구 실행을 중단해 적용 여부를 다시 확인한다.

## 16. Open Authorization Issues

미확인 항목은 실제 내부 권한 범위와 적용 의무 충돌, R1–R6의 구체적 채택/효력 시점·기간, 별도 S1 승인 및 정확한 허용 파일·실행/출력 상한, 제한 adapter의 구현 가능성·보안 실증이다. 이 중 방향 승인 자체는 이미 확인됐으므로 재승인을 기다리는 항목으로 되돌리지 않는다. Tier 1/2 입력 구현과 사람 검토·운영 승인도 아직 없다.

고정 합성 실험·정적 코드 감사는 수집 완전성, 실제 계정/시계/운영 문맥, 독립 정확도 또는 권한을 입증하지 않는다. NIST/MITRE 배경과 기존 정책 조건의 관측 근거는 [ER-0](evidence_research_er0.md), 현재 missing evidence는 [G0](counterfactual_explanation_readiness_audit_er1d_g0.md)를 참조한다. 정책 임계값을 바꾸거나 법적 권한 판단을 새로 확정하지 않는다.

## 17. Final Decision

`ER_1D_S0_G3_POLICY_DECISION_RECORDED_LOCAL_CONDITIONAL_GO`는 실제 사용자 방향 결정의 기록과 정책 적용 계약 정리에 한정한다. 정책 효력은 `SOLO_RESEARCH_POLICY_EFFECTIVENESS_PENDING`, S1 구현은 `ER_1D_S1_IMPLEMENTATION_HOLD`다. 권한·의무 확인 및 정책 효력 기록 이후에도 실제 S1 구현 승인과 별도 기술·보안 Gate 전에는 코드를 시작하지 않는다.

### 검증 기록

변경 전 로컬 전체 pytest: 3893 passed, 2 warnings. TDD RED: 문서·색인 부재로 G3 계약 테스트 4 failed. 작성 후 G3 및 S0/G1/G2/G0/P 문서 계약 GREEN: 20 passed. 변경 후 전체 `uv run pytest -q`: 3897 passed, 2 warnings. `uv run python -m app.evaluation`: Synthetic Boundary 79/79, Risk 70/70, Case 70/70, Linux Process 합성 21/21. `uv lock --check`, `uv run python -m compileall -q app tests`, `git diff --check` 성공. 기준 SHA의 종료 CI 확인은 §2와 같고 새 로컬 커밋의 원격 CI 결과가 아니다. 변경 범위는 이 신규 문서, docs/index.md, G3 문서 계약 테스트로 제한했다. 문서 테스트와 합성 평가 수치는 승인권한·정책 효력·독립 검토·S1 구현 승인 또는 운영 탐지 성능을 증명하지 않는다.
