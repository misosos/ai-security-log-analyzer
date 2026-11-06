# ER-1D-S0-G1 — Solo Research Governance 결정 자료

## 1. Executive Summary

**`SOLO_RESEARCH_POLICY_PROPOSED` / `PROPOSED_NOT_APPROVED` / `SOLO_RESEARCH_AUTHORIZATION_PENDING`**. 1인 개발자의 합성 연구 지속을 위해 제한적 정책 개정안과 S1 진입 조건을 제안한다. 이번 요청은 정책 변경·구현 승인·서명이 아니다. `S1 착수 HOLD`와 기존 ER-1D 구현 HOLD를 유지한다. 추천은 현재 Option C로 설계와 기존 평가를 계속하고, 소유자가 명시적으로 선택할 수 있도록 Option B의 정책 개정안을 심사 자료로 준비하는 것이다.

## 2. Exact Start Gate

시작 SHA `15f632054578d5bb4bad5743974319e4c9fe298b`; Exact CI `42223892480`은 push / completed / success, head 일치. Locked Python 3.12 regression, Linux, Restricted Report, Chromium/axe, tracked-file 단계 성공, Artifact 0. HEAD/local main/origin main/GitHub main 일치, tree clean, ahead/behind 0/0. `v0.4.0` tag와 Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 불변. `AGENTS.md` 및 관련 security-analysis/security-testing 지침을 따른다. `ER_1D_S0_G1_START_GATE_GO`. 시작 로컬 macOS pytest `3887 passed, 2 warnings`; CI는 Ubuntu 결과다.

## 3. 기존 HOLD와 정책 충돌

| 근거 | 현행 문장 및 의미 | 제안과의 관계 |
|---|---|---|
| [ER-1D-P §14](counterfactual_sensitivity_explanation_design_er1d_p.md) | “별도 reviewer 검토와 실제 제출/누락·이견 처리, digest 확인, 독립성 근거 및 수동 승인 없이는 구현을 시작하지 않는다.” | 연구 전용 구현 예외가 명시되지 않아 B를 현 상태에서 시행하면 충돌한다. |
| [ER-1D-P §15](counterfactual_sensitivity_explanation_design_er1d_p.md) | “다음 구현을 별도 승인 후에만 시작한다”; human approval 부재는 구현 HOLD | 단순 S0/G1 성공은 승인이나 예외가 아니다. |
| [ER-1C-R §13](counterfactual_independent_review_er1c_r.md) | “ER-1D 기능 개발 전 반드시 별도 사람 검토”와 30건 완결·이견 처리·digest·독립성·승인 요구 | Production Gate는 그대로 유지; 연구 예외를 원하면 적용 범위를 명시적으로 결정해야 한다. |
| [ER-1D-G0 §5·9](counterfactual_explanation_readiness_audit_er1d_g0.md) | owner-bound safe aggregate 등 증거 부재, 독립 검토와 승인 후 구현 Gate 재평가 | Missing Evidence와 경계는 정책 결정으로 해소되지 않는다. |
| [ER-1D-S0 §3·9](counterfactual_solo_research_track_er1d_s0.md) | 연구용 구현 예외는 미해결, S1 포함 구현 HOLD | G1은 변경안만 준비한다. |
| [ER-0 §4·7](evidence_research_er0.md), [ER-1B](counterfactual_detector_replay_er1b.md) | private owner/context·원문은 공개 금지, 재생과 설명의 근거 범위를 구분 | 좁은 연구라 해도 evidence/privacy 계약은 유지한다. |

기록은 작성 당시의 판단이다. 이후 권한 있는 결정이 있으면 날짜·범위·기준 SHA와 새 정책 문서를 연결하고 적용 시점부터 효력을 정의한다. 과거 HOLD 기록을 지우거나 당시부터 예외가 있었다고 고치지 않는다.

## 4. 프로젝트 소유자의 권한 및 한계

| 결정 | 판단 | 조건과 한계 |
|---|---|---|
| A 내부 연구 정책 변경 | 실제 프로젝트 소유자에게 해당 저장소의 내부 정책을 변경할 권한이 있고 다른 구속력이 없다면 변경을 결정할 수 있다. | 이 대화나 Git 작성자 이름만으로 법적 신원·소유권·조직 또는 제3자 의무를 확인할 수 없다. 권한 근거와 적용 의무를 결정 전에 확인해야 하며, 확인되지 않으면 승인 불가. 법률 판단을 여기서 확정하지 않는다. |
| B 연구용 구현 승인 | 적용 가능한 내부 정책을 명시적으로 개정한 후 승인권자가 범위를 정할 수 있다. | 정책 개정과 S1 범위 승인은 별도 기록. 자동 테스트나 Codex 의견은 승인자가 아니다. |
| C 독립 검증 완료 | 작성자의 자기 검토만으로 완료할 수 없다. | 독립 검토자·제출 및 이견 처리·독립성 근거를 확인해야 한다. |
| D Production/운영 | 연구 권한과 별개다. | 기존 독립 사람 검토와 수동 승인 요구 및 실제 운영 NO_GO 유지. |

`AGENTS.md`는 명시적 요청 없는 commit/push를 금지하고 보안 의미·데이터 경계를 정하지만, 정책 변경 권한자의 신원을 인증하는 절차는 제공하지 않는다. 외부 계약이나 법적 의무의 부재는 확인되지 않았다. 권한 확인이 안 된 경우 B를 승인할 수 없다.

## 5. Option A/B/C 비교

| 기준 | A 기존 HOLD 유지 | B 연구 전용 정책 변경 제안 | C 설계·기존 평가만 계속 |
|---|---|---|---|
| 기존 정책 | 충돌 없음 | 현행 포괄 HOLD와 충돌; 승인된 장래 개정 필요 | 충돌 없음 |
| 보안 위험 | 새 코드 위험 최소 | 경계 실패·private context 누출 위험 증가 | 기존 평가의 범위·한계 유지 |
| 재현성 | 기존 자료만 | 고정 합성 입력·결정성 검사로 확보 가능하나 구현 전 미증명 | 기존 고정 평가 재실행 가능 |
| 독립 검증 신뢰성 | 독립 검토 대기 | 자기 검토와 자동 검사는 독립성 제공 안 함 | 독립 검토 대기 |
| 1인 실행 가능성 | 검토자 확보까지 구현 대기 | 권한 확인·정책 개정·격리 검증 후 후보 | 현재 설계·학습 가능 |
| 구현 복잡도 | 없음 | adapter·검증·출력 경계 비용 | 새 구현 없음 |
| 포트폴리오 실질 가치 | 검토 절차와 위험 통제 | 제한적 실험 근거를 만들 가능성, 미승인·미검증 표시 필요 | 기존 결과 및 설계의 한계 있는 설명 |
| 향후 Production 위험 | 기존 Gate 유지 | 연구 결과를 운영 승인으로 오인할 위험; 별도 Gate 필수 | Production 연결 없음 |

## 6. 추천 Governance 경로

현재 C를 선택해 기존 합성 평가와 설계를 계속하고, B를 소유자가 심사할 수 있는 `PROPOSED_NOT_APPROVED` 안으로 제공한다. A는 가장 보수적인 대안이다. B는 S1의 자동 승인, 독립 검토 완료 또는 Production 예외가 아니다. 허용 권한이 확인되지 않거나 소유자가 선택하지 않으면 기존 A/C 경계와 HOLD를 유지한다.

## 7. 연구용 격리 경계

B가 향후 승인될 경우 후보 경로는 `app/evaluation/research_er1d/`의 별도 평가 코드와 전용 테스트다. 고정 합성 Corpus만, 명시적 오프라인 실행만 허용한다. 임의 사용자 경로·URL·Corpus 입력, 외부 네트워크·LLM, Production API/UI 및 Investigation 상태, Feature Flag를 통한 암묵적 활성화, 자동 대응·자동 승인은 금지한다. Parser/Detector/Correlation/Risk, 기존 Corpus/Label, Replay 공개 계약, Snapshot/Pin을 수정하지 않는다. Raw Log, IP/Account, 원본 Timestamp, private owner/context/Evidence, 경로 및 예외 원문은 출력하지 않는다. 이 경계가 Production 또는 기존 Replay 공개 계약 변경 없이는 구현 불가능하면 S1 HOLD다.

연구 기록의 `AUTOMATED_VERIFIED`, `SELF_REVIEWED`, `NOT_VERIFIED`, `INDEPENDENT_REVIEW_PENDING`은 별도 차원이며 기존 Public DTO나 승인 상태에 넣지 않는다. 자동 검사 통과는 독립 정확도 검증이 아니다.

## 8. S1 기술적 Feasibility

분류: **`FEASIBLE_ONLY_WITH_RESTRICTED_ADAPTER` — 코드 독해에 기초한 조건부 후보이며 구현·보안 검증으로 입증된 가능성이 아니다.** 기존 공개 Replay DTO만으로 owner 결속을 사후 복원할 수 없다. 제한 adapter가 아래 조건을 충족하지 못하거나 Production/Replay 계약 변경이 필요하면 `BLOCKED_BY_PRODUCTION_CHANGE` 또는 HOLD로 재분류한다.

1. `app/main.py::_analyze_normalized_logs_with_context()`는 실행마다 `AnalysisRunOwner`를 생성하고 `detect_attacks_with_context()`에 전달한다. `analyze_with_source_role_snapshot()`은 같은 실행의 analysis, source roles, `brute_window_contexts`, owner를 bundle로 반환한다. 실행 중과 반환 bundle의 수명 동안에만 이 객체들을 함께 확인할 수 있으며 공개 ReplayScenarioResult에는 owner/context가 없다.
2. `app/analyzer/pipeline.py::detect_attacks_with_context()`는 Brute 선택 context를 만들고 owner에 detection 결과를 결속한다. `app/detector/brute_force.py::validate_brute_window_context()`는 member event의 IP·account·event·시간·count와 context 범위를 검사한다. `brute_evidence_matches_context()`는 선택 context와 Detection Evidence의 count·source·범위 등을 대조한다. context의 멤버 내부 정합성만으로 원천 수집 완전성이나 외부 출처 인증이 증명되지는 않는다.
3. `app/evaluation/counterfactual_replay.py::_execute_production()`은 합성 bytes를 임시 파일로 전달해 Production 경로를 호출하고, bundle owner가 analysis에 결속됐는지, context owner가 같은지와 Brute Evidence 일치를 확인한다. 음성 결과는 context가 없어야 하므로 선택 window 수치를 발명할 수 없다. 비교의 scope·Parser 및 binding 검사는 `counterfactual_comparison.py::compare_runs()`가 담당한다.
4. Replay `SafeFacts`의 event/failure/account/IP 및 target IP count/span은 Parser 사전 검증 집계다. Brute selected-window 값이 아니며 owner-bound private context를 담지 않는다. Spray는 `summarize_ip_failures()`의 같은 IP 전체 실패 features와 `detect_password_spray()`의 whole-span 조건을 사용한다.
5. 후보 adapter는 고정 합성 bytes를 기존 Production 호출 경로에 넘기고, **같은 bundle의 수명 안에서** owner와 analysis/source-role binding, subject, context owner, Evidence 및 membership을 검증한 후 bounded aggregate만 복사해야 한다. 임시 파일 무결성·parser disposition·scope·버전·negative/partial·예외·경계 실패를 기존 Replay와 일관되게 검사해야 한다. 이것은 필요한 설계이지 현재 존재하는 API 보증이 아니다. 별도 임의 DTO와 사후 계산을 결합하면 cross-run 오귀속이 가능하다.
6. private context는 식별값과 timestamp/member events를 보유하므로 출력·로그·예외·Public DTO에 노출하지 않는다. adapter 내부 접근 자체도 연구 전용 실행 및 privacy 검증을 요구한다. 기존 Replay를 복제하는 구현으로 검증 경계를 우회하지 않는다. 현재 안전한 adapter·예외 시 불완전 상태 매핑·필요한 변경 범위는 실증되지 않았다.

## 9. 연구 전용 정책 변경 초안

**제안만**: 독립 검토자 부재로 고정 합성 연구가 중단되는 문제를 다루되, 권한이 확인된 소유자가 명시적으로 승인한 특정 연구 단계·기준 SHA·허용 파일에만 오프라인 실험을 허용하는 범위 제한 정책을 별도 신설한다. 적용 대상은 승인된 S1 합성 평가 adapter 및 전용 테스트; Production 설명, 실제 로그, 운영·외부 연결, 후속 단계는 적용 대상 밖이다. §7의 금지사항과 fixed schema, no network/LLM, parser·owner·membership·privacy·결정성 및 회귀 검사를 필수로 한다. 자기 검토와 자동 검증, 독립 검토 대기 상태를 분리한다.

공개 시 “고정 합성 Corpus의 연구 결과이며 자기 검토/자동 검사만 수행했고 독립 사람 검토와 운영 검증은 미완료”를 명시한다. 침해·공격 성공·회피율·운영 정확도 또는 독창성을 입증했다고 주장하지 않는다. 데이터 유출, cross-run 결속 실패, 예상 밖 네트워크·Production 상태 변경, 불명확한 정책/입력 scope, 필수 테스트 실패, 승인 범위 초과 시 즉시 실행 중단 및 HOLD. 수정 전 원인·증거를 비공개로 보존하고 승인권자가 범위와 대책을 재검토한다.

예외의 만료는 승인 시 명시된 날짜 또는 승인된 기준 SHA·Corpus/정책/adapter 범위 변경 중 먼저 발생하는 시점으로 제안한다. 날짜는 결정자가 정하며 현재 비어 있다. 만료 또는 위반 시 연구 실행 중단, 분리된 연구 변경을 검토 가능한 방식으로 되돌리고 생성물을 승인된 비공개 절차로 격리·폐기하며 기존 Production과 Corpus 불변을 검증한다. 사용자 작업물 삭제나 파괴적 Git 조작은 자동 수행하지 않는다.

정책 개정 시 [ER-1D-P §14–15](counterfactual_sensitivity_explanation_design_er1d_p.md), [ER-1C-R §13](counterfactual_independent_review_er1c_r.md), [G0 §5·9–10](counterfactual_explanation_readiness_audit_er1d_g0.md), [S0 §3·9·13](counterfactual_solo_research_track_er1d_s0.md)에 새로 승인된 연구 예외의 좁은 범위와 유효 시점을 연결하고 Production Gate는 그대로 유지하는 후속 개정이 필요하다. 기존 문구와 과거 결정은 역사적 기록으로 보존하고, 별도 정책 문서가 충돌 시 우선 적용되는 범위를 명확히 정의해야 한다. 이번 G1은 그 문서들을 개정하지 않는다.

## 10. 사용자 명시적 승인 절차

권한 확인 후 소유자가 정책 변경안과 S1 실행 범위를 각각 검토한다. 승인 기록에는 결정자 권한의 근거, 실제 승인 날짜, 기준 Commit SHA, 합성 데이터·허용 파일·Production 호출 범위, 금지 변경, 개정 대상 정책과 정확한 예외 문구, 실패 중단·롤백 조건, 자기 검토와 독립 검토의 한계, 만료·재검토, 후속 S1 시작 조건을 담는다. 소유자 본인이 실제 결정과 날짜를 기록한다. 이 요청 또는 본 문서의 추천은 승인이나 서명이 아니다.

## 11. S1 진입 Gate

모든 조건을 별도 확인해야 한다: (1) 승인권한과 적용 의무 확인, (2) 명시적 연구용 정책 개정 승인, (3) 기존 문서 충돌 해소와 기록, (4) 정확한 기준 SHA 및 성공한 Push CI, (5) 합성 오프라인 격리 확정, (6) 허용 파일 목록 확정, (7) Production 호출 및 변경 금지 경계, (8) 동일 실행 Run Owner/Evidence Membership 계획, (9) privacy·네트워크·LLM 차단 계획, (10) 실패·반증 테스트 계획, (11) 유출 시 즉시 HOLD, (12) 연구 결과 미검증·독립 검토 대기 표시. 한 항목이라도 미충족이면 S1 착수 HOLD다.

## 12. 위협·실패·반증 매트릭스

다음은 후속 S1 테스트 계획이며 아직 구현·통과한 결과가 아니다. 각 상황에서 raw exception을 내보내지 않고 전체 안전한 결과 또는 해당 Claim을 보류한다. 기존 상태 및 fixed reason은 변경하지 않는다. 안전한 기대 결과가 나오지 않거나 유출·Production 변경이 있으면 즉시 HOLD한다.

| 주입 사례 | 안전한 기대 결과 | HOLD 조건 |
|---|---|---|
| 다른 실행의 Run Owner 결합 | owner binding 불일치, aggregate/Claim 거부 | 교차 실행 결합 수용 |
| 잘못된 Evidence Membership | 검증 실패 및 Claim 보류 | 위조 membership 수용 |
| Brute selected-window와 target IP SafeFacts 혼동 | 범위 불일치로 비교 중단 | 전체 IP count를 선택 창으로 출력 |
| Spray whole-span과 sliding window 혼동 | Production 전체 span만 적용; 다른 범위 보류 | sliding 값을 Production 근거로 사용 |
| Parser PARTIAL/REJECTED | 부분 범위 표시 또는 NOT_EVALUATED/INCOMPARABLE | 거부를 NOT_DETECTED로 표현 |
| Missing Account / Timestamp | 필요한 Predicate NOT_EVALUATED | 임의 0/False 또는 원문 출력 |
| Invalid Policy Version | unsupported/mismatch 및 비교 중단 | 다른 정책으로 재해석 |
| Empty Evidence | DETECTED에 필수 근거 없으면 binding 실패 | 빈 Evidence로 검증 성공 Claim |
| Missing Source Provenance | 근거 미확보, Claim 보류 | 출처를 추정해 결속 |
| Raw Log canary 출력 | closed allowlist·canary 부재 확인 | 원문 또는 canary 노출 |
| IP/Account 유출 | 안전한 집계·opaque scope만 출력 | 실제 또는 합성 원본 식별자 노출 |
| 공개 DTO에 Private Context 노출 | context/owner/Evidence 직렬화 거부 | 객체·멤버·timestamp 노출 |
| 예기치 않은 네트워크 요청 | network 차단 fixture에서 호출 0 | 연결 시도 발생 |
| 기존 Production 결과 변경 | 전후 기존 결과·계약 동일 | 기존 결과 또는 Production 코드 변화 |

## 13. 기존 독립 검토 Gate 보존

ER-1C-R/H0 Label-Blind Packet, 정책, 응답 양식과 digest·30건·불일치 처리는 그대로 유지한다. 연구 예상값·기존 Label·Replay를 독립 검토자에게 정답으로 제공하지 않는다. 공개 저장소의 Label 때문에 완전한 blind를 기술적으로 보장하지 못한다. 독립 사람의 실제 제출·독립성 근거·누락/이견 adjudication·manual approval이 없으면 `INDEPENDENT_HUMAN_REVIEW_PENDING` / `MANUAL_APPROVAL_REQUIRED`다. 소유자 자기 검토나 LLM은 독립 검토가 아니다.

## 14. 남은 미결정 사항

실제 승인권자의 권한과 적용 가능한 외부 의무, B 선택 여부, 정책 문구·만료일·허용 파일, adapter의 안전한 전체 입력 결속과 negative/partial 처리, 독립 검토자 확보는 확인되지 않았다. §8은 코드 독해를 바탕으로 한 후보이며 S1 구현 가능성을 증명하는 실험이 아니다. 개인 정보, 원천 로그 완전성, 공격 의도·침해 및 운영 정확도는 합성 실험으로 증명할 수 없다.

## 15. 최종 판정

`ER_1D_S0_G1_GOVERNANCE_DECISION_PACKET_LOCAL_CONDITIONAL_GO`는 이 결정 자료와 문서 회귀에만 적용한다. `SOLO_RESEARCH_AUTHORIZATION_PENDING`; 승인권자의 결정 전 S1 착수 HOLD. `INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`, `ER_1D_IMPLEMENTATION_HOLD`, `ER_2F_USER_ACCEPTANCE_PENDING` 및 실제 사용자 자료·조직 운영·자동 대응 `NO_GO`를 유지한다.

### 검증 기록

변경 전 전체 pytest 3887 passed, 2 warnings. 문서 계약 RED: 문서와 색인 부재로 3 failed. G1 및 S0/P/G0 문서 계약 GREEN 13 passed. 변경 후 전체 `uv run pytest -q` 3890 passed, 2 warnings. `uv run python -m app.evaluation`: Synthetic Boundary 79/79, Risk 70/70, Case 70/70, Linux Process 합성 21/21; 운영 성능을 뜻하지 않는다. `uv lock --check`, `uv run python -m compileall -q app tests`, `git diff --check` 성공. 문서 테스트는 독립 검토나 정책 승인을 증명하지 않는다.
