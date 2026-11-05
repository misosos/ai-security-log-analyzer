# ER-2A-R1 — Comparison State Integrity Remediation

## 1. Executive Summary

ER-2A의 읽기 전용 보고서 검증에 탐지 결과·비교 상태·outcome reason 간 일관성 검사를 추가한다. 이는 합성 replay DTO의 내부 모순을 거부하는 검증이며 새 탐지 또는 인과 판단이 아니다.

## 2. Start Gate

시작 HEAD/main/origin/main/GitHub main `e5c08a10c26d7d9022c2dd186f794df57c76d519`, behind/ahead 0/0. Exact push CI `41871492715` completed/success; 전체 회귀, Linux, Restricted Report, Chromium/axe, tracked-file 단계 성공, artifact 0. `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`. 시작 트리에는 아래 ER-2C 초안 세 untracked 파일만 있었다.

## 3. Defect Reproduction

실제 replay의 DETECTED/NOT_DETECTED/LOST 행을 메모리에서 PRESERVED로 바꾸고 comparison 집계를 함께 맞추면 `build_report()`가 기존에 수용했다. Development와 Holdout 모두 재현했고, 기존 `AnalystReport` projection을 같은 방법으로 바꾸면 `render_markdown()`도 수용했다. Corpus 파일은 수정하지 않았다.

## 4. Root Cause

기존 검증은 상태 enum, parser 완전성, 결과 집계의 일치를 확인했으나 detection 쌍과 comparison outcome 및 outcome reason의 대응을 검사하지 않았다. 집계가 일치해도 개별 행이 모순될 수 있다.

## 5. Trust Boundary

`counterfactual_comparison.compare_runs()`가 scope·subject·binding·실행 완료를 판단한다. ER-2A는 공개 DTO에서 확인할 수 있는 결과 불변식만 검증한다. 숨겨진 provenance를 복원하거나 실행 근거의 진위를 독립적으로 증명하지 않는다.

## 6. Comparison State Invariants

| Baseline | Variant | Comparison |
|---|---|---|
| DETECTED | DETECTED | PRESERVED |
| DETECTED | NOT_DETECTED | LOST |
| NOT_DETECTED | DETECTED | GAINED |
| NOT_DETECTED | NOT_DETECTED | UNCHANGED_ABSENT |

위 표는 outcome comparison을 주장한 경우에만 적용하며 양쪽 parser VERIFIED가 필요하다. REJECTED/NOT_EVALUATED parser는 DETECTED를 허용하지 않는다.

## 7. Reason Code Invariants

각 outcome은 각각 `OUTCOME_PRESERVED`, `OUTCOME_LOST`, `OUTCOME_GAINED`, `OUTCOME_ABSENT_BOTH`를 요구하고 다른 outcome reason의 혼입을 거부한다. Baseline·Variant 실행 reason은 그대로 허용한다. Reason은 자동 생성·수정하지 않는다.

## 8. INCOMPARABLE/UNDETERMINED Preservation

두 detection 상태가 유효하더라도 subject/scope 불일치면 INCOMPARABLE, evidence binding 또는 label provenance 부족이면 UNDETERMINED가 가능하다. 이 상태를 outcome으로 강제하지 않는다. PARTIAL/REJECTED 및 EXECUTION_FAILED를 탐지 음성으로 전환하지 않는다.

## 9. Implementation Changes

`_validate_outcome()`를 `_validate_row()`와 `_validate_projection()`에서 공통 호출한다. 따라서 `build_report()`와 `render_markdown()` 양쪽이 적용 대상이다. Producer, Corpus, 분석 API 및 UI는 변경하지 않았다.

## 10. TDD RED/GREEN

신규 outcome 변조 및 reason 검증 12개는 수정 전 12 failed (DID NOT RAISE). 수정 후 ER-2A 집중 테스트 29 passed. 실제 양쪽 corpus의 네 outcome, 집계 조작, 직접 projection, scope/evidence 제외와 parser 예외를 검사한다. 정상 Development/Holdout 분포는 기존 테스트가 검증한다.

## 11. Full Regression

시작 시 초안 포함 전체 pytest: 3787 passed, 2 deprecation warnings. ER-2A/Replay/Holdout/Corpus/Detector Accuracy 집중 회귀: 122 passed. 종료 전체 pytest: 3805 passed, 동일한 2개 deprecation warnings. 순차 실행한 evaluation: synthetic boundary 79/79, risk 70/70, case 70/70, Linux process 합성 분류 21/21; 이는 Linux 호스트 검증이나 운영 성능을 뜻하지 않는다.

## 12. ER-2C Worktree Preservation

초안 세 파일은 untracked 상태로 보존하며 커밋하지 않는다. 시작 SHA-256: projection `4616a6ddde62245e6b6367b244997267a9c5807baa169deff49df2906ec2bd0f`; CLI `ce7d8b9226d2f4c2e2f702bd141890ba465acd9c117436fb1afa028f48d63b3b`; test `bc75da92e5799906aa9fe20bdf22a8f61921fc4ede1849cad179e3423cc6466c`. 종료 시 해시를 재확인한다.

## 13. Remaining Limitations

ER-2A DTO에 없는 private subject·scope·owner와 evidence binding의 진위를 이 검사만으로 입증할 수 없다. 합성 결과는 운영 정확도나 공격 성공을 뜻하지 않는다. 독립 사람 검토는 `INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`다. `ER_1D_IMPLEMENTATION_HOLD`와 `ER_2C_IMPLEMENTATION_HOLD`를 유지한다. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`다.

## 14. ER-2C Re-entry Gate

이 복구 커밋을 사용자가 push한 뒤 exact SHA push CI 성공, artifact 0, 신규 회귀 성공 및 초안 무결성과 Git 상태를 확인하고 별도 재개 지시가 필요하다.

## 15. Final Decision

필수 회귀와 초안 보존이 모두 확인될 경우 `ER_2A_R1_COMPARISON_INTEGRITY_LOCAL_CONDITIONAL_GO`. 이 판정은 ER-2C 구현 완료 또는 운영 승인이 아니다.
