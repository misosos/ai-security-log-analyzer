# Phase 36.9G-R2 — Brute Window Context 소유권 독립 종결 검증

## 1. Executive Summary

**판정: `PHASE_36_9G_R2_CONTEXT_OWNERSHIP_HOLD`**

독립 감사에서 R1의 owner 결속은 한 방향만 단일성을 보장하는 것으로 확인됐다. 한 `AnalysisRunOwner`를 두 Analysis 객체에 결속하는 시도는 거부되지만, 이미 다른 owner가 결속된 동일 Analysis 객체에 새 owner를 결속하는 것은 허용된다. 합성 재현에서 새 owner의 Context를 기존 Analysis 및 그 Source-role snapshot과 조합해 wrapper를 만들었고, 실제 `project_investigation_cases_from_analysis()`가 Case 1개를 생성했다.

이는 R2가 명시한 “다른 Owner를 이미 결속된 Analysis에 덮어쓰기 불가” 및 실행 간 소유권 단일성 기준을 충족하지 않는다. 이번 Phase는 Closure HOLD다. Production 코드를 수정하지 않았고, 다른 검증 결과로 이 실패를 상쇄하지 않는다.

## 2. 시작 exact-SHA Gate

- 기준 SHA: `ea0015836a34329e964c0285fbed8f665c826e7a`
- GitHub Actions Run: `41044485341`
- Branch `main`; local HEAD/main/origin/main/GitHub main 모두 기준 SHA
- Ahead/behind `0/0`; 시작 working tree clean
- Event `push`, exact head SHA, `completed/success`, artifact 0개
- Locked Python 3.12, lock 검증, 전체 regression, Linux process/checkpoint 및 SSH recovery, TCP Syslog, JSONL, restricted report, Chromium/axe, tracked-file 검사 성공
- v0.4.0 target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 불변

## 3. Phase 36.9G HOLD 및 R1 수정 요약

기존 [36.9G HOLD 기록](brute_window_post_remediation_closure_36_9g.md)은 A Context를 값이 같은 B 분석에 재사용한 당시 결함 기록이며 수정하지 않았다. [R1 기록](brute_window_run_ownership_remediation_36_9g_r1.md)은 실행별 owner 추가, owner와 Analysis의 단방향 결속, Context/wrapper/Case/Correlation 검사 및 3345개 전체 pytest 통과 결과를 보존한다.

R2 baseline은 `3345 passed, 2 warnings`였다. 시작 시 변경 사항은 없었다. tag 및 dependency/lockfile은 변경하지 않았다.

## 4. Run Ownership 코드 감사

`AnalysisRunOwner`는 새 객체로 생성되고 `_bind_analysis()`가 처음 호출된 Analysis 객체를 보유한다. 같은 owner에 두 번째 Analysis를 결속하려 하면 `invalid_analysis_context`로 거부한다. `BruteWindowContext`는 생성 시 owner 참조를 보유하고, wrapper는 owner가 wrapper의 Analysis 객체와 identity가 같은지 확인한다. Source-role snapshot은 별도로 `_analysis is analysis`를 확인한다.

그러나 Analysis 객체 쪽에는 owner의 단일 결속을 기록하는 상태가 없다. 따라서 별개의 새 `AnalysisRunOwner`도 동일 Analysis dict를 자신의 최초 Analysis로 결속할 수 있다. wrapper는 두 번째 owner가 해당 Analysis에 결속됐다는 주장만 검사하므로, 원래 owner가 이미 존재한다는 것을 알 수 없다.

정적 신뢰 경로는 `main._analyze_normalized_logs_with_context()`에서 owner를 만들고 detector/Correlation에 전달한 뒤 최종 Analysis에 결속한다. Restricted report도 같은 contextual 경로를 사용한다. Live accumulator는 proposal마다 새 owner를 만든다. Local Text/File 및 Sample API는 기본 `_analyze_checklist_input()` 경로에서 `analyze_with_source_role_snapshot()`을 사용한다. API 테스트에서 analyzer를 주입한 legacy 경로는 wrapper가 없는 결과를 사용하며 Case adapter의 기존 feature/evidence 검증을 따른다. Production `app/` 내 `detect_attacks()`와 `correlate_attacks()` 직접 사용은 CLI 주 분석 경로가 아니라 detection accumulator의 detection-only oracle 및 별도 파이프라인 진입점이다. Context가 없는 직접 Correlation은 fail-closed한다.

값 동등성, 이벤트 객체 identity, Analysis 객체 identity 및 run owner identity는 서로 다른 속성이다. 현재 결함은 같은 Analysis 객체에 owner B를 추가 결속해 소유권 주장 자체를 중복시킬 수 있는 역방향 단일성 누락이다.

## 5. Cross-run / 동일 Analysis 재사용 재현

독립 재현은 합성 fixture `bf_late_noise_then_success.log`만 사용했다.

1. 정상 Run A를 수행해 `Analysis A`, Owner A, Context A, Source-role A를 얻었다.
2. 같은 fixture를 다시 파싱해 이벤트 값은 같지만 별도 객체인 입력 B를 만들었다.
3. Owner B를 생성해 이미 Owner A에 결속된 `Analysis A`에 결속했다. 호출은 거부되지 않았다.
4. B 입력에서 Owner B의 Context를 선택했다.
5. `Analysis A + Source-role A + Context B + Owner B` wrapper를 구성했다.
6. 실제 Case projection 결과는 `case_count=1`이었다.

출력 재현: `same_analysis_distinct_owner=ACCEPTED cases=1`, `owner_a_is_owner_b=False`.

새 테스트 `tests/test_brute_window_ownership_closure_36_9g_r2.py`는 정상 동일 실행 수용과 owner 단일 Analysis 결속을 확인하고, Analysis에 두 번째 owner를 연결하는 시도가 거부돼야 한다고 요구한다. 실행 결과는 `2 passed, 1 failed`; 실패는 해당 거부가 발생하지 않은 것이다. 이는 테스트 기대를 완화하거나 xfail로 숨기지 않았다.

## 6. Wrapper·Case Adapter·Correlation 검증 상태

R1의 서로 다른 Analysis 객체에 대한 A/B Context 교차 거부 테스트는 이번 실행에서 기존 R1 focused suite와 함께 `9 passed`로 통과했다. owner A가 Analysis A에 이미 결속된 뒤 Analysis B에 재결속하려는 경우도 기존 단방향 검사에 의해 거부된다. 하지만 동일 Analysis에 owner B를 추가 결속할 수 있으므로 wrapper와 adapter의 현 owner 일치 검사만으로는 소유권 단일성을 증명하지 못한다.

R1 Brute Correlation 계약 및 시간 endpoint 테스트는 이전 커밋에서 전체 regression을 통과했다. R2에서는 이 신규 역방향 결속을 Correlation까지 확장한 별도 통합 검증을 완료하지 않았다. Case adapter에서 실제 Case 생성이 이미 재현됐으므로 Closure는 차단한다.

## 7. Candidate C, 전체 Feature 및 Password Spray

Production 탐지 코드를 변경하지 않았다. R2 baseline evaluation 재실행 결과:

- 36.9C current Brute: `TP 4 / FP 0 / FN 0 / TN 3`
- 36.9D Candidate C: `TP 17 / FP 0 / FN 1 / TN 5`
- 36.9D Whole-span: `TP 9 / FP 0 / FN 9 / TN 5`
- Boundary 79/79; Parser 195/200 (ignored 2, rejected 3); Risk 70/70; Case 70/70; Linux process 21/21
- 기존 36.9C synthetic operational false-alert 후보 7건; 36.9D 정책별 후보 2건

이 값들은 합성 corpus 결과이며 실제 정확도를 뜻하지 않는다. R2에서 추가 offset/mixed-source 및 차등 Password Spray 행렬은 실행하지 않았다. HOLD 사유가 해결되지 않아 전체 독립 Closure matrix를 완료하지 않았다.

## 8. Live, Source-role, API, Report 및 Checklist

R1 baseline 전체 회귀에는 Live, Source-role, Local Text/File, Sample, Report 및 Checklist 테스트가 포함됐고 모두 통과했다. R2 신규 검증에서 이 API 경로를 다시 end-to-end로 호출하지 않았다. R2 owner 중복 결속이 private wrapper/Case 경계에서 수용될 수 있으므로 이 결과만으로 요청 간 소유권 종결을 승인할 수 없다.

추가적인 R2 Privacy canary, Live proposal 교차 owner, 동시 요청, SSE, Offset-equivalent, Mixed Application/SSH 및 성능 benchmark는 `NOT_RUN`이다. 테스트되지 않은 것을 PASS로 표시하지 않는다.

## 9. 테스트 수 및 이력

- R1 시작/완료 baseline: `3345 passed, 2 warnings`
- R2 시작 baseline full pytest: `3345 passed, 2 warnings`
- R2 신규 파일: 3 collect nodes (`2 passed, 1 failed`)
- R2 전체 collect-only: `3348 tests collected`
- R1 ownership 및 기존 36.9G 재현 focused: `9 passed`

테스트를 삭제, skip 또는 xfail하지 않았다. 신규 실패는 R1에서 주장한 소유권 역결속 차단을 독립 검사하여 발견했다. 전체 R2 pytest는 의도된 새 RED가 남아 있어 완료 실행하지 않았다.

## 10. 성능·Privacy/Security 한계

이번 R2에서 새 대규모 selector benchmark나 추가 API/SSE Privacy matrix를 실행하지 않았다. 기존 R1의 redacted repr 및 Public schema 보존 결과는 그대로이나, 그것은 owner↔Analysis 단일 결속의 역방향 보장을 제공하지 않는다. Owner는 동일 프로세스 내부 capability이며 악의적 Python 코드에 대한 암호학적 인증이 아니다.

## 11. 후속 조치 및 최종 판정

새 Production 버그를 이번 Closure에서 수정하지 않았다. 후속 remediation은 Analysis↔Owner 관계를 단일하고 신뢰된 생성 경계에서만 만들도록 설계해야 한다. 해결안은 공개 analysis dict에 owner를 넣거나 전역 mutable registry를 도입하지 않아야 하며, 동일 Analysis 객체의 두 번째 owner binding 및 Case projection 수용을 RED로 유지해야 한다. 수정 후에는 Case adapter, Correlation, API/Live, Privacy, 전체 regression을 다시 검증해야 한다.

**최종: `PHASE_36_9G_R2_CONTEXT_OWNERSHIP_HOLD`**

36.10A로 이동하지 않는다. 다음 단계는 단일 목적의 Owner↔Analysis 단일 결속 remediation이어야 한다. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`; 실환경 탐지 정확도는 `UNVERIFIED`; 기존 Renderer는 `KEEP_LEGACY`다.
