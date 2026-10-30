# Phase 36.9G-R1 — Brute Window Context 실행 소유권 보완

## 1. Executive Summary

판정은 `PHASE_36_9G_R1_RUN_OWNERSHIP_REMEDIATION_LOCAL_CONDITIONAL_GO`다.

36.9G의 RED는 서로 다른 분석 실행의 값이 같은 Brute Window Context를 다른 실행의 Case wrapper에 연결했을 때 Case가 만들어지는 결함을 재현했다. 이번 변경은 불투명한 `AnalysisRunOwner`를 실행마다 생성하고 Analysis, Window Context, private wrapper 및 Brute 전용 Correlation에 identity로 결속한다. 공개 분석 dict나 API schema에는 owner를 추가하지 않았다.

소유권은 동일 프로세스 안의 우발적 실행 간 재사용을 막는 provenance 계약이다. 악의적인 같은 프로세스 코드에 대한 암호학적 인증은 아니다. 실제 운영자료나 운영환경은 검증하지 않았다.

## 2. 시작 Gate

- 기준 SHA: `984a9f9cc7c59c826dcb061f1794ff08194ab0a3`
- GitHub Actions Run `41036766597`: exact SHA, `push`, `completed/success`, artifact 0개
- 필수 Python 3.12, Linux process/SSH recovery, pytest, TCP Syslog, JSONL, restricted report, Chromium/axe 및 tracked-file 검사 성공
- Branch `main`, local/main/origin/GitHub SHA 일치, ahead/behind `0/0`
- v0.4.0 target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

## 3. Dirty Working Tree 보존

시작 시 예상된 세 자산만 dirty/untracked 상태였다. 기존 36.9G RED 테스트, HOLD 문서, docs index 변경을 삭제하거나 덮어쓰지 않았다. HOLD 문서는 당시 결함의 역사 기록으로 남아 있고, R1 결과는 이 문서에 별도로 기록한다.

## 4. 36.9G Context Isolation HOLD 및 RED 재현

`tests/test_brute_window_contract_closure_36_9g.py`는 동일 합성 입력의 실행 A Context를 실행 B Analysis에 넣어 Case 1개가 생성되는 것을 확인했다. 재실행 시 기대한 rejection이 발생하지 않아 RED가 재현됐다. 수정 후 wrapper 생성 경계에서 `invalid_analysis_context`로 fail-closed한다. 이 테스트는 성공 결과를 약화하지 않고 wrapper 생성 또는 Case projection 단계의 안전한 거부를 요구한다.

## 5. 원인 및 전달 구조

정적 경로는 `main._analyze_normalized_logs_with_context()`에서 Detection을 만들고 Correlation/Risk를 계산한 뒤 private wrapper로 전달한다. 기존 Context는 이벤트·IP·계정·시간·Evidence를 검증했으나 Analysis 실행 identity가 없었다. Source-role snapshot은 이미 `_analysis is analysis`를 검사해 별도 provenance 보호를 제공했다.

Case 경로는 `AnalysisWithSourceRoleSnapshot`에서 `project_investigation_cases_from_analysis()`와 `_build_subject_inputs()`로 들어가 typed Case adapter를 통과한다. Brute Correlation은 별도로 `correlate_attacks()`에서 `correlate_brute_force_to_success()`를 호출한다. Live 경로는 revision prefix마다 selector·Correlation·Case 입력을 재구성하므로 각 proposal에 별도 owner를 생성한다. Restricted report도 같은 private wrapper 계약을 사용한다.

## 6. Run Ownership 계약

`AnalysisRunOwner`는 실행마다 새로 만들어지고 한 번만 특정 Analysis 객체에 결속된다. wrapper는 Source-role snapshot이 같은 Analysis 객체를 가리키는지, owner가 같은 Analysis 객체에 결속됐는지, 모든 Context의 owner가 동일 객체인지 검증한다. 비교는 값의 동등성이 아니라 `is` identity다.

`BruteWindowContext`의 owner는 생성자 입력·repr·비교에서 감춰진 내부 필드다. `dataclasses.replace()`는 owner를 복사하지 않으며 검증에서 거부된다. owner repr도 redacted다. owner는 전역 registry/cache에 저장되지 않는다. 요청/Analysis가 종료되면 wrapper와 Context 참조가 해제될 수 있다.

## 7. Context·Wrapper 결속 및 Case Adapter

wrapper 재구성으로 A Context를 B Analysis에 붙이는 시도는 거부된다. Context mapping에 서로 다른 owner가 섞인 경우도 wrapper 전체를 거부한다. Case adapter는 owner가 정확한 analysis 객체에 결속됐는지, adapter가 소비하는 `results`가 그 Analysis의 실제 `results`인지, Context owner가 같은지 확인한 뒤 기존 subject, membership, Evidence 검증을 수행한다. wrapper를 거치지 않는 내부 adapter 호출도 다른 실행의 owner/results 조합을 거부한다.

Context 없는 legacy 분석은 기존 whole-span 계약으로 계속 검증된다. 새 Sliding Window Evidence는 현재 실행 Context 없이 legacy 값처럼 통과하지 않는다.

## 8. Correlation 소유권 검증

정적 main, restricted report, Live proposal은 동일 실행 owner를 selector와 Brute 전용 correlation에 전달한다. Brute relation은 Context owner와 전달된 owner가 같은 경우에만 진행하며 기존 실제 event object membership 검증도 유지한다. 따라서 같은 NormalizedEvent 객체 목록을 재사용해 다시 분석한 실행 B owner로 Context A를 제시하면 relation을 만들지 않는다. 이벤트 객체 identity와 run ownership은 별개의 조건으로 검사한다.

실패 endpoint, 동일 IP/계정, 성공의 엄격한 후행, 60초 상한, 성공 시각 동률 fail-closed 정책은 바꾸지 않았다. 일반 Authentication Transition과 Password Spray Correlation의 로직은 변경하지 않았다. Context 없는 standalone `detect_attacks()` 결과만으로 별도 `correlate_attacks()`를 호출하면 Brute 전용 관계는 fail-closed이며, 소유권을 보존하는 분석 경로는 `analyze()`/private contextual path를 사용해야 한다.

## 9. Live Monitoring 및 Source-role

Live accumulator는 각 분석 proposal에서 새 owner를 만들고 그 proposal의 결과에 결속한 뒤 adapter를 호출한다. revision 간 Context 재사용을 허용하지 않는다. 정적 full-prefix oracle 테스트도 실제 contextual 분석 경로를 사용하도록 맞췄다. Source-role snapshot의 기존 Analysis 객체 identity binding은 별도로 유지되며 owner가 role 근거를 대신하거나 role을 승격하지 않는다.

## 10. 기존 Brute 동작 및 Password Spray

late-noise 탐지 정책, 임계값, window 선택, 전체 IP feature 및 Spray detector를 수정하지 않았다. owner 격리는 Brute Window Context의 실행 경계만 추가한다. 회귀 테스트에서 Brute 5회/20초 evidence와 전체 IP 6회/70초 feature는 기존 값으로 유지된다. Password Spray는 공통 `summarize_ip_failures()` feature와 기존 Evidence/Correlation 경로를 사용한다.

## 11. Privacy/Security

owner, Context, 계정, raw event를 repr로 노출하지 않는다. Public analysis dict, Detection Evidence schema, Case DTO, Report 및 Checklist schema는 변경하지 않았다. 실패 메시지는 `invalid_analysis_context` 또는 기존 adapter의 고정 오류 문구만 사용한다. 전역 provenance registry와 네트워크 호출은 추가하지 않았다.

## 12. 회귀 결과

36.9G 재현 테스트와 신규 ownership 테스트, 36.9F Production, 36.9E consumer-contract, 36.9D 평가, Correlation, Live-prefix, Source-role focused 검증을 실행했다. 첫 focused 실행에서 이전 직접 pipeline 호출자가 Context 없이 Brute relation을 기대한 테스트가 발견됐다. 이 호출은 owner를 보존하지 않는 legacy 조합이므로 fail-closed를 유지하고, 신뢰된 batch oracle은 contextual 분석 경로로 옮겼다. 기대를 단순히 낮추지 않고 해당 검증 경계를 실행 owner와 Case projection까지 포함하도록 변경했다.

기존 RED와 신규 ownership tests, 36.9F/36.9E/36.9D focused tests, Correlation, Live prefix/worker, SSH checkpoint, Source-role 검증을 실행했다. 최종 ownership focused는 8개, 기존 G 재현은 1개, 36.9F는 10개, 36.9E는 25개, 36.9D는 29개 통과했다. 추가 Correlation/Live/SSH/Source-role focused 집합은 211개 통과했다.

전체 pytest는 `3345 passed, 2 warnings`로 완료됐다. 기존 시작점은 `1 failed, 3336 passed, 2 warnings`였으므로 기존 36.9G RED가 GREEN이 되었고 R1 ownership 테스트 8개가 추가됐다. 36.9G의 한 RED 시나리오를 통과시키기 위해 오류 발생 위치를 wrapper 생성 시점 또는 adapter projection 시점 모두 허용하는 형태로 기록했으며, 거부 자체와 안전 오류 문구 요구는 유지했다.

Evaluation 결과는 36.9F Current Brute `TP 4 / FP 0 / FN 0 / TN 3`, 36.9D Candidate C `TP 17 / FP 0 / FN 1 / TN 5`, 36.9D Whole-span `TP 9 / FP 0 / FN 9 / TN 5`로 기존 기록과 일치했다. 기존 합성 Operational false-alert 후보는 36.9C 7건, 전용 36.9D 평가의 정책별 2건으로 유지됐다. 전체 `app.evaluation`은 Boundary 79/79, Parser 195/200 (ignored 2, rejected 3), Risk 70/70, Case 70/70, Linux process 21/21을 보고했다.

`python3 -m compileall -q app tests`, `uv lock --check`, `git diff --check`, `npm run test:a11y --silent`도 성공했다. 접근성 스크립트는 Chromium 시나리오를 실행했고 외부 요청은 0건으로 보고했다. 로컬 macOS 검증이며 새 커밋의 Linux CI를 대신하지 않는다.

## 13. 한계 및 Rollback

`AnalysisRunOwner`는 Python 프로세스 내부 capability이며 임의의 악의적 코드가 내부 객체를 직접 변조하는 것을 막는 암호학적 경계가 아니다. 별도 프로세스/실제 운영환경의 보안성을 주장하지 않는다. rollback은 이번 owner 전달·검증 변경과 관련 테스트만 되돌리는 좁은 변경이어야 하며, 36.9G RED/HOLD 기록은 삭제하지 않는다.

## 14. 다음 Closure 조건

후속 `Phase 36.9G-R2 — Brute Window Context Ownership Independent Closure`에서 새 exact-SHA CI, 독립 교차 실행, Case/Correlation 격리, File/Text API, Live parity, 평가 무결성, 개인정보 및 전체 회귀를 다시 검증해야 한다. 이 R1 판정만으로 36.9G 전체 Closure 완료나 36.10A 진입을 승인하지 않는다.

## 15. 최종 판정

`PHASE_36_9G_R1_RUN_OWNERSHIP_REMEDIATION_LOCAL_CONDITIONAL_GO`

이 판정은 로컬 합성 검증 및 이번 소유권 결함의 최소 remediation 범위에 한정된다. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`; 실환경 정확도는 `UNVERIFIED`; 기존 Renderer는 `KEEP_LEGACY`다.
