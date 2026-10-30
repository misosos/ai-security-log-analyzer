# Phase 36.9F — Brute Force Sliding Window Production 복구

## 1. Executive Summary

Phase 36.9F는 36.9D에서 확인한 late-noise 미탐을 Candidate C(per-IP·계정별 sliding window)로 해결하고, 36.9E에서 확인한 Evidence·Correlation·Case 계약 충돌을 내부 typed `BruteWindowContext`로 처리한다. IP 전체 failure feature와 Password Spraying-like 정책은 그대로 유지한다. 비공개 Context는 공개 분석 dict나 API schema에 추가하지 않는다.

검증 범위는 예약 주소와 합성 로그를 사용한 로컬·자동 테스트다. 실제 환경 탐지 정확도, 계정 침해 또는 공격 성공을 입증하지 않는다.

## 2. 시작 Gate

- 기준 SHA: `71f5e605ae76c0603bc8b5cbbb79ae5bd3148b7c`
- GitHub Actions Run: `41028938541`
- Branch `main`; local HEAD/main/origin/main/GitHub main 일치; ahead/behind `0/0`; 시작 working tree clean
- Exact head SHA, `push`, `completed/success`, artifact 0개 확인
- Locked Python 3.12, Linux process/SSH, 전체 regression, TCP Syslog, JSONL, restricted report, Chromium/axe, tracked-file invariant 성공
- v0.4.0 tag/Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 불변

시작 시점의 로컬 전체 테스트 기준은 `3327 passed, 2 warnings`였다. 새 커밋 SHA의 GitHub CI는 이 기록에 포함되지 않는다.

## 3. 이전 36.9C/36.9D/36.9E 결과

36.9C의 당시 Brute 결과는 TP 3 / FP 0 / FN 1 / TN 3이었고 `bf_burst_with_late_noise`가 미탐이었다. 36.9D의 별도 24개 전용 corpus에서 Whole-span은 TP 9 / FP 0 / FN 9 / TN 5, Candidate C per-account는 TP 17 / FP 0 / FN 1 / TN 5, known-benign 경보 후보는 정책별 2건이었다. 36.9E는 기존 adapter가 5회/20초 Evidence와 6회/70초 feature의 불일치를 거부하고 기존 Brute correlation이 70→80초를 골랐음을 shadow 검사했다.

위 과거 문서와 당시 결과는 보존한다. 아래 Current 결과는 이번 Production 코드 재실행이다.

## 4. RED 재현

Production 수정 전 테스트 실행에서 4개 실패·2개 통과를 관찰했다. 주요 실패는 late-noise 미탐, 공개 분석 dict만 Case adapter에 전달할 때 내부 Context 부재, 기존 adapter의 5/20 대 6/70 invariant 충돌이었다. 추가로 초기 테스트 두 건은 naive timestamp 사용 및 과거 동작을 현재 분석 함수에 기대한 테스트 구성 오류로 판명되어 입력/검증 범위를 분리했다.

수정 후 별도 focused 실행에서 2건이 남았다. 기존 correlation 테스트의 입력 timestamp가 naive여서 새 UTC-aware 선택자가 fail-closed했고, 과거 Whole-span assertion이 이제 바뀐 Production 동작을 검사하고 있었다. 테스트를 aware 시간으로 고쳤고, historical whole-span 거부는 `detect_brute_force(features, events)` 직접 호출로 보존하면서 Production 결과는 별도로 true임을 확인했다.

## 5. 새 Production Window Selector

`app/detector/brute_force.py:select_brute_window_contexts()`는 source IP와 알려진 계정별 실패를 정렬한 뒤 선형 two-pointer scan을 수행한다. 전체 비용은 그룹별 정렬 `O(n log n)` 및 이후 선형 탐색 `O(n)`이며 모든 window 조합을 열거하지 않는다. 선택된 timestamp 종료 그룹의 모든 동시 관측을 포함한다. 동일 timestamp는 서로 다른 행으로 보존하고 자동 중복 제거하지 않는다.

## 6. Candidate C 선택 정책

- 같은 IP, 같은 비어 있지 않은 계정, `login_failed`만 집계
- 최소 5개, UTC-aware timestamp, 양 끝 포함, 경과시간 `≤60s`
- 가장 이른 qualifying 종료 시각, 그 시각의 관측 전체 포함
- 같은 종료에서 가장 이른 시작, 이어 짧은 span, 이어 더 많은 행 기준
- 서로 다른 계정이 동일한 최종 우선순위를 가지면 fail-closed
- 누락 계정은 candidate count에 포함하지 않음
- invalid/naive timestamp를 가진 subject는 후보 Context를 만들지 않음
- 원문·UUID·배열 순서로 계정이나 동률을 임의 선택하지 않음

24개 36.9D 전용 시나리오의 Production 결과를 기존 평가기 Candidate C의 detection, event count, 시작/종료 시각, 계정과 대조하는 테스트를 추가했다.

## 7. Typed Private Window Context

Production `BruteWindowContext`는 subject IP, 숨겨진 대상 계정, UTC start/end, 실패 수, 선택 창의 실제 `NormalizedEvent` tuple을 보유한다. `repr`은 항상 `BruteWindowContext(<redacted>)`다. Context는 요청별 `AnalysisWithSourceRoleSnapshot`의 private immutable mapping에만 전달되며 공개 analysis dict에 넣지 않는다.

검증기는 context 타입, 실제 IP literal, detection type, 계정, UTC-aware/UTC endpoint, 60초 상한, member count, min/max 시각과 실제 membership을 검사한다. Brute evidence matcher는 정해진 Evidence 집합과 source/value/range를 엄격히 확인한다. Correlation은 context의 실제 event object들이 같은 입력 log list에 포함됐는지도 identity로 확인하여 다른 실행의 context 재사용을 거부한다.

## 8. IP 전체 Feature 불변

`summarize_ip_failures()`는 변경하지 않았다. 전체 `failure_count`, `target_users`, `unique_target_count`, `window_seconds`, `within_window`, 평균 간격/변동, `login_succeeded`는 기존과 같이 해당 IP의 모든 관측 실패를 뜻한다. late-noise fixture에서는 6회/70초/`within_window=False`가 유지된다.

## 9. Detection Evidence

기존 public Evidence schema를 사용한다. `multiple_login_failures`는 선택 창 안의 행 수와 정확한 `(start_utc, end_utc)`를 담는다. `single_target_user=1`이며 원 계정 문자열을 value로 넣지 않는다. `failures_within_short_window`는 선택 창 경과 초다. 전체 IP feature와 Evidence가 다르더라도 둘 다 각자의 범위를 보존한다. Context가 없거나 계정 동률이면 Detection/Evidence를 생성하지 않으며 naive timestamp에서 legacy whole-span fallback도 하지 않는다.

## 10. Correlation Endpoint

Brute 전용 `correlate_brute_force_to_success()`만 변경했다. Context와 Detection Evidence가 일치하고 선택 member가 현재 입력 안에 있을 때, endpoint는 선택 창의 마지막 실패다. 성공은 같은 IP·계정, window end보다 엄격히 뒤, 최대 60초 이내여야 한다. 가장 이른 성공 하나만 허용하며 동일 최단 timestamp의 복수 row는 fail-closed한다. 20→21초 및 20→80초(60초)는 허용, 20초 동시/이전 및 20→81초는 거부한다.

일반 Authentication Transition과 Password Spray→Success는 기존 `_closest_authentication_pair()` 기반 동작을 유지한다. 관계는 시간적 관측일 뿐 원인·침해를 증명하지 않는다.

## 11. Case Adapter 변경

`project_investigation_cases_from_analysis()`는 기존 exact dict와 private wrapper를 모두 받는다. Context가 있는 Brute detection에 한해 실제 context와 Evidence를 검증하고 선택 계정 하나를 detection-specific `IncidentCaseDetectionInput.target_accounts`로 전달한다. IP 전체 account 목록은 그대로 유지한다. Context 없는 forged 5/20 Evidence는 기존 전체 feature 계약에서 계속 거부되고, Password Spray 검증은 변경하지 않았다.

## 12. Case Assembler 및 Account Scope

Assembler가 새 Case rule을 추가하지 않도록 `IncidentCaseDetectionInput`의 내부 detection-specific target scope만 Brute에 사용한다. Brute observation의 evidence time range는 선택 창에서 오며 Brute→Success 관계의 failure endpoint는 창 종료다. 다른 detection과 Password Spray는 기존 subject-level scope를 유지한다. 공개 DTO에는 계정 원문을 추가하지 않았다.

## 13. Risk 영향

Risk 산식과 level/confidence 결정은 수정하지 않았다. Risk rationale에서 volume·temporal·targeting 값은 “IP 전체” 범위로 표시하고, Brute Evidence의 실패 수/기간은 “선택된 반복 실패 창”으로 구분했다. Brute signal이 새로 생기면 기존 heuristic 결과가 달라질 수 있지만 이를 침해 확률로 해석하지 않는다. Brute correlation signal은 Context가 없거나 창 밖 endpoint만 있는 경우 생성되지 않는다.

## 14. Report/Checklist 영향

기존 Case-bound checklist 흐름과 legacy renderer를 유지했다. 새 범위 표시 rationale을 닫힌 report projection allowlist에 추가했다. Case projection은 wrapper를 받아 내부 Context를 확인하며 report projection은 공개 analysis만 받아 기존 닫힌 schema를 유지한다. Context/계정/raw log를 API·HTML·Checklist에 직렬화하지 않는다.

## 15. Local API E2E

Application late-noise + success 합성 로그를 text 입력 API에 전송하고 Case 요약과 report가 생성되는지 확인했다. 응답에서 계정 canary, 원문 로그, fixture 경로는 노출되지 않았다. 동일 로그를 세 파일 업로드 API에 넣어 Case 생성과 개인정보 비노출을 확인했다. API schema와 resource limit은 변경하지 않았다.

## 16. 기존·신규 평가 결과 비교

기본 synthetic boundary evaluation은 수정 전 `78/79`였고 실패는 `brute_above:detection`이었다. 기존 예상 Evidence는 6회/50초 전체 집합을 설명했지만 새 계약은 가장 빠른 qualifying window인 5회/40초를 설명한다. 독립된 5회 threshold 및 40초 시각에 맞춰 이 scenario의 expected evidence를 갱신했고, 수정 후 boundary `79/79`가 됐다. Risk 70/70, Case 70/70, parser 195/200 (ignored 2, rejected 3), Linux process 21/21 유지.

36.9C Historical Brute matrix: TP 3 / FP 0 / FN 1 / TN 3. Current 실행: TP 4 / FP 0 / FN 0 / TN 3; late-noise는 FN에서 TP로 바뀌었다. 전체 46개 fixture와 독립 라벨은 유지했다. 다른 6개 Detector metric은 기존과 동일하다. Operational false-alert 후보는 총 7건 유지되며 Brute benign-retry 후보가 기존대로 관찰된다.

36.9D Candidate C 평가기(24개)는 그대로 TP 17 / FP 0 / FN 1 / TN 5이며 별도 비교값이다. 이는 Production 수정 후 Current baseline과 합산하지 않는다. 별도 24개 corpus에서 Production selector와 Candidate C의 탐지 여부·선택 window가 모두 일치한다.

## 17. Pattern FP/FN 변화

고정된 36.9C behavioral label에 대해 알려진 Brute FN 1건이 TP로 바뀌었고 새 Pattern FP는 관찰되지 않았다. 작은 합성 표본에서의 결과이며 운영 FP율·FN율을 의미하지 않는다. Known-benign Brute retry는 운영 맥락상 false-alert 후보로 남아 있다.

## 18. Operational False-alert 후보

36.9C 합성 Operational Context에서 총 7개 후보가 유지됐다(Brute retry 1, 다른 6개 detector 각각 1). Brute 경보 패턴은 승인된 인증 점검이나 정상 반복 오류와도 겹칠 수 있다. 로그만으로 정상/공격 의도를 판정하지 않으므로 Detection과 운영상 오탐 후보를 분리한다.

## 19. Privacy/Security

합성 데이터 및 문서용 IP만 사용했다. Context `repr`, public JSON, Case projection, report, API 오류 응답에서 사용자 계정과 raw line이 노출되지 않는 테스트를 수행했다. API text/file 경로는 기존 private staging, limiter, worker 경계를 유지했다. 외부 network·SIEM·LLM·Vector/VM은 사용하지 않았다. OS-level hard CPU/memory cap 및 secure erase는 보장하지 않는다.

## 20. 성능·결정성

모든 후보 조합을 생성하는 평가 구현과 달리 Production은 정렬 후 계정별 two-pointer scan을 쓴다. 동일 timestamp는 한 종료 그룹으로 묶어 해당 시각 모든 행을 포함한다. 24개 corpus 전부에서 입력 source와 결과가 Candidate C per-account와 일치했다. 입력 순서 역전, microsecond 초과, 동률·중복·missing account 경계도 focused tests로 확인했다. 단일 요청 상한의 OS 강제 자원 제한을 주장하지 않는다.

## 21. 전체 Regression

시작 로컬 baseline: `3327 passed, 2 warnings` (macOS, Python 3.12). 최종 `uv run pytest -q`: **3336 passed, 2 warnings** (macOS, Python 3.12). 전체 evaluation은 boundary 79/79, Parser 195/200 (ignored 2, rejected 3), Risk 70/70, Case 70/70, Linux process 21/21이다. 36.9C Current Brute는 TP4/FP0/FN0/TN3, 36.9D Candidate C 전용 평가는 TP17/FP0/FN1/TN5다. Detector Accuracy JSON/Text 및 Brute Window JSON/Text CLI 모두 성공했다.

`uv sync --locked --dev`, `uv lock --check`, `python3 -m compileall -q app tests`, `git diff --check` 성공. `npm run test:a11y --silent` 성공: 25 상태 시나리오, 외부 요청 0, 검사 viewport에서 axe·overflow·clipping·target-size·gap 위반 0. 시작 SHA CI의 필수 Linux·Chromium gate도 성공했다. 새 로컬 커밋 SHA의 GitHub CI는 별도다.

## 22. Known Limitations

- 동일 행 중복은 수집 중복인지 별도 시도인지 구분할 ingestion ID가 없어 제거하지 않는다.
- 실패 이벤트 누락은 임계값 미달로 이어질 수 있다.
- 계정 누락 이벤트는 Candidate C window에서 제외되며, 그 사실은 Brute attribution 부족을 뜻한다.
- 입력은 현재 지원하는 Application 내부 형식 및 ISO-style SSH subset의 parser output에 제한된다.
- 합성 평가/loopback API는 실제 Apache·NGINX·OpenSSH deployment compatibility를 입증하지 않는다.
- 동일 시각의 여러 성공 이벤트는 모호성으로 fail-closed한다.

### Research Basis

NIST SP 800-63B-4의 rate limiting 안내는 인증자/가입자 계정에 대한 온라인 시도 제한을 다루지만, 이 프로젝트의 로그 기반 탐지 횟수나 60초 시간창을 정당화하지 않는다. MITRE ATT&CK T1110.001은 password guessing에서 반복 인증 실패와 잠금이 관찰될 수 있음을 설명하지만 실패 기록 자체가 성공이나 악의성을 증명하지 않는다. MITRE DET0551은 시간창·시도 임계값을 탐지 전략의 조정 가능한 heuristic으로 다룬다. 따라서 5회/60초는 이 저장소의 기존 계약 및 합성 corpus에서 검증한 프로젝트 heuristic이며 보편 표준이 아니다.

출처 확인일: 2026-10-30.

- NIST SP 800-63B-4, *Authentication and Authenticator Management*: https://pages.nist.gov/800-63-4/sp800-63b.html
- MITRE ATT&CK T1110.001, *Password Guessing*: https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK DET0551, *Account Discovery / Brute Force Detection Strategy*: https://attack.mitre.org/detectionstrategies/DET0551/

### Observable Evidence Mapping

| 입력 관측 | 정규화/계약 | 탐지·소비 의미 |
|---|---|---|
| 지원 parser가 만든 `login_failed`, aware timestamp, source IP, user | 실제 `NormalizedEvent` membership | 동일 IP·알려진 동일 계정별 실패 행 집계 |
| Context UTC start/end 및 tuple member | selector가 실제 입력 event에서 생성하고 adapter/correlation 재검증 | 선택 window의 Evidence와 correlation endpoint |
| 전체 IP의 모든 실패·계정·시각 | `summarize_ip_failures()` 기존 feature | 전체 volume/temporal risk 및 기존 Spray 의미 |
| 같은 IP·계정의 window 종료 후 성공 | success event, aware timestamp | 시간 관계만 기록; 계정 침해나 인과성 아님 |

### Limitations

로그는 실제 입력 시도 식별자, 사용자 의도, 승인된 점검 여부, credential 유효성, NAT 뒤 행위자, 서버 측 계정 상태 또는 공격 성공을 제공하지 않는다. 계정 문자열은 관측 label일 뿐 신원 증명이 아니다. 공유 IP는 여러 사용자·호스트의 관측을 결합할 수 있다. 이 단계는 합성 fixture와 로컬 테스트만 평가하며 실제 환경 정확도는 `UNVERIFIED`다.

## 23. Rollback 계획

회귀 발생 시 이번 변경 집합에서 Candidate selector 호출, private context 전달, Brute 전용 correlation, Brute-only adapter scope, scope-labelled Risk/report rationale만 되돌린다. 전체 IP 요약 및 Password Spray 변경은 없으므로 해당 경계를 보존한다. 승인된 36.9C/36.9D 평가 자산·문서 및 무관한 사용자 변경은 제거하지 않는다. 롤백 기준은 Password Spray 결과 변화, full feature 변화, Evidence mismatch, 창 밖 correlation, Case/API 오류, privacy leakage, parser regression, non-determinism/performance failure 또는 전체 pytest 실패다.

## 24. 다음 Phase 검증 제안

다음 단일 제안은 **Phase 36.9G — Brute Window Post-Remediation Regression & Contract Closure**다. 새 커밋의 exact-SHA Ubuntu CI, Candidate C 24개 비교, full regression, duplicate/missing input 한계, API·Case·Report privacy, 성능/결정성, old/current evaluation baseline을 독립 재검증한다. 실제 자료·조직 운영 또는 자동 대응으로 확장하지 않는다.

## 25. 최종 판정

최종 판정: `PHASE_36_9F_BRUTE_WINDOW_PRODUCTION_REMEDIATION_LOCAL_CONDITIONAL_GO`. 새 commit SHA의 GitHub CI는 Push 이후 별도 필수 검증이다.
