# Phase 36.9E — Brute Force Evidence·Correlation 계약 평가

## 1. Executive Summary

**Phase 판정: `PHASE_36_9E_EVIDENCE_CORRELATION_CONTRACT_LOCAL_CONDITIONAL_GO`**

합성 shadow 검증으로 Candidate C(IP·계정별 창)와 현행 consumers 사이의 충돌 및 다음 구현 계약을 확인했다. Production Detector, Correlation, Risk, Case, API/schema는 변경하지 않았다.

권고는 **Contract B: Brute 전용 내부 Window Context sidecar**다. IP 전체 `features`와 Password Spray 의미를 그대로 두고, 선택된 창의 account·UTC 경계·실제 창 소속 normalized failure 행을 private context로 별도 전달한다. Detection Evidence는 그 창의 count와 time range만 담는다. Brute→Success 관계는 선택 창의 마지막 실패 시각을 endpoint로 사용하고 같은 IP·계정의 엄격히 이후 성공만 60초 이내에서 연결한다. 서로 다른 이벤트 후보가 같은 최소 endpoint를 가지면 fail-closed한다.

이 계약은 기존 공개 schema를 유지할 수 있는 설계 후보로 평가됐다. Case adapter는 현재 후보 Evidence를 거부하므로 36.9F에서 typed internal context 인수와 detection별 계정 scope를 추가해야 한다. 기존 adapter를 우회하거나 전체 feature를 창 통계로 덮어쓰는 방식은 승인하지 않는다.

## 2. 시작 Gate

- 시작 SHA: `885f1268f16ecbef016df9cbdf24cb54e77b88ad`
- GitHub Actions [Run 41019687380](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41019687380): exact SHA, `push`, `completed/success`, artifact 0개
- Locked Python 3.12, 전체 regression, Linux process/SSH recovery, TCP Syslog, JSONL runtime, restricted report, Chromium/axe, tracked-file invariant: 모두 성공
- branch `main`; HEAD/local main/origin main/GitHub main 일치, ahead/behind `0/0`, working tree clean
- v0.4.0 tag와 Release target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

이는 시작 SHA에 대한 CI 근거다. 이번 Phase 커밋의 CI 근거가 아니다.

## 3. Phase 36.9D 권고 및 이번 재검증

`docs/brute_force_window_semantics_evaluation_36_9d.md`와 두 평가 CLI를 다시 확인했다. 24개 corpus의 Candidate C는 TP 17 / FP 0 / FN 1 / TN 5, Recall `0.944444`였고, Whole-span Recall은 `0.500000`이었다. Known-benign 합성 경보 후보는 정책별 2건이었다. 기존 detector accuracy corpus는 46개, Brute FN 1건이었다.

이번 Phase에서도 `uv run python -m app.evaluation.brute_window_cli --format text/json` 및 `uv run python -m app.evaluation.detector_accuracy_cli --format text/json`를 재실행했다. 결과는 위 기록과 일치했다. 이는 소규모 합성 평가이며 운영 정확도나 계정 침해의 근거가 아니다.

## 4. 현재 Production 데이터 흐름

실제 주요 경로는 다음과 같다.

```text
load_normalized_logs()
→ detect_attacks()
  → summarize_ip_failures() (IP별 전체 실패 feature)
  → detect_brute_force()와 detect_password_spray()
→ correlate_attacks(logs, results)
→ assess_risk()
→ project_investigation_cases_from_analysis()
→ Case / report projection / Checklist binding
```

`app/analyzer/pipeline.py:detect_attacks()`는 `summarize_ip_failures(logs)`를 한 번 계산해 Brute Force와 Password Spray에 같은 IP 단위 feature를 전달한다. `app/main.py:_analyze_normalized_logs()`는 탐지, correlation, risk 순으로 처리한다. `app/analyzer/incident_case_adapter.py`는 분석 결과의 닫힌 계약을 검증한 뒤 typed Case 입력을 만들며, `app/local_investigation_api.py:_worker()`는 Case projection을 먼저 만든 다음 report projection과 response/checklist 입력을 만든다.

## 5. IP 전체 Feature 계약

`app/detector/brute_force.py:summarize_ip_failures()`의 feature는 IP 전체 `login_failed` 집합의 관찰값이다.

| 필드 | 현재 의미 |
|---|---|
| `failure_count` | 해당 IP의 전체 실패 이벤트 행 수 |
| `target_users`, `unique_target_count` | 전체 집합의 알려진 계정만 수집 |
| `window_seconds` | 전체 실패의 min timestamp부터 max timestamp까지 |
| `within_window` | 전체 span이 60초 이하인지 |
| `average_interval`, `interval_variability` | 전체 실패 timestamp 간격 통계 |
| `login_succeeded` | 같은 IP에 성공 이벤트가 하나라도 있는지 |

Brute Force는 전체 실패 5회 이상, 알려진 고유 계정 1개, 전체 `within_window=True`를 요구한다. Password Spray는 전체 실패 4회 이상, 알려진 계정 3개 이상 및 같은 `within_window`를 사용한다. 공용 요약 feature를 Candidate C 창으로 바꾸면 Spray, Risk와 기존 consumer까지 의미가 바뀌므로 금지한다.

## 6. Candidate C Window Context 계약

36.9D의 선택 정책을 그대로 유지한다.

- 같은 source IP와 하나의 알려진 대상 계정별로 분리
- UTC-aware 시간, 창 시작/끝 포함, span `≤60s`
- 알려진 계정 소속 실패 행 5개 이상
- 누락 계정 행으로 임계값을 채우지 않음
- 선택 순서: 가장 이른 qualifying end, 그 다음 가장 이른 start
- 다른 계정의 동순위 선택이 남으면 임의 계정 선택 없이 fail-closed
- 원시 입력 배열 위치, raw log, UUID로 보안 의미를 선택하지 않음

평가 전용 `app/evaluation/brute_window_consumer_contract.py`의 `BruteWindowContext`는 IP, 비공개 account, UTC 경계, 창 count 및 실제 `NormalizedEvent` membership을 보유한다. builder는 IP·계정·event type·시간 범위·count·양 끝 timestamp를 다시 검사한다. `repr`에서 계정과 이벤트 목록을 숨기며 Context 자체는 공개 결과나 API field가 아니다. 이벤트 membership은 정규화 이벤트의 현재 in-process 참조로 입증한다. 수집 event ID가 없으므로 동일한 행 중복은 별도 관찰 행으로 남는다.

## 7. Detection Evidence 계약

선택된 창만 설명한다.

| 기존 Evidence type | Candidate C에서의 값 |
|---|---|
| `multiple_login_failures` | 선택 창 내부 실패 수, time_range=(window start, window end) |
| `single_target_user` | 알려진 단일 계정 수 `1`; 원 계정 문자열은 evidence value로 넣지 않음 |
| `failures_within_short_window` | 선택 창의 실제 UTC 경과 초 |

IP 전체 통계는 기존 `features`에서만 유지한다. 선택창 count와 전체 count를 혼합하지 않는다. Candidate 없음 또는 모호한 계정 동률에서는 Detection과 Window Evidence를 만들지 않는다. 기존 Evidence schema는 변경하지 않는다.

Shadow builder는 위 기존 `DetectionResult` 형태를 사용해 계약을 확인한다. 현재 Case adapter가 이 결과를 받아들이지 않는 점은 실패를 숨기지 않고 아래와 같이 보존한다.

## 8. Evidence/Feature 불일치 및 Case Adapter 재현

재현 fixture `sample_logs/brute_window_evaluation/bf_late_noise_then_success.log`는 Application parser에서 7개 이벤트(실패 6, 성공 1)로 읽혔다. 실패는 같은 IP·계정이며 0–20초에 5개, 70초에 하나가 더 있다.

| 범위 | 실패 수 | 알려진 계정 수 | 시간 범위 |
|---|---:|---:|---:|
| IP 전체 feature | 6 | 1 | 70초, `within_window=false` |
| Candidate C | 5 | 1 | 20초 |

Shadow 테스트는 Candidate C Evidence와 **변경하지 않은** 전체 feature를 `project_investigation_cases_from_analysis()`에 전달했다. 실제 `IncidentCaseAdapterError(code="invalid_detection_contract")`로 거부됐다. `incident_case_adapter.py:_authentication_detection()`은 `failed_count == features.failure_count`, target count와 전체 account 집합, `window_seconds == features.window_seconds`, `features.within_window=True`를 동시에 요구한다. 이 사례에서는 count `5 != 6`, duration `20 != 70`, whole-span false가 충돌한다.

이를 해결하려고 전체 feature를 5/20으로 바꾸지 않았다. 그렇게 하면 IP 전체 통계와 Risk volume/temporal 설명을 잃고 Spray의 shared input을 왜곡한다. 현재 adapter의 거부는 기존 계약을 지키는 동작이며 Candidate 정책과의 **`CURRENT_CONTRACT_INCOMPATIBLE`**이다.

## 9. 내부 계약 대안 비교

| 대안 | 평가 | 근거 |
|---|---|---|
| A. 기존 전체 feature를 창 값으로 변경 | 거부 | 6/70 전체 통계를 손실하고 shared `within_window` 및 Spray·Risk 의미를 바꾼다. |
| B. Brute 전용 내부 Window Context sidecar | **권장** | 전체 feature를 보존하고 membership/account/endpoints를 검사하며 correlation·Case 입력에서 재사용할 수 있다. 공개 schema 변경은 필요하지 않도록 별도 내부 typed 인수로 운반한다. |
| C. Detection Evidence만 사용 | 부족 | scalar count와 time_range는 창에 속한 실제 이벤트 집합, 사용자 귀속, 중복 여부를 증명하지 못한다. 공개 projection은 계정 참조를 의도적으로 제거한다. |

36.9F에서는 분석 worker 안에서 context를 생성하고 correlation과 Case adapter로 전달하는 private typed sidecar를 사용한다. 기존 `AnalysisWithSourceRoleSnapshot` 계열 내부 wrapper를 확장할지, 별도 내부 run dataclass로 묶을지는 36.9F 구현 시작 시 실제 callback 경계를 확인해 가장 작은 변경을 택한다. worker 경계를 넘어 공개 response에 context를 직렬화하지 않는다.

Case adapter는 내부 context로 Brute evidence를 검증하고 `IncidentCaseDetectionInput`에 **해당 Brute detection의 대상 계정 하나**를 내부 scope로 전달해야 한다. 기존 subject-level `target_accounts` 전체는 유지해 Password Spray 등 다른 detection은 기존 의미를 계속 사용한다. `incident_case.py`는 detection별 account scope를 사용할 수 있도록 최소 조정한다. public DTO에는 계정 원문을 추가하지 않는다.

## 10. Correlation 시각 및 membership 정책

현행 `app/correlation/attack_chain.py:_closest_authentication_pair()`는 같은 IP·같은 알려진 계정, failure strictly before success, `≤60s` 조건으로 **전체 IP 로그**에서 가장 가까운 pair를 찾는다. Brute detection이 true인 경우에도 선택된 Brute Window를 받지 않는다.

합성 0–20초 실패 5건, 70초 늦은 실패, 80초 성공 시:

- 현행 함수: `70→80초`, delta 10초를 선택
- 선택된 창의 종료 시각 정책: `20→80초`, delta 60초를 선택
- 따라서 현행의 Brute relation은 탐지 창 바깥 실패를 근거로 사용한다.

**권장 endpoint 정책은 선택된 창의 마지막 실패 시각**이다. 성공은 선택 창 종료보다 엄격히 뒤에 있어야 하고, 같은 source IP·같은 계정이어야 하며, delta `≤60s`다. 따라서 종료 20초 뒤 21초와 80초 성공은 관계 후보, 81초는 제외, 종료와 동시 또는 이전 성공은 제외다. 창 바깥 실패는 Brute relation endpoint가 될 수 없다. 일반 `failed_to_successful_login` 관계는 기존 정책을 유지하고 Brute relation과 분리한다.

Window 내부의 가장 가까운 실패 정책은 성공이 창이 끝나기 전에 발생하면 미완성 Brute pattern의 관계를 만들 수 있다. 종료 endpoint 정책은 창이 완성된 후의 성공만 연결하고 Case adapter의 detection range와도 맞으므로 우선한다. 둘 이상의 서로 다른 성공 이벤트가 가장 빠른 동일 시각을 가지면 ingestion ID가 없는 현 상태에서는 fail-closed한다. 동일 최소 delta의 원시 row를 collapse하거나 입력 순서로 고르지 않는다.

Shadow `correlate_window_end_to_success()`는 이 정책을 평가 전용으로 구현했다. 현행 Production correlation 함수는 바꾸지 않았다.

## 11. 동률·중복·누락 및 시간 기준

- 5회/20초, 5회/정확히 60초, 61초 거부, 60초+1µs 거부는 기존 36.9D 테스트에서 재실행했다.
- 입력 역순, 동시 timestamp, duplicate failure rows, IP 혼합, late 다른 계정, missing account, 서로 다른 계정 동률도 기존 36.9D corpus 및 새 shadow 테스트에서 확인했다.
- Candidate C의 계정 동률은 `detected=false`, window context/evidence 없음이다.
- 36.9D의 identity 없는 duplicate row는 실제 distinct attempt와 duplicate collection을 구분할 수 없어서 제거하지 않는다. 중복 수집이 count를 부풀릴 수 있다.
- 성공 이벤트의 가장 빠른 timestamp가 복수 row에 대응할 경우 shadow correlation은 fail-closed한다.
- 모든 창/관계 비교는 aware timestamp를 UTC로 정규화한다. naive 또는 잘못된 membership은 context 검증 실패다.

## 12. Password Spray 불변

공통 `summarize_ip_failures()`와 `detect_password_spray()`를 수정하지 않았다. 신규 shadow test는 4회/3계정의 60초 포함과 61초 제외, late noise, IP 분산, missing user, 중복 row에서 기존 전체 통계 및 결과를 검사했다. 36.9D fixture `bf_spray_boundary.log`도 전체 evaluation에서 기존 경계를 유지했다.

36.9F에서 Candidate C를 위해 공통 `within_window` 값을 변경하지 않는다. Spray는 전체 IP feature, count, account cardinality, Evidence, correlation, risk 및 Case 경계를 기존대로 유지해야 한다.

## 13. Risk 영향

실제 `build_risk_factors()`는 전체 `features`에서 volume·temporal signal 및 likelihood의 원시 통계를 구성하고, Detection·Correlation signal을 별도로 본다. shadow 결과는 다음처럼 갈렸다.

- whole-span baseline: Brute detection 없음, 6회/70초 feature, brute-success relation 없음
- Candidate evidence를 넣고 현행 correlation 사용: Brute detection 있음, relation은 창 밖 70→80초, Risk level `MEDIUM`, confidence `HIGH`
- Candidate evidence와 shadow 창 endpoint relation 사용: relation은 20→80초/60초, 전체 volume/temporal feature는 계속 6회/70초

현재 rationale에는 후보 window 기준 “5회/20초”가 나오고, 별도 volume·temporal signal에는 IP 전체 “6회/70초”가 나온다. 각 숫자는 서로 다른 범위에서는 참이지만 UI/보고서에서 범위 라벨이 없으면 서로 모순으로 읽힐 수 있다. 36.9F에서는 산식 변경 없이 rationale에 “선택 Brute 창”과 “전체 IP 관찰”을 구분해 표기하고, 잘못된 Brute correlation signal이 Risk에 들어가지 않도록 해야 한다. Risk level은 침해확률이 아니라 기존 heuristic이다.

## 14. Case / Timeline / Checklist / Report 영향

- Case adapter는 현재 Candidate Evidence를 reject한다. 따라서 local worker의 순서상 (`project(analysis)` → report projection → response/checklist binding) adapter 충돌이면 endpoint는 `CASE_PROJECTION_FAILED`로 종료하고, 같은 요청에서 report 생성 및 Case-bound Checklist 입력까지 도달하지 않는다.
- 내부 detection-specific account scope와 Window Context membership을 adapter가 검증하면 Case detection의 start/end/count는 선택 창에 맞출 수 있다. Brute relation은 선택 창 마지막 실패를 사용하므로 assembler의 membership 검증 범위에 들어온다.
- 전체 IP feature를 창 값으로 덮어쓰면 Case·Risk·Spray 모두 오염될 수 있어 금지한다.
- report projection은 shadow candidate Detection Evidence를 독립적으로 받아 failed count 5, target count 1, window 20을 보고했고 HTML에 합성 account 이름을 노출하지 않았다. 다만 현재 local API의 실행 순서는 Case projection이 먼저이므로 adapter를 해결하기 전에는 API 응답/Report가 완료되지 않는다.
- Legacy API projection도 기존 닫힌 DTO에서 계정명 및 내부 Evidence type을 노출하지 않았다.
- Checklist는 Case projection 이후 bound Case fields를 만든다. Case adapter 실패를 무시하고 Checklist를 계속 만들면 안 된다.
- `KEEP_LEGACY` renderer를 유지한다. Public DTO/schema 변경은 이번 권고에 포함하지 않는다.

## 15. Shadow Test 결과

신규 `tests/test_brute_window_consumer_contract_36_9e.py`는 **25 passed**다. 실제 parser·pipeline·Correlation·Risk·Case adapter·report projection 소비자를 호출한다. 평가 shadow helper 테스트는 선택 창 membership과 제안 correlation 결과를 확인한다.

RED 재현:

1. 새 shadow test를 먼저 작성한 초기 실행은 helper 미구현으로 test collection에서 실패했다.
2. 기존 Case adapter를 Candidate 5/20 Evidence 및 6/70 unchanged features에 직접 연결해 `invalid_detection_contract`를 재현했다.
3. 기존 Brute correlation에 Candidate detection을 주면 window 밖 실패 70초와 성공 80초가 선택되는 것을 재현했다.
4. Candidate detection이 Risk signal/rationale에는 추가되면서 전체 통계는 6/70으로 유지되는 것을 확인했다.
5. 별도 shadow context/endpoint contract는 25개 테스트에서 통과한다. 기존 adapter가 Candidate를 수용하게 된 것은 아니며 해당 거부는 `CURRENT_CONTRACT_INCOMPATIBLE`로 남긴다.

테스트는 assertion을 약화하거나 production consumer를 우회해 green 처리하지 않았다.

## 16. 개인정보 및 보안

기존 36.9D 합성 fixture와 예약 문서용 IP만 사용했다. raw log, 외부 네트워크, SIEM, LLM, 모델, Vector/VM은 사용하지 않았다. Window Context `repr`과 Detection Evidence에 account string이 포함되지 않는 것을 검사했다. legacy response 및 HTML projection에서 synthetic account가 노출되지 않는 것을 검사했다. Correlation 내부 결과는 기존 내부 contract처럼 account를 포함할 수 있으나 public projection은 alias 정책으로 노출을 막는다. Context는 공개 API, report 또는 checklist payload에 직렬화하지 않는다.

합성 검증은 secure erase, OS hard memory/CPU cap, 실제 사용자 자료 경계까지 보장하지 않는다.

## 17. 기존 Regression 및 환경

- 시작 baseline `uv run pytest -q`: **3302 passed, 2 warnings** (macOS, Python 3.12)
- 시작 SHA exact CI Run `41019687380`: Linux/Chromium 필수 gate 모두 성공, artifact 0
- 36.9D Candidate C 및 36.9C detector accuracy 평가: 재실행 결과 기존 기록 유지
- `uv sync --locked --dev`: 성공; `uv lock --check`: 성공
- 36.9D 전용 평가: 24개, whole-span TP9/FP0/FN9/TN5, Candidate C TP17/FP0/FN1/TN5; known-benign 경보 후보 정책별 2건
- 36.9C 정확도 CLI: 46개, Brute Force TP3/FP0/FN1/TN3, operational false-alert 후보 7건; 기존 기준 유지
- 기본 evaluation CLI: boundary 79/79, parser 195/200 (ignored 2, rejected 3), Risk 70/70, Case 70/70, Linux process 21/21
- 신규 36.9E focused shadow tests: **25 passed**; 36.9D 및 주요 Parser/API/Correlation/Risk/Case/Report/Privacy/Collector/Linux Audit focused 묶음: **656 passed, 2 warnings**
- 전체 `uv run pytest -q`: **3327 passed, 2 warnings** (macOS, Python 3.12); baseline보다 신규 shadow 테스트 25개 증가
- `python3 -m compileall -q app tests`: 성공; `git diff --check` 및 신규 파일 공백 검사: 성공
- `npm run test:a11y --silent`: 성공, 25개 상태 시나리오, 외부 요청 0, 테스트된 viewport에서 axe 오류·overflow·clipping·target 크기/간격 위반 0
- Production 경로(`app/detector`, parser, pipeline, risk, correlation, case, API, frontend), dependency 및 lockfile diff: 0
- 위 Linux/Chromium CI는 시작 SHA 증거다. 로컬 접근성 실행은 이번 작업 중 별도 수행했으며, 새 커밋 SHA에 대한 CI는 아직 실행하지 않았다.

## 18. Research Basis

- **NIST SP 800-63B-4**, Digital Identity Guidelines: Authentication and Authenticator Management, 현재 공식 웹 문서. 특정 verifier/authenticator와 subscriber account 조건에서 rate limiting을 요구한다. 이는 인증 서비스 자체의 통제 지침이며 본 프로젝트의 5회/60초 탐지 임계값이나 Brute 창과 성공의 상관 기준을 정의하지 않는다. 따라서 임계값은 프로젝트 heuristic으로 유지한다. [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- **MITRE ATT&CK T1110.001 Password Guessing**, Version 1.7, last modified 2026-05-12. 반복 인증 시도가 실패·계정 잠금과 연관될 수 있다고 설명하고, 잠금 정책이 조직별임을 전제한다. 이 내용은 패턴과 운영 맥락을 분리하고 성공/침해로 과장하지 않도록 한다. [MITRE T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- **MITRE ATT&CK DET0551**, Password Guessing via Multi-Source Authentication Failure Correlation, Version 1.0, last modified 2026-05-12. TimeWindow와 attempt threshold를 분석 mutable element로 설명하며 예시 threshold를 보편 규칙으로 고정하지 않는다. 이는 프로젝트의 60초 관계 경계를 산업 표준이라고 부르지 않고 기존 engineering heuristic으로 표시하는 근거다. [MITRE DET0551](https://attack.mitre.org/detectionstrategies/DET0551/)
- **Microsoft Learn — Sign-in log activity details**, last updated 2026-03-04. 제품의 sign-in logs는 request/correlation/token 식별자를 제공하지만 correlation ID는 client parameter 기반이며 정확성이 보장되지 않는다고 경고한다. 이 제품 전용 형식을 우리 parser에 일반화하지 않는다. 다만 현재 NormalizedEvent에는 신뢰 가능한 ingestion/session ID가 없으므로 duplicate identity를 발명하지 않고 모호한 동률을 fail-closed하는 설계 근거로 사용한다. [Microsoft Entra sign-in log details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details)

### Observable Evidence Mapping

```text
현 프로젝트가 기록한 auth outcome와 timestamp
→ NormalizedEvent(event_type, user, src_ip, timestamp, source)
→ 동일 IP·계정의 실제 login_failed membership을 UTC 60초 창에 귀속
→ 선택 창 안 실패 수와 start/end를 Detection Evidence로 기록
→ 창 endpoint보다 뒤의 같은 IP·계정 success만 최대 60초 내 relation 후보
→ 관측 관계로 제한; intent, credential correctness, compromise 또는 causation은 확정하지 않음
```

현재 raw inputs에는 stable attempt ID, session ID, NAT 내부 client ID, verifier lockout/rate-limit state가 없다. 그러므로 실제 시도 수, 동일 actor, duplicate-vs-distinct attempt 및 성공 원인을 확정할 수 없다.

### Limitations

5회 threshold와 60초 detection/correlation window는 이 저장소의 engineering heuristic이다. 반복적인 정상 사용자 입력, 승인된 점검, 공유 NAT, duplicate collection은 경보를 만들 수 있다. 일부 실패 누락, 늦은 로그, 시계 오차, 계정 누락은 창 결과에 영향을 준다. 성공은 계정 탈취를 증명하지 않고, 실패→성공 관계는 인과성을 증명하지 않는다. 실제 조직 운영 결과는 검증하지 않았다.

## 19. 최소 Production 수정 및 Rollback

36.9F 제안 범위:

1. `app/detector/brute_force.py`: 공통 `summarize_ip_failures()`를 건드리지 않고 Brute 전용 C window 선택기와 private Window Context 생성.
2. `app/analyzer/pipeline.py` 및 내부 분석-run wrapper: Context를 현재 분석 worker의 in-process/typed private sidecar로 운반. public result key/schema에는 포함하지 않음.
3. `app/correlation/attack_chain.py`: Brute 전용 correlation 인수로 Context membership/endpoint를 받고 창 종료 뒤 같은 IP·계정 success만 연결. 일반 authentication transition과 Password Spray correlation은 보존.
4. `app/analyzer/incident_case_adapter.py`, `app/analyzer/incident_case.py`: Brute Evidence를 Context에 검증하고 Brute detection 전용 account scope를 Case assembler에 전달. 전체 features와 spray account scope 보존.
5. `app/analyzer/risk.py` 및 필요 시 `app/analyzer/report_projection.py`: 계산식과 public schema는 유지하고 전체 IP 통계와 선택 Brute 창의 라벨을 명시적으로 구분.

**Rollback 기준:** context/membership/count/time/account mismatch, ambiguous tie 오수용, 창 밖 correlation, Spray feature/detection 변화, Risk rationale가 window/전체 범위를 혼합, Case/Timeline/report/checklist 범위 왜곡, privacy/API/schema 회귀 중 하나라도 발생하면 Candidate 경로를 되돌리고 whole-span 정책을 유지한다. API/schema 추가가 필요하거나 Context를 안전하게 비공개로 유지할 수 없으면 별도 설계/HOLD다.

## 20. Phase 36.9F 구현 Gate 및 최종 판정

36.9F는 별도 승인 후 진행한다. 필수 RED에는 6/70 aggregate 대 5/20 window, exact 60초/+1µs, wrong account/IP, missing user, duplicate, tie, reversed input, 21/80/81초 success, same-time success, out-of-window late failure, Case adapter membership, Risk scope labels, Report/Checklist redaction이 포함돼야 한다. Spray의 shared features와 기존 fixture output은 불변이어야 한다.

최종 판정은 `PHASE_36_9E_EVIDENCE_CORRELATION_CONTRACT_LOCAL_CONDITIONAL_GO`다. 이는 합성 shadow 검증과 최소 내부 계약 제안이 완료됐다는 뜻이며 Production 변경 완료 또는 실제 운영 승인이 아니다.
