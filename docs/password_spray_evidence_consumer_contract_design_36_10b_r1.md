# Phase 36.10B-R1 — Password Spray Evidence·Consumer Contract 설계

## 1. Executive Summary

**판정: `PHASE_36_10B_R1_CONTRACT_DESIGN_LOCAL_CONDITIONAL_GO`** (로컬 합성 characterization와 문서 검토가 모두 통과하는 경우). 이는 설계 산출물 승인이지 Production Window 적용 승인이 아니다. Production 정책은 whole-span으로 유지하고 Phase 36.10B의 `MORE_EVIDENCE_REQUIRED`도 유지한다.

36.10B에서 Current는 TP15/FP1/FN4/TN10, Sliding IP Window는 TP17/FP1/FN2/TN10, Known-account Window는 TP16/FP1/FN3/TN10이었다. 세 정책 모두 Known Benign 경보 후보 3건, 중복 전달 Pattern FP 1건, Distributed IP 미탐을 보였다. Window 후보가 회복한 두 late-noise 사례만으로 운영상 경보, IP 귀속 또는 Consumer 일관성 문제는 해결되지 않는다.

현재 whole-IP feature와 Spray Detection Evidence는 같은 전체 실패 집합을 나타낸다. Correlation은 그 Detection을 gate로만 사용하고 선택 Window를 받지 않는다. Risk는 Detection/Correlation 분기와 함께 전체 IP count·target·span을 계속 사용한다. Case adapter는 Spray evidence를 전체 feature에 맞춰 검증하며, Report의 Spray projection은 count 3개만 공개한다. 따라서 후보 Window Evidence를 기존 mapping에 대입하면 Case는 거부하고 Report projection 자체로는 구간·membership을 구분할 수 없다.

## 2. 시작 Gate 및 CI

- Repository: `ai-security-log-analyzer`; branch `main`
- 기준 SHA / HEAD / local main / origin main / GitHub main: `a499e1c7c7cec7654f9c2ba533a7eadd474c8dd4`
- 시작 Working Tree: clean; ahead/behind `0/0`
- GitHub Actions [Run 41192120468](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41192120468): 정확한 Head SHA, `push`, `completed / success`
- Locked Python 3.12 전체 회귀, 필수 Linux, Chromium/axe, tracked-file 검사 성공; Artifact 0개
- v0.4.0 tag/release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`: 변경하지 않음
- UI3 Safari 수용 상태: `SAFARI_USER_ACCEPTANCE_PENDING`, 변경하지 않음

시작 CI는 기준 SHA의 Gate 근거다. 이후 로컬 Phase 커밋의 CI를 뜻하지 않는다.

## 3. 36.10B 평가 결과

평가 Corpus는 36개 독립 합성 시나리오이며 Pattern matrix의 분모는 30개(positive 19, negative 11)다. 기존 46-scenario 평가 Corpus와 Brute corpus는 별개다.

| 정책 | TP | FP | FN | TN | 알려진 benign 경보 후보 |
|---|---:|---:|---:|---:|---:|
| Current whole-span | 15 | 1 | 4 | 10 | 3 |
| Sliding IP Window | 17 | 1 | 2 | 10 | 3 |
| Known-account Window | 16 | 1 | 3 | 10 | 3 |

이는 고정 합성 집합의 기술 통계다. 실환경 precision/recall, 오탐률 또는 운영 경보량의 추정이 아니다. 두 late-noise 합성 시나리오에서 Current FN이 후보 TP로 바뀌었으나, Batch/NAT 경보 후보와 중복 전달 FP는 유지됐다.

## 4. Current Production Policy

실제 경로는 `pipeline.detect_attacks_with_context()` → `summarize_ip_failures()` → `detect_password_spray()`다. `app/detector/password_spray.py`는 IP 전체 실패 feature를 사용한다.

- 같은 source IP로 그룹화
- 실패 행 4개 이상
- non-empty 사용자 문자열의 고유 수 3개 이상
- 전체 실패 timestamp의 min/max span이 60초 이하
- 성공 이벤트는 실패 count에서 제외
- 계정 없는 실패는 failure count에는 포함, known target 수에는 미포함
- 동일하게 보이는 중복 행은 각각 계산
- 계정 문자열은 별도 정규화 없이 정확한 문자열 기준
- 시간 창은 inclusive (`<=60s`); Parser에서 생성된 timestamp는 Pipeline에서 UTC 정규화

4/3/60은 프로젝트 휴리스틱이며 표준·벤더의 권위 있는 threshold가 아니다. Detection type은 `password_spraying_like`다. 동일 비밀번호나 의도·성공은 현재 telemetry로 관측되지 않는다.

`summarize_ip_failures()`는 `failure_count`, `target_users`, `unique_target_count`, 전체 `window_seconds`, `within_window` 및 전체 간격 통계를 만든다. 성공 이벤트를 feature 시간 범위에 포함하지 않는다. `detect_password_spray()`의 세 Evidence는 전체 실패 수, 전체 알려진 target 수, 전체 span을 나타낸다.

## 5. Whole-span vs Selected Window

이 두 관측 단위는 별도로 유지해야 한다.

| 범위 | 의미 | 예시 값 |
|---|---|---|
| Whole-IP Aggregate | 분석 입력에서 해당 IP로 정규화된 모든 실패 이벤트 | 전체 failure count, 알려진 target 집합, 첫/마지막 실패, 전체 span, 평균 간격 |
| Selected Spray Window | 별도 후보 정책이 qualifying 조건에 선택한 실제 subset | start/end UTC, member 수, member 내 알려진 target 수, membership, 선택 규칙 |

36.10B late-noise 합성 패턴에서 Whole-IP가 5회/4계정/90초이고 후보 Window가 4회/4계정/15초가 될 수 있다. 한 범위 값을 다른 범위의 설명문에 넣지 않는다. Window endpoint를 전체 관측 종료라고 하거나 전체 계정 수를 Window 안 계정 수라고 말하지 않는다. 전체 feature를 Window 값으로 덮어쓰는 방식은 Risk 및 기존 소비자 의미를 오염하므로 금지한다.

## 6. Evidence Contract 후보

아래는 향후 내부 계약 후보이며 이번 Phase에서 구현하지 않는다. Public Evidence/API/Projection 변경도 승인하지 않는다.

권장 내부 `SprayWindowContext`는 별도 타입으로 설계한다. 최소 의미 필드: private policy ID, canonical subject IP, UTC start/end, selected failure count, known target count, missing-account member count, selected source set, selection rule ID, exact normalized member-event references, AnalysisRun owner binding. 원 계정과 raw event는 외부 serialization/repr/error/log에 노출하지 않는다. `missing-user count`는 불확실성을 설명하되 특정 사용자를 추정하지 않는다.

검증 불변식:

1. 모든 member는 실제 normalized `login_failed` event다.
2. 모든 member는 같은 Analysis Run의 event다.
3. 모든 member는 같은 canonical source IP에 속한다.
4. start/end UTC는 실제 member의 최소/최대 timestamp와 일치한다.
5. 양 끝은 aware UTC이며 end ≥ start다.
6. selected failure count는 member 개수와 같다.
7. known target 수는 member의 실제 non-empty account 집합에서 계산한다.
8. 누락 계정은 임의 계정으로 매핑하지 않는다.
9. 중복을 출처 증거 없이 자동 제거하거나 병합하지 않는다.
10. window 선택은 입력 순서 변경에 결정적이며 동일 end 후보의 tie rule이 명시돼야 한다.
11. 다른 Run의 Context 또는 member 재사용은 거부한다.
12. Brute context와 타입·owner·semantics가 교차 사용되지 않는다.
13. Window 밖 event는 Window Detection Evidence로 포함하지 않는다.
14. 불완전하거나 서로 불일치하는 Context는 Correlation/Risk/Case 경계에서 fail closed한다.

현재 평가 후보의 “가장 이른 qualifying end, 그 끝에서 조건을 보존하는 가장 짧은 window”는 후보 정책일 뿐 승인된 Production 정책이 아니다. 동일 end 내 결정성과 계정 누락·중복 의미에 대한 추가 계약이 선행돼야 한다.

## 7. Spray Context와 Analysis Run Provenance

Brute `BruteWindowContext`의 재사용은 부적절하다. 기존 Brute Context는 하나의 known account에 대한 실패 window와 Brute 전용 Detection을 소유한다. Spray는 다중 known account, 일부 missing account, source 혼합 가능성을 갖는 집합이다. 타입 이름만 바꿔 공유하면 Brute의 단일 계정 불변식이 부정확하게 적용될 수 있다.

권장 방향은 기존 `AnalysisRunOwner`의 one-run/one-final-analysis 원칙을 재사용하되 별도 `SprayWindowContext`를 만드는 것이다. Owner는 같은 실행 경계임을 나타내며 Context 검증은 멤버십·IP·시각·count·target 집합의 사실성을 별도로 확인한다. Detector → Context 생성 → Detection binding → Correlation → Risk → Case adapter → 닫힌 Report projection이 동일 실행 결과를 따라야 한다.

| 시나리오 | 기대 거부/검증 경계 |
|---|---|
| A의 Context를 B 결과에 삽입 | AnalysisRunOwner / adapter binding에서 거부 |
| 같은 값으로 새 Context 재포장 | exact event reference와 Context binding 검사에서 거부 |
| A Detection을 B Context에 연결 | Detection-Evidence/Context 일치 검증에서 거부 |
| 다른 Run member 하나 치환 | member object identity/owner 검증에서 거부 |
| member 순서 변경 | 입력 순서 무관한 canonical selection은 허용; 선택 결과 identity는 그대로여야 함 |
| count, timestamp, IP, account scope 변경 | Context 재검증 불일치로 거부 |
| 다른 Run Correlation/Risk 혼합 | staged Analysis provenance binding에서 거부 |
| Brute Context를 Spray로 전달 | exact type 및 semantic validator에서 거부 |

이는 신뢰된 정상 내부 호출 흐름의 accidental cross-run misbinding에 대한 설계다. 동일 프로세스의 악의적 Python 코드, reflection/private mutation, 임의 코드 실행에 대한 보장을 의미하지 않는다. 정상적인 독립 재분석은 새 Owner와 새 Context가 새 Pipeline을 수행하면 허용된다.

## 8. Correlation Consumer

`app/correlation/attack_chain.py:correlate_password_spray_to_success()`는 Detection의 `is_detected`만 확인한 다음 `_closest_authentication_pair()`를 **전체 IP 로그**에서 실행한다. 그 함수는 알려진 동일 계정, 같은 non-empty IP, failure < success, aware/naive parity, delta ≤60초 조건을 사용하고 가장 짧은 delta를 선택한다. 동일 최소 delta의 서로 다른 event pair는 no relation으로 fail closed한다. Detection Evidence나 Spray Window Context는 인자로 받지 않는다.

### Characterization: Window 밖 endpoint

합성 이벤트: 실패 0/5/10/15초 (각기 4개 계정), 늦은 같은 사용자 실패 90초, 성공 95초. Current whole-span Detector는 5회/4계정/90초라 false다. 36.10B Sliding 평가기는 0–15초 후보 Window를 true로 반환한다. 후보 Detection을 기존 Correlation 함수에 의도적으로 주입해 consumer만 특성화하면 현재 함수는 90→95초, delta 5초를 선택한다. 이는 **현재 Pipeline이 후보 Window를 production에 연결한다는 뜻이 아니다.** 후보 Detection을 연결할 경우 현재 Correlation이 선택된 Window의 15초 endpoint를 보장하지 않는다는 증거다.

### Correlation 대안

| 옵션 | 이점 | 위험 / 조건 |
|---|---|---|
| A. 기존 closest pair 유지 | 기존 동작 호환 | Window 밖 failure가 선택될 수 있어 Evidence 범위와 불일치; 채택 불가 상태 |
| B. Window member failure만 후보 | 실제 member를 endpoint 후보로 제한 | success가 Window 뒤인지, 해당 계정이 member known account인지 정해야 함; multi-account Window에 임의 단일 actor 의미를 부여하면 안 됨 |
| C. Window end를 anchor로 사용 | Detection 범위와 시간축이 일관됨 | 창의 어느 known account 성공과 연결할지 정의 필요; endpoint는 event가 아니라 집계 시각일 수 있어 relation 의미·Case 검사 변경 필요 |
| D. 계정 귀속 불명확 시 관계 없음 | 보수적, false association 감소 | 성공/누락 계정 경계에서 relation을 잃을 수 있음; generic auth transition과 Spray relation 분리 필요 |

후속 설계 추천은 **B와 D 결합**이다. member event 중 성공 계정과 동일한 실제 known account failure가 포함되고 정확히 하나의 unambiguous pair/endpoint가 검증될 때만 관계를 만든다. 그 외에는 Spray→Success 관계를 만들지 않고 generic authentication transition은 기존 별도 의미로 둔다. 이는 credential reuse·same actor·causation을 증명하지 않는다. 성공이 window 안/동일 end인지/밖인지, 다른 계정인지, missing-user event가 있을 때의 관계 금지, equal-delta distinct event tie, duplicate row 정책을 별도 acceptance corpus에서 결정해야 한다.

Brute overlap에서 Brute correlation은 trusted single-account Brute Window end를 쓴다. Spray correlation은 현재 whole-IP closest pair다. 서로 다른 endpoint를 하나의 “인증 캠페인 종료”로 합치지 않는다.

## 9. Risk Consumer

`app/analyzer/risk.py:build_risk_context()`는 per-IP 전체 `features`, Detection, Correlation을 병합한다. `evaluate_likelihood()`의 순서상 Spray detection + Spray→Success correlation 분기는 먼저 HIGH likelihood를 선택하고 whole-span `within_window` 여부를 검사하지 않는다. Correlation이 없을 때 Spray-only 분기는 `target_scope >= 3 and within_window`를 요구한다. 따라서 후보 Window가 참이고 Whole-IP span이 60초 초과이며 관계가 없으면 Spray-only 분기는 건너뛴다. 반대로 Window 밖의 90→95초 correlation이 주입되면 Spray+Success 분기가 HIGH likelihood다.

Risk의 volume/temporal/targeting signals는 계속 whole-IP count, span, target count를 사용한다. Window Detection Evidence와 전체 feature 통계를 섞으면 숫자 자체는 각각 관측 사실이어도 label 없는 화면에서 모순으로 보인다. Future contract는 Risk가 Detection Context와 Whole-IP Context를 각각 provenance-검증하고 분기 rationale에 범위명을 명시하도록 해야 한다. 완전한 evidence validation 이전에는 window detection이 current whole-span feature를 조용히 override하지 못해야 한다. Score, weight, confidence 산식은 이번 Phase에서 변경하지 않는다.

Risk/Confidence는 통계 보정된 공격 확률이 아니다. `KNOWN_BENIGN` 합성 label은 Runtime 입력이 아니며 현재 Runtime은 승인된 batch 작업 여부를 알지 못한다. Unknown context는 safe/benign으로 해석하지 않는다. Brute/Spray가 같은 실패 행을 공유할 때 독립 관찰 수나 Risk contribution을 이중 계산하지 않는 정책도 별도 정의가 필요하다.

## 10. Case Adapter와 Incident Case

`app/analyzer/incident_case_adapter.py:_authentication_detection()`은 Spray Detection에 정확히 세 Evidence type/source를 요구한다. Count는 `features.failure_count`, target count는 `features.unique_target_count` 및 target account tuple 길이와 같아야 한다. Window seconds는 `features.window_seconds`와 같고 feature `within_window=True`여야 한다. 60초 초과는 거부된다. Canonical UTC failure time range가 제공되면 그 span도 Evidence duration과 일치해야 한다. Spray 전용 Window Context/membership은 현재 없다.

따라서 late-noise 예시의 candidate 4/4/15 Evidence를 unchanged whole features 5/4/90과 함께 case adapter에 넣으면 `IncidentCaseAdapterError(code="invalid_detection_contract")`로 거부된다. 이는 현재 adapter 계약이 불완전 후보를 fail-closed하는 characterization이지 기능 결함은 아니다.

`incident_case.py`의 현재 supported rule은 `CASE-BRUTE-SUCCESS-01`과 `CASE-AUTH-TRANSITION-01`이다. Spray Detection은 `unsupported_for_case_assembly` 사유의 independent observation으로 남고, Spray→Success relation도 `CASE-SPRAY-SUCCESS-01`의 `NO_GO_UNTYPED_PRODUCTION_TARGET_MEMBERSHIP` 상태 때문에 독립 관찰/no-go로 남는다. 따라서 현재 Spray-only Detection으로 Incident Case rule이 생성되지는 않는다. Sliding 도입 전 Detection-specific scope와 window endpoint membership을 adapter가 검증하고 typed assembler까지 전달하더라도 Spray Case 자체는 별도 설계·승인을 받아야 한다. 같은 event가 Brute와 Spray evidence에 모두 포함되면 독립 관측 두 개로 과장하면 안 된다. Public case projection에 raw log, 원 계정, 새 Window field를 추가하지 않는다.

## 11. Report Projection

`report_projection.py:PasswordSprayingLikeEvidenceProjection`에는 `failed_attempt_count`, `target_account_count`, `time_window_seconds` 세 scalar만 있다. `_authentication_evidence()`는 현재 Detection evidence에서 이 값만 투영한다. 시작/끝, member identity, missing-user count, selected policy ID가 없어 현재 projection은 whole-span인지 future selected window인지 독립적으로 구별할 수 없다.

후속 적용 전에 private validated semantic projection이 whole-IP aggregate와 selected window를 나눠야 한다. Public schema는 별도 승인 없이는 변경하지 않는다. 기존 19-field Investigation Workspace Projection과 Renderer Rollback을 유지한다. 필요한 문구의 의미 후보(미승인): “선택된 관측 구간에서 여러 계정에 대한 인증 실패 패턴이 확인됨”; “같은 비밀번호 사용 또는 침해를 입증하지 않음”; “기록된 IP가 한 명의 사용자나 행위자를 뜻한다고 단정할 수 없음.” Window count를 전체 실패 count라고 쓰지 않는다.

## 12. Restricted Report / Checklist / Guidance / UI

Restricted/HTML report는 승인된 closed projection을 소비한다. 내부 Context, member events, raw event, 계정 원문, 새 provenance field를 외부/HTML/Checklist/Guidance로 흘려보내면 안 된다. Checklist v2와 Guidance는 현재 명시적 요청·Case binding 계약을 유지한다. 현재 UI는 검증된 projection만 표시하며 Window 전용 표시 계약은 없다. 이 Phase에서는 Frontend, CSP, API, 19-field schema, `KEEP_LEGACY`를 변경하지 않는다.

## 13. Static / Live Parity

같은 전체 정규화 event set을 같은 owner/run semantics로 batch 처리한다면 후보 선택은 입력 순서와 무관해야 한다. Live의 prefix는 아직 오지 않은 event를 알 수 없으므로 전체 입력 Static 결과와 모든 시점에 일치한다고 보장할 수 없다.

후속 validation은 같은 prefix만 서로 비교하며 다음을 별도 구분해야 한다.

- 동일 normalized prefix, 입력 순서 변형: 결정성/동일 결과
- batch 분할과 prefix: prefix별 재계산 parity
- late noise 도착: 이후 revision에서 결과 변경 가능성
- retransmission/duplicate: source가 증명하는 event identity 없이는 추가 event로 취급
- checkpoint/rotation/resume/누락: 관측 집합 차이; 조용한 equality 주장 금지
- 다른 AnalysisRun: Context 재사용 거부
- offset equivalent: UTC 정규화 후 동일 시각
- boundary를 나눠 전달: rolling buffer semantics와 window 완성/만료 기준 별도 정의

기존 Live proposal/revision/checkpoint/resource/privacy 계약은 변경하지 않는다. 현재 UI의 live parity와 실제 collector 안정성은 본 Phase에서 실행하지 않았다.

## 14. 중복 이벤트

현재 Parser/Event schema 전반에 안정된 공통 event ID가 보장되지 않는다. 동일 내용의 두 행은 실제 반복 시도일 수 있고, 수집 재전달일 수도 있다. 따라서 “Duplicate-looking Events ≠ Proven Duplicate Deliveries.”

| 방안 | 평가 |
|---|---|
| 현재처럼 각 행 계산 | 관찰 행 수와 일치하지만 재전달이 threshold를 부풀릴 수 있음 |
| 원천의 신뢰 가능한 event ID가 있는 경우만 dedupe | 정확한 source contract가 추가된 경우에만 가능; 현재 공통 ID 없음 |
| 중복 의심을 별도 limitation으로 표시 | 탐지를 침묵 제거하지 않으면서 불확실성 표기 가능; 현재 parser 신호 부족 |
| 중복 의심만으로 차단 | 실제 반복 시도를 놓칠 수 있어 근거 부족 |

이번 Phase는 dedup 기능이나 새 Parser Field를 만들지 않는다. “중복 전달”이 독립적인 Manifest 근거로 확정된 synthetic corpus 외에는 Pattern label로 확정하지 않는다.

## 15. NAT / Shared Egress / Known Benign

현재 Runtime에서 Source IP는 Parser에 관측된 주소다. 그 주소가 실제 사용자나 단일 행위자를 식별한다고 볼 수 없고, Runtime은 승인된 Batch 운영 맥락도 알지 못한다. 36.10B `KNOWN_BENIGN`은 manifest의 독립 생성 메타데이터이지 Runtime 신뢰 신호가 아니다. 휴리스틱으로 탐지를 제거하거나 unknown을 benign으로 바꾸지 않는다.

MITRE ATT&CK T1110.003은 Password Spraying을 여러 계정에 적은 수의 비밀번호를 시도하는 행위로 설명하고, 낮은 속도·장기간 분산으로 좁은 threshold를 피할 수 있음을 기술한다. 이는 프로젝트 4/3/60 값을 정당화하지 않으며, 현재 로그의 “같은 비밀번호” 관측을 제공하지 않는다. Microsoft Entra의 공식 sign-in-log 문서는 IP/위치 해석이 mobile carrier/VPN 등으로 단정적이지 않을 수 있음을 안내한다. Microsoft Password Spray incident response playbook은 IP·계정·시간 및 후속 활동을 함께 조사하도록 안내한다. 이는 분석 한계를 지지할 뿐 현재 parser의 NAT/승인 맥락 관측 근거가 아니다.

### Research Basis → Observable Evidence Mapping → Limitations

| 자료 | 사실과 설계 영향 |
|---|---|
| [MITRE ATT&CK T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) (페이지에 표시된 last modified: 2025-10-24) | 다수 계정에 단일/소수 비밀번호를 시도하는 정의와 threshold 회피를 설명한다. 후보 Window는 관측 실패/계정 다양성만 설명하고 credential reuse를 주장하지 않는다. 4/3/60은 프로젝트 heuristic으로 남는다. |
| [Microsoft Entra sign-in log activity details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details) (현재 문서, 2026-10-31 확인) | IP와 물리 위치의 결정적 연결이 없고 VPN/mobile carrier 주소 풀 등이 영향을 준다고 설명한다. IP를 공격자/단일 주체 identity로 취급하지 않는 설계에 반영한다. |
| [Microsoft password spray incident response playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-password-spray) (현재 문서, 2026-10-31 확인) | IP·시간대·계정과 후속 활동을 추가 맥락과 함께 조사하도록 안내한다. 자동 Case/Risk가 침해를 확정하지 않고 추가 IdP/MFA/session evidence를 요구해야 한다. |

Observable map: 연구상 행위 설명 → 필요한 실제 시도/계정/IP/time telemetry → 현재 `NormalizedEvent.event_type`, `.user`, `.src_ip`, `.timestamp` 및 Parser source → 프로젝트 heuristic aggregation. 현재 로그는 비밀번호 값, 계정 소유권, 공용 egress 여부, 승인 업무, event delivery identity, 동일 행위자, 성공 원인을 보이지 않는다. FP 가능성에는 정상 동시 로그인, batch, NAT, duplicate delivery가 있고 FN에는 저속·multi-IP·missing user·unsupported format·수집 누락이 있다. 추가 요구 telemetry는 source별 stable event ID/sequence, IdP request/session identifier, authoritative account identity, trusted NAT/proxy/automation inventory 및 승인된 운영 맥락이다.

## 16. Consumer Compatibility Matrix

| Consumer | 현재 입력/의미 | 향후 Window에 필요한 계약·위험 | Fail-closed / 테스트 / 공개 영향 / 승인 조건 |
|---|---|---|---|
| Detector `detect_password_spray` | whole features + all IP failures; whole-span evidence | 별도 context 생성; public detection meaning을 몰래 바꾸지 않음 | member/evidence invariant; unit + pipeline; public 불변; 추가 corpus 통과 후 |
| Shared Features `summarize_ip_failures` | all IP failures/count/users/span | aggregate whole-span으로 계속 유지; Window 값을 덮으면 Brute/Spray/Risk 영향 | 값 변경 거부; dual-scope test; schema 영향 없음; consumer migration 계획 |
| Correlation `correlate_password_spray_to_success` | Detection bool + all IP logs에서 closest pair | 현재 Window 바깥 failure 선택 가능; member/target account join 필요 | unowned/ambiguous member는 관계 없음; boundary/tie/missing-account corpus; relation schema 의미 승인 |
| Risk `build_risk_context/evaluate_likelihood` | whole features + Detection + correlation | spray-only whole `within_window`; relation 분기는 HIGH likelihood; range mismatch | mismatched scope 거부/범위 label; detection/risk matrix test; Risk DTO 불변; rationale 설계와 승인 |
| Case Adapter `_authentication_detection`, `_correlations` | 3 Spray evidence와 전체 feature 동등성 | 4/4/15 vs 5/4/90 불일치로 거부; Window context 전달 없음 | Context/evidence/member 검증 거부; adapter test; public field 없음; typed internal migration 필요 |
| Incident Case `assemble_incident_cases` | validated typed detection/relation/risk | 현재 Spray-success assembly는 account membership/endpoint 의미에 의존 | 불명확한 relation 및 overlap 거부; rule/duplicate observation tests; Case DTO 불변 |
| Case Projection `build_investigation_case_projection` | assembled closed cases | selected window provenance는 현재 projection에 없음 | private context 제거, 허용된 scalar만; privacy test; schema 변경은 별도 승인 |
| Report Projection `_authentication_evidence` | 3 scalar values | scalar-only projection은 범위를 식별 못함 | validate semantic scope before projection; report test; Public DTO 변경 필요 여부 별도 gate |
| Restricted Report | validated report/case inputs | Window wording/membership and limitations absent | raw/context 금지, invalid projection reject; canary test; external contract unchanged |
| Checklist | validated Case-bound request inputs | no Window fields today; checklist meaning must not recast counts | stale/mismatched Case reject; opt-in POST tests; API unchanged |
| Guidance | explicit Case-bound local guidance | cannot infer benign context or reuse private window | explicit request and stale response isolation; no API/schema change |
| Investigation Workspace | 19-field projection, case/risk/relation summary | no selected window membership; whole-vs-window display risk | closed projection only; privacy/meaning tests; keep 19 fields/legacy renderer |
| Static Analysis | full parsed input and one analysis run | deterministic window possible, but whole-span remains separate | owner-bound context; order/source/tie corpus; no Public change |
| Live Monitoring | evolving prefix/proposal/revision | late event can revise selected candidate; checkpoint gaps differ from full static input | proposal ownership and revision consistency; prefix/late/duplicate tests; SSE unchanged |
| Trusted Analysis Provenance | Owner binds Detector→Correlation→Risk→final result | Spray-specific context not currently owned | cross-run/member replacement reject at consumer boundary; provenance tests; private only |

Unknown source-specific event IDs, Spray Case anchor acceptance in every report path, and exact Restricted Report presentation are `UNVERIFIED` beyond cited code/tests; do not infer support from a design document.

## 17. 설계 대안 비교

| 방안 | Evidence / provenance | Consumer / 호환성 | 비용·잔여 위험 | 판단 |
|---|---|---|---|---|
| A. Current whole-span 유지 | 현재 evidence/features 일치 | 모든 현행 consumer 유지 | late-noise FN 4 remains in 36.10B corpus; NAT/duplicate ambiguity remains | 지금 즉시 production 안전 변경은 없음 |
| B. Detector에 Sliding만 적용 | detector Evidence는 selected window, feature는 whole-span | correlation, Risk, Case가 범위 불일치; adapter 실제 거부 | 낮은 초기 비용이나 잘못된 relation/risk/report 의미 위험 큼 | 거부 |
| C. Run-owned Spray Context + consumer 동시 설계 | 정확한 membership, UTC, source, account scope 검증 | Correlation/Risk/Case/Report/Static/Live 동시 migration 필요 | 구현 및 검증 범위 넓음; 운영 false-alert 문제는 잔존 | 장기 설계 구조 후보 |
| D. 추가 근거까지 정책 보류 | 현 계약 유지 | 변경 없음 | late-noise 누락은 그대로 | **최우선 안전 경로** |

권고는 D를 우선하고, 추가 증거가 후보를 계속 지지할 때 C의 설계/validation을 단계적으로 진행하는 것이다. B는 compatibility evidence에서 실제 adapter rejection과 Correlation 시간축 불일치가 확인돼 수용하지 않는다. 이는 정책을 영구히 유지한다는 결정이 아니다.

## 18. Failure Modes 및 추가 Corpus 요구

| Corpus 묶음 | 독립 라벨/필드 | Acceptance 관찰 |
|---|---|---|
| Duplicate | stable event ID 없음/있음, 확정 전달 중복, 실제 retry, replay, same timestamp | 중복 근거와 실제 반복의 라벨 독립성, 정책별 threshold 영향 |
| Shared egress | 승인 Batch, multi-user NAT, mixed source, unknown actor | Pattern label과 operational label 분리, 같은 IP가 사용자 identity 아님 |
| Correlation edge | window member success, outside failure/success, 다른 account, same end, equal delta, late noise | member/time/account constraint, ambiguous fail closed, generic relation 분리 |
| Consumer compatibility | Detection, Risk, Case, Report, Checklist projection | 동일 실행 scope, rationale 범위 label, invalid evidence 거부, privacy canary |
| Parser coverage | missing user, timestamp/offset, partial parse, unsupported source | parsed/ignored/rejected 분모 독립; Parser fail을 TN으로 오인 금지 |
| Static/Live | same prefix, reordered input, batch split, checkpoint/rotation, late/replay | same-prefix parity와 아직 미도착한 이벤트에 따른 revision을 구분 |

Scenario 수를 임의의 통과 목표로 삼지 않는다. 각 묶음은 최소 positive/negative/unknown 및 parser-observability label 근거, 예상 member set, policy별 기대 결과를 후보 출력과 독립적으로 고정해야 한다. `KNOWN_BENIGN`은 test manifest 안에만 둔다.

## 19. Characterization Tests

신규 `tests/test_spray_consumer_contract_design_36_10b_r1.py`는 실제 production `detect_attacks`, `correlate_password_spray_to_success`, `correlate_attacks`, `assess_risk_with_metadata`, Case adapter와 Report projection을 호출한다. 5개 테스트는 whole-span count/evidence 현재 조건, Sliding 평가와 Production 분리, window 밖 90→95초 correlation, whole-span Risk 통계와 Detection/Relation 분기, Case adapter 불일치 거부 및 scalar-only report projection을 특성화한다. Candidate Detection 주입은 하위 consumer의 현재 수용 계약을 살펴보는 합성 boundary test일 뿐 Pipeline wiring이 아니다. 미래 Window Acceptance Criteria는 이 현행 characterization과 별도 후속 테스트로 유지한다.

## 20. Privacy / Security 및 Production Non-change

합성 이벤트만 사용하며 테스트 출력에 raw event, 계정 secret, credential, private Context를 출력하지 않는다. 새 Context는 설계상 private-only이며 repr/serialization/logging에서 제외해야 한다. 외부 네트워크나 LLM을 호출하지 않는다. Raw account/IP를 새로운 public report field로 추가하지 않는다.

이번 Phase의 Production 수정 금지: Parser, Detector, Pipeline, Correlation, Risk, Case, API/Schema, Frontend, Live Monitoring, Checklist, Report, 36.10B evaluator/corpus/Ground Truth, CI 및 dependency. Public `investigation-workspace-ui/v1` 19-field contract, CSP, legacy renderer/rollback은 불변이다.

## 21. 기존 Regression, 한계와 미검증

- 기존 evaluator 지표는 별도 실행 결과 그대로 유지해야 하며, 36.10B의 신규 corpus를 기존 46-case 점수에 합산하지 않는다.
- UI3 Navigation E2E는 기존 실행 방법으로 별도 확인한다. 구형 stale DOM 테스트의 과거 실패는 통과로 표시하지 않는다.
- Safari user acceptance는 `SAFARI_USER_ACCEPTANCE_PENDING`.
- 실환경 precision/recall, NAT ownership, approved job context, source event ID availability, 실제 collector duplicate rate, 조직 운영은 `UNVERIFIED`/`NO_GO`.
- 모델 기반 AI `NOT_TESTED`; OS hard CPU/memory limit 및 secure erase 보장 없음; Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`; Renderer `KEEP_LEGACY`.
- 동일 프로세스의 악의적 private object mutation과 arbitrary code execution 방어를 주장하지 않는다.

## 22. 권고 다음 Phase

**우선 권고: `Phase 36.10B-R2 — Spray Window Consumer Contract Independent Validation`의 앞부분을 추가 근거 corpus expansion으로 시작하고, 같은 작업 안에서 scope를 제한한 consumer compatibility synthetic validation을 수행한다.** 36.10B 결과가 `MORE_EVIDENCE_REQUIRED`이고 현재 상관관계와 Case 거부가 재현되어 있으므로, 바로 Production 적용 설계보다 duplicate/shared-egress/correlation-edge 독립 라벨을 먼저 늘리는 것이 가장 작은 안전 단위다.

R2 acceptance 이후에도 consumer validation이 일관되고 후보 근거가 남을 때만 별도 승인된 production remediation phase를 제안한다. 현재 단계에서 Sliding Window Production 적용은 승인하지 않는다.

## 23. Rollback

허용되는 변경은 새 characterization 테스트, 본 문서와 `docs/index.md` 링크뿐이다. 롤백은 이 Phase 산출물만 제거한다. Production 변경이 발견되면 범위 위반으로 HOLD하고 해당 변경을 성공 산출물로 커밋하지 않는다. 기존 HOLD/Closure 기록과 Ground Truth는 수정하지 않는다.

## 24. Final Decision

모든 characterization·evaluation·regression이 실제로 통과하고 Production diff가 없는 경우에만 `PHASE_36_10B_R1_CONTRACT_DESIGN_LOCAL_CONDITIONAL_GO`로 판정한다. 이는 private Spray Context 및 downstream consumer 계약을 설계할 수 있다는 로컬 합성 범위 결론이다. Current policy의 결과는 계속 `MORE_EVIDENCE_REQUIRED`; 운영 사용, 실데이터, Production Sliding 적용을 승인하지 않는다.

다음 후속 단계: `Phase 36.10B-R2 — Spray Window Consumer Contract Independent Validation` (추가 duplicate/shared-egress/correlation edge 근거 + 독립 consumer boundary 검증). Correlation 설계 대안은 B+D 결합을 평가 기준으로 제안하되, 별도 Acceptance Corpus 결과 전에는 구현 계약으로 확정하지 않는다.
