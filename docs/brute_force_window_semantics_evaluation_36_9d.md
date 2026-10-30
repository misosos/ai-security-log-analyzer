# Phase 36.9D — Brute Force 시간창 의미 평가

## 1. 요약

기존 Brute Force 탐지기는 IP별 전체 실패 묶음이 60초 이내인지 확인한다. Phase 36.9C의 `bf_burst_with_late_noise.log`는 처음 20초에 동일 IP·계정의 실패 5회, 70초에 추가 실패 1회를 두어, 5회 burst가 존재해도 전체 span이 70초가 되어 현재 규칙이 탐지하지 않는 경우를 재현한다.

평가 전용 후보 3개를 추가로 비교했다. 24개 합성 시나리오에서 현재 정책은 9 TP/9 FN, Sliding A는 14/4, B는 16/2, C는 17/1이었다. 네 정책 모두 이 작은 corpus에서는 Pattern FP가 관측되지 않았다. 승인된 합성 인증 시험 2건은 네 정책 모두 탐지해 운영상 false-alert 후보로 별도 집계했다. `PATTERN_UNDETERMINED` 1건은 confusion matrix에서 제외했다.

결과만으로 운영상 우수성을 확정할 수 없다. 특히 계정 식별 누락, 공유 IP, 중복 수집, 둘 이상의 계정이 동등한 burst를 만든 경우, 그리고 선택된 burst 종료 시각과 기존 Correlation이 고르는 실패 시각의 차이가 남는다. 평가 단계의 정책 판정은 **`CANDIDATE_RECOMMENDED`**이며 Candidate C를 별도 remediation 설계의 기준 후보로만 권고한다. 이는 production 정책 채택 또는 구현 승인이 아니다. Production Detector는 변경하지 않았다.

## 2. 시작 Gate

- 시작 SHA: `ecd9ddc13fb7a1dec07d9f81371b2a2eee35ca35`
- GitHub Actions Run [41016471106](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41016471106): 정확한 head SHA, `push`, `completed/success`
- Locked Python 3.12, Linux process/SSH recovery, 전체 pytest, TCP Syslog Linux, JSONL runtime Linux, restricted report, Chromium/axe, tracked-file invariant: 모두 성공
- Artifact: 0개
- branch `main`; local HEAD, local `main`, `origin/main`, GitHub `main` 일치; ahead/behind `0/0`; 시작 working tree clean
- v0.4.0 원격 annotated tag object `855a92827a605805b62c627ed719958620150ec4`, peeled tag 및 Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지 확인

이는 **시작 SHA**의 CI 결과다. 이번 평가 커밋에 대한 Linux CI 결과가 아니다.

## 3. 현행 Brute Force와 Password Spraying-like 구현

코드 위치: `app/detector/brute_force.py`, `app/detector/password_spray.py`, 호출부 `app/analyzer/pipeline.py`.

`group_failures_by_ip()`는 `login_failed`를 `src_ip`별로 모은다. `summarize_ip_failures()`는 해당 IP의 실패 전체에서 `failure_count`, 정렬된 알려진 `target_users`, `unique_target_count`, `window_seconds=min(timestamp)..max(timestamp)`, `within_window=(전체 span ≤ 60초)`, 평균 간격 및 간격 변동성을 만든다.

`detect_brute_force()`는 실패 5회 이상, 알려진 고유 계정 수 정확히 1, `within_window=True`를 모두 요구한다. Evidence의 실패 수와 time range도 IP의 **전체 실패 목록**을 사용한다. 이 방식은 임의의 60초 subwindow를 찾지 않는다. `user`가 비어 있거나 누락되어도 고유 계정 수 계산에서 제외되며, 그 실패 이벤트는 `failure_count`에는 남는다.

중요하게도 `summarize_ip_failures()` 출력은 `pipeline.detect_attacks()`에서 Brute Force와 Password Spraying-like 모두에 전달된다. Spray 규칙은 실패 4회 이상, 알려진 계정 3개 이상, 같은 `within_window`를 사용한다. 공통 요약의 `within_window` 의미를 바꾸면 Spray도 바뀐다. 이번 Phase에서는 이 공유 기능을 수정하지 않았다.

이 5회/60초는 표준 또는 벤더가 정한 공격 임계값이 아니라 **프로젝트가 가진 기존 engineering heuristic**이다. 후보도 정책 비교를 위해 같은 값을 사용했다. NIST SP 800-63B-4는 특정 verifier/authenticator 조건에서 계정별 실패 시도 rate limiting을 요구하지만, 로그 분석기의 5회/60초 탐지 임계값을 규정하지 않는다. MITRE ATT&CK T1110은 Password Guessing과 Password Spraying을 서로 다른 하위 기술로 구분하지만, 이 프로젝트의 시간창을 규정하지 않는다.

## 4. Phase 36.9C 미탐 재현

`sample_logs/detector_accuracy/bf_burst_with_late_noise.log`를 직접 읽었다.

| 현지 입력 시각 | 이벤트 | 계정 | IP |
|---|---|---|---|
| 09:00:00, 05, 10, 15, 20 | `login_failed` 5건 | 동일 합성 계정 | `198.51.100.23` |
| 09:01:10 | `login_failed` 1건 추가 | 동일 합성 계정 | 동일 IP |

Application parser는 6건 모두 `login_failed`로 정규화하고, 입력에서 같은 계정과 IP를 보존했다. 최초 5건 span은 20초이고 전체 6건 span은 70초다. 직접 `summarize_ip_failures()` → `detect_brute_force()`를 실행한 결과 `failure_count=6`, `unique_target_count=1`, `window_seconds=70`, `within_window=false`, 탐지 `false`였다. 분석 파이프라인도 이 실패 목록을 빠짐없이 동일 IP Detector에 전달한다. 따라서 해당 미탐은 Parser 누락이 아니라 현재 whole-span 조건의 결과다.

## 5. 후보 정의

새 코드는 `app/evaluation/brute_window_policy.py`에만 있으며 Production Pipeline에서 import하지 않는다. `app/evaluation/brute_window_evaluation.py`는 정적 fixture를 parser에 전달하고 현재 실제 Detector 결과와 후보 계산을 나란히 평가한다.

| 이름 | 정의 |
|---|---|
| Current whole-span | Production의 `summarize_ip_failures()`와 `detect_brute_force()`를 그대로 호출. 전체 IP의 실패 5회 이상, 알려진 고유 계정 하나, 전체 span ≤60초. |
| Sliding A — 전체 IP 단일 계정 | 전체 IP 실패 묶음의 **알려진** 계정 집합이 하나여야 한다. 그 뒤 60초 이하 후보 구간에서 실패 5회 이상과 알려진 계정 집합 하나를 요구한다. |
| Sliding B — 구간 내 단일 계정 | 후보 구간 안에서 실패 5회 이상과 알려진 고유 계정 하나를 요구한다. 구간 밖의 다른 계정 실패는 제외할 수 있다. |
| Sliding C — IP·계정 선그룹 | 알려진 계정을 IP 내에서 각각 분리하고 계정별 60초 이하 구간에 실패 5회 이상을 요구한다. 사용자 없는 행은 계정별 실패 수에 포함하지 않는다. |

A와 B는 사용자 누락 이벤트를 실패 개수에는 세지만 알려진 계정 수에는 세지 않는다. 따라서 알려진 계정 하나와 누락 계정 실패가 함께 있어도 탐지 후보가 될 수 있다. 이것은 누락 계정을 기존 계정으로 추정한다는 뜻은 아니지만, 단일 계정인지 확인할 수 없는 경보를 내는 한계다. C는 누락된 사용자 행을 어느 계정에도 귀속하지 않으며 그 행으로 임계값을 채우지 않는다.

모든 후보는 timestamp가 timezone-aware인지 확인하고 UTC로 변환한다. 경계는 양 끝 포함, `end-start ≤ 60초`다. 초 단위 fixture에서 60초/61초를 확인했고, normalized event 단위에서 60초+1µs는 제외했다. 입력 순서와 무관하게 시간순 평가한다.

### 후보 창 선택과 Evidence

구간을 시작·종료의 고유 timestamp 조합으로 열거한다. 동일 timestamp의 모든 행을 포함한다. 후보 창은 실패 5회 이상과 알려진 계정 수 하나를 만족한다. C는 앞서 계정별 분리를 적용한다. 동일 문자열/동일 초 입력도 자동 dedup하지 않으며 별도 입력 행으로 센다. 현재 신뢰할 수 있는 ingestion event ID가 없기 때문이다.

비교 가능한 선택 규칙은 `earliest`, `shortest`, `most_failures`, `fastest_threshold`다. 기본 후보는 `fastest_threshold`: 가장 이른 종료, 그 다음 시작, span, 실패 수 순으로 선택한다. `bf_late_noise_61_after_60`에서 `fastest_threshold`는 0–60초의 다섯 행을 선택하지만 `shortest`는 15–61초의 다섯 행을 선택한다. 따라서 같은 탐지 여부라도 Evidence 시간 범위가 달라질 수 있다.

동일 우선순위의 창이 서로 다른 계정에 걸리면 계정 문자열의 사전순으로 선택하지 않는다. 후보는 존재하지만 단일 Evidence를 고를 수 없으므로 `detected=false`, `candidate_present=true`, `exclusion=window_selection_ambiguous`, 창 Evidence 없음으로 표현한다. 동률에서 어떤 계정을 고르는 것이 안전한지 근거가 없기 때문이다.

| 필드 | 후보 평가 Evidence 의미 |
|---|---|
| `failure_count` | 선택 창 안의 행 수 |
| `full_failure_count` | 해당 subject IP의 전체 입력 실패 행 수; 별도 필드 |
| `unique_target_count` | 선택 창에 관측된 알려진 계정 수 |
| `window_seconds` | 선택 창 끝과 시작의 UTC 경과 초 |
| `start_time`, `end_time` | 선택 창 경계의 정규화 UTC 시각 |
| `average_interval` | 창 내부 정렬 이벤트 timestamp 간격의 산술 평균; 같은 초 중복 간격은 0 |
| `interval_variability` | 창 내부 간격의 평균 절대 편차 |

이들은 평가 JSON의 후보 필드이며 기존 `DetectionResult` Evidence 모델을 바꾸지 않는다. 공용 CLI 결과는 계정명·IP·raw log를 포함하지 않는다.

## 6. Corpus와 라벨

전용 정적 corpus는 `sample_logs/brute_window_evaluation/manifest.json` 및 24개 `.log` fixture다. 기존 36.9C 46개 corpus와 분리했다. 모두 직접 작성한 Application 또는 승인된 ISO-style SSH 문법의 합성 입력, 고정 날짜와 예약 주소, `synthetic_user_*` 계정이다. parser가 24개 전부 예상 이벤트 수와 failure count를 보존하는지 별도로 확인한다.

manifest는 시나리오 ID 중복, fixture 집합 불일치, 절대경로/상위경로/하위경로, symlink, 과도한 크기, source·라벨 allowlist, 잘못된 subject IP, timestamp contract, 후보 기대값을 거부한다. 외부 파일·네트워크를 읽지 않는다. 기대값과 Behavioral/Operational 라벨은 manifest에 사전 작성되어 있으며 실행 결과에서 역생성하지 않는다. 실행 결과가 명시된 정책 기대값과 다르면 평가 오류로 종료한다.

| 라벨 종류 | 값 | corpus 수 |
|---|---|---:|
| Behavioral Pattern | `PATTERN_PRESENT` | 18 |
| Behavioral Pattern | `PATTERN_ABSENT` | 5 |
| Behavioral Pattern | `PATTERN_UNDETERMINED` | 1 |
| Operational Context | `SIMULATED_ATTACK` | 14 |
| Operational Context | `KNOWN_BENIGN` | 2 |
| Operational Context | `AMBIGUOUS` | 7 |
| Operational Context | `UNVERIFIED` | 1 |

Behavioral 라벨은 독립 시나리오 설명에서 동일 IP·알려진 계정에 관측 실패 다섯 건이 60초 안에 배치됐는지 미리 정한 것이다. 운영 맥락 라벨은 합성 시나리오 저자가 제공한 별도 설명이다. `AMBIGUOUS`는 Behavioral 라벨이 확정돼 있으면 Pattern matrix에는 포함하지만, 운영상 정상/공격 분류로 쓰지 않는다. 누락 계정 시나리오는 Pattern `UNDETERMINED`여서 네 정책 matrix에서 제외하고 TN으로 세지 않는다.

## 7. 시나리오별 Current/Candidate 결과

`+`는 탐지, `-`는 미탐/미탐지, `?`는 탐지 후보는 존재하지만 동등 계정 창 때문에 증거를 선택하지 않아 fail-closed 한 경우다. ground truth는 Behavioral Pattern 라벨이며 탐지 결과에서 만들지 않았다.

| Scenario | Pattern / Context | Whole | A | B | C | B 선택 Evidence |
|---|---|:---:|:---:|:---:|:---:|---|
| `bf_positive_20s` | present / simulated | + | + | + | + | 5건, 20초 |
| `bf_positive_60s` | present / simulated | + | + | + | + | 5건, 60초 |
| `bf_outside_61s` | absent / simulated | - | - | - | - | — |
| `bf_below_threshold_4` | absent / simulated | - | - | - | - | — |
| `bf_late_noise_70s` | present / simulated | - | + | + | + | 5건, 20초 |
| `bf_late_noise_61_after_60` | present / simulated | - | + | + | + | 5건, 60초 |
| `bf_late_noise_120s` | present / simulated | - | + | + | + | 5건, 20초 |
| `bf_reversed_input` | present / simulated | + | + | + | + | 5건, 20초 |
| `bf_equal_timestamp` | present / ambiguous | + | + | + | + | 5건, 0초 |
| `bf_two_bursts` | present / simulated | - | + | + | + | 첫 5건, 20초 |
| `bf_success_after_burst` | present / simulated | + | + | + | + | 실패 5건, 20초 |
| `bf_mixed_ips` | absent / simulated | - | - | - | - | — |
| `bf_mixed_accounts_same_window` | present / ambiguous | - | - | - | + | B 혼합 창 거부; C 계정 A의 5건 |
| `bf_account_changes_late` | present / ambiguous | - | - | + | + | A의 5건, 20초 |
| `bf_missing_account` | undetermined / unverified | + | + | + | - | 4 known + 누락 1행; matrix 제외 |
| `bf_duplicate_rows` | present / ambiguous | + | + | + | + | 행을 dedup하지 않고 5건 계산 |
| `bf_missing_event` | absent / simulated | - | - | - | - | 4행만 관측 |
| `bf_ssh_positive` | present / simulated | + | + | + | + | 5건, 20초 |
| `bf_shared_nat_mixed` | present / ambiguous | - | - | + | + | 계정 A의 5건, 다른 계정은 뒤에 나타남 |
| `bf_spray_boundary` | absent / simulated | - | - | - | - | Brute 패턴 없음; 기존 Spray 조건은 충족 |
| `bf_benign_auth_test` | present / known benign | + | + | + | + | 승인된 합성 인증 시험, 5건/20초 |
| `bf_benign_retry_boundary` | present / known benign | + | + | + | + | 합성 사용자 재시도, 5건/60초 |
| `bf_late_noise_then_success` | present / ambiguous | - | + | + | + | 선택 종료 20초; 기존 Correlation은 70초 실패 선택 |
| `bf_two_account_tied_windows` | present / ambiguous | - | - | - | ? | 두 계정의 동순위 창; C는 단일 Evidence 선택 거부 |

표의 모든 값은 `uv run python -m app.evaluation.brute_window_cli --format json` 실행에서 확인했다. Manifest는 fixture별 현재/후보 기대 결과와 이유를 보유한다. 별도 직접 UTC normalized-event 테스트가 60초+1µs 제외, timezone offset이 다른 동일 순간의 동일 처리, naive timestamp fail-closed를 검사한다.

## 8. Confusion Matrix

평가 단위는 `scenario × subject IP × Brute Force policy`다. `PATTERN_UNDETERMINED` 1건은 제외한다. `SIMULATED_ATTACK`/`KNOWN_BENIGN`은 Behavioral Pattern matrix와 합산하지 않고 별도 맥락으로 유지한다.

| Policy | TP | FP | FN | TN | Precision | Recall | F1 | Positive support | Negative support | Undetermined 제외 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Current whole-span | 9 | 0 | 9 | 5 | 1.000000 | 0.500000 | 0.666667 | 18 | 5 | 1 |
| Candidate A — global account | 14 | 0 | 4 | 5 | 1.000000 | 0.777778 | 0.875000 | 18 | 5 | 1 |
| Candidate B — window account | 16 | 0 | 2 | 5 | 1.000000 | 0.888889 | 0.941176 | 18 | 5 | 1 |
| Candidate C — IP/account | 17 | 0 | 1 | 5 | 1.000000 | 0.944444 | 0.971429 | 18 | 5 | 1 |

이 결과는 24개의 hand-authored 합성 scenario에서 정한 패턴 정의의 충족도를 비교한다. 0 FP 또는 1.0 Precision을 운영 성능으로 일반화할 수 없다. 후보 C의 유일 FN은 두 계정이 같은 시각·동일 우선순위 burst를 각각 만들었을 때 단일 Evidence를 고르지 않은 `bf_two_account_tied_windows`다. 낮은 FN을 위해 임의 계정을 선택하지 않는 결과다.

`KNOWN_BENIGN`으로 별도 작성한 2건은 네 정책 모두 탐지했다. 따라서 각 정책의 합성 운영상 false-alert 후보는 2건이다. 이는 Pattern FP와 다른 측정이며 실제 오탐률이 아니다. 7개 `AMBIGUOUS` 시나리오의 결과는 시나리오별 표에서 확인하고 운영 정상 또는 공격으로 분류하지 않았다.

## 9. Parser와 Detector의 분리

모든 24개 fixture에서 `load_normalized_logs()`가 예상 이벤트 수, 예상 실패 수, source, aware timestamp를 보존했다. Application은 `Asia/Seoul` parser 설정에서 UTC normalized event로 전달됐다. SSH fixture는 현재 지원되는 ISO-style `sshd` subset을 사용했다. Parser 제외는 0이다. 현재 정책의 FN은 미탐 fixture에서 parser가 6개 실패를 모두 전달한 후 `min..max=70초` 조건 때문에 발생했다.

별도 normalized-event 테스트에서 naive timestamp는 후보 계산을 거부하고, 서로 다른 offset으로 표현된 같은 UTC 시각은 동등하게 처리한다. 지원되지 않는 로그 형식 추가나 Parser 변경은 없다.

## 10. Correlation·Risk·Case 영향

`app/correlation/attack_chain.py::correlate_brute_force_to_success()`는 Brute Force Detection이 있을 때만 관계를 검사한다. 내부 `_closest_authentication_pair()`는 동일 IP·동일 계정, 실패 시각 < 성공 시각, 60초 이하의 쌍에서 가장 짧은 delta의 유일한 쌍을 선택한다. Detection이 어떤 window를 선택했는지는 입력받지 않는다.

합성 `bf_late_noise_then_success`에서 최초 다섯 실패의 후보 창은 UTC 00:00:00–00:00:20이며, 70초의 late failure 뒤 80초에 성공이 있다. 후보 Detection을 가정해 기존 Correlation 함수를 별도로 실행하면 실패 70초→성공 80초, delta 10초를 선택한다. 즉 후보 Brute Evidence 시간창과 Correlation failure endpoint가 다를 수 있다. 이 관계는 두 관측 시각의 근접성을 나타낼 뿐 burst와 성공의 원인 관계나 계정 탈취 증거가 아니다. 기존 production 분석에서 이 입력은 Brute 탐지가 없으므로 해당 Brute→success correlation도 만들어지지 않는다.

기존 Risk는 Brute Detection 또는 Brute→success correlation을 likelihood heuristic에 사용한다. Detection 추가 시 risk level/confidence, Case projection, checklist evidence 연결이 바뀔 수 있다. 특히 `incident_case_adapter`는 Detection의 `failure_count`, target count, window 값이 현재 공유 feature와 일치하는지 계약 검사한다. 후보 window의 5건을 Evidence로 사용하면서 공유 feature는 전체 6건/70초를 가리키면 현재 adapter 계약과 맞지 않을 수 있다. 이번 Phase는 실제 후보 결과를 production Risk/Case에 주입하거나 변경하지 않았다.

## 11. Password Spraying-like 경계

`bf_spray_boundary`는 동일 IP·네 계정 분포의 인증 실패 4건이다. Brute Force 단일 계정 패턴은 없고, 기존 Password Spraying-like는 네 실패·세 계정·30초이므로 탐지된다. 후보 evaluator는 Spray 탐지를 바꾸지 않는다.

향후 Brute Force 개선은 `summarize_ip_failures()`의 공통 `within_window`를 수정하지 않고 Brute Force 전용 시간창 선택을 따로 계산해야 한다. 그렇지 않으면 Spray의 전체 span 의미, `failure_count`, `unique_target_count` 및 Evidence가 예기치 않게 함께 바뀔 수 있다. Pipeline, risk, `incident_case_adapter`, report 및 case consumers는 후보 창 내부 count와 전체 IP 집계 count를 혼합하지 않도록 별도 계약 검토가 필요하다.

## 12. 중복·누락·다중 IP/계정 해석

- 중복 행은 고유 event ID가 없으므로 제거하지 않았다. 다섯 행을 다섯 실패로 세는 것은 관측 입력 기준 구현 동작이며, 실제 다섯 시도라는 증명은 아니다.
- 네 건만 남긴 이벤트 누락 fixture는 세 후보 모두 threshold에 도달하지 못했다. 로그 누락·수집 지연이 미탐을 만들 수 있다.
- IP가 둘로 분산된 시나리오는 subject IP마다 따로 계산해 합산 임계값을 만들지 않는다.
- 여러 계정이 같은 구간에 섞이면 A/B는 단일 계정 조건상 탐지하지 않는다. C는 IP/account별 분리 결과에서 다섯 건을 충족하는 한 계정이 있으면 후보를 만든다.
- 다른 계정 실패가 시간적으로 멀리 있으면 B/C는 burst 계정을 탐지할 수 있지만 A는 전체 IP account set 조건에서 거부한다.
- 하나의 계정 burst와 같은 IP 다른 계정 실패가 늦게 있으면 NAT/공유 IP/별도 사용자인지 로그만으로 판별할 수 없다.
- C에서 같은 우선순위 burst가 여러 계정에 있으면 증거를 임의로 고르지 않는다. 현재 평가 형식에서는 Detection을 fail-closed하고 tie를 별도 표시한다.
- 사용자 없는 실패는 A/B의 알려진 계정 cardinality를 늘리지 않지만 threshold 행 수에는 포함될 수 있다. C는 해당 행을 계정별 count에서 제외한다. 이는 향후 명시적으로 선택해야 할 정책 차이다.

## 13. Research Basis 및 Observable Evidence Mapping

### Research Basis

- **NIST, SP 800-63B-4, Digital Identity Guidelines: Authentication and Lifecycle Management** (현행 공식 NIST 문서, 2025 발간본). §3.2.2는 해당 verifier/authenticator 조건에서 subscriber account의 실패 인증 시도를 제한하고 throttling하라고 규정하며, 실패 횟수에 따라 delay 또는 risk signals를 고려할 수 있다고 설명한다. 이 근거는 계정 단위 관측이 보안 통제에서 중요하다는 점에만 반영했다. 로그 탐지 5회/60초나 sliding window를 지시하지 않는다. [공식 문서](https://pages.nist.gov/800-63-4/sp800-63b.html)
- **MITRE ATT&CK, Brute Force T1110** (현재 페이지 version 2.8, last modified 2026-05-12). Password Guessing과 Password Spraying을 하위 기술로 구분하고, 반복 credential guessing이라는 행위 개념을 설명한다. 이는 한 계정 guessing과 여러 계정 spraying의 분석 범위를 분리하는 데 사용했다. 특정 횟수 또는 시간창 근거로 쓰지 않았다. [T1110](https://attack.mitre.org/techniques/T1110/), [Password Guessing T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- **CISA, Identity and Access Management Recommended Best Practices for Administrators** (2023-12 PDF, 공식 CISA 자료). 접근 시도 패턴에 사용자/IP/시간 맥락과 계정 잠금 위험을 함께 봐야 함을 보조 근거로만 참고했다. 특정 threshold를 도출하지 않았다. [공식 PDF](https://www.cisa.gov/sites/default/files/2023-12/ESF%20IDENTITY%20AND%20ACCESS%20MANAGEMENT%20RECOMMENDED%20BEST%20PRACTICES%20FOR%20ADMINISTRATORS%20PP-23-0248_508C.pdf)

### Observable Evidence Mapping

```text
반복 실패와 대상 계정/시각을 구분해 관측해야 함
→ parser가 제공하는 login_failed, timestamp, src_ip, user
→ IP별 실패 묶음; 후보는 UTC 정규화 후 지정된 60초 창
→ 5회 이상 및 알려진 대상 계정의 cardinality 정책
→ 검증된 입력 패턴 관찰 (공격 성공·의도·동일 행위자 확정은 아님)
```

현재 입력에는 인증 세션 식별자, 실제 사용자·NAT 뒤 단말, 시도 고유 ID, verifier의 rate-limit/lockout 상태가 없다. 이 필드가 없으므로 다중 로그 행이 실제 고유 시도인지, 공유 IP 사용자인지 확정할 수 없다.

### Limitations

이 corpus는 작은 수의 hand-authored 시나리오이고 실제 조직의 benign activity base rate를 대표하지 않는다. 동일 IP는 동일 행위자를 증명하지 않는다. 실패 횟수는 공격 성공을 말하지 않는다. 성공 이벤트는 계정 탈취 증거가 아니다. 로그 누락·중복·시계 skew·수집 시각 역전은 별도 고려가 필요하다. 60초는 기존 project heuristic이지 NIST/ATT&CK/CISA 기준이 아니다. 평가에서 발견한 recall 증가는 실제 운영 precision/recall 증가를 보장하지 않는다.

## 14. Privacy/Security

- 고정 합성 Application·SSH fixture, `synthetic_user_*`, 예약 문서용 IP만 사용
- 평가 코드 offline, deterministic, no current time/random/network/LLM
- fixture 16 KiB 이하, manifest 128 KiB 이하, 최대 64 scenario/512 events
- closed manifest schema, 중복 ID/key 및 path traversal/symlink 거부
- CLI 오류는 고정 오류 코드만 출력
- CLI text/JSON에는 scenario ID·집계·정책 evidence만 포함; raw line, 계정, IP, 파일 경로 없음
- production parser, detector, shared feature, correlation, risk, case, API, schema, UI 변경 없음
- OS-level hard memory/CPU cap 또는 secure erase를 주장하지 않음

## 15. 회귀 및 검증

### RED → GREEN 기록

평가 전용 후보 구현보다 먼저 36.9D focused 테스트를 작성하고 실행했다. 첫 실행은 후보 모듈이 아직 없어 수집 단계에서 실패했다. 후보 구현 후 경계 테스트에서 계정 누락 행의 집계와 timezone 정규화 기대가 명세와 맞지 않는 사례를 확인해 평가 계약을 명시하고 구현/기대를 정렬했다. 이 과정에서 기존 production 동작을 바꾸거나 실패 assertion을 삭제·skip·xfail·완화하지 않았다. 최종 focused suite는 29개 테스트를 통과했다. 이 RED는 후보 평가기 계약을 고정하기 위한 것으로 production Detector의 실패를 green으로 감춘 것이 아니다.

### 변경 전 기준선

시작 시 로컬 `uv run pytest -q`: **3273 passed, 2 warnings** (macOS, locked Python 3.12). 시작 SHA의 Linux/Chromium CI 근거는 §2에 기재했다.

### 이번 Phase 실행

- `uv sync --locked --dev`: PASS
- `uv lock --check`: PASS
- 신규 focused `tests/test_brute_window_evaluation_36_9d.py`: **29 passed**
- `uv run python -m app.evaluation`: PASS; boundary 79/79, parser 195/200 (ignored 2, rejected 3, unexpected 0), risk 70/70, case 70/70, Linux process 21/21
- `uv run python -m app.evaluation.detector_accuracy_cli --format text`: PASS; 36.9C corpus 46 scenarios, Brute FN 1 유지, operational false-alert candidates 7 유지
- 기존 detector-accuracy JSON CLI: PASS
- 신규 brute-window text/JSON CLI: PASS; 24 scenarios, Parser exclusion 0; 결과는 위 표 참조
- `uv run pytest -q`: **3302 passed, 2 warnings** (macOS 로컬, 148.87초)
- `python3 -m compileall -q app tests`: PASS
- `git diff --check`: PASS; 새 untracked 파일도 별도 공백 검사 완료
- `npm run test:a11y --silent`: PASS; Chromium 25 states, `external_requests=0`, 주요 viewport 및 320px 200% equivalent에서 overflow/clipping/target-size/gap 실패 0
- Linux 전용 검증: 이번 로컬 실행에서 재현하지 않음. 시작 SHA exact Run에서만 성공 근거를 유지

## 16. 정책 평가 및 후속 구현 방향

**정책 결과: `CANDIDATE_RECOMMENDED` — Candidate C를 별도 Production remediation 설계의 기준 후보로 추천한다.** 이는 구현 승인이 아니다. C가 계정별 grouping으로 다른 계정의 late noise를 분리했고, 누락 사용자 행으로 임계값을 채우지 않았으며, 모호한 동률에는 계정을 임의 선택하지 않고 fail-closed했기 때문이다. 20초·정확히 60초 포함, 입력 순서 역전과 다중 IP 분리를 통과했다. 반면 평가 corpus에 known-benign 운영 사례는 두 건뿐이고 duplicate/공유 NAT 맥락은 모호하다. 따라서 단순 metric 순위가 채택 이유가 될 수 없다.

다음 Production 변경은 별도 Phase에서만 진행한다. 제안은 Brute Force 전용 집계로 `summarize_ip_failures()`의 공통 의미를 보존하고, 동일 `src_ip`·알려진 `user`별로 failure event를 그룹화한 뒤 UTC-aware inclusive 60초 창에 5개 이상 관측 행이 있는지 보는 것이다. 선택은 earliest qualifying end (fastest threshold), 다음 earliest start를 사용하고 서로 다른 계정의 동순위 tie는 fail-closed한다. 동일 행 중복은 event ID가 추가될 때까지 제거하지 않는다. missing-user 행은 계정 그룹에 포함하지 않는다.

구현 전 반드시 다음을 설계/검증해야 한다.

1. **Evidence**: 선택 창 내부 `failure_count`, 전체 IP 실패 수 별도, target count 1, 선택 start/end/window seconds, interval 통계의 합의된 의미. 기존 feature/evidence 계약을 자동으로 덮어쓰지 않는다.
2. **Correlation**: Brute evidence window와 `_closest_authentication_pair()`가 고른 failure timestamp의 일치 정책. 36.9D late failure→success fixture를 RED로 두고 window 밖 실패가 burst-success relationship의 evidence가 되는지 명시적으로 통제한다.
3. **Password Spray 불변**: shared `summarize_ip_failures().within_window`를 변경하지 않고, existing spray boundary 및 full synthetic evaluation을 통과시킨다.
4. **Risk/Case**: `incident_case_adapter`, risk, case projection/report가 내부 window count와 full-IP features를 혼합하지 않는지 producer-to-consumer 통합 테스트로 확인한다.
5. **Rollback**: 새 Brute 전용 후보가 mismatch/ambiguous timestamp/account를 만들거나 spray/risk/case regression을 유발하면 feature flag 없이 이전 whole-span detector로 rollback. API/model schema 변경이 필요하면 별도 설계/HOLD.

Production 변경을 허용할지 여부: **`CONDITIONAL_GO`** — 단 Candidate C 정책 고정, 위 Evidence/Correlation/Password Spray/Case 조건을 먼저 승인된 후속 Phase에서 해결할 경우에 한한다. 이번 Phase 자체로 production 동작을 변경하지 않았다.

## 17. 최종 판정

평가 프레임워크와 합성 corpus는 로컬에서 재현 가능하게 구성했으며, 현재 FN과 세 후보의 정책 차이를 측정했다. 후보 정책은 기존 Detector를 대체하지 않는다. 신규 focused 29 tests, 기존 평가 CLI, detector accuracy CLI, 전체 pytest 3302 passed, compileall, Chromium/axe 및 privacy-safe output 확인이 통과했다. Phase 판정은 `PHASE_36_9D_WINDOW_SEMANTICS_EVALUATION_LOCAL_CONDITIONAL_GO`다. 정책 선택은 별도 결과인 `CANDIDATE_RECOMMENDED`이며 production 구현은 조건부다.

경계: 실제 사용자 자료 `NO_GO`, 조직 운영 `NO_GO`, 자동 대응 `NO_GO`, 실환경 정확도 `UNVERIFIED`, 모델 기반 AI/Safari/VoiceOver/실제 모바일 `NOT_TESTED`, Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`, OS-level hard resource cap 미보장, renderer `KEEP_LEGACY`.
