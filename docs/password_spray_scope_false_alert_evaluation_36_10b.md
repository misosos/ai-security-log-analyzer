# Phase 36.10B — Password Spray 범위 및 운영상 오경보 평가

## 1. Executive Summary

이 평가는 기존 `password_spraying_like` Production 정책을 유지한 채, 실제 분석 Pipeline을 호출하는 현재 whole-span 정책과 두 개의 **평가 전용** Window 후보를 36개 합성 시나리오에서 비교한다. Production Detector, Pipeline, Correlation, Risk, Case, API, UI에는 변경이 없다.

현재 정책은 점수 대상 30개 시나리오에서 TP 15, FP 1, FN 4, TN 10을 기록했다. Sliding IP Window 후보는 FN을 2개 줄였지만 중복 전달 시나리오의 Pattern FP와 정상 Batch/NAT의 운영 경보 후보를 제거하지 못했다. Known-account 후보는 한 개의 알려진 계정 누락 시나리오를 놓쳐 Sliding보다 TP가 하나 적었다. 세 정책 모두 동일한 세 개의 `KNOWN_BENIGN` 관측을 탐지해 운영상 경보 후보가 3개였다.

따라서 이번 독립 평가의 정책 결론은 **`MORE_EVIDENCE_REQUIRED`**다. Sliding 후보의 late-noise 이점은 재현됐지만, 작은 합성 집합만으로 Production 변경을 승인할 근거는 부족하다. 실제 운영 정확도나 오탐률을 추정하지 않는다.

## 2. 시작 Gate

- Repository: `ai-security-log-analyzer`
- Branch: `main`
- 기준 SHA / local HEAD / local main / origin main: `f99c2778f66aca7409156916b88df5c79f8a7b1c`
- GitHub Actions Run: `41190088111`, 정확한 SHA의 `push`, `completed / success`
- 필수 Locked Python 3.12, 전체 회귀, Linux recovery, SSH, TCP Syslog, JSONL, restricted report, Chromium/axe 검사 성공
- Artifact: 0개
- 시작 Working Tree: clean, ahead/behind `0/0`
- v0.4.0 target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`: 불변

36.10A-UI3의 `SAFARI_USER_ACCEPTANCE_PENDING` 상태는 확인만 했으며 변경하지 않았다.

## 3. 현재 Production 정책

`app/analyzer/pipeline.py`는 정규화 이벤트를 IP로 묶고 `summarize_ip_failures()`가 산출한 IP 전체 feature를 Brute와 Spray-like Detector에 전달한다. `app/detector/password_spray.py`의 현재 조건은 다음과 같다.

- 해당 IP의 실패 이벤트 4회 이상
- 실패 이벤트에서 알려진 사용자 문자열의 고유 수 3개 이상
- IP 전체 실패의 최소·최대 timestamp 차이가 60초 이하

`is_within_window()`는 `(end - start).total_seconds() <= 60`으로 경계를 포함한다. 계정이 없는 실패는 실패 횟수에는 포함되지만 target 집합에는 들어가지 않는다. 성공 이벤트는 `login_failed`가 아니므로 실패 수에서 제외된다. 동일한 실패 행이 중복 전달되면 별도 실패로 센다. 사용자 이름은 non-empty 문자열을 set에 넣으므로 대소문자나 표기를 정규화하지 않는다.

현재 Detector는 전체 실패 수, 고유 target 수, 전체 실패 시간 범위를 Evidence로 낸다. IP는 집계 key일 뿐 동일 행위자·공격자 신원을 증명하지 않는다. 이번 평가의 4/3/60은 기존 프로젝트 휴리스틱이며 표준이나 벤더의 권위 있는 임계값이 아니다.

## 4. 평가 경계와 Corpus

새 Corpus는 `sample_logs/spray_scope_evaluation/manifest.json`과 39개의 합성 fixture로 구성된 36개 독립 시나리오다. 기존 46개 Detector Accuracy Corpus와 24개 Brute Window Corpus는 수정하지 않았다.

각 시나리오는 다음 축을 따로 기록한다.

- Behavioral Pattern: `PATTERN_PRESENT` 20, `PATTERN_ABSENT` 12, `PATTERN_UNDETERMINED` 4
- Operational Context: `KNOWN_BENIGN` 5, `CONTEXT_UNKNOWN` 9, `SIMULATED_ATTACK` 21, `NOT_LABELED` 1
- Parser status: `VERIFIED` 29, `PARTIAL` 5, `REJECTED` 1, `IGNORED` 1

Ground Truth는 후보 정책 결과를 보기 전에 생성 fixture의 알려진 이벤트 구성과 관측 가능성으로 정했다. `KNOWN_BENIGN`은 fixture 생성 메타데이터이며 Parser 이벤트에는 전달되지 않는다. `SIMULATED_ATTACK` 역시 생성 상황을 나타낼 뿐 런타임 로그가 공통 행위자나 의도를 입증하지 않는다.

Manifest는 closed schema, 고유 ID·fixture, documentation-only IP/user 값, fixture 경로 containment 및 symlink 금지, UTF-8/JSON 중복 키·비표준 상수 거부, 크기·개수 상한을 검사한다. 상한은 최대 128 scenario, fixture당 8 KiB, manifest 128 KiB, 입력 파일당 128줄, 시나리오당 최대 512 parsed event, 전체 최대 4096줄이다. Corpus 밖 파일을 열지 않으며 네트워크나 외부 모델 호출을 하지 않는다.

## 5. Parser 관측

36개 시나리오의 총 149줄 가운데 143줄이 Parsed, 1줄 Ignored, 5줄 Rejected였다. 3개 시나리오는 Parser status 또는 일부 record rejection 때문에 정책 혼동행렬에서 제외했고, `PATTERN_UNDETERMINED` 3개도 각 정책 분모에서 별도로 제외했다. 60초+1µs fixture는 Application parser가 소수 초 timestamp를 지원하지 않아 4행 중 1행이 거부된다. 따라서 해당 fixture는 Parser 실패 제외로 처리하며, 실제 경계는 별도 `NormalizedEvent` 단위 테스트에서 정확히 검증했다.

현재 Application 및 SSH auth parser는 고정 timestamp 형식과 등록된 `Asia/Seoul` 시간대 설정을 사용한다. 입력의 임의 offset suffix나 fractional seconds를 지원한다고 가정하지 않는다. parser가 지원하지 않는 offset fixture 4행은 모두 거부돼 정책에 조용히 전달되지 않았다. 성공/실패 outcome 및 source, event type, 누락 계정·IP 수, UTC 시간 범위를 JSON 관측 결과로 기록하고 raw log는 출력하지 않는다.

## 6. 비교 정책

| 정책 | 평가 동작 |
|---|---|
| `current_whole_span` | 실제 `app.main.analyze()` 호출. Pipeline의 실제 Detector 결과와 feature 기반 4/3/60 조건 일치까지 검사 |
| `sliding_ip_window` | 평가 코드에서 IP별 timestamp 정렬, 최소 4회 및 3개 알려진 계정이 60초 안에 있는 가장 이른 qualifying end 선택. 누락 계정 실패는 횟수에는 포함하나 target은 아님 |
| `known_account_window` | 같은 window 조건에서 계정이 알려진 실패만 실패 수와 계정 수로 계산 |

동일 end time 후보는 안정된 정렬을 사용하고, 처음 qualifying end를 택한 뒤 그 end에서 조건을 유지하는 가장 짧은 prefix로 줄인다. 동일 시각 레코드는 자동 deduplicate하지 않는다. 후보 Evidence metadata에는 subject, UTC start/end, 선택 실패 수, 알려진 target 수, source가 담기며 Production Evidence schema와 분리되어 있다.

두 후보는 `app/evaluation/`의 offline 평가에만 존재한다. Pipeline, Live, Risk, Correlation, Case, Report/API에 연결하지 않는다.

## 7. 결과

분모는 Pattern 라벨이 확정되고 정책 실행이 가능한 30개 시나리오(positive support 19, negative support 11)다.

| 정책 | TP | FP | FN | TN | Precision | Recall | F1 | Pattern support |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Current whole-span | 15 | 1 | 4 | 10 | 0.937500 | 0.789474 | 0.857143 | +19 / −11 |
| Sliding IP Window | 17 | 1 | 2 | 10 | 0.944444 | 0.894737 | 0.918919 | +19 / −11 |
| Known-account Window | 16 | 1 | 3 | 10 | 0.941176 | 0.842105 | 0.888889 | +19 / −11 |

숫자는 이 작은 고정 합성 Corpus의 기술 통계이며 실제 운영 Precision/Recall 또는 확률 추정이 아니다. 3개 parser 제외와 3개 undetermined는 각 정책마다 분리 집계한다. 분모가 없는 metric은 `not_applicable`을 반환한다.

## 8. Late Noise, Known Benign, NAT 및 누락 계정

- `late_noise_other_account`, `late_noise_same_account`: 초기 4건·3계정의 15초 burst 뒤 90초 시점 추가 로그가 whole-span을 늘려 Current가 놓쳤다. Sliding과 Known-account는 15초·4건의 창으로 탐지했다. 이 두 시나리오가 Current FN에서 후보 TP로 바뀐 근거다.
- `one_missing_username`: 세 계정이 보이는 burst에서 네 번째 실패 계정이 누락됐다. Current와 Sliding은 실패 건수를 포함해 탐지하지만 Known-account는 알려진 실패가 세 건이라 놓친다.
- `known_benign_batch`: 독립 생성 메타데이터에 승인된 Batch 인증 검증이 있다. 세 정책 모두 관찰 패턴을 탐지했다. 이는 Pattern TP이면서 Operational false-alert candidate일 수 있다.
- `shared_nat_multiple_users`: 정상 사용자들이 같은 egress IP를 공유하는 합성 조건에서 세 정책 모두 탐지했다. 로그만으로 사용자 행위를 단일 주체로 귀속할 수 없다.
- `duplicate_delivery_three_attempts`: 실 시도 세 개 가운데 한 로그가 중복 전달되어 네 행이 됐다. 세 정책이 모두 탐지했다. Pattern label은 생성 메타데이터의 실제 시도 구성에 따라 absent로 정했으므로 이것이 유일한 Pattern FP다. Parser에는 event ID/deduplication 신호가 없다.
- Known benign 탐지 후보는 모든 정책에서 `duplicate_delivery_three_attempts`, `known_benign_batch`, `shared_nat_multiple_users` 세 건이다. 이 값은 시나리오 후보 수이지 실환경 오탐률이 아니다.

## 9. 분산 IP, 중복·순서, Brute 겹침

두 개 또는 네 개 IP로 분산한 합성 시나리오는 같은 계정 집합을 만들더라도 세 정책 모두 per-IP 조건 때문에 놓쳤다. 생성 메타데이터는 fixture 안에서 시나리오 공통성을 알고 있지만 관측 로그가 동일 actor를 증명하지는 않는다. 이번 Phase는 Global spray detector를 만들지 않는다.

Input 역순과 같은 timestamp 사례에서 후보 정책의 결과는 동일하게 유지됐다. 중복 행은 제거되지 않고 횟수에 포함되며, 정확히 60초는 포함, 60초+1µs는 제외된다. Application parser의 실제 timestamp 표현 제한은 앞서 별도 Parser 제외로 기록했다.

Brute 겹침 fixture에는 22초 안에 실패 7건, 같은 계정 5건 및 총 3계정이 있어 현재 Brute와 Spray-like 조건이 함께 성립한다. Brute 전용 선택 Window와 Spray의 전체 IP feature/Evidence 범위는 서로 다르다. 이를 하나의 공통 window로 치환하지 않았다.

## 10. Consumer 영향 검토

현재 `correlate_password_spray_to_success()`는 Spray detection이 참일 때 동일 IP 로그에서 `_closest_authentication_pair()`를 사용한다. 후보 정책을 적용하면 Detection 발생 여부뿐 아니라 그 Evidence 시간 범위가 변하지만, 현재 Spray Correlation은 Brute의 소유된 선택 Window endpoint를 사용하지 않는다. 따라서 후보 Window를 Production에 넣으면 success 관계 시간축과 Evidence·Feature 범위를 따로 설계해야 한다.

Risk는 Spray detection 및 Spray→success correlation에 따라 rationale/level 산정 경로를 선택한다. Case adapter/report projection은 Spray evidence, 계정 scope, 관계를 소비한다. Window 후보를 현재 결과 mapping에 덮어쓰면 Risk 기여, Case 포함 근거, report evidence가 서로 다른 시간 범위를 가리킬 수 있다. Static/Live provenance와 parity도 재검증 대상이다. 이번 단계는 소비자 변경 없이 평가에 한정한다.

## 11. 구현·테스트·성능

신규 구현:

- `app/evaluation/spray_scope_policy.py`
- `app/evaluation/spray_scope_evaluation.py`
- `app/evaluation/spray_scope_cli.py`
- `sample_logs/spray_scope_evaluation/`
- `tests/test_spray_scope_evaluation_36_10b.py`

Evaluator는 deterministic sorting/JSON, bounded file/schema validation, 고정된 error code, raw line 미출력 기능을 갖는다. 현재 production parity 검사는 실제 `analyze()` 실행 결과의 Detector Boolean과 production feature 조건을 비교한다.

독립 테스트 16개가 통과했다. 초점은 36개 라벨 차원과 parser status, 세 정책 혼동행렬, late noise/missing user/distributed IP, 정확 60초와 +1µs, offset-equivalent UTC 정렬, 중복 전달, Brute/Spray 동시 탐지의 서로 다른 Evidence 범위, Parser 및 undetermined 제외, 결정성, 네트워크 미사용, manifest duplicate key/path traversal/duplicate ID/fixture/symlink/크기/UTF-8/NaN 거부다.

이번 실행의 제한된 로컬 합성 측정은 scenario 36개, 입력 149줄, Production 경로 약 32–63 ms, 두 후보 계산 합계 약 4–8 ms, 추적 Python allocation 약 347–350 KB였다. 반복 실행의 작은 차이도 timer/환경 영향을 받는다. 이는 공정한 상대 benchmark, 자원 상한, 운영 부하 성능을 의미하지 않는다. JSON key와 scenario 순서는 안정적이나 측정 시간·allocation 값은 실행마다 달라질 수 있다.

## 12. 기존 평가 Regression

기존 evaluator는 그대로 실행했고 기존 Corpus/Ground Truth를 수정하지 않았다.

- 기존 전체 synthetic evaluator: boundary `79/79`; Password Spray TP2/FP0/FN0/TN5; Parser 195/200, ignored 2, rejected 3; Risk 70/70; Case 70/70; Linux process 21/21
- 46-scenario detector accuracy: Password Spray TP2/FP0/FN0/TN5, positive support 2, negative support 5, undetermined 1; 기존 operational false-alert candidate 1
- 24-scenario Brute Window: 기존 current whole-span TP9/FP0/FN9/TN5 및 후보 결과 유지

새 36개 Corpus는 다른 분모로 별도 보고하며 기존 지표에 합산하지 않는다. Detector Accuracy CLI JSON에는 7개 Detector에 걸친 기존 Operational false-alert 후보가 총 7건으로 나타났고, 그중 기존 Spray 후보는 `spray_benign_batch` 1건이다.

## 13. Research Basis와 관측 한계

MITRE ATT&CK T1110.003은 Password Spraying을 다수 계정에 걸친 password guessing behavior로 분류하며, 낮은 빈도·장기간 분산과 같은 행위가 단일 좁은 시간창에서 보이지 않을 수 있음을 설명한다. 이는 이 프로젝트의 4/3/60 임계값을 정당화하지 않는다. [MITRE ATT&CK T1110.003](https://attack.mitre.org/techniques/T1110/003/)

Microsoft Entra 공식 sign-in log 문서는 기록된 IP가 VPN·mobile carrier 및 주소 공유 환경에서 실제 사용자 위치/주체와 다를 수 있음을 안내한다. Microsoft incident response playbook도 sign-in 맥락을 함께 검토하도록 안내한다. 이는 공유 NAT 경보 후보의 해석상 주의 근거이지 현재 Parser가 조직 승인 정보나 실 사용자 귀속을 가진다는 뜻은 아니다. [Microsoft sign-in log activity details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details), [Microsoft password spray response playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-password-spray)

### Observable Evidence Mapping

| 평가 결론 | 관측 근거 | 제한 |
|---|---|---|
| 4/3/60 현재 정책 | 실제 Pipeline의 IP feature, `password_spray` Detection, 해당 Evidence | 프로젝트 규칙 의미만 확인 |
| Window 경계/late noise | Parser가 만든 UTC `login_failed` timestamp와 계정 field | 공격 의도·동일 비밀번호는 미관측 |
| NAT 후보 | 한 IP의 여러 계정 이벤트와 독립 합성 context metadata | 실제 사용자/IP 소유 관계는 미관측 |
| 분산 IP miss | fixture의 IP별 관측과 시나리오 생성 라벨 | 공통 actor는 로그만으로 증명 안 됨 |
| 중복 영향 | 같은 이벤트 행이 반복된 fixture, event ID 부재 | 실환경 수집기가 중복을 얼마나 만드는지 미측정 |

## 14. 정책 결론 및 다음 단계

**판정: `MORE_EVIDENCE_REQUIRED`.** Sliding 후보는 이 Corpus에서 recall을 0.789474에서 0.894737로 높이고 FN을 4에서 2로 줄였지만, duplicate Pattern FP 1건과 정상 Batch/NAT 운영상 경보 후보 3건은 그대로다. Known-account 후보는 known target 모호성에 보수적이지만 누락 계정 시나리오 하나를 놓쳐 FN이 Sliding보다 1건 많다. 집계 단위가 작고 operational labels는 통제된 synthetic context이므로 Production 권고로 승격하지 않는다.

권장 후속 Phase는 `36.10B-R1 — Password Spray Evidence & Consumer Contract Design`이다. Production 수정 전, 상위 소비자가 whole-span feature와 별도 spray window를 동시에 표현할 수 있는 Evidence/Correlation/Risk/Case/Report 계약을 설계하고, 중복 수집 및 shared egress context의 추가 합성 corpus 요구사항을 확정한다. 계정 누락 시 정책 선택과 Static/Live parity도 설계 Gate에 포함해야 한다.

이 평가에서 `KEEP_CURRENT`도 `CANDIDATE_RECOMMENDED`도 확정하지 않는다. 더 큰 독립 corpus와 명시적 Consumer 계약 검토 전까지 Production 정책은 현재대로 둔다.

## 15. Privacy, Security 및 변경 경계

CLI는 documentation-only IP와 합성 `spray_` 계정만 수용하며 raw log, 비밀번호, 사용자 식별 정보 또는 인증정보를 출력하지 않는다. 외부 네트워크, LLM, 전역 상태, Production API 호출은 없다. `analyze()`는 평가 과정에서 in-process Production 분석을 호출하지만 합성 fixture만 입력하고, 반환 결과는 평가 결과로만 사용한다.

수정하지 않은 계약: Detector/Parser/Pipeline/Correlation/Risk/Case/API/Frontend/Live/Checklist/Report, 기존 평가 Corpus 및 Ground Truth, lockfile, CI, UI3 Safari 수용 상태. v0.4.0 tag/release도 불변이다.

## 16. Limitations 및 Rollback

- 이 Corpus는 작고 의도적으로 구성됐으며 조직의 정상 로그인·Batch·NAT 분포를 대표하지 않는다.
- 동일 IP는 행위자 식별자가 아니며 동일 비밀번호 사용, credential reuse, compromise, 공격 성공을 증명하지 않는다.
- 저속 시도는 이 휴리스틱 시간창을 벗어날 수 있다. 여러 IP로 분산된 활동은 현재 per-IP detector에서 놓칠 수 있다.
- 계정 누락은 target 수와 window 정책을 다르게 바꿀 수 있고 중복 로그는 임계값을 넘길 수 있다.
- auth parser의 timestamp 형식·timezone 지원은 제한적이다. 별도 지원 형식 확장이나 실제 collector 동작을 입증하지 않는다.
- 실환경 운영 경보율, Precision/Recall, 실제 사용자 자료 보호, 조직 운영 readiness는 미검증이다. OS hard CPU/memory cap이나 secure erase를 보장하지 않는다.
- UI Safari 사용자 수용은 계속 `SAFARI_USER_ACCEPTANCE_PENDING`이다.

Rollback은 평가 전용 신규 코드, corpus, 테스트, 문서와 docs index 링크를 제거하는 범위로 한정한다. Production 경로가 수정된 경우는 이번 Phase 경계 위반으로 처리한다. 재검증은 시작 SHA로 돌아가 baseline CLI/pytest 및 정확한 새 CI Gate를 확인한다.

## 17. 최종 판정

전체 회귀는 `3383 passed, 2 warnings`로 종료됐다(기준 대비 신규 16개). `uv sync --locked --dev`, `uv lock --check`, `python3 -m compileall -q app tests`, `git diff --check`가 통과했다. 신규 spray CLI text/JSON 모두 정상 출력했다. 기존 전체 평가, Detector Accuracy, Brute Window CLI의 text/JSON 실행도 성공했고 위 기존 수치와 일치했다.

`npm run test:a11y --silent`의 Chromium/axe pilot은 25개 상태를 실행했고 외부 요청은 0건이었다. 320px 및 200% equivalent reflow에서 수평 overflow/clipping 없음이 기록됐다. UI3 Navigation E2E `node tests/ui_navigation_closure_36_10a_ui3.mjs`도 통과했다: sample POST 1, guidance POST 1, checklist POST 0(해당 테스트 실행에서 명시적 Checklist 요청은 수행하지 않음), Case reference 2, 지연된 Case 응답 격리 및 invalid/stale route 처리 통과, 외부 요청 0, CSP 검증 성공. UI3의 Safari 수용 상태는 여전히 `SAFARI_USER_ACCEPTANCE_PENDING`; 실제 Safari/VoiceOver/모바일 사용자 수용을 이번 평가로 완료하지 않았다.

변경 파일은 평가 코드 3개, 39개 합성 fixture와 manifest, 독립 테스트 1개, 본 문서 및 `docs/index.md`다. Production 파일·기존 Corpus·Ground Truth·API/UI는 변경하지 않았다. 로컬 커밋 생성 전 Git 상태와 전체 diff를 마지막으로 검사한다.

현재 확인한 로컬 평가·테스트의 조건부 결론은 `PHASE_36_10B_SPRAY_SCOPE_EVALUATION_LOCAL_CONDITIONAL_GO`다. 이는 평가 산출물과 회귀 실행이 성공했다는 의미이며 Password Spray 정책의 Production 변경 승인이 아니다.
