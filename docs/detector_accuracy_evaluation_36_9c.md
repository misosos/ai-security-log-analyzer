# Phase 36.9C — 탐지 규칙 합성 정확도 및 오탐·미탐 평가

## 1. Executive Summary

기존 결정적 Detector 7종을 대상으로 별도 합성 corpus 46개 시나리오를 구성하고, Parser가 기대 이벤트와 필수 필드를 보존했는지 확인한 뒤 기존 분석 파이프라인의 실제 탐지 여부를 비교했다. 평가지표는 detector별 scenario × subject × detector 단위이며, Parser에서 제외된 입력과 `PATTERN_UNDETERMINED` 라벨은 confusion matrix에서 제외했다.

주요 관측은 Brute Force에서 1건의 미탐이다. 첫 20초의 5회 실패 뒤 전체 집계 범위를 70초로 만드는 추가 실패가 있으면, 기존 구현은 모든 실패의 min/max 범위를 사용해 경보를 만들지 않는다. 이는 합성 평가 목표에서 정의한 짧은 subwindow 패턴과 구현의 전체 span 조건이 다른 데서 나온다. 이 동작을 이번 Phase에서 바꾸지 않았다. 운영 맥락이 `KNOWN_BENIGN`인 합성 시나리오에서 탐지가 발생한 7건은 Pattern FP로 계산하지 않고 별도 운영상 오탐 후보로 기록했다.

작은 합성 corpus의 metric은 입력한 규칙과 경계조건이 평가 코드에서 기대대로 처리되는지를 측정한다. 실제 공격 분포, 실제 조직의 정상 행위, 운영 환경 Precision/Recall을 입증하지 않는다. 탐지 결과는 침해 확정이나 공격 성공을 뜻하지 않는다.

## 2. 시작 Gate

- 시작 SHA: `cbf550814e886002ef669e680d6595dc6727b163`
- GitHub Actions Run: `41012745624`
- Event/status/conclusion: `push` / `completed` / `success`
- Artifact: 0개
- exact head SHA, Python 3.12 locked regression, Linux process/SSH recovery, 전체 pytest, TCP Syslog, JSONL, restricted report, Chromium/axe, tracked-file invariant: 모두 성공
- branch 및 local HEAD/local main/origin/main/GitHub main 일치, ahead/behind 0/0, 시작 working tree clean
- v0.4.0 tag 및 Release target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

위 CI는 **시작 기준 SHA**에 대한 근거다. 이번 Phase에서 만들 새 SHA의 Ubuntu CI 성공을 뜻하지 않는다.

## 3. 기존 평가 기준선

변경 전 macOS 로컬 기준선에서 `uv run pytest -q`는 `3249 passed, 2 warnings`였다. 기존 `uv run python -m app.evaluation`은 Boundary 79/79, Brute Force 11 TP, Password Spray 2 TP, Path Traversal 2 TP, SQLi 5 TP, XSS 5 TP, Sensitive Resource 4 TP, Web Scan 3 TP로 기록됐다. 기존 parser corpus는 195/200, ignored 2, rejected 3, unexpected parse/rejection 0; Risk 70/70, Case 70/70, Linux process 21/21이었다.

이 기준선은 기존 평가 CLI의 corpus 결과다. 이 문서의 새 46개 시나리오와 합산하거나 새로운 정확도 수치로 재표현하지 않는다. 변경 후 재실행 결과는 아래 검증 기록에 별도로 기재한다.

## 4. 평가 대상 Detector 및 실제 구현 조건

코드 확인 위치: `app/detector/brute_force.py`, `app/detector/password_spray.py`, `app/detector/web_attack.py`, 연결은 `app/analyzer/pipeline.py`다.

| Detector | 실제 관측 조건 | 주의할 의미 |
|---|---|---|
| `brute_force` | 동일 `src_ip`의 `login_failed` 이벤트 5개 이상, 알려진 고유 user가 정확히 1개, 전체 실패 최소·최대 timestamp 차이 60초 이하 | 전체 실패 집합의 span 검사다. 이동 시간창이 아니며 중복 입력도 개수에 포함된다. |
| `password_spraying_like` | 동일 IP 실패 4개 이상, 고유 계정 3개 이상, 전체 실패 span 60초 이하 | 여러 계정의 실패 패턴 관측이다. 동일 credential 사용이나 공격 의도를 증명하지 않는다. |
| `path_traversal` | path 또는 query를 percent decode가 안정될 때까지 풀고 `../` 또는 `..\\` 포함 여부 확인 | 문자열 패턴 관측이다. 파일 접근 성공을 뜻하지 않는다. |
| `sql_injection_like` | bounded web request에서 Boolean quote/numeric equality, UNION SELECT 형태, quote 및 SQL 주석 패턴 중 하나 | SQL 유사 문자열 관측이다. DB 실행·영향을 입증하지 않는다. |
| `xss_like` | bounded web request에서 `<script`, 제한된 `onerror/onload/onclick=`, `javascript:` 중 하나 | 응답 실행 또는 브라우저 실행을 입증하지 않는다. |
| `sensitive_resource_probing_like` | 정규화된 path에서 `.env`, `.git/config|head`, `.bak|.old|.orig` suffix 패턴 | 요청 경로 관측이다. 파일 내용 노출을 의미하지 않는다. |
| `web_scanning_like` | 60초 내 6 request 이상, 6개 path/query 조합 이상, 4xx 3개 이상 | 스캔 유사 요청 묶음이며 악의성, 도구 신원 또는 의도를 확정하지 않는다. |

신규 web detector는 UTC-aware timestamp, 대문자 ASCII method, 100–599 status, 최대 target 2048자, 제한된 percent decode/UTF-8/control 검사를 적용한다. 기존 traversal 규칙은 다른 decode 계약을 사용한다. 이번 평가는 두 구현을 통합하지 않았다.

## 5. 평가 설계 및 라벨 계약

각 시나리오는 단일 `detector`, 입력 `source`, 문서용 주소 범위의 단일 subject를 지정한다. 평가 단위는 해당 시나리오의 subject에 대해 지정한 Detector 하나가 탐지됐는지 여부다. 각 fixture는 분석 엔진 실행 전에 독립적으로 작성한 `behavioral_pattern`, `operational_context`, `label_basis`, `context_basis`를 manifest에 보유한다. 평가기는 탐지 결과를 이용해 라벨을 생성하거나 변경하지 않는다.

- Behavioral Pattern: `PATTERN_PRESENT`, `PATTERN_ABSENT`, `PATTERN_UNDETERMINED`
- Operational Context: `SIMULATED_ATTACK`, `KNOWN_BENIGN`, `AMBIGUOUS`, `UNVERIFIED`
- Pattern matrix는 `UNDETERMINED`만 제외한다. `AMBIGUOUS` 운영 맥락이라도 관측 패턴 존재 여부가 독립적으로 확정됐으면 Pattern 평가에 포함한다.
- `KNOWN_BENIGN` 맥락에서 탐지된 결과는 운영 false-alert 후보로 별도 계산한다. Pattern label이 present라면 Pattern FP로 중복 계산하지 않는다.
- Parser rejection/partial은 Detector의 FN/FP로 오인하지 않으며 별도 Parser contribution으로 분류하고 평가에서 제외한다.

Confusion 정의: `TP=(present, detected)`, `FP=(absent, detected)`, `FN=(present, not detected)`, `TN=(absent, not detected)`. Precision=`TP/(TP+FP)`, Recall=`TP/(TP+FN)`, F1=`2TP/(2TP+FP+FN)`. 분모 0은 `not_applicable`이다. `AMBIGUOUS`를 TN으로 자동 계산하지 않는다.

## 6. Corpus 및 무결성

새 corpus는 `sample_logs/detector_accuracy/manifest.json`과 46개의 정적 `.log` fixture로 구성된다. 전부 직접 작성한 합성 로그이며 고정 날짜·순서·문서용 IPv4 주소·합성 사용자명을 사용한다. 실제 자료, credential, 외부 네트워크 접근은 사용하지 않았다. corpus는 기존 `sample_logs/evaluation/`과 분리되어 있다.

manifest 검증기는 closed key set, UTF-8/중복 JSON key, schema version, ID 중복, source/detector 조합, 허용 라벨, 문서용 IP 범위, required field allowlist, fixture의 단일 파일명·symlink·크기·존재, manifest와 fixture 집합의 정확한 일치를 확인한다. fixture 입력 상한은 8 KiB, manifest 상한은 128 KiB, scenario 상한은 128개다. 결과는 고정 순서로 출력하고 입력 행 원문·query·IP·fixture path를 출력하지 않는다.

Corpus 첫 실행에서 경계 fixture가 `09:00:60`, `00:00:61`처럼 범위 밖 초를 사용해 Parser rejection으로 빠지는 데이터 오류를 발견했다. 이 값들을 60초·61초의 올바른 분/초 timestamp로 고쳐 의도한 boundary를 보존했고, 최종 corpus Parser exclusion은 0이다. 이 수정은 Detector 코드를 바꾸지 않았다.

| 분류 | 시나리오 수 |
|---|---:|
| Behavioral `PATTERN_PRESENT` | 26 |
| Behavioral `PATTERN_ABSENT` | 18 |
| Behavioral `PATTERN_UNDETERMINED` | 2 |
| Context `SIMULATED_ATTACK` | 17 |
| Context `KNOWN_BENIGN` | 17 |
| Context `AMBIGUOUS` | 7 |
| Context `UNVERIFIED` | 5 |

## 7. Parser 입력 계약 및 원인 분리

지원된 Application/SSH/Access 문법을 fixture로 사용하고 각 fixture에서 정규화 이벤트 개수, event type, source IP, 필수 timestamp/authentication/http field를 별도 검사했다. 계정별 인증 규칙은 결정 가능한 시나리오의 `user`도 필수화했고, SQLi/XSS 패턴은 `http.query`, query 기반 traversal은 해당 query를 필수화했다. 이 corpus 실행에서는 Parser exclusion이 0이었다. Parser의 검증과 탐지기 실행을 따로 기록하며, Parser가 필요한 의미 필드를 보존하지 못하는 경우에는 그 시나리오를 metric에서 제외하고 `PARSER_CONTRIBUTION`으로 보고하도록 했다.

새 평가 결과에서 `bf_burst_with_late_noise`는 Parser가 6개 이벤트와 필요한 필드를 정상 제공했지만 Brute Force Detector가 탐지하지 않았다. 따라서 이 사례는 Parser 오류가 아니라 Detector 집계 정책에 따른 FN이다.

## 8. Confusion Matrix 결과

새 runner: `uv run python -m app.evaluation.detector_accuracy_cli --format text` 또는 `--format json`. 아래 표는 이번 corpus의 재실행 결과다.

| Detector | TP | FP | FN | TN | Precision | Recall | F1 | Positive / Negative support | 제외: undetermined / parser |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Brute Force | 3 | 0 | 1 | 3 | 1.000000 | 0.750000 | 0.857143 | 4 / 3 | 1 / 0 |
| Password Spraying-like | 2 | 0 | 0 | 5 | 1.000000 | 1.000000 | 1.000000 | 2 / 5 | 1 / 0 |
| Path Traversal | 5 | 0 | 0 | 1 | 1.000000 | 1.000000 | 1.000000 | 5 / 1 | 0 / 0 |
| SQL Injection-like | 4 | 0 | 0 | 2 | 1.000000 | 1.000000 | 1.000000 | 4 / 2 | 0 / 0 |
| XSS-like | 4 | 0 | 0 | 1 | 1.000000 | 1.000000 | 1.000000 | 4 / 1 | 0 / 0 |
| Sensitive Resource Probing-like | 4 | 0 | 0 | 2 | 1.000000 | 1.000000 | 1.000000 | 4 / 2 | 0 / 0 |
| Web Scanning-like | 3 | 0 | 0 | 4 | 1.000000 | 1.000000 | 1.000000 | 3 / 4 | 0 / 0 |

이 표는 매우 작은 hand-authored synthetic pattern set의 기술적 결과다. 특히 web 탐지의 positive support는 3–5건 규모이며 운영 정확도 순위로 해석하지 않는다.

## 9. False Positive / False Negative 및 운영 맥락

### Pattern false negative

- `bf_burst_with_late_noise` — 동일 계정·IP에서 첫 20초 동안 5회 실패 후 70초 시점에 추가 실패를 배치했다. 독립 label은 “첫 subwindow에 5회 실패 패턴 존재”다. 구현은 전체 실패 집합의 최솟값과 최댓값 차이를 검사하므로 70초 전체 span을 가진 입력은 탐지되지 않는다. Detector FN 1건이다. 패턴은 의도상 존재하지만 현재 구현 조건이 이동 window가 아니어서 missed subwindow로 기록했다.

그 밖의 확정 Pattern FP/FN은 이 corpus에서 관측되지 않았다. 이것은 해당 패턴 계열에서 오류가 없다는 보장이 아니라 현재의 좁은 시나리오 목록에서 관측되지 않았다는 뜻이다.

### 운영상 false alert 후보

`KNOWN_BENIGN` 맥락이지만 탐지된 7개: `bf_benign_retries`, `spray_benign_batch`, `traversal_docs_search`, `sqli_documented_example`, `xss_document_search`, `sensitive_inventory`, `scan_benign_scanner`. 이 시나리오들은 각각 pattern label이 present이므로 Pattern matrix의 TP다. 운영 맥락에서는 경보 검토에 정상적인 사용자 실수, 문서 검색, 인벤토리 점검, 승인 스캐너 같은 맥락 정보가 필요할 수 있음을 보여준다. 이 작은 합성 사례를 실운영 false positive rate로 환산하지 않는다.

모호한 crawler/보안 테스트와 근거 불충분 사례는 Operational label로 유지한다. 공격 성공, 계정 탈취, 데이터 유출, 공격 의도를 추론하지 않았다.

## 10. Correlation 및 Risk 영향

새 평가기는 기존 `app.main.analyze`를 호출하고 그 결과의 detector slot을 읽는다. Parser 및 Detector/Correlation/Risk 코드를 바꾸지 않았다. 각 fixture가 단일 source·단일 subject 시나리오이므로 이 corpus는 복합 공격 chain의 상관 정확도 평가를 주장하지 않는다. 기존 CLI 회귀 실행은 Risk 70/70 및 Case 70/70 기준을 재확인하며 새 corpus와 별도 보고한다.

개별 시나리오에서 Risk는 기존 heuristic 결과로 산출되며 침해 확률이 아니다. 새 runner는 Risk를 metric에 포함하지 않고, 이번 corpus만으로 Risk나 Checklist 정책을 평가했다고 주장하지 않는다. 재실행한 기존 평가에서는 인증 transition 6/6, brute-force→success 3/3, spray→success 1/1이었으며 Risk 70/70, Case 70/70이었다. 이들은 기존 corpus의 synthetic 결과다. Correlation은 인과관계가 아니다. Case/Checklist/API projection의 새 46개 corpus별 통합 평가는 이번 범위가 아니다.

## 11. 평가 품질·보안·개인정보

새 runner는 기존 `python -m app.evaluation` CLI를 변경하지 않는다. 실행은 local fixture only이며 임의 네트워크, LLM, 모델 다운로드가 없다. JSON은 stable key order, text는 고정 detector 순서다. Parser/분석 실패는 고정 코드만 반환하며 입력 원문이나 시스템 경로를 오류에 넣지 않는다. 출력 canary 검증에서 사용자명, 합성 IP, `login_failed` 원문이 JSON 결과에 포함되지 않았다. scenario ID, label, 집계 결과만 노출한다.

Confusion matrix 산술, 분모 0, 미정 라벨, Parser 제외, 중복 ID, unknown detector/source/label, 누락 fixture, path traversal, 고정 출력, 진단 개인정보, CLI exit code를 전용 테스트로 검증했다.

초기 focused 실행에서 FP만 있는 행의 F1을 테스트가 `not_applicable`로 잘못 예상했다. 실제 정의상 `2TP+FP+FN` 분모가 0이 아니므로 결과는 `0.000000`이다. 테스트 기대값을 수학 정의에 맞게 바로잡았으며 평가 산식은 변경하지 않았다.

## 12. 기존 Regression 및 전체 검증

변경 전 기준선은 3절 참조. 변경 후 실행 기록:

- 환경: macOS 로컬, locked Python 3.12 환경
- `uv sync --locked --dev`: PASS
- `uv lock --check`: PASS
- 신규 focused + Parser compatibility + Parser/Detector/Correlation/Risk + File/Text API + HTML/privacy + TCP Syslog/JSONL + Linux Audit security: `548 passed, 2 warnings`
- `uv run python -m app.evaluation`: PASS; 기존 수치 계약 재현 (Boundary 79/79, parser 195/200, correlation 6/6·3/3·1/1, Risk 70/70, Case 70/70, Linux process 21/21)
- 신규 text 및 JSON CLI: PASS; 46 scenarios, parser contribution 0, operational false-alert candidates 7
- `uv run pytest -q`: `3270 passed, 2 warnings`
- `npm run test:a11y --silent`: PASS; Chromium suite, 외부 요청 0, 지정 viewport에서 overflow/clipping/target/gap 실패 0
- `python3 -m compileall -q app tests`: PASS
- `git diff --check`: PASS; tracked 및 새로 추가한 text 52개 파일 trailing whitespace 검사 PASS

Linux 전용 검증은 이번 macOS 로컬 실행으로 주장하지 않는다. Linux process/SSH, TCP Syslog Linux, JSONL runtime Linux, restricted report 및 tracked-file CI 근거는 시작 SHA `cbf5508`의 exact successful Run `41012745624`에 한정된다. 새 완료 커밋의 Ubuntu CI는 아직 실행되지 않았다. 기존 `uv run python -m app.evaluation` CLI 출력·수치 계약은 별도 유지했다.

## 13. 통계적 한계

- corpus는 46개 hand-authored synthetic scenario이며 독립적인 실제 사건 표본이 아니다.
- 일부 detector는 positive/negative support가 매우 작고, 이 조건에서 1.0 metric이 나와도 일반화 근거가 아니다.
- Behavioral label은 탐지 규칙에서 정의한 관측 패턴이고, Operational Context는 시나리오 저자의 합성 맥락이다. 둘은 실제 침해 판정이 아니다.
- 같은 detector를 대상으로 작성한 corpus이므로 알려지지 않은 입력 분포, Parser 변형, NAT, 수집 누락·중복, 시간 skew를 포괄하지 않는다.
- Confidence interval이나 조직별 베이스레이트 보정은 하지 않았다. 실제 정확도, precision, recall, F1은 `UNVERIFIED`다.

## 14. Detector 개선 우선순위

1. **Brute Force 전체-span 기반 집계의 missed subwindow 평가 및 후속 설계** — 이번에 1건의 재현 가능한 synthetic FN이 확인됐다. 먼저 별도 RED corpus로 입력 순서, 중복, late noise, 누락을 넓혀 요구 의미를 확정해야 한다. 이 Phase에서는 코드/임계값 변경 금지.
2. **운영 맥락 기반 경보 해석** — 7개 합성 known-benign 사례도 관측 패턴 조건을 만족했다. Detector 신호와 실제 맥락/정책 신호를 분리해서 다뤄야 하며 지금은 자동 억제 근거가 없다.
3. **Web 패턴 평가 support 확대** — SQLi/XSS/path/resource 규칙의 현재 1.0은 각 5–6 positive/negative 이하의 작은 corpus 결과다. 인코딩, 정상 검색, 프록시/로그 변형 등 지원 parser 범위 안의 독립 시나리오를 늘려야 한다.

## 15. 후속 Phase 제안

최우선 단일 제안: **Phase 36.9D — Brute Force Window Semantics Remediation Evaluation**.

- 목표: 전체-span 조건과 이동 subwindow 요구를 분리해 합성 입력에서 현재 동작 및 후보 의미를 확정한다.
- RED 계획: 4/5/6회, 정확히 60초/61초, 20초 burst 뒤 late noise, 입력 순서 역전, duplicate event, missing event, 여러 계정/IP, Application·SSH 형식을 독립 fixture로 추가하고 현재 구현 결과를 명시적으로 확인한다.
- 변경 예상: 우선 테스트·설계 문서. Detector 수정은 명시적 별도 승인된 후속 단계에서만 검토한다. 이번 제안 자체로 임계값 변경을 승인하지 않는다.
- Acceptance: 라벨 근거와 Parser 검증이 Detector 출력과 독립적이고, 현재 구현에서 subwindow missed pattern을 재현하며, 중복/누락/순서 경계를 명세하고, 기존 전체 회귀 baseline을 유지한다.
- 보안·개인정보: 문서용 IP와 가짜 계정만 사용, 실제 운영 로그·credential 금지, 결과는 pattern observation으로만 표기.
- HOLD: Parser가 지원하지 않는 형식 의존, ground truth 누수, 불명확한 60초 경계, Detector 결과를 라벨로 역생성, 기존 detection 의미의 무단 변경.
- 연결: 해당 계약이 독립 리뷰를 통과하면 별도 remediation 계획을 작성한다. 운영 정확도 검증은 실제 자료 사용 승인 없이 진행하지 않는다.

## 16. 판정

평가 방법과 집계 구현은 합성 입력에서 검증됐고, 결과는 Brute Force missed subwindow 1건과 운영 false-alert 후보 7건을 드러냈다. 기존 분석 규칙은 변경하지 않았다. 이 판정은 합성 평가 하네스와 corpus에 한정된 `LOCAL_CONDITIONAL_GO`이며 실제 보안 운영 readiness가 아니다.

경계 유지: 실제 사용자 자료 `NO_GO`, 조직 운영 `NO_GO`, 자동 대응 `NO_GO`, 실환경 탐지 정확도 `UNVERIFIED`, 모델 기반 AI 및 Safari/VoiceOver/실제 모바일 `NOT_TESTED`, Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`, OS-level hard memory/CPU cap 미보장, renderer `KEEP_LEGACY`.
