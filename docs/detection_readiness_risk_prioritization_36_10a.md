# Phase 36.10A — 탐지 준비도 및 잔여 위험 우선순위 평가

## 1. Executive Summary

판정은 `PHASE_36_10A_DETECTION_READINESS_PRIORITIZATION_LOCAL_CONDITIONAL_GO`다. 기준 SHA의 CI와 로컬 평가·전체 회귀가 통과했고 Production 코드는 변경하지 않았다. 이 평가는 저장소의 명시된 합성 입력과 계약에 한정된다. 실제 로그, 조직 운영 또는 자동 대응의 승인을 뜻하지 않는다.

현재 가장 먼저 보완할 일은 Detector 규칙을 넓히는 것이 아니라 **Password Spray-like의 운영상 오탐 가능성과 전체-span 정책을 독립적인 합성 경계 평가로 더 잘 규정하는 것**이다. 현재 이 Detector의 독립 corpus는 양성 2건·음성 5건뿐이며, 그중 승인된 정상 batch 입력 1건이 탐지되는 Operational false-alert 후보로 기록된다. 36.10B에서는 먼저 정상 batch, NAT/shared source, late noise, 다중 IP, 누락·중복 이벤트를 분리해 정책 후보와 근거를 평가해야 한다. 평가 근거가 충분해지기 전에는 Production 임계값이나 규칙을 바꾸지 않는다.

주요 잔여 위험은 제한된 로그 형식으로 인한 미관측, 작은 자기작성 corpus의 일반화 한계, 같은 IP 기준 인증 귀속의 불확실성, HTTP request-only evidence의 성공 여부 한계, 그리고 OS 수준 CPU·메모리 격리 부재다. 아래 매트릭스는 구현 여부와 운영 신뢰도를 분리한다.

## 2. 시작 Gate

- 기준 SHA: `cd5a02d66ef4ed30e6264ff5a0aa1dd435692ec2`
- GitHub Actions Run: `41068841854`
- `main`, local HEAD, local main, `origin/main`, GitHub main은 기준 SHA로 일치했고 ahead/behind `0/0`, 작업 트리는 clean이었다.
- Run은 기준 SHA의 `push`, `completed / success`; 필수 Locked Python 3.12, lockfile, 전체 회귀, Linux checkpoint/process·SSH, TCP Syslog, JSONL, Restricted report, Chromium/axe, tracked-file 단계가 성공했다. Artifact 0개.
- v0.4.0 tag/Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`은 변경하지 않았다.
- 로컬에서 `uv sync --locked --dev`, `uv lock --check`, 평가 CLI 및 전체 pytest를 다시 실행했다. 시작 SHA CI는 이 Phase의 문서 변경 후 커밋 CI를 대신하지 않는다.

## 3. Phase 36.9A 대비 변경 사항

36.9A는 Parser 호환성 및 탐지 평가 강화를 상위 우선순위로 제안했다. 이후 36.9B에서 지원 형식을 부분집합으로 고정하고 세 가지 false acceptance를 수정했으며, 36.9C에서 46개 시나리오로 Detector 기준선을 만들었다. 36.9D~F는 Brute의 late-noise 미탐을 재현·비교하고 Candidate C를 Production에 적용했다. 36.9G 계열은 Context 재사용, Owner 결속, 결과 재포장 문제를 각 HOLD로 기록한 뒤 실행 provenance를 보완하고 독립 Closure를 수행했다.

현재는 Brute의 36.9C Historical FN을 Current에서 해결한 상태이며, 과거 HOLD는 당시 근거로 보존한다. Parser compatibility 전체 문제를 모두 해결한 것은 아니다. 지원 fixture의 세 FALSE_ACCEPT는 수정됐지만 실제 배포 로그 형식 전체의 호환성은 여전히 미검증이다.

## 4. 현재 Architecture Inventory

```text
File / Text / Local Collector
        ↓
Loader → Source별 Parser → NormalizedEvent (UTC 정규화)
        ↓
7개 Deterministic Detector
        ↓
Per-IP 및 Global Correlation
        ↓
Risk heuristic / confidence
        ↓
Case Adapter → Case / independent observation
        ↓
Report / Checklist / Investigation Workspace
```

| 계층 | 구현 및 입력·출력 계약 | 확인 근거 | 주요 제한 |
|---|---|---|---|
| Loader / Parser | 선택한 source parser가 텍스트 행을 NormalizedEvent 또는 무시/거부로 변환 | `app/loader/file_loader.py`, `app/parser/` 및 compatibility evaluation | 자동 source 감지, 임의 multiline·설정 변형, 지원되지 않는 syslog envelope 전체 지원 아님 |
| Detection | per-IP grouping, 인증 요약 및 웹 request observations를 별도 Evidence로 생성 | `app/analyzer/pipeline.py`, `app/detector/`, accuracy CLI | 규칙은 관측 패턴 분류이며 공격 성공·신원을 증명하지 않음 |
| Correlation | 시간·IP·계정 조건에 맞는 관계를 구성하며 Brute는 선택 Window endpoint와 private provenance를 확인 | `app/correlation/attack_chain.py`; `app.evaluation`의 관계 corpus | 관계는 인과성·계정 침해 증거가 아님; 평가 support가 작음 |
| Risk | likelihood/impact/confidence heuristic과 관측 근거·상관을 결합 | `app/analyzer/risk.py`; 70/70 기존 경계 corpus | 보정된 확률이 아니며 동일 사건의 Detection/Correlation이 독립 근거 수를 뜻하지 않음 |
| Case | 승인된 Detection/Relation을 supported observation 및 기존 rule로 조립 | `incident_case_adapter.py`, `incident_case.py`; 70/70 및 provenance closure | Case는 조사 단위이지 확정 Incident가 아님 |
| Report / Checklist | 닫힌 projection과 allowlist 기반 설명·제한·다음 단계 구성 | `report_projection.py`, restricted report, API/Checklist 회귀 | source access 및 실제 운영 보관·삭제·권한 절차는 별도 검증 필요 |
| Live / Collector | bounded local tail, TCP Syslog/JSONL loopback runtime 및 revision/proposal 상태 | `live_monitoring/`, `log_collection/`, CI와 synthetic parity | remote TLS·durable replay·HA·조직 규모 backpressure를 승인하지 않음 |
| Linux Audit | 별도 loader/parser 및 process/session 관찰·집계 경로 | `linux_audit_loader.py`, `parser/linux_audit.py`, 21/21 synthetic consistency | 일반 Detector 7종의 여덟 번째 항목이 아니며 host-wide agent 운영은 미검증 |

### Research Basis 및 Observable Evidence Mapping

공식 [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/index.html)은 brute force의 여러 하위 유형(Password Guessing, Password Spraying, Password Cracking, Credential Stuffing)을 구분한다. 이는 행위 분류를 돕지만 이 저장소의 5회/60초 정책을 정당화하거나 탐지를 공격 성공으로 증명하지 않는다. [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)의 throttling 요구는 인증 서비스를 운영하는 verifier의 방어 통제에 관한 것이며, 사후 로그 분석기 임계값과 같은 계약이 아니다. [OWASP WSTG SQL Injection Test](https://wstg.owasp.org/v4.1/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection/)는 입력 패턴 관찰만이 아니라 애플리케이션이 사용자 입력을 쿼리로 실행하는지 확인해야 취약점 성공을 판단할 수 있음을 보여준다. 따라서 이 보고서는 요청 문자열을 SQL 실행·브라우저 실행·파일 노출의 증거로 확대하지 않는다.

관측 매핑은 현재 이벤트 계약 그대로다: 인증 source는 timestamp, event type, `user`, `src_ip`, 일부 authentication method/service를 제공한다. Access는 timestamp, source IP, HTTP method/path/query/status/response size를 제공하지만 response body, route handler의 실제 실행, SQL statement, 브라우저 DOM 실행은 제공하지 않는다. 필요한 필드가 없으면 결과는 미탐 가능성/불확실성으로 남긴다. 이 조사는 새로운 규칙이나 연구 내용을 코드에 적용하지 않았다.

## 5. Detector 7종 Readiness Matrix

운영 준비도 `UNVERIFIED`는 기능이 없다는 뜻이 아니라 실제 workload와 독립 ground truth로 운영상 성능을 확정하지 않았다는 뜻이다.

| Detector | 필수 필드 | 현재 규칙 | 합성 검증 | FP 위험 | FN 위험 | 운영 준비도 | 우선순위 |
|---|---|---|---|---|---|---|---|
| Brute Force | aware timestamp, IP, 알려진 account, 실패 event | IP·account별 실패 ≥5, ≤60초 Candidate C; 동률 fail-closed | 46개 평가 TP4/FP0/FN0/TN3; 별도 24개 Candidate C TP17/FP0/FN1/TN5 | 정상 재시도/자동화/공유망이 같은 관측 패턴을 만들 수 있음; 합성 후보 1건 | 느린·분산 IP·누락 account 및 parser 밖 이벤트 | `UNVERIFIED` | P2; 추가 운영 맥락 평가 |
| Password Spraying-like | IP별 failure count, unique known accounts, whole-span `within_window` | 실패 ≥4, account ≥3, 전체 IP span ≤60초 | TP2/FP0/FN0/TN5; operational candidate 1건 | 승인 batch/공유 출구가 같은 IP·계정 분포를 만들 수 있음 | 분산 IP, 느린 시도, late noise는 전체-span 조건을 깨뜨릴 수 있음 | `UNVERIFIED` | **P1 / 36.10B 최우선** |
| Path Traversal | Access IP, timestamp, path/query | 반복 URL decode 후 `../` 또는 `..\\` 관찰 | TP5/FP0/FN0/TN1 | 검색·문서·테스트 URL 탐색 | 인코딩/정규화, 비지원 parser 형식, 다른 구분 표현 | `UNVERIFIED` | P2 |
| SQL Injection-like | UTC, HTTP path/query, method/status canonical request | bounded decode 후 Boolean/UNION/comment 패턴 | TP4/FP0/FN0/TN2 | 문서 예시/검색/보안 테스트; 합성 operational candidate 1건 | body 기반/POST body, 변형 문법 및 서버측 parameter 처리 불가 | `UNVERIFIED` | P2 |
| XSS-like | UTC, HTTP path/query | script element, 일부 event handler, `javascript:` 패턴 | TP4/FP0/FN0/TN1 | 문서 검색/테스트 문자열; operational candidate 1건 | 인코딩·컨텍스트별 변형 및 실제 렌더링 미관측 | `UNVERIFIED` | P2 |
| Sensitive Resource Probing-like | UTC, HTTP path | `.env`, 일부 `.git`, `.bak/.old/.orig` path 관찰 | TP4/FP0/FN0/TN2 | 인벤토리·백업 확인; operational candidate 1건 | 다른 민감 경로 및 실제 응답 본문/파일 노출 미관측 | `UNVERIFIED` | P2 |
| Web Scanning-like | UTC, IP grouping, path/query, status | 한 IP에서 60초 내 ≥6 request, ≥6 distinct targets, ≥3 client errors | TP3/FP0/FN0/TN4 | 승인 scanner/crawler/health inventory; operational candidate 1건 | 낮은 속도, 적은 target, 성공/5xx 위주 또는 source 분산 | `UNVERIFIED` | P2 |

“합성 검증” 수치는 단일 현재 46-scenario corpus의 detector 행별 support다. Path Traversal 등 일부는 negative support가 1~2개라 현재 행렬의 FP 0은 운영 FP 부재의 근거가 아니다.

## 6. Brute Force 현재 정책

현재 Production selector(`app/detector/brute_force.py`)는 알려진 계정과 같은 source IP로 실패를 분리하고, 5회 이상 및 60초 이하의 창 중 가장 이른 qualifying end를 선택한다. 선택 동률이 서로 다른 계정에 걸리면 fail-closed하며 계정 누락 이벤트는 창에 넣지 않는다. 신뢰된 실행 Context는 선택 Window의 실제 member events를 보유하고 Correlation/Case에서 provenance를 검증한다. 자동 deduplication은 하지 않는다.

공유 IP feature는 전체 범위 그대로 유지한다. 대표 late-noise 입력은 전체 실패 6회/70초와 선택 Brute Window 5회/20초를 동시에 나타낸다. Brute→Success relation은 선택 창 종료 20초와 같은 IP·계정의 80초 성공 사이 60초를 표현한다. 70초 실패를 해당 Brute relation endpoint로 사용하지 않는다.

잔여 위험: NAT/shared egress는 서로 다른 사용자 요청을 단일 IP로 묶을 수 있다. 반대로 같은 행위가 여러 IP에 나뉘면 단일 IP 규칙에서 보이지 않을 수 있다. user 누락은 해당 Brute window에서 제외된다. 로그 누락, replay/중복, clock skew 또는 timezone 설정 오해는 count와 시간 순서를 바꿀 수 있다. 성공 이벤트가 수집되지 않으면 “공격이 실패했다”고 결론낼 수 없다. ATT&CK T1110은 분류 참고이며 임계값의 보편 기준이 아니다.

## 7. Password Spray 위험

`detect_password_spray()`는 Brute 전용 sliding window가 아닌 기존 IP 전체 feature를 소비한다. 전체 `failure_count >= 4`, `unique_target_count >= 3`, `within_window=True`이면 탐지하고 Evidence에도 전체 count와 전체 window 통계를 사용한다. 동일 비밀번호 여부는 NormalizedEvent에 없으므로 “같은 비밀번호를 여러 계정에 시도”했음을 확인하지 못한다. 따라서 이름의 `-like` 경계를 유지해야 한다.

같은 source IP 여러 계정은 공유 NAT/프록시, batch job, 승인된 인증 점검 등과 구분하기 어렵고, 여러 IP에 분산된 시도는 이 Detector에 집계되지 않는다. late-noise가 전체 span을 60초 초과로 늘리면 짧은 초기 burst가 있더라도 전체-span 조건은 실패할 수 있다. Brute와 같은 IP에서 동시 관측 시 각 규칙이 다른 증거 범위를 의미한다. 36.10B는 이 정책을 바꾸기 전에 차등 corpus와 독립 라벨의 충분성을 평가해야 한다.

## 8. Web Detector 5종 위험

| Detector | 코드상 관측 | 현재 못 증명하는 것 | FP 후보 / FN 가능성 |
|---|---|---|---|
| Path Traversal | 반복 percent decode 후 URL path/query의 `../` 또는 `..\\`; 일부 method/status/response size evidence | 파일시스템 경로 해석, 실제 파일 읽기, 응답 본문 | 문서/검색/테스트 문자열이 후보; parser 및 representation 변형은 놓칠 수 있음 |
| SQL Injection-like | 제한된 canonical request의 query 패턴 | SQL statement 생성/실행, DB 접근 결과, 데이터 변경/반환 | 예시 검색·보안 스캔은 candidate; body/다른 문법은 현재 관측 불가 |
| XSS-like | query의 제한된 script/event/scheme 패턴 | 브라우저의 HTML context, 실행, 피해자 세션 영향 | 문서 검색·테스트 payload는 candidate; encoding/contextual 변형은 놓칠 수 있음 |
| Sensitive resource probing-like | path의 일부 `.env`, `.git/config|head`, backup suffix | 파일 존재, 인증 우회, 파일 내용 노출 | 정상 인벤토리 후보; 목록 외 경로 및 body 결과 미관측 |
| Web scanning-like | IP별 60초 내 최소 request/distinct/error count | 자동화 주체·의도, 서비스 영향, 공격 성공 | 승인 scanner/crawler 후보; 저속·분산 탐색은 놓칠 수 있음 |

HTTP 2xx/200이나 응답 크기만으로 취약점 악용 또는 데이터 반환을 단정하지 않는다. Access parser의 method/path/query/status는 요청 관측이다. Response body, application tracing, WAF disposition, session, DB audit는 이 경로의 입력이 아니다.

## 9. Parser–Detector Coverage Gap

| Source | 지원 형식 | 생성 Event / 제공 필드 | 연결 Detector | 누락 필드 / 미지원 |
|---|---|---|---|---|
| Application | 프로젝트 고정 `YYYY-MM-DD HH:MM:SS LEVEL EVENT key=value...` | event type, user, ip, application/protocol/user_agent key, authentication outcome/service; registry가 naive 시각을 Asia/Seoul로 설정 후 UTC 정규화 | Brute, Spray, auth Correlation, Risk | 제품 로그 표준 아님; 일반 포맷·timezone 자동 식별 안 함; 같은 credential 정보 없음 |
| SSH | `YYYY-MM-DD HH:MM:SS` + 허용된 `sshd` process marker 및 Failed/Accepted password/publickey 문구 | user, from IP, method, source port 일부, invalid-user 일부, outcome | Brute, Spray, auth Correlation, Risk | RFC3164/RFC5424 envelope, 일반 syslog 연도/zone 변형, 임의 sshd 버전/locale 지원 보장 없음 |
| Access | NCSA core subset: IP literal, bracketed offset timestamp, 3-token request, status 100–599 및 bytes/`-` | IP, method, path/query, status, response size | 5개 web observation Detector | 모든 Apache/Nginx `LogFormat`·escaping·error log 아님; User-Agent, Referer, remote user, request/response body 누락 |
| Linux Audit | audit record grouping 및 별도 semantic/process/session parser | audit event ID/types, syscall/process/UID/path 일부, session 및 source metadata | 별도 Linux Audit process/session 분석·집계 | 일반 7종 Detector 입력으로 세지 않음; host-wide agent 및 조직 권한/정책 미검증 |

36.9B/R1에서 hostname-as-IP, 비-sshd 문구, HTTP status 999의 기존 세 false acceptance는 거부되도록 수정됐고 R2는 해당 이전 HOLD 조건이 범위 내에서 닫혔다. 새 지원 형식 확대가 확인된 것은 아니다.

| Gap | 영향 | 분류 |
|---|---|---|
| 비지원/부분 형식은 Detection 전에 reject/ignore될 수 있음 | 이벤트가 Detector에 도달하지 않아 coverage gap이 생김 | `SUPPORTED_BY_CODE`, 환경별 범위는 `UNVERIFIED` |
| Application/SSH timezone는 registry 가정에 의존 | 실제 producer timezone이 다른데 설정을 그대로 쓰면 correlation window가 달라질 수 있음 | `SUPPORTED_BY_CODE` |
| Access는 IP literal로 제한되고 proxy topology는 없음 | source IP가 NAT/proxy egress일 수 있으며 원 사용자 식별이 아님 | `SUPPORTED_BY_CODE` / 환경 영향 `UNVERIFIED` |
| Authentication user/account가 없거나 애매함 | brute account window 및 일부 관계를 만들 수 없음 | `SUPPORTED_BY_CODE` |
| HTTP body, DB/app execution, response content 부재 | 요청 pattern만 분류 가능; exploit outcome 불가 | `SUPPORTED_BY_CODE` |
| syslog, encoding, locale, log rotation 배포 변형 | parse failure 또는 부분 필드 손실 가능 | `UNVERIFIED` |

## 10. Detector Accuracy 재평가

실행: `uv run python -m app.evaluation.detector_accuracy_cli --format text/json`.

| Detector | TP | FP | FN | TN | positive / negative support | 제외 undetermined |
|---|---:|---:|---:|---:|---:|---:|
| Brute Force Current | 4 | 0 | 0 | 3 | 4 / 3 | 1 |
| Password Spraying-like | 2 | 0 | 0 | 5 | 2 / 5 | 1 |
| Path Traversal | 5 | 0 | 0 | 1 | 5 / 1 | 0 |
| SQL Injection-like | 4 | 0 | 0 | 2 | 4 / 2 | 0 |
| XSS-like | 4 | 0 | 0 | 1 | 4 / 1 | 0 |
| Sensitive Resource Probing-like | 4 | 0 | 0 | 2 | 4 / 2 | 0 |
| Web Scanning-like | 3 | 0 | 0 | 4 | 3 / 4 | 0 |

Corpus 총 46 scenario다. 별도 `app.evaluation` 결과는 boundary 79/79, parser 195/200 (ignored 2, rejected 3, unexpected parse/rejection 0), 인증 correlation 6/6, Brute→success 3/3, Spray→success 1/1, Risk 70/70, Case 70/70, Linux process consistency 21/21이다. CLI는 SSH scenario 13개에서 자동화 승인 맥락 부족 1건을 confusion matrix에서 제외한다. 이 지표는 정의된 self-authored fixtures의 통과·분류 결과이지 외부 검증 corpus의 운영 Precision/Recall이 아니다.

Brute 비교 이력은 36.9C Historical `TP3/FP0/FN1/TN3`, Current `TP4/FP0/FN0/TN3`; 36.9D Candidate C `TP17/FP0/FN1/TN5`, Whole-span `TP9/FP0/FN9/TN5`다. Ground Truth와 historical FN은 변경하지 않았다.

## 11. Pattern FP와 Operational False Alert

Pattern FP는 독립 pattern label이 absent인데 탐지된 경우다. 이번 46-scenario matrix에서는 Detector별 Pattern FP가 0이다. Operational false-alert candidate는 behavioral pattern이 존재하더라도 합성 설명에서 정상 맥락이 주어진 탐지다. 현재 7건: `bf_benign_retries`, `spray_benign_batch`, `traversal_docs_search`, `sqli_documented_example`, `xss_document_search`, `sensitive_inventory`, `scan_benign_scanner`. 이는 Pattern FP 7건이 아니며 운영 오탐률도 아니다.

36.9D Brute 24개 평가에서는 모든 정책에서 known benign 후보 2건이 별도로 탐지됐다. Candidate C는 pattern matrix TP17/FP0/FN1/TN5였다. 그 FN은 동률 계정 창을 임의 선택하지 않는 fail-closed 결과다. 36.9D의 운영 후보 수와 36.9C evaluator의 7건은 서로 다른 corpus/측정 단위이므로 합산하지 않는다.

### Detector별 위험 근거 분류

| Detector | FP 위험 / 필요한 추가 정보 | FN 위험 | 분류 및 근거 |
|---|---|---|---|
| Brute | 정상 재시도·인증 health test와 구분하려면 account-owner/approved test 맥락 | slow/distributed/missing user, parser 밖의 auth source | 정상 재시도 후보 `OBSERVED_IN_TEST`; 조건 `SUPPORTED_BY_CODE`; 실제 NAT/분산 빈도 `UNVERIFIED` |
| Spray | batch/NAT의 계정 분포 및 승인 작업 여부 | multi-IP, slow attempts, late noise가 전체-span 경계 초과 | benign batch `OBSERVED_IN_TEST`; whole-span/IP 계약 `SUPPORTED_BY_CODE`; 실제 발생량 `UNVERIFIED` |
| Path Traversal | 문서 검색·보안 테스트 경로 | 미지원 encoding/parser target | docs-search candidate `OBSERVED_IN_TEST`; 표현 한계 `SUPPORTED_BY_CODE`; 실제 workload `UNVERIFIED` |
| SQLi-like | 검색 결과/문서의 payload 문자열 | body POST, 다른 syntax, app/DB context 미관측 | 문서 검색 candidate `OBSERVED_IN_TEST`; 필드 한계 `SUPPORTED_BY_CODE`; 실행 여부 `UNVERIFIED` |
| XSS-like | payload 예시 검색/반사 테스트 | context-sensitive encoding, 실제 DOM execution 미관측 | search candidate `OBSERVED_IN_TEST`; 구현 subset `SUPPORTED_BY_CODE`; 피해자 노출 `UNVERIFIED` |
| Sensitive | 승인 inventory가 보호 경로 확인 | 목록 외 파일명·body 결과 없음 | inventory candidate `OBSERVED_IN_TEST`; path allowlist `SUPPORTED_BY_CODE`; 실제 파일 존재 `UNVERIFIED` |
| Web scanning | 승인 crawler/scanner가 빠른 여러 4xx를 생성 | low-and-slow, multi-IP, fewer targets, status outside 4xx | scanner candidate `OBSERVED_IN_TEST`; threshold `SUPPORTED_BY_CODE`; 운영 빈도 `UNVERIFIED` |

`PLAUSIBLE_RISK`는 저장소 fixture로 재현된 사실이 아니라 관측 필드/그룹 규칙에서 파생되는 위험에만 쓴다. 여기서는 실제 조직 발생률을 알 수 없으므로 이를 재현된 버그라고 기록하지 않는다.

## 12. Correlation Readiness

| 관계 | 현재 조건·근거 | 한계 |
|---|---|---|
| Failed Login → Successful Login | per-IP 인증 실패/성공 pair, 순서·상관 창; 합성 6/6 | 동일 IP·계정 관측이지 credential reuse나 인과성 증거 아님 |
| Brute → Success | 검증된 Window Context의 마지막 실패 시각, 동일 IP·계정, 엄격히 이후, ≤60초, 최단 성공 동률 fail-closed; 3/3 synthetic | 관측되지 않은 success는 부재 증거 아님; support 제한 |
| Spray → Success | Spray Detection이 있는 경우 기존 closest authentication pair; 1/1 synthetic | Spray 전체-span evidence와 마지막 실패 pair의 관측 범위 구분 필요 |
| Post-authentication activity | 인증 성공 뒤 지원되는 activity/file observation과 시간관계 | application/file evidence subset; 행위가 로그인에 의해 원인됐음을 뜻하지 않음 |
| Multi-IP Authentication | 계정별 60초 내 3개 이상 IP 실패 | proxy/NAT 및 합법적 이동·공유 계정 맥락 없음 |
| Distributed Authentication → Success | multi-IP 실패와 같은 계정의 60초 이내 success | 인과관계/실제 인증 주체 보장 없음 |

36.9G 계열은 Brute Context의 실행 provenance가 Correlation과 Case까지 이어지는 계약을 여러 차례 독립 테스트로 보완했다. 현재 Closure는 합성 및 내부 consumer 경계의 근거다. Live/collector의 모든 실제 배포 수집 순서와 producer timezone에서 같은 신뢰성을 입증하지 않는다.

## 13. Risk / Case / Report Readiness

- Risk `likelihood`, `impact`, `confidence`는 별도 heuristic 차원이다. confidence는 통계적으로 보정된 공격 확률이 아니다. 고정 metadata와 지원 feature에 따라 현재 점수화된다.
- Risk의 volume/temporal/targeting은 IP 전체 feature를 사용하고 Brute evidence는 선택 Window를 사용한다. 코드 설명은 두 관측 범위를 구분한다. 동일한 실패 이벤트에서 나온 Detection과 Correlation을 독립 사건 두 건으로 셀 수 없다.
- Case rule은 기존 `CASE-BRUTE-SUCCESS-01`, `CASE-AUTH-TRANSITION-01` 등 허용 규칙으로 supported observations/relations를 조립한다. Case 생성은 사건/침해 확정이 아니다.
- Report projection은 Detection, correlation, risk와 제한 설명을 closed DTO로 구성한다. Raw event, 원문 account 및 private run ownership를 공개 분석 계약에 넣지 않는다.
- Checklist는 검증된 Case-bound evidence/role을 참조한다. 근거 없는 role 추론이나 단순한 탐지 개수만으로 우선순위를 확정하지 않는다.
- 분석가가 추가로 확인할 정보: 인증 서비스/계정 소유자, 정상 배치/스캐너 승인, proxy/NAT topology, source clock와 timezone, 누락/중복 수집, 서버측 response/DB/session audit. 현재 로그가 제공하지 않으면 “미확인”으로 남긴다.

## 14. Static / Live / Collector Readiness

| 입력 경로 | 지원 Source | 탐지 연결 | Correlation | Case | 검증 근거 | 주요 제한 |
|---|---|---|---|---|---|---|
| 정적 File | Application, supported SSH, Access subset, 별도 Linux Audit | 전체 contextual pipeline | 지원 관계 | projection | pytest/evaluator 및 file tests | 형식 subset, 실제 배포 인코딩·회전 미검증 |
| 정적 Text | 명시한 단일 source 입력 subset | 전체 contextual pipeline | 지원 관계 | projection/report | local Text API tests | 자동 감지·임의 혼합 포맷 아님 |
| Local Live file | 설정된 source role/file tail parser subset | prefix/revision accumulator | contextual analysis | revision-bound proposal/Case path | parity, recovery 및 Linux CI synthetic tests | exactly-once·모든 filesystem/rotation 조합 보장 아님 |
| TCP Syslog | bounded local pilot frame 및 Application/SSH parser | collector runtime → live parser path | 지원 pipeline | 지원 경계까지 | CI TCP Syslog Linux | TLS/인증/remote 조직 collector 준비 완료 아님 |
| JSONL runtime | bounded local JSONL schema/adapter | normalized event adapter | 지원 pipeline | 지원 경계까지 | CI JSONL runtime | 임의 JSON schema, durable replay, HA 아님 |
| Linux Audit | 별도 file/API/분석 경로 | process/session 분석 | Linux Audit 관계 | 별도 projection | 21/21 synthetic process consistency, Linux CI | privileged host-wide deployment/운영 미검증 |
| Vector/VM | 현재 승인되지 않음 | 없음 | 없음 | 없음 | 별도 static preflight 수준 | `USER_ACTION_REQUIRED / ISOLATION_BLOCKED` |

Live/static parity는 검증된 동일 관측 prefix 기준이다. 이는 실시간 원격 생산 환경에서 loss/replay/order/rotation을 보장하지 않는다. TCP/JSONL의 bounded queue 및 loopback CI 성공을 remote TLS, durable replay, HA 또는 조직 확장성으로 확대하지 않는다.

## 15. Privacy / Security / 격리

현재 저장소 계약에는 Local API 입력 크기·행 수·시간 제한 및 분석 worker 경계, sample API 제한, restricted report 입력/실행 제한, Live queue/history 제한, TCP/JSONL queue/frame/connection bounds가 있다. 이는 구체적인 소프트웨어 상한이지 OS 전체 CPU/memory cap은 아니다.

| 영역 | 현재 근거 | 잔여 위험 |
|---|---|---|
| 입력 개인정보 | projection allowlist, repr/privacy tests, 제한 입력 계약 | 실제 운영 로그의 계정/IP가 local files, crash output, backup에 남는 생명주기 미검증 |
| API 접근 | local investigation API는 local-only 경계를 지향; default local interface 사용 | 조직 단위 인증/인가·원격 TLS 운영 절차가 이 API에서 승인되지 않음 |
| Restricted report | 고정 schema, size/line/event/runtime bounds와 제한 출력 | 배포 호스트 권한, 파일 보관·삭제, 서비스 경계는 별도 승인 필요 |
| Collector | loopback 및 bounded frame/queue, rejection/drop counters | 외부 TLS/authentication, durable replay/HA, drop alerting 운영은 미승인 |
| CPU / memory | 입력/queue/count/time bounds가 여러 경로에 존재 | OS-level hard cap, CPU quota, memory cgroup, forced worker termination 후 정리 보장 없음 |
| Filesystem lifecycle | 임시 파일 cleanup/recovery에 합성 검증 | SIGKILL/power loss, media remanence, secure erase 미보장 |
| Isolation | worker/process 및 bounded local runtime 경계 일부 | adversarial multi-tenant sandbox/container/VM 격리 아님; Vector/VM 격리는 요구 사용자 작업 미완료 |
| External services | 이번 Phase 외부 전송 없음; LLM path는 일반 분석 입력에 자동 연결되지 않음 | 외부 서비스 정책·자격증명·운영 승인 없음 |

## 16. Operational Readiness Blockers

| 영역 | 필요한 조건 | 현재 근거 | 미충족 사항 | 검증 방법 | 상태 |
|---|---|---|---|---|---|
| 실제 탐지 정확도 | 독립적이고 승인된 정상/공격 라벨 및 현장 분포 검증 | 46개·24개 합성 corpus | 실제 log/ground truth 미사용 | 승인·비식별화 계획, 독립 라벨링, shadow 검증 | `NO_GO` |
| Parser/profile | 실제 producer/version/config를 고정하고 수집 누락률 확인 | 21 fixture profile 및 195/200 parser aggregate | 설치별 형식·timezone·proxy 검증 없음 | 샘플 승인 후 source별 fixture와 reject/partial 집계 검증 | `UNVERIFIED` |
| False alert 운영 | benign workload, scanner/batch ownership, triage 정책 | 합성 operational candidates 7건 | 현장 빈도/분석가 부담 불명 | 승인된 benign corpus 및 shadow triage | `UNVERIFIED` |
| 접근 제어/전송 | 승인된 identity, authn/authz, TLS, secret rotation, network boundary | local loopback API/collector 합성 tests | 조직 원격 운영 경계 승인 안 됨 | 별도 deployment security/host acceptance | `BLOCKED` |
| 자원 제한 | OS hard CPU/memory, worker lifetime, queue/drop monitoring, load profile | 앱 수준 size/queue/time bounds | 강제 OS cap 및 실부하 자료 없음 | 격리된 호스트에서 quota, stress, kill/recovery 계획 검증 | `UNVERIFIED` |
| 보존·삭제 | raw input/report/log retention 및 crash cleanup 정책 | 제한 projection/일부 temp cleanup tests | abrupt power loss/SIGKILL 후 secure erase 보장 없음 | 파일시스템·backup·retention 운영 검증 | `UNVERIFIED` |
| 수집 신뢰성 | remote auth/TLS, durable replay, HA, loss detection | loopback TCP/JSONL synthetic CI | remote/durable 수집 미승인 | 별도 수집 아키텍처 및 failure-injection acceptance | `USER_ACTION_REQUIRED` |
| AI 설명 | input governance 및 no-invention | deterministic pipeline separation | 모델 경로는 이번 평가에서 테스트되지 않음 | 별도 privacy/model/data contract | `NOT_TESTED` |

실제 사용자 자료, 조직 운영, 자동 대응은 현재 `NO_GO`다. 이 표는 운영 승인 체크리스트의 일부일 뿐 완료 승인이 아니다.

## 17. Top 5 Remaining Risks

| 순위 | 위험 | 현재 근거 | 영향 | 검증 공백 | 우선순위 | 다음 조치 |
|---:|---|---|---|---|---|---|
| 1 | Password Spray의 전체-span/IP 단위 규칙과 정상 batch/NAT 경계가 충분히 평가되지 않음 | 코드 조건 4 failures/3 accounts/whole span ≤60s; corpus positive 2, negative 5; `spray_benign_batch` operational candidate | 탐지 누락 또는 정상 batch의 조사 부담 | late noise, slow/distributed, shared egress 및 mixed Brute 차등 독립 matrix 없음 | P1 | 36.10B에서 독립 라벨 기반 평가·정책 비교를 우선하고 결과 전 Production 변경 금지 |
| 2 | 좁은 Parser profile과 실제 배포 로그 사이의 coverage gap | parser compatibility 21 fixtures; app/SSH 고정 subset, Access core subset; parser aggregate 195/200 | 이벤트가 누락/부분 파싱돼 Detector에 도달하지 않을 수 있음 | producer version/config, locale, proxy, timezone, collector별 악성 fixture 경로 | P1 | 36.10C에서 하나의 우선 Source/version을 고정하고 bounded profile acceptance 추가 |
| 3 | 합성 accuracy corpus가 작고 저장소 내부에서 작성·평가됨 | detector별 positive support 2–5, negative 1–5; 7 operational candidates | 지표가 실제 workload의 FP/FN을 대표하지 못함 | 외부 독립 labels 및 배포 분포 없음 | P1 | 단계적으로 독립 fixture review; 실제 자료는 별도 승인 gate 뒤에만 고려 |
| 4 | 앱 수준 bounds가 OS 자원/비정상 종료 격리를 보장하지 않음 | API/report/count/queue/time bounds와 worker 있음; hard CPU/memory cap 미보장 | 극단 입력·동시 실행에서 호스트 압박 또는 잔여 임시 데이터 | 실제 peak load, hard quota, SIGKILL/power loss, host cleanup | P1 (운영 blocker) | Production 사용 전 host isolation/cgroup 및 termination acceptance를 별도 설계·검증 |
| 5 | Web Detector가 request pattern만 관측해 실제 실행·영향을 알 수 없음 | event schema는 method/path/query/status/size; body/DB/browser telemetry 없음 | 탐색과 성공을 혼동할 위험, 서버측 결과에 대한 미탐 | app/WAF/DB/browser/server-side outcome integration 없음 | P2 | 보고 문구 경계를 유지하고 필요 telemetry가 승인될 때만 제한된 연결 평가 |

순위는 관측된 영향 범위, 평가 support, 현재 consumer 경계, 검증 비용을 정성 비교한 것이다. 수치 확률·severity score를 임의 생성하지 않았다. 4번은 구현 결함이 재현됐다는 의미가 아니라 실제 운영 전 차단 조건이다. 5번은 현재 telemetry의 구조적 한계이지 탐지 버그가 아니다.

## 18. Prioritization Method

P0는 재현 가능한 직접 신뢰경계·개인정보 문제에만 부여한다. 이번 감사에서 새로운 P0를 재현하지 않았다. P1은 탐지 범위나 운영 안전성에 큰 영향을 미치고 코드·테스트 근거가 있으며 명확한 독립 검증 경로가 있는 항목이다. P2는 의미를 바꾸지 않고 한정 평가로 다룰 수 있지만 즉시 운영 차단과는 구분되는 항목이다. P3는 장기 확장 후보에 사용한다.

위험 발생 가능성은 코드/fixture의 실제 관측에 한해 강하게 표현했다. NAT, 배포 형식 차이, 운영 부하 같은 값은 환경별 검증이 없으므로 `UNVERIFIED`로 남겼다. `Pattern FP=0`은 benign operational candidates를 지우거나 보정하지 않는다.

## 19. Phase 36.10B/C/D Roadmap

### Phase 36.10B — Password Spray Scope & Operational False-Alert Evaluation (**최우선 추천**)

- **문제:** whole-span IP aggregation과 정상 batch/shared egress의 관계가 작은 corpus에서만 관측돼, 기존 정책의 coverage와 operational alert burden을 설명하기 어렵다.
- **근거:** `app/detector/password_spray.py`, `summarize_ip_failures()`, 현재 evaluator의 Spray positive 2/negative 5, `spray_benign_batch`.
- **변경 후보:** 우선 corpus/evaluator/test/document only. 독립 시나리오 라벨로 current whole-span을 유지한 채 late-noise, 60/61초, multi-IP, missing account, duplicate, benign batch, Brute overlap을 비교한다. 별도 승인된 다음 단계 전까지 Production 규칙은 바꾸지 않는다.
- **유지 계약:** shared whole-IP feature, Brute Candidate C, existing Evidence/Correlation/Risk/Case/API schema 불변.
- **사전 조사:** Password Spray의 observable telemetry와 ATT&CK T1110.003의 행동 범위를 구분; account identity, IP/proxy scope, duplicate semantics 정의.
- **Acceptance:** 독립 라벨 manifest와 evaluator가 detector output을 사용해 label을 생성하지 않음; support/exclusions 명시; current baseline 재현; operational candidate는 Pattern FP와 분리; 전체 regression 통과.
- **회귀 위험:** 기대값을 현재 구현에 맞추는 label leakage, Brute shared-feature 의미 오염, operational candidate를 FP로 합산.
- **HOLD:** 라벨 모호성, parser exclusion 혼입, ground truth 수정, Spray와 Brute 계정 범위 혼동, 불충분한 독립 benign coverage.
- **효과:** Production semantics를 바꾸기 전 Spray false-alert/miss tradeoff를 설명할 근거를 얻음.

### Phase 36.10C — One-Profile Parser/Detector Coverage Closure

- **문제:** 지원 subset과 실제 producer 형식의 차이 및 parser rejection/partial disposition이 운영 탐지 coverage에 미치는 영향.
- **근거:** parser compatibility 21개 직접 작성 fixture, Access combined의 partial fields, ISO-style SSH 제한, 195/200 aggregate.
- **변경 후보:** 사용자가 지정한 하나의 source와 producer/version/config만 대상으로 fixture/Parser contract 및 pipeline propagation 검증. 어떤 새 형식을 구현할지는 사전 조사 후 결정한다.
- **유지 계약:** 다른 source parser, Detector 의미, 공개 event schema, API contract는 변경하지 않음.
- **사전 조사:** 공식 source-format 문서/버전, escaping, timezone, proxy와 hostname/IP semantics; 합성 fixture에 비밀정보 없음.
- **Acceptance:** supported/partial/rejected 구분, invalid event가 result key가 되지 않음, parser→detector E2E와 기존 corpus/full regression 통과.
- **회귀 위험:** false acceptance, timezone drift, API preflight/runtime mismatch.
- **HOLD:** producer 사양 불명, hostname을 IP처럼 처리, 기존 format regression, scope가 여러 parser로 확장.
- **효과:** 하나의 명확한 source profile에서 탐지 도달률과 입력 계약을 설명.

### Phase 36.10D — Resource Containment & Abrupt-Termination Acceptance

- **문제:** app-level bounds는 있지만 OS-level hard CPU/memory cap, SIGKILL 이후 cleanup 및 실측 capacity 보장은 없음.
- **근거:** local API 32 KiB file / 80 KiB total / 512 lines / worker timeout, restricted report limits, Live/collector bounded queues; release checklist host acceptance requirements.
- **변경 후보:** Production code보다 먼저 배포 격리·resource quota·temporary storage lifecycle을 설계하고 isolated host에서 acceptance test. 이 Phase 범위의 로컬 audit만으로 조직 deploy는 하지 않음.
- **유지 계약:** API/public schema, parser/detector policy, raw data privacy, fail-closed input limits.
- **사전 조사:** target OS/service manager, cgroup/container, worker count, storage, approved synthetic load profile, retention.
- **Acceptance:** hard limits와 process behavior를 target host에서 검증, abrupt termination/restart cleanup, queue saturation/drop handling, resource/retention evidence 기록.
- **회귀 위험:** quota가 정상 분석을 중단, cleanup이 evidence 보존 요구와 충돌, worker 수 배수로 capacity 계산 오류.
- **HOLD:** 격리 호스트/운영자 승인 부재, hard limit 검증 불가, 실제 자료 필요성 발생, secure erase를 입증 없이 주장.
- **효과:** 기능별 app bounds와 운영 호스트 자원 경계를 구분해 설치 승인에 필요한 근거 제공.

## 20. 최우선 후속 Phase 선정

**Phase 36.10B를 먼저 추천한다.** 현재 Brute는 36.9F 이후 독립 remediation와 provenance closure를 거쳤다. Spray는 기능은 구현되어 있지만 작은 positive support(2)와 관측된 정상 batch candidate가 있으며 whole-span/IP grouping의 late-noise 및 공유망 조건을 별도 Candidate 비교로 다루지 않았다. 이 작업은 Production 코드를 바꾸지 않고 독립 라벨과 평가를 확장할 수 있어 가장 작은 위험 기반 다음 단계다. 36.10C는 실제 producer/version의 입력이 지정돼야 하고, 36.10D는 격리된 운영 호스트와 사용자 측 승인 조건이 필요하다.

## 21. 전체 Regression

- `uv sync --locked --dev`: PASS
- `uv lock --check` (시작 및 종료): PASS
- `uv run python -m app.evaluation`: PASS; boundary 79/79, Parser 195/200 (ignored 2/rejected 3), Risk 70/70, Case 70/70, Linux process 21/21; 관계 평가 6/6, 3/3, 1/1.
- Detector Accuracy text/json: PASS; 46 scenarios, Current Brute 4/0/0/3, 다른 여섯 행은 §10과 일치.
- Brute Window text/json: PASS; 24 scenarios, Whole-span 9/0/9/5, Candidate C 17/0/1/5, 계정별 후보는 14/0/4/5 및 16/0/2/5.
- 전체 `uv run pytest -q`: PASS, `3367 passed, 2 warnings` (macOS/Python 3.12, 197.75초).
- `python3 -m compileall -q app tests`: PASS; `uv lock --check`: PASS; `git diff --check` 및 새 문서 whitespace: PASS.
- `npm run test:a11y --silent`: PASS, 25 states, external requests 0, elapsed 117999ms. 전체 pytest와 Chromium/axe는 중첩하지 않았다. 이는 자동화된 Chromium/axe 결과이며 Safari/VoiceOver/실제 모바일 접근성 검증이 아니다.
- Production 코드, 테스트, evaluation corpus, Ground Truth, dependency/lockfile, API schema, CI workflow 변경 없음.

## 22. 미검증 범위

- 실제 사용자·조직 로그, 운영 FP/FN·정확도·처리량 및 분석가 triage 시간.
- 실제 Apache/Nginx/OpenSSH deployment variant 전체, syslog envelope, timezone/proxy topology.
- 원격 TLS 수집, durable replay, HA, 실제 organization backpressure.
- OS hard CPU/memory cap, host-level isolation, abrupt power loss/SIGKILL 이후 secure erase.
- 모델 기반 AI `NOT_TESTED`; Safari/VoiceOver/실제 모바일 `NOT_TESTED`.
- Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`; Renderer `KEEP_LEGACY`.

## 23. 잔여 위험

합성 corpus가 작고 self-authored라 evaluation에 과적합될 수 있다. 동일 로그 event duplicate/dropped rows는 집계·상관 근거를 왜곡할 수 있다. Proxy/NAT IP는 개인·endpoint 정체성을 말하지 않는다. Password Spray의 same-password 의미는 현재 schema에서 확인할 수 없다. Web request pattern은 server execution 및 impact를 뜻하지 않는다. 앱 수준 입력 상한은 OS 수준 resource isolation을 대체하지 않는다.

## 24. 최종 판정

`PHASE_36_10A_DETECTION_READINESS_PRIORITIZATION_LOCAL_CONDITIONAL_GO`

판정 범위는 현재 코드 inventory, 저장소의 과거 문서, 재실행한 synthetic evaluator 및 로컬 regression, 그리고 우선순위 제안이다. 이는 실제 환경의 탐지 정확도, 조직 운영, 실제 사용자 자료 분석 또는 자동 대응 승인이 아니다.
