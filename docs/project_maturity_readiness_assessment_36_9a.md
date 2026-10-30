# Phase 36.9A — 프로젝트 성숙도·실무 준비도 평가

## 1. Executive Summary

이 저장소는 **합성 데이터로 검증된 로컬 조사 보조 도구**다. 여러 고정 형식의 입력, 결정적 탐지·관계·위험도 분석, 사례 projection, 웹 조사 작업공간, 제한된 수집 pilot을 제공한다. 현재 근거로 실제 조직 운영이나 실제 로그에 대한 정확도·안정성을 입증할 수 없다. 운영 준비가 된 SIEM/EDR 제품으로 분류하지 않는다.

이번 평가는 코드와 기존 기록을 읽고, 고정된 합성 평가 명령을 실행한 범위의 감사다. 실데이터를 수집하거나 새 수집기, Vector, VM, 모델을 실행하지 않았다. 감사 중 production 코드/API/schema를 수정하지 않았다.

**관측 가능한 성과:** 합성 경계 corpus 79/79, Linux process corpus 21/21 일관성, narrow detection matrix의 TP/FP/FN 집계는 현재 corpus에서만 보고됐다. 이는 운영환경 precision/recall이 아니다. Parser format coverage, 독립 ground truth, 다양한 제품 버전·조직별 설정 평가는 부족하다.

**가장 먼저 할 일:** 실제 제품 문서에 근거해 지원 로그 형식을 명명하고, 형식별 합성 compatibility corpus로 Parser 수용/거부 경계를 확장·검증한다. 이 Phase의 권고는 **Phase 36.9B — Supported Log Format Compatibility Profiles**다. 보안 의미를 바꾸는 parser 확장 전에 해당 제품의 공식 문서와 Observable Evidence Mapping을 새 작업의 선행 조건으로 삼는다.

## 2. 시작 Gate

| 항목 | 검증 결과 |
|---|---|
| 기준 SHA | `09b8a649e71f8b21eab03c485c1b5b258ad6c586` |
| Branch / HEAD / local main / origin/main / GitHub main | `main`, 모두 기준 SHA |
| `origin/main...HEAD` | behind 0 / ahead 0 |
| Working tree 시작 상태 | clean |
| 지정 Actions Run | [41003791594](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41003791594), head SHA 일치, push, completed, success |
| Artifact | artifact 0 (0개) |
| 필수 CI jobs | Locked Python 3.12 regression, Linux process/SSH recovery, OpenAPI property pilot, complete regression, TCP Syslog Linux, JSONL runtime Linux, restricted report/benchmark, Chromium/axe, tracked-file invariant 모두 success |
| v0.4.0 | tag/Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지 |

이는 지정된 시작 SHA에 대한 CI 증거다. 이번 문서 작업 뒤의 새 SHA에 대한 CI 증거는 아니다.

이번 감사에서 로컬로 실행한 기준선: `uv sync --locked --dev`, `uv lock --check`, `uv run python -m app.evaluation`. 전체 pytest는 문서 변경 후 실행한다. Run의 모든 필수 job 통과는 기록하지만, 로컬 재실행처럼 표현하지 않는다.

## 3. 프로젝트 현재 구조

| 단계 | 코드 및 계약 | 검증 근거와 한계 |
|---|---|---|
| 파일 입력 | `app/api.py`, `app/local_investigation_api.py`: 로컬 multipart 3개 파일 및 bounded validation | 기존 API 테스트, 36.8B/D 기록. 32 KiB/file, 80 KiB total, 96 KiB envelope |
| 텍스트 입력 | `POST /api/v1/investigations/text`, `app/models/local_text_investigation.py` | 36.8B–E; 단일 allowlisted source, JSON bounds, 합성 loopback E2E. 실무 로그 다양성 미입증 |
| 수집 | `app/live_monitoring/`, `app/log_collection/`, TCP Syslog 및 JSONL runtime | 제한된 loopback pilot과 Linux CI. 내구성, 원격 TLS/인증, HA/replay 보장 아님 |
| Loader/Parser | `app/loader/file_loader.py`, `app/parser/registry.py`, source parser modules | 해당 합성 fixtures 및 parser tests. 지원 범위는 아래 형식 목록으로 제한 |
| 분석 | `app/analyzer/pipeline.py`, `app/detector/`, `app/correlation/`, `app/analyzer/risk.py` | unit, scenario, bounded synthetic evaluation. 실제 환경 정확도 없음 |
| 결과 | Case/public projections, checklist registry, report projection | API/privacy tests와 UI regression. 내부 raw event와 공개 projection을 구분 |
| 화면 | `frontend/app.js`, `frontend/style.css`, `app/web_ui.py` | Chromium/axe CI와 합성 사용자 검수. Safari/VoiceOver/실기기 미검증 |

파이프라인은 로그 → normalization → deterministic detection → relation/correlation → heuristic risk → case projection → UI/report다. 외부 LLM은 기본 흐름에 들어 있지 않다. 기능이 있는 것과 실제 업무 데이터에서 의미가 검증된 것은 별개다.

## 4. 기능 Inventory

| 기능 | 분류 | 현재 범위 |
|---|---|---|
| 세 파일 local upload | 구현됨 | application/SSH/access 파일을 함께 받는 기존 endpoint |
| 단일 source text input | 구현됨 | application/SSH/access 중 하나, 명시적인 로컬 요청 |
| local file live monitoring | 일부 구현됨 | 사용자가 설정한 제한된 단일 파일·checkpoint 흐름 |
| TCP Syslog | 합성 검증 pilot | loopback, 제한된 연결/queue/frame; 원격 운영 수집 아님 |
| JSONL collector | 합성 검증 pilot | 제한된 loopback application/SSH event adapter/runtime; durable queue 아님 |
| Linux Audit | 일부 구현됨 | 보호된 별도 분석/API 흐름과 합성/CI 검증; 일반 사용자용 수집 에이전트 아님 |
| Vector | 사용 불가/차단 | `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`; 실행 검증을 완료한 기능이 아님 |
| 조사 UI | 구현됨 | Dashboard와 Overview/Timeline/Tasks/Evidence/Checklist/Guidance/Report |
| lexical guidance | 제한된 로컬 기능 | 명시적 요청, 고정 corpus 및 검증된 citation |
| embedding/local LLM | 실험 또는 차단 | production 분석 경로가 아님 |

## 5. 구현·검증 Evidence Matrix

상태 표기: 구현 상태는 `IMPLEMENTED`, `PARTIAL`, `PROTOTYPE`, `DESIGN_ONLY`, `NOT_IMPLEMENTED`; 검증은 `UNIT_VERIFIED`, `SYNTHETIC_E2E_VERIFIED`, `USER_ACCEPTED_SYNTHETIC`, `LINUX_CI_VERIFIED`, `UNVERIFIED`, `BLOCKED`다.

| 영역 | 구현 상태 | 검증 수준 | 주요 한계 | 다음 조치 |
|---|---|---|---|---|
| 로그 입력 | `PARTIAL` | `SYNTHETIC_E2E_VERIFIED`, `LINUX_CI_VERIFIED` | 명명된 형식 subset만; 외부 collector/format breadth 부족 | 36.9B 형식 profile |
| Parser | `IMPLEMENTED` | `UNIT_VERIFIED`, `SYNTHETIC_E2E_VERIFIED` | 실제 버전·설정 조합 및 변형 coverage 부족 | 별도 합성 compatibility corpus |
| Detector | `IMPLEMENTED` | `UNIT_VERIFIED`, `SYNTHETIC_E2E_VERIFIED` | 작은 self-labeled corpus, 독립 TP/FP/FN 부재 | 형식 coverage 후 36.9C 평가 |
| Correlation | `IMPLEMENTED` | `UNIT_VERIFIED`, 제한된 `SYNTHETIC_E2E_VERIFIED` | 관찰 가능한 키/시간 조건에 한정 | 누락·중복·시간 이상 matrix |
| Risk | `IMPLEMENTED` | `UNIT_VERIFIED`, `SYNTHETIC_E2E_VERIFIED` | heuristic 분류이며 확률 calibration 아님 | 설명 및 경계 테스트 |
| Investigation UI | `IMPLEMENTED` | `USER_ACCEPTED_SYNTHETIC`, `LINUX_CI_VERIFIED` | synthetic Chromium; Safari/VoiceOver/실기기 미검증 | 유지, 별도 실제 환경 acceptance |
| Checklist | `IMPLEMENTED` | `UNIT_VERIFIED`, `USER_ACCEPTED_SYNTHETIC` | 역할 기반 제한 응답, 사용자 운영 효과 미평가 | citation/상태 회귀 |
| Report | `IMPLEMENTED` | `UNIT_VERIFIED`, `LINUX_CI_VERIFIED` | 공개 보고 projection; 실제 데이터 취급 승인 없음 | privacy 범위 유지 |
| AI 보조 기능 | `PARTIAL` | lexical은 synthetic/unit; 모델은 `NOT_TESTED`/차단 | 외부 LLM helper 존재하나 기본 경로 미호출; embedding/local model 미통합 | 호출 경계와 secret/privacy 별도 검토 |
| Privacy | `PARTIAL` | `UNIT_VERIFIED`, `SYNTHETIC_E2E_VERIFIED` | local boundary를 운영 인증/인가로 오해 금지 | 운영 사용 전 별도 threat review |
| Resource isolation | `PARTIAL` | 제한된 worker/timeout CI | OS hard memory/CPU cap 없음, limiter process/app scope | 별도 resource containment Phase |
| 운영 준비도 | `PROTOTYPE` | 제한된 local/Linux CI | 인증, TLS, durable storage, HA, audit/ops lifecycle 미충족 | 실제 운영 승인 보류 |

## 6. 로그 입력 지원 범위

| 경로 | 실제 동작 | 검증 범위 | 미보장 |
|---|---|---|---|
| 파일 업로드 | 세 개의 source 파일을 기존 local multipart API에 전달 | 합성 files, API/UI 및 regression tests | 임의 log bundle/압축 파일 |
| 텍스트 입력 | application, ssh, access 중 한 source를 명시해 제출 | 36.8B–E synthetic loopback, bounded request | 여러 source 혼합, 자동 감지 |
| Live monitoring | 설정된 로컬 파일 tail/checkpoint | existing recovery/rotation tests, Linux CI 일부 | 모든 rotation/FS/network mount 조합, exactly-once |
| TCP Syslog | loopback pilot의 제한된 frame 처리 | 합성 application/SSH, Linux CI acceptance | 인증/TLS, 원격 수집, 내구성 |
| JSONL | loopback JSONL event adapter/runtime | bounded synthetic event tests, Linux CI | Vector deployment, durable replay, general JSON schema |
| Linux Audit | 별도 제한 API/parser/process observation | targeted tests/CI | host-wide production agent, 배포/권한 운영 |
| Vector | 운영 가능하다고 판정하지 않음 | static preflight 문서 일부 | 실제 실행 및 격리 통합 |

지원 포맷은 명시된 Parser가 인식하는 문법뿐이다. 파일 확장자나 제품 이름만으로 해당 형식 지원을 추정하면 안 된다.

## 7. Parser 호환성

근거: `app/parser/registry.py`, `app/parser/auth_log.py`, `app/parser/ssh_auth.py`, `app/parser/access_log.py`, `app/loader/file_loader.py`.

- Application parser는 timestamp `%Y-%m-%d %H:%M:%S`, level/event 및 key=value 필드 형태를 기대한다. application timezone은 Asia/Seoul로 해석되는 경로가 있다.
- SSH parser는 `YYYY-MM-DD HH:MM:SS` timestamp와 Failed/Accepted password/publickey 문구, user, from IP 형식을 대상으로 한다. 표준 배포에서 자주 보이는 `Mon dd hh:mm:ss host sshd[pid]: ...` prefix/연도 생략 변형을 모두 처리한다고 볼 근거는 없다. 현재 parser의 구체 regex subset만 지원으로 본다.
- Access parser는 NCSA 계열 quoted request 및 `%d/%b/%Y:%H:%M:%S %z` timestamp 형태를 대상으로 한다. request는 method, target, protocol의 세 토큰이어야 한다. User-Agent 등 trailing fields는 탐지에 쓰지 않는다. 모든 Apache/Nginx 설정이 호환된다는 뜻은 아니다.
- Loader는 UTF-8 텍스트 줄 단위 처리다. 여러 줄 이벤트, 임의 인코딩, syslog year 추정, timezone 없는 Access 시각 보정, 순서 역전·중복 dedup 지원을 보장하지 않는다.

주요 compatibility risk는 parser rejection/필드 누락이 Detection에 도달하지 않는 것, timezone 가정이 시간 상관을 바꾸는 것, reverse proxy/NAT 주소를 원 사용자·host로 오인하는 것이다. 실제 parser가 제공하지 않은 필드/의미를 만들어내면 안 된다.

## 8. Detector 평가 현황

읽기 전용으로 `uv run python -m app.evaluation`을 실행했다. 출력은 `app/evaluation/` 코드와 고정 synthetic corpus 기반이다.

### 현재 합성 결과

- Boundary corpus: **79/79 scenario pass**
- Linux process corpus: **21/21** consistency
- Detection corpus: brute force 11, password-spraying-like 2, path traversal 2, SQL injection-like 5, XSS-like 5, sensitive resource probing-like 4, web scanning-like 3 positive examples. 현재 보고된 confusion matrix에서 각 항목 TP가 positive support와 같고 FP/FN은 0이었다.
- Parser corpus: 200개 입력 중 195 parsed, 2 ignored, 3 rejected; unexpected parse/rejection 0.
- SSH scenario 13개 중 ambiguous operational scenario 하나는 confusion matrix에서 제외됐다.
- Relation synthetic counts는 실패→성공 6, brute→success 3, spray→success 1의 제한된 positive support다.

이 결과는 기능과 synthetic boundary 재현을 보여준다. **운영환경 precision/recall이 아니다.** 같은 repository가 corpus와 expected labels를 소유하며, 독립적으로 수집·검수된 정상 로그와 실제 사고 ground truth가 없다. Support가 적고 배포 설정 분포도 대표하지 않는다. 79/79는 평가 scenario 통과 비율이지 운영 탐지 정확도가 아니다.

### Rule별 행태와 오류 가능성

| 규칙 | 코드 조건 요약 | 필요한 관측 필드 | 오탐/미탐 가능성 | 평가 수준 |
|---|---|---|---|---|
| Brute force | `app/detector/brute_force.py`: IP별 실패 5회 이상, 한 계정, 전체 span 60초 이내 | IP, user, outcome, timestamp | 공유 NAT/테스트 계정은 오탐 가능; 다른 window/누락·실패 표기 변형은 미탐 | synthetic positive 11; 실데이터 미검증 |
| Password spraying-like | `password_spray.py`: IP별 실패 4회 이상, 고유 계정 3개 이상, span 60초 이내 | 위와 동일 | NAT 및 다수 정상 계정 오탐; IP 분산·긴 주기·부분 로그 미탐 | support 2 |
| Path traversal | `web_attack.py`: path/query의 반복 percent decode 결과에서 `../` 또는 `..\\` 관찰 | HTTP target path/query | 탐색 시도도 잡힐 수 있고 성공 의미 아님; custom encoding/parser 누락 미탐 | support 2, parser/eval synthetic |
| SQL injection-like | SQL boolean/UNION/comment 형태의 bounded target pattern | request target | 정상 검색 문자열/테스트 경로 오탐 가능; body/encoded/custom route는 미탐 | support 5 |
| XSS-like | script/event-handler/javascript scheme 패턴 | request target | 테스트/문서 URL 오탐 가능; body/DOM context 부재로 넓은 미탐 | support 5 |
| Sensitive resource probing-like | `.env`, `.git/config/head`, backup suffix 등 target pattern | request target | 정상 내부 배포 점검 오탐; encoded/custom path 미탐 | support 4 |
| Web scanning-like | IP별 60초, 요청 6+, distinct canonical target 6+, 4xx 3+ | IP, target, status, timestamp | crawler/health/security scanner 오탐; 더 느린 scan, 필드 부족 미탐 | support 3 |

여기서 “like/observation”은 관찰된 요청 패턴을 뜻한다. exploit 성공·침해·의도를 뜻하지 않는다. HTTP 200도 성공 증거가 아니고, 4xx도 모든 요청이 실패했다는 증거가 아니다.

### 네 평가 층위

| 검증 종류 | 현재 상태 |
|---|---|
| 기능 동작 | parser/detector/correlation unit 및 scenario tests 존재 |
| 경계값 | bounded decoders, thresholds, malformed inputs 및 79 scenario synthetic evaluation 일부 검증 |
| 합성 정확도 | 좁은 self-labeled corpus confusion counts 존재; 독립 평가 아님 |
| 실제 환경 정확도 | `UNVERIFIED`; precision/recall/F1을 실무 성능으로 산출할 근거 없음 |

운영 FP/FN에 대한 TP/FP/FN을 만들거나 extrapolate 하지 않는다.

## 9. Correlation/Risk 신뢰성

- `app/correlation/attack_chain.py`와 pipeline은 동일 IP·user 및 시간 순서를 이용해 인증 실패 다음 성공 관계 등을 계산한다. 일부 relation은 60초 이내이며 ambiguous closest match는 제외하는 규칙을 갖는다. 정확한 관계 종류·조건은 코드와 tests가 정의한다.
- 여러 IP에서 같은 user 실패가 관찰되는 조건 등은 관찰 가능한 IP/user/time에 한정한다. NAT, 프록시, 공유 계정, clock skew, event loss는 actor attribution을 약화한다.
- Linux Audit session/process 관계는 해당 telemetry가 실제로 연결된 경우에 제한된다. 일반 OS 프로세스와 외부 로그인 사이의 임의 correlation을 하지 않는다.
- Relation은 시간·논리적 지원 관계다. 인과, 동일 행위자, 공격 경로 또는 성공을 확정하지 않는다.
- `app/analyzer/risk.py`는 결정적 likelihood/impact 및 context 규칙으로 categorical risk와 confidence/rationale를 만든다. 이는 calibrated compromise probability가 아니다. privileged account는 맥락이며 단독 탐지가 아니다.
- 텍스트 단일 source input scope와 checklist의 검증된 source-role provenance는 분리된다. Risk와 analyst review priority도 별도 표시된다.
- 분석 한계, 부분 입력, detection 없음은 안전 판정이 아니다.

평가상 부족한 부분: 모든 correlation type의 독립 confusion matrix, clock skew/out-of-order/dedup sensitivity, Risk calibration 자료는 `UNVERIFIED`.

## 10. Investigation Workspace/UI

`frontend/app.js`는 2,657줄, UTF-8 149,889 bytes이며 `app/web_ui.py`의 fixed asset 상한은 160 KiB다. 현재 상한 안이지만 여유가 제한적이고 기능 간 결합도/변경 회귀 위험을 정량 측정하지 않았다. 이번 Phase에서 리팩터링하지 않았다.

기능: Dashboard, case list/detail, Overview, Timeline, Tasks, Evidence, explicit Checklist, lexical Guidance, scope notice, HTML report. 기존 UI rollback은 `USE_WORKSPACE_DETAIL_SHELL_36_6B` 및 `KEEP_LEGACY`로 유지된다.

36.6–36.8 기록에서 synthetic Chromium/axe, 접근성·responsive automation과 사용자 acceptance가 단계별로 완료됐다. 36.8E는 로컬 production UI의 합성 흐름을 대상으로 사용자 10/10 최종 PASS로 기록한다. 그 결과는 synthetic acceptance 범위다. 이번 감사는 이를 실데이터 수용으로 확대하지 않는다. Safari, VoiceOver, native browser zoom, 실제 모바일 기기는 `NOT_TESTED`.

## 11. AI 기능의 실제 상태

- 결정적 pipeline이 현재 관측·탐지·관계·risk의 권위자다.
- `app/analyzer/llm.py`에는 `GEMINI_API_KEY` 기반 외부 Gemini client/helper가 있고 분석 projection을 보내 자유 텍스트를 받는 코드가 있다. 코드 검색에서 기본 UI/API 분석 경로의 호출자는 확인되지 않았다. 따라서 기본 분석에서 자동 호출되는 기능이라고 보지 않는다. Helper 자체를 운영 검증한 것도 아니다.
- 외부 LLM에 실제 조사 자료를 보낼 수 있는 실행 경로가 있다면 별도 explicit authorization, data minimization, privacy/security review 전 사용하지 않는다. 현재 실제 사용자 자료에 대한 사용은 `NO_GO`.
- Checklist 도움말은 고정된 lexical corpus를 기반으로 사용자가 명시적으로 요청하는 로컬 기능이다. 탐지·관계·risk를 생성하거나 바꾸지 않는다.
- Embedding pilot은 synthetic 비교이며 production 통합이 아니다.
- Local LLM은 공급망, 격리, resource, storage gate에서 막혔으며 모델 추론은 `NOT_TESTED`.

AI가 제품명에 있다는 사실은 모델 기반 운영 기능의 증거가 아니다.

## 12. 보안·개인정보 경계

### 검증된 local boundary

`app/local_web.py`는 공식 local launcher에서 `127.0.0.1`, 단일 worker, reload off로 실행한다. Local API는 host/origin/forwarded-header 검증을 적용한다. upload/text 경로는 bounded parsing, UTF-8/control checks, line/body caps, app-instance limiter(동시 1, 60초당 6회), spawned worker, 10초 worker timeout, private temp staging/cleanup, bounded response를 사용한다. Text input은 96 KiB wire, 32 KiB text, 2048 bytes/line, 512 lines를 제한한다. 해당 상세는 36.8B/D 문서 및 tests에 남아 있다.

이는 **로컬 합성 검증**이다. 서로 다른 process/app instance 사이의 global quota가 아니고 OS hard memory/CPU cap도 아니다. 강제 OS 종료 후 orphan cleanup 및 secure erase를 보장하지 않는다. 임시 파일은 필요한 분석 과정에서 디스크에 기록된다.

### 공개/비공개와 배포 위험

Public DTO/report는 내부 분석 데이터의 일부를 privacy projection으로 축약하지만, 공개화가 모든 raw input을 전부 비밀화하는 것은 아니다. 공개 화면/report/canary 테스트는 해당 계약의 범위만 보증한다.

Deprecated `/api/analyze` route가 `app/api.py`에 남아 있다. 이 legacy 경로는 local investigation wrapper와 동일한 loopback guard를 공유하지 않는 경로가 있으므로 직접 ASGI 배포·원격 노출을 지원한다고 보지 않는다. 이는 원격 exploit이 재현됐다는 뜻이 아니다. **비공식 원격 deployment를 금지하고, 배포 노출 검토를 후속 보안 과제로 둔다.** Basic local app은 사용자/역할 인증을 제공하는 조직용 multi-user 서비스가 아니다.

인증·인가, TLS termination/reverse proxy hardening, durable audit trail, multi-user tenant separation, backup/restore, OS sandbox/cgroup resource ceilings, operational retention/incident response는 현재 로컬 도구를 hosted 운영 서비스로 바꾸기에 부족하다.

## 13. 운영 준비도

| 운영 항목 | 상태 및 근거 |
|---|---|
| 설치/실행 | uv lock 및 local launcher 존재; 개발자 로컬 실행에 적합 |
| 버전/의존성 | pyproject/uv.lock 고정 및 CI Python 3.12 확인 |
| 장애 처리 | bounded errors, timeout, worker cleanup tests 존재; host crash/OS kill 복구는 다름 |
| 수집기 연결 | loopback pilot; 외부 수집 운영 연결 미승인 |
| 데이터 손실 | memory queue/checkpoint 일부; durable end-to-end guarantee 미확인 |
| 결과 보존 | local in-process/app state 또는 파일별 구현; 조직 보존/검색/backup 체계 아님 |
| 인증/권한 | general workspace는 조직 multi-user authN/authZ가 아님; protected Linux Audit path 별도 |
| 감사 | 운영자 행동/설정 변경의 immutable audit system 아님 |
| 관측성 | 개발/CI 진단 존재; 운영 SLO, alerting, on-call 체계 없음 |
| 배포/업데이트 | 로컬 실행 및 repository CI. 서명된 운영 배포/rollback lifecycle 검증되지 않음 |
| 문서/인계 | phase 문서는 풍부하나 실제 SOC runbook/운영 인계 아님 |

판정: 로컬 합성 조사/교육/개발 보조 범위. 조직 production use는 `NO_GO`.

## 14. 코드 품질

강점은 locked dependencies, layered pipeline, closed API DTO, deterministic tests, schema/property pilot, extensive phase docs다. `uv sync --locked --dev` 및 `uv lock --check`는 이번 감사 기준선에서 통과했다.

부족하거나 측정되지 않은 부분:

- `frontend/app.js` 단일 대형 entry가 asset 상한에 근접; 기능 간 독립 테스트는 있으나 모듈 분리/변경 영향 분석 부족.
- API error contract는 세대별로 다름(legacy upload/text/checklist/protected APIs); 의도된 차이와 문서/code 일치 지속 확인 필요.
- Hypothesis/Schemathesis는 특정 contract/property pilot 범위다. 전체 API fuzzing이나 보안 증명이 아니다.
- Test count와 CI pass는 회귀 방지 근거이지 현장 정확도나 지원 형식 breadth 증거가 아니다.
- Phase 기록의 승인 상태는 시점·환경 제한과 함께 읽어야 한다.

이번 Phase는 코드 refactor를 하지 않았다.

## 15. GAP 목록

분류: `DEFECT` = 확인된 잘못된 동작, `VALIDATION_GAP` = 구현은 있으나 근거/환경 검증 부족, `CAPABILITY_GAP` = 기능 없음/불충분, `ENVIRONMENT_BLOCKER` = 안전한 검증 환경이 없음. 확인된 production defect가 아닌 항목을 버그라 부르지 않는다.

| ID | 유형 / 영역 | 관측 사실 및 근거 | 영향·보안/사용성 | 난이도 / 선행 | 필요한 검증 | 우선순위 |
|---|---|---|---|---|---|---|
| G-01 | `VALIDATION_GAP` Parser compatibility | parser regex/format은 좁은 subset; 표준 배포 변형 corpus 부재 | 유효 로그가 무시/거부되면 분석 누락; 형식 혼동 위험 | 중 / 공식 format profile 결정 | 합성 acceptance/rejection matrix, timezone·encoding·ordering | P1 |
| G-02 | `VALIDATION_GAP` Detector 정확도 | 79 scenario self-labeled, support 작은 matrix, 운영 labels 없음 | 실제 FP/FN 및 workload 적합성 미지 | 중~상 / G-01 범위 고정 후 | 독립 expected outcomes, benign corpus 다양화, error analysis | P1 |
| G-03 | `VALIDATION_GAP` Correlation/Risk | 제한된 synthetic relation; calibration/clock skew/NAT 평가 부족 | 관계/risk 오해 및 잘못된 우선순위 가능 | 중 / profile 및 test harness | time/order/dedup/NAT stress, categorical calibration 검토 | P1 |
| G-04 | `CAPABILITY_GAP` 운영 서비스 보안 | multi-user auth/TLS/audit/tenant boundary/durable ops 체계가 없음 | 조직 공유/원격 배포에 부적합 | 상 / 별도 threat model | deployment threat model, authZ, secrets, audit, backup tests | P0 차단 조건(운영 도입 전); 현재 로컬 실행 결함이라는 뜻 아님 |
| G-05 | `VALIDATION_GAP` 자원 격리 | app-instance quota/worker timeout은 있으나 OS hard memory/CPU isolation 없음 | hostile/large input의 host resource upper bound 증명 불가 | 상 / target OS/runtime 결정 | cgroup/process resource tests, cancellation/cleanup soak | P1 |
| G-06 | `ENVIRONMENT_BLOCKER` Vector/VM | 기존 records `USER_ACTION_REQUIRED / ISOLATION_BLOCKED` | external collector 연동 검증 불가 | 상 / 사용자 격리 환경 조치 | egress-denied disposable VM acceptance | P2, blocker 해소 전 실행 금지 |
| G-07 | `CAPABILITY_GAP` durable collection/retention | bounded queue/checkpoint 존재하나 durable event store/replay/HA 보장 없음 | 재시작/장애 시 보존 요구가 있는 SOC 사용 제한 | 상 / 요구사항·threat model | crash/restart/rotation/loss accounting | P2 |
| G-08 | `VALIDATION_GAP` real browser/runtime | Chromium synthetic only; Safari/VoiceOver/real devices NOT_TESTED | 대상 사용자 환경의 접근성 미입증 | 중 / 해당 환경 | manual browser/device acceptance | P2 |
| G-09 | `VALIDATION_GAP` dormant external LLM helper | helper can send analysis to external provider; default call site not found | 향후 호출 추가 시 sensitive data egress risk | 중 / call-site/data policy inventory | static call graph + network sink tests + explicit approval | P0 for enabling AI; no default invocation defect established |
| G-10 | `CAPABILITY_GAP` case management/ops | persistence/search/assignment/retention/audit workflows absent or not established | multi-analyst handoff unavailable | 중~상 / product scope | requirements and privacy model | P2 |
| G-11 | `DEFECT` | 이번 감사에서 재현·확정한 production defect 없음 | — | — | 새 결함 발견 시 isolated reproduction | 현재 defect 확인 없음 |

G-04/G-09의 P0는 실제 로컬 synthetic use에서 P0 defect를 발견했다는 뜻이 아니다. 원격 조직 운영 또는 AI egress를 승인하기 전에 닫아야 하는 gate다.

## 16. P0/P1/P2 우선순위

### P0 — 노출/사용 승인 차단 gate

- 원격·multi-user 조직 운영은 인증, 권한, TLS/deployment hardening, audit, retention/recovery, OS-level resource containment가 별도 검증되기 전까지 **NO_GO**.
- External LLM helper 호출을 제품 흐름에 연결하거나 실데이터를 전송하는 것은 explicit data/privacy/security review 전까지 **NO_GO**.
- 확인된 공식 loopback 경로에서 새 개인정보 노출 defect를 발견했다는 판정은 없다.

### P1 — 실무 분석 신뢰성

1. **Phase 36.9B 로그 형식 compatibility profiles**: 먼저 지원 입력 형식과 parser acceptance/rejection을 명확히 한다.
2. **Phase 36.9C detector evaluation corpus**: benign/attack-like 합성 데이터를 늘리고 independent expected outcomes와 per-rule error analysis를 만든다.
3. Correlation/Risk sensitivity: time skew, missing/duplicate events, shared IP/user, partial source coverage를 평가한다.
4. Worker resource ceilings/cleanup: process/OS-level budget을 검증 가능한 실행 환경에서 평가한다.

### P2 — 범위 확장

- Vector/remote collector integration (isolation blocker 해소 후 별도 gate).
- durable case storage/search/multi-analyst workflow.
- 추가 source/parser profile, 모델 explanation 또는 embedding. 신뢰도와 개인정보 검증 후에만 고려한다.
- Safari/VoiceOver/실제 기기 수용 검증.

## 17. 후보 Phase 비교

| 후보 | 실무 가치 | 기존 동작 영향 | 위험 / 난이도 | 합성 재현성 | 선행/산출물 |
|---|---|---|---|---|---|
| A. 로그 형식 호환성 강화 | 분석 전 단계의 유효 로그 수용/명시적 거부 개선; 높음 | parser semantics에 영향 가능, 작은 adapter 범위 권장 | 중; format 추측은 오탐·시간 오해 유발 | 높음: 명명된 공식 형식별 fixtures | 공식 vendor/product docs → profile matrix → parser tests/coverage report |
| B. 탐지 정확도 평가 강화 | FP/FN 및 rule scope 이해; 높음 | 분석 코드 변경 없이 먼저 corpus/evaluator 중심 가능 | 중; 기대 label 편향 위험 | 높음: synthetic benign/adversarial boundary, 실데이터 없이 가능 | parser profile 범위 고정 권장 → per-rule evaluation report |
| C. 보안·운영 안정성 | 원격/hostile 운영 준비에 필수 | runtime/deployment 큰 영향 | 높음; 실행 격리 환경 필요 | 일부 높음, OS/VM 환경 의존 | threat model, disposable isolation, resource metrics |

**최우선 추천 Phase:** Phase 36.9B — Supported Log Format Compatibility Profiles. 입력이 parser에 도달하더라도 format mismatch/시간 의미 오류가 발생하면 뒤의 정확도 측정은 왜곡된다. 그러므로 먼저 명명된 입력 프로파일과 reject boundary를 고정한다. detector 성능 개선을 주장하는 단계는 아니다.

## 18. 최우선 다음 Phase — 구체 제안

### Phase 36.9B — Supported Log Format Compatibility Profiles

1. **목표:** 현재 세 parser의 실제 수용 문법을 명명하고, 공식 제품/형식 문서와 연결한 합성 fixture acceptance/rejection matrix를 만든다.
2. **구현 범위:** 우선 format inventory와 read-only baseline; 사용자 지정 범위 승인 후 작은 parser adapter/parser format profile만 구현. Format auto-detection은 하지 않는다. 탐지/correlation/risk 조건은 바꾸지 않는다.
3. **변경 예상 파일:** 조사 후 결정. 후보는 `app/parser/ssh_auth.py`, `app/parser/access_log.py`, `app/parser/auth_log.py`, parser registry/tests, 새 synthetic fixtures 및 별도 문서. API/schema는 필요성 입증과 별도 승인 전 변경하지 않는다.
4. **RED 계획:** 먼저 현재 parser에 대해 공식 문서 기반 형식 변형 fixtures를 추가해 기대 acceptance/rejection 차이를 드러낸다. 실패가 현재 코드 동작을 의미하는지 확정하고, 요구 profile이 승인되기 전 unsupported format을 억지로 accept하지 않는다.
5. **Acceptance Criteria:** 지원 각 형식의 timestamp/timezone/field grammar 문서화; 정상/경계/잘못된 fixture 결과 확정; rejection 이유/parse accounting 보존; existing fixture 결과 및 API/UI contracts unchanged; unit + full pytest; privacy canary 0; lint/diff/CI.
6. **보안/개인정보:** synthetic data only, no real logs, no external service; raw sample에 실제 IP/credential 금지; parser fields must remain observable and bounded; hostname/proxy/NAT 의미를 추론하지 않음.
7. **HOLD:** 공식 format semantics 불명, timestamp timezone 모호, 기존 security meaning 변경 필요, unsupported source에 대한 추측, 기존 fixture 결과 변화의 근거 부족.
8. **다음 Phase 연결:** profiles 고정 뒤 36.9C에서 rule-specific synthetic evaluation/FP/FN boundary를 넓힌다. 운영 resource/deployment readiness는 별도 36.9D 후보이며 실제 데이터/운영 gate와 결합하지 않는다.

이번 권고는 계획이다. **Phase 36.9B 구현은 이번 36.9A에서 시작하지 않는다.**

## 19. 현재 승인·미승인 범위

- 이 Phase의 제한된 판단: 문서 기반 maturity/readiness assessment와 합성 evaluator 실행.
- 실제 사용자 자료: `NO_GO`
- 조직 운영: `NO_GO`
- 자동 대응: `NO_GO`
- 모델 기반 AI: 운영 기능 `NOT_TESTED`; 기본 흐름에서 호출되지 않음을 코드 조사로 확인한 범위에 한정.
- Safari / VoiceOver / 실제 모바일: `NOT_TESTED`
- Vector/VM: `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`
- OS-level hard memory cap: 미보장
- 강제 종료 후 orphan cleanup / secure erase: 미보장
- 기존 renderer: `KEEP_LEGACY`

## 20. 최종 평가

### Q1. 현재 AI Security Log Analyzer는 어떤 수준의 제품인가?

근거에 맞는 표현은 **합성 검증용 로컬 조사 보조 도구**다. 일부 입력 경로와 collector pilot은 loopback/Linux에서 합성 검증됐고, Dashboard/조사 작업공간은 synthetic user acceptance가 있다. 결정적 분석 엔진과 report/checklist는 실제 코드다. 그러나 실무 형식 breadth, independent detection accuracy, organization auth/audit, durable operations, OS hard resource boundary, Safari/real-device coverage는 입증되지 않았다. 운영 서비스로 부르거나 실제 조직 데이터 사용을 승인하지 않는다.

### Q2. 실제 보안 분석 도구로 발전하기 위해 지금 가장 먼저 해야 할 작업은 무엇인가?

**Phase 36.9B — Supported Log Format Compatibility Profiles**를 먼저 진행한다. 공식 제품/형식 문서에 맞춘 명명된 synthetic fixtures로 parser가 무엇을 수용하고 거부하는지 고정하고, timezone·필드 누락·prefix 변형의 의미를 기록한다. 이는 실무 호환성의 기반이면서 이후 Detector 평가가 잘못된 parser 입력으로 왜곡되는 것을 막는다. 이 후에 36.9C에서 rule-specific synthetic evaluation을 확장하고, 실제 운영은 별도의 보안·배포 승인 전까지 금지한다.

### 최종 판정

`PHASE_36_9A_PROJECT_MATURITY_ASSESSMENT_LOCAL_CONDITIONAL_GO`

이 판정은 문서 평가와 지정된 로컬 검증 범위에 한정된다. 제품 운영 적합성 또는 사용자 자료 사용 승인이 아니다.
