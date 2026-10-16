# Phase 23.4 — OpenAPI/API property fuzzing 도입 gate

**판정: CONDITIONAL GO (설계만).** 이번 단계는 **no installation**, no Schemathesis execution, no dependency/lock/CI/API/production change다. Phase 23.5에서 검증된 wheel-only 공급망, local-only 실행, OpenAPI와 실제 runtime 간 차이, 개인정보 출력 및 CI 비용을 측정한 뒤 도입을 결정한다. Phase 23.3의 Semgrep은 `SUPPLY_CHAIN_BLOCKED`이며 설치·실행·CI 연결을 재시도하지 않는다.

## 시작 근거

2026-10-16 시작 시 `main` = `origin/main` = `c55e365324e0dc4851c0ff3a52cf922762d7cd1a`, working tree clean이었다. [동일 SHA의 Ubuntu CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38913461596)는 completed/success: locked Python 3.12 install, Linux checkpoint 검증, 전체 **2,264 passed, 기존 경고 2개, 새 경고 0개, 46.72초**. 기존 Hypothesis property suite는 전체 회귀에 포함되지만 독립 CI job이라고 주장하지 않는다. 변경 전 로컬 전체 회귀는 **2,264 passed, 동일한 기존 경고 2개, 84.73초**였다. 공개 v0.2.0 annotated tag와 Release의 target `2520e317475f96d48b4bfeef8f7ee04d63720308`은 불변이다.

## 공식 배포·공급망과 아직 입증하지 않은 사항

조사 시점의 [공식 GitHub release v4.31.1](https://github.com/schemathesis/schemathesis/releases/tag/v4.31.1)는 2026-10-14 게시됐고 annotated tag는 source commit `76b10a59d248eaf578df82841edb48c8e25a2e44`를 가리킨다. [PyPI `schemathesis` 4.31.1](https://pypi.org/project/schemathesis/4.31.1/)과 [해당 tag의 `pyproject.toml`](https://github.com/schemathesis/schemathesis/blob/v4.31.1/pyproject.toml)은 MIT, Python `>=3.11`(Python 3.12 포함), 기본 요구로 `anyio`, `click`, `harfile`, `hypothesis-graphql`, `hypothesis`, `jsonschema-rs`, `pyrate-limiter`, `pytest`, `PyYAML`, `requests`, `rich`, `typing-extensions`, `werkzeug`를 선언한다. 현재 프로젝트의 `hypothesis==6.170.0`은 선언된 `>=6.130.12,<7` 범위와 **metadata상 호환**한다. 실제 lock resolver의 전체 전이 dependency·버전 충돌은 검사하지 않았으므로 설치 가능하다는 증명은 아니다. CLI `st`/`schemathesis`와 pytest plugin은 **같은 기본 distribution의 entry point**이고 `tests`·`dev` optional extra는 pilot 실행에 자동 필요하다고 가정하지 않는다. MIT source-checkout 프로젝트에 개발용 MIT 도구를 쓴다는 사실만으로 배포 의무까지 법률 보증하지 않는다.

배포 후보는 플랫폼 공통 `py3-none-any` wheel `schemathesis-4.31.1-py3-none-any.whl` (1,122,419 bytes, PyPI SHA-256 `157529ed712cce00ead84a17e9e4a8f6a07e460c0b6e4901d037d9e313db99d1`)과 sdist `schemathesis-4.31.1.tar.gz` (3,374,438 bytes, `90359dff0a97edbc440b58eb874d8a1c7712d43e7ebdd35959592767728fa4e0`)이다. macOS arm64와 Ubuntu x86_64 모두 본체는 이 플랫폼 독립 wheel 후보이나 **직접 요구 `jsonschema-rs>=0.58.6,<0.59.0`는 Rust/native platform wheel**이다. [PyPI `jsonschema-rs` 0.58.6](https://pypi.org/project/jsonschema-rs/0.58.6/)에는 macOS arm64를 포함한 universal2 `cp310-abi3` wheel 및 Linux x86_64 manylinux `cp310-abi3` wheel이 보인다. 실제 resolver가 정확히 이 판을 고를지는 미확인이다. wheel 내부 executable/native 목록·설치 hook·sdist build action·서명/provenance·모든 전이 dependency/optional extra·platform별 hash 재계산은 **NOT_TESTED**. Python wheel 자체에는 npm식 lifecycle script 계약이 없지만 build backend의 sdist 실행과 전이 native code는 별도 위험이므로 Phase 23.5에서는 wheel-only, 고정 artifact/hash, build 금지로 검사한다. PyPI metadata의 hash는 게시 주장이지 독립 provenance가 아니다. 이 단계는 네트워크에서 metadata/source만 읽었으며 artifact를 설치·실행하지 않았다.

## local-only·telemetry·실패 산출물 경계

[공식 Python app guide](https://schemathesis.readthedocs.io/en/stable/guides/python-apps/)의 `schemathesis.openapi.from_asgi('/openapi.json', app)`는 서버 연결 대신 ASGI callable에 요청한다. Phase 23.5 기본 후보는 합성 fixture의 fresh app만 in-process로 호출하고 외부 URL·remote `$ref`·remote schema·Cloud/login·report upload를 사용하지 않는다. CLI는 별도의 외부 HTTP 대상과 report 옵션을 갖는 [공식 CLI reference](https://schemathesis.readthedocs.io/en/stable/reference/cli/)이므로 이번 최소 pilot에서는 사용하지 않는다. [v4 migration guide](https://schemathesis.readthedocs.io/en/stable/migration/)는 과거 Schemathesis.io 기능 종료를 설명하지만, 그것만으로 모든 현재 코드 경로가 네트워크 0건이라고 보증하지 않는다. pytest pilot에는 별도 egress-deny/spy 검증이 필요하다. Host·Origin·loopback 검사도 in-process client의 기본 주소를 승인된 loopback으로 명시하고, 원격 접근 거부는 별도 real loopback smoke로 확인한다.

[공식 reporting reference](https://schemathesis.readthedocs.io/en/stable/reference/configuration/)의 JUnit/VCR/HAR/JSON/NDJSON에는 요청·응답·헤더가 남을 수 있다. 실패의 재현 `curl`, pytest stdout/stderr, Hypothesis shrunk example에도 synthetic multipart payload·filename·path·canary가 실릴 수 있다. `--output-sanitize` 같은 출력 마스킹을 신뢰 경계로 삼지 않는다. 기본 **no report upload**, no cassette/HAR/VCR/JSON artifact, no GitHub artifact, no external SaaS; 합성 최소 반례만 로컬 실패 출력에 허용하고 CI 출력에 호스트 절대 경로가 없는지 검사한다. example DB 비활성화와 생성 산출물 미추적을 유지한다. 실제 로그·기본 monitor config·사용자 홈 자료는 사용하지 않는다.

## 현재 OpenAPI와 실제 runtime의 차이

`app.api.create_app().openapi()`와 route producer 및 관련 pytest를 직접 확인했다. 기본 앱의 OpenAPI는 5개 경로다. live 경로는 **서비스가 주입된 앱에서만** OpenAPI에 추가되며 비활성 앱의 실제 GET은 고정 404다. Linux Audit **보호 앱**은 별도 security config/authorization dependency의 `POST /api/analyze-linux-audit`를 추가하고 로컬 3파일·로컬 Linux Audit route를 추가하지 않는다. 아래 `OpenAPI` 열의 `기본/활성/보호`는 노출 variant를 뜻한다. `requestBody 없음`은 실제 body 금지가 아닌 **schema에서 생성할 정보가 없다는 뜻**이다.

| Endpoint | OpenAPI / request·response 계약 | 접근 경계와 pilot 적합성 |
| --- | --- | --- |
| GET /api/health | 기본·활성·보호, 입력 없음, 200 JSON(`status`)이나 명시적 response model 없음 | health만 직접 생성 가능. 인증 없음; 개인정보 가치 낮아 pilot 보조 |
| POST /api/analyze | 기본·활성·보호, **deprecated**, `application_file`·`ssh_file`·`access_file` 필수 `multipart/form-data`; 200 `AnalysisResponse`, 422 선언 | legacy는 local-only/Host/Origin guard가 로컬 업로드와 다름. 세 합성 파일 fixture 필요; `Deprecation: true` header와 safe nested projection 별도 검사. 최소 pilot에는 오류·privacy로 제한 |
| POST /api/v1/investigations/sample | 기본·활성·보호, OpenAPI requestBody·query 없음; 200 `InvestigationResponse`와 고정 오류 model | runtime은 **body/query/content-type을 거부**. schema-generated 정상 요청만으로 unknown 입력 거부를 증명할 수 없어 custom negative request 필요. rate/concurrency 격리, analyze/adapter 호출 횟수, deterministic safe output 검사 |
| POST /api/v1/investigations | 기본·활성, OpenAPI requestBody **없음**(Request로 수동 multipart 파싱), `LocalInvestigationResponse`와 오류 model | 실제는 3개 named file만 허용, loopback/Host/Origin/forwarded guard, byte·line·UTF-8·staging 상한. Schemathesis 자동 multipart 생성 불가; Phase 23.5 최소 pilot 제외, 이후 bounded fixture harness |
| POST /api/v1/investigations/linux-audit | 기본·활성, OpenAPI requestBody **없음**, `LinuxAuditInvestigationResponse`와 오류 model | 실제는 `audit_file` 하나, loopback/Host/Origin/forwarded guard, 별도 worker. multipart fixture·process cleanup 필요해 최소 pilot 제외. 보호 앱의 `/api/analyze-linux-audit`와 혼동 금지 |
| GET /api/v1/live/status | **활성에만** OpenAPI, 입력 없음, 200 `LiveStatusResponse` 및 고정 오류 model | 비활성 앱에서는 schema 미포함·실제 404. 활성 fresh synthetic service로 닫힌 schema와 status safe projection 검사. loopback/Host/Origin/forwarded, query 거부는 custom requests |
| GET /api/v1/live/events | **활성에만** OpenAPI, 200 `text/event-stream` 문자열 및 오류 model; `Last-Event-ID`는 OpenAPI header parameter로 선언되지 않음 | 일반 JSON fuzz 부적합. 별도 bounded stream harness에서 invalid/future/foreign/gap, query cursor 거부, connection slot, LF framing·single-line JSON 검사. 최소 pilot 제외 |

보호 앱은 인증/인가와 audit sink가 필요하고 fresh app을 함부로 생성하면 fixture 밖 side effect가 생긴다. 보호 route의 auth 헤더·권한 조건은 별도 security suite에 남긴다. OpenAPI에 표현되지 않은 Host·Origin·forwarded header 정책, local upload의 수동 request parsing, SSE 상태 의미를 Schemathesis가 자동 발견한다고 주장하지 않는다.

## 검사할 property와 실제 적용 방식

[공식 checks reference](https://schemathesis.readthedocs.io/en/stable/reference/checks/)의 `not_a_server_error`, `status_code_conformance`, `content_type_conformance`, `response_schema_conformance`, `negative_data_rejection`은 출발점이다. 다만 이 앱은 **의도된 고정 500 응답도 선언**하므로 모든 5xx를 곧바로 보안 버그로 처리하거나 허용하지 않는다. 예상하지 않은 5xx, traceback·원문 예외·절대 경로 노출, invalid 요청의 HTTP 200 빈 결과, content type/schema 위반은 실패다. 선언된 500은 고정 error_code/message/recovery의 안전성을 별도 검사한다. `positive_data_acceptance`의 기본 expected statuses에는 일부 5xx가 포함되므로 그대로 성공 판정하지 않는다. OpenAPI 미선언 runtime guard로 인한 400/403은 schema-conformance 실패와 제품 실패를 분리해 triage한다. schema가 틀리면 우회 allowlist로 숨기지 않고 후속 별도 API schema 변경 승인을 판단한다.

모든 요청은 합성 account/IP/path/query/filename/raw line canary만 사용하며 응답 JSON/headers와 표준 오류에서 canary·hash/부분문자열이 없는지 확인한다. `api/analyze`는 privacy-safe nested projection과 deprecated header, sample은 no-input·unknown body/query/multipart 거부와 동일 입력 결정성, live status는 비활성 404/활성 closed schema·raw session/event/history 비노출을 우선한다. Linux Audit은 executable·argv·account·audit ID 비노출과 별도 pipeline 격리, 로컬 3파일은 repeated/missing/unknown field·size/UTF-8/binary/archive/line 제한·staging cleanup을 **후속 focused harness**에서 검사한다. SSE는 `Last-Event-ID` 및 replay ordering/gap, streaming 종료·slot 정리를 기존 `tests/test_live_http.py`와 후속 별도 fuzz harness로 검사한다. 정상 200이라도 탐지·위험도·사례의 의미를 Schemathesis가 검증하는 것은 아니다.

생성 크기는 각 endpoint의 실제 입력 상한보다 작게 제한하고 archive bomb·무제한 body·실제 자원 고갈을 생성하지 않는다. request count/max_examples, deadline, per-request timeout, 전체 suite time budget은 Phase 23.5 측정 후 고정하며 seed 고정·무조건 retry·flaky allowlist를 쓰지 않는다. 시간/rate 상태는 fresh app/session과 적절한 module-scoped client로 격리한다. 79/79·21/21·70/70 합성 평가는 별도 유지한다. 기존 Hypothesis 6.170.0은 **내부** parser·lease queue·safe projection을, Schemathesis 후보는 **OpenAPI 생성 HTTP 요청/응답**을 담당한다. 내부 property를 중복 작성하지 않는다.

## CI 비용, 대안, Phase 23.5 gate

기준선은 동일 SHA의 macOS 전체 pytest 84.73초와 Ubuntu CI 전체 pytest 46.72초다. 도구 미설치로 추가 CI 비용은 **미측정**. 목표 후보는 기본 PR in-process bounded suite **+10초 이내**이지만 보장·SLA가 아니다. 최소 pilot에서 cold/warm 3회와 생성 case 수·5xx·schema finding·artifact bytes를 기록하고, multipart/SSE/real loopback은 별도 focused 단계로 분리한다. 전체 API route를 무제한 한 번에 fuzz하지 않는다.

| 대안 | 이 프로젝트에서의 가치/비용 |
| --- | --- |
| 기존 Hypothesis 직접 HTTP strategy | dependency 증가 없음, runtime guard까지 명시 가능; OpenAPI 변경에 따라 case 자동 확장·schema conformance를 수작업해야 함 |
| FastAPI TestClient parameterized boundary tests | 가장 낮은 공급망·CI 비용, 정확한 상태/cleanup 검증에 적합; 예상하지 못한 request 조합 탐색이 좁음 |
| Schemathesis in-process ASGI | OpenAPI에서 request 조합·response schema를 자동 대조; native transitive·report privacy·schema/runtime gap과 비용 검증 필요 |
| Dredd / RESTler / OWASP ZAP | 별도 runtime/네트워크/credential·report 경계와 setup 비용이 더 큼; 이 작은 local FastAPI pilot의 첫 선택 아님 |

**Phase 23.5 최소 추천:** sample exact no-input, 활성/비활성 live status, legacy /api/analyze의 bounded 오류·privacy projection. GO gate는 (1) wheel-only artifact와 전이 graph·license·native/install hook 확인, Hypothesis 6.170.0 locked resolver 통과, (2) local-only egress 0과 no report upload, (3) 기존 테스트가 놓치는 OpenAPI/HTTP 조합의 실질적 추가 가치, (4) false positive triage 및 CI 시간 허용, (5) 합성 반례 출력 privacy이다. 공급망·Linux wheel·실측 비용·실제 발견률은 남아 있어 현 단계는 **CONDITIONAL GO**이며 별도 승인 전 설치·dependency·CI 추가는 하지 않는다. 이 도구가 운영 탐지율, 무유실, 인증 경계, 개인정보 무노출을 증명한다는 주장은 금지한다.
