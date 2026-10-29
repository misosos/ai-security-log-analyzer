# Phase 36.8B — 제한된 로컬 로그 텍스트 분석 API

## 범위와 판정

이 Phase는 브라우저 UI가 아닌 로컬 backend 입력 경계만 구현한다. `POST /api/v1/investigations/text`는 한 요청에 `application`, `ssh`, `access` 중 한 종류의 UTF-8 로그를 받는다. 기존 세 파일 multipart endpoint, 분석 규칙, 조사 작업공간 및 사용자 수용 기록은 유지한다.

최종 로컬 판정: `PHASE_36_8B_TEXT_INPUT_BACKEND_LOCAL_CONDITIONAL_GO` (필수 로컬 검증 후 확정). 이는 새 커밋의 Ubuntu CI 성공이나 실제 사용자 자료·조직 운영 승인을 뜻하지 않는다. 실제 자료·조직 운영·자동 대응은 `NO_GO`, 모델 기반 AI와 Safari·VoiceOver·실제 모바일 검증은 `NOT_TESTED`다.

## 시작 Gate

기준 SHA `a943e11a58e474ee0464117ae49b70c8a402570a`, Actions Run `40890502320`을 시작 전에 다시 확인했다. branch `main`, 시작 tree clean, local/remote/GitHub SHA 일치, ahead/behind `0/0`; exact SHA의 `push / completed / success`, artifact 0개였다. Linux pytest, TCP Syslog, JSONL, restricted report, Chromium·axe 및 tracked-file invariant 성공이었다. `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`을 가리켰다. 이는 시작 SHA의 CI 증거다.

## 확정된 API 계약

### Request

`POST /api/v1/investigations/text`

```json
{"schema_version":1,"source":"ssh","log_text":"합성 SSH 로그 문자열"}
```

- `Content-Type`은 `application/json` 또는 UTF-8 charset을 명시한 JSON만 허용한다. content encoding은 identity만 허용한다.
- 최상위 필드는 정확히 `schema_version`, `source`, `log_text`; 알 수 있는 추가 필드, 누락, 중복 JSON key, 중첩 구조, 잘못된 타입, NaN/Infinity, 잘못된 UTF-8 및 lone surrogate는 거부한다.
- schema version은 boolean이 아닌 정수 `1`; source는 `application | ssh | access`; text는 strict UTF-8 문자열이다.
- query string은 거부하며 파일과 텍스트를 한 요청에 혼합하지 않는다.

### 제한과 검증 순서

| 경계 | 상한/정책 |
|---|---:|
| JSON wire body | 96 KiB; Content-Length 사전 검사와 실제 `Request.stream()` 누적 검사 |
| 로그 text UTF-8 | 32 KiB |
| 한 줄 | 2,048 bytes |
| 줄 수 | 512 |
| 본문 수신 timeout | 10초 |
| 분석 worker timeout | 기존 10초 |
| 동시 분석 | 같은 FastAPI app에서 파일·텍스트 합계 1건 |
| 요청 횟수 | 같은 app limiter에서 60초당 6회 |

상위 ASGI server가 개별 chunk를 전달하기 전에 할당하는 메모리까지 handler가 제한한다고 주장하지 않는다. 빈/공백, NUL 및 허용하지 않는 C0/C1 control, DEL, 단독 CR, 과도한 크기/줄, 선택 source와 맞지 않는 형식은 분석 전에 거부한다. LF, CRLF, 마지막 LF 유무는 허용한다. source 형식의 사전 확인은 기존 `_compatible` 기준을 재사용하며 Parser의 최종 검증을 대체하지 않는다.

### 성공 Response

새 closed envelope는 기존 local 결과를 감싸고 입력 범위를 표시한다.

```json
{
  "schema_version":"1",
  "input_scope":{"mode":"text","source":"ssh","notice_code":"PARTIAL_SINGLE_SOURCE"},
  "result":{"schema_version":"2"}
}
```

`result`는 기존 `LocalInvestigationResponse` 그대로다. `input_scope.source`는 사용자가 선택한 분류이지 검증된 source role이 아니다. Checklist role은 동일 분석에서 얻은 trusted source-role snapshot과 기존 case binding을 통해서만 표시한다. 응답은 128 KiB 이내로 제한한다.

### 오류 Response

모든 텍스트 오류는 정확히 `error_code`, `user_message`, `recovery_action`, `retryable`, `field`를 가진 closed model이다. `field`는 `source`, `log_text`, `null` 중 하나다. 고정 코드는 media type, JSON/schema, source, empty/text/format/size/line, local-only/query, body/analysis timeout, concurrency/rate, analysis/case/report/response failure를 구분한다. 사용자 입력 일부, 파일 경로, 내부 예외는 오류에 포함하지 않는다. 상세 HTTP status와 문구는 `app/local_investigation_api.py`의 `_TEXT_ERRORS`가 기준이다.

OpenAPI는 request streaming을 위해 Python 인자에서 자동 생성되지 않는 request body를 닫힌 schema로 명시하고, 성공/오류 response model도 공개한다. 별도 schema/API 버전 변경은 하지 않는다.

## 기존 입력 및 분석 경로

기존 `POST /api/v1/investigations`는 multipart-only이고 `application_file`, `ssh_file`, `access_file` 세 파일을 각각 요구한다. 필드 이름, 오류 model, 응답 shape, HTML report 및 세 source 입력 의미는 바꾸지 않았다. 기존 file endpoint와 신규 text endpoint는 `create_app()`에서 생성한 같은 `_LocalLimit` admission 인스턴스를 공유한다. 이는 해당 app 인스턴스 안의 보호이며 여러 app/process 전체 quota를 보장하지 않는다.

요청 검증 후에만 요청별 private temporary directory(0700)에 고정 내부 파일명 `input-1.log`로 기록한다. 파일은 `O_EXCL | O_NOFOLLOW`, mode 0600이며 사용자 filename을 받지 않는다. worker에는 선택 source 하나만 전달하고 기존 spawn worker, Loader/Parser, Detector, Correlation, Risk, case projection, report projection을 재사용한다. 완료·분석 오류·timeout·취소 시 `TemporaryDirectory` cleanup 및 worker 종료 경로가 적용된다. 입력 크기 32 KiB, 동시 worker 1개, 10초 worker timeout으로 작업량을 제한한다. 기존 spawn worker에는 OS 수준의 별도 hard memory limit이 없으므로 프로세스 메모리 상한을 보장한다고 주장하지 않는다. 운영 배포 전 hard memory budget이 필요하면 플랫폼별 worker 자원 제한을 별도 검토해야 한다. 강제 OS 종료 뒤 orphan cleanup이나 secure erase는 보장하지 않는다.

단일 source를 기존 파이프라인에 직접 전달하고, 없는 source용 빈 파일은 생성하지 않는다. 합성 fixture 기준 결과:

| Source | 사례 | 독립 관찰 | Checklist 연결 |
|---|---:|---:|---|
| Application | 1 | 2 | 실제 생성된 case에만 ref 부착 |
| SSH | 1 | 0 | trusted snapshot으로 SSH role 연결 |
| Access | 0 | 2 | 사례/ref를 만들지 않음 |

Access의 사례 0은 안전 판정이나 입력 실패가 아니다. source 간 관계가 없다는 사실도 공격 부재를 뜻하지 않는다. Checklist는 response에 실재하는 projected case만 registry에 등록하며 별도 명시적 Checklist POST 전에는 생성되지 않는다. Checklist 요청 전후 analysis response 불변을 테스트했다.

## HTML 보고서 범위

텍스트 전용 report renderer에서만 다음 고정 안내를 추가한다.

> 입력한 로그 범위에서만 분석한 결과입니다. 다른 로그나 누락된 시간대에 발생한 활동은 포함되지 않을 수 있습니다.

같은 분석 report projection에서 보고서를 만들며 분석을 다시 실행하지 않는다. 파일 업로드 renderer의 기본 인자는 기존 동작을 유지한다. 텍스트 안내는 상수 HTML text이며 원문을 삽입하지 않는다. 기존 escaping·alias projection·보고서 크기 검증을 유지하며 합성 privacy canary와 파일 report 비교 테스트를 추가했다.

## TDD와 검증

Production 수정 전 새 endpoint 호출 테스트는 404로 실패했다(초기 RED: 36개 실패 사례에서 route 부재 확인). 구현 후 신규 focused suite는 48개 통과했다. 이 과정에서 OpenAPI streaming request body 누락을 focused test로 확인해 닫힌 request schema를 명시했다.

신규 테스트 범위:

- Application/SSH/Access 단일 source, LF/CRLF/final-LF, response scope, report notice 및 기존 file report 불변
- 명시적 Checklist POST와 실제 case ref, Access의 사례 미생성
- closed request, duplicate key, invalid UTF-8/lone surrogate, control/CR-only, empty, source mismatch
- wire 및 text/line/count 상한과 실제 chunk 누적 제한
- loopback/Host/Origin/forwarding/cross-site/query 보안
- privacy canary, Linux Audit app route 비노출, OpenAPI contract
- 파일/텍스트 혼합 rate window와 동시 admission 공유
- staging 0700/0600, 고정명, worker 실패 후 삭제

시작 CI는 새 코드를 검증한 것으로 간주하지 않는다.

- 신규 text API focused: 52 passed; Local API·Checklist·Report 포함 focused 합계 160 passed
- 전체 pytest: 3,157 passed, warning 2개
- `uv sync --locked --dev` 및 `uv lock --check`: 성공
- Python compile/import 및 `git diff --check`: 성공
- `npm ci --ignore-scripts --no-audit --no-fund`: 성공 후 `npm run test:a11y --silent`: 성공, 24 states, axe violation 0, 외부 요청 0
- TCP Syslog·JSONL·restricted report 로컬 회귀: 146 passed; Linux 전용 acceptance는 macOS에서 `NOT_TESTED`, 새 SHA Ubuntu CI 필요
- Dependency/lockfile 변경: 없음

## 개인정보·운영 경계 및 제외

Loopback-only, literal host/origin 검증, forwarded header 거부, query 거부, body/worker timeout, shared per-app request limiter, 고정 오류, spawn worker와 제한된 staging을 사용한다. 로그 text는 URL, 응답, HTML, logger 또는 exception에 반향하지 않는다. 외부 네트워크 및 LLM 호출, 브라우저 저장, Frontend 입력 UI는 이 Phase에 없다. 이 API는 로컬 HTTP 서버로 텍스트를 전송하는 backend 기능이지 브라우저 메모리 내부 처리 기능이 아니다.

후속 Phase 36.8C는 파일/텍스트 입력 선택, source 선택, 제한 안내, textarea, 명시적 submit, pending 중복 방지, 안전한 오류·성공 처리, 기존 Dashboard 연결과 접근성 검증을 구현해야 한다. 이후 36.8D에서 전체 privacy/equivalence/security 회귀, 36.8E에서 합성 데이터 사용자 검수를 별도로 수행한다.
