# Phase 36.8A — 로그 텍스트 직접 입력 설계

## 1. Phase 목적 및 범위

분석가가 터미널, SIEM 또는 로그 조회 도구에서 복사한 합성 또는 승인된 로컬 로그를 파일로 저장하지 않고 직접 붙여넣어 분석하는 기능의 구현 설계다. 기존 파일 업로드를 유지하며, 이 Phase에서는 API·Frontend·Parser·Detector를 구현하지 않았다.

핵심 설계 방향은 **기존 multipart 계약과 분리된 로컬 전용 텍스트 endpoint**, 요청 한 건당 한 source, 기존 경로 기반 Loader/Parser/Analyzer 재사용이다. 설계 후보 endpoint와 schema는 승인된 계약이 아니며 후속 구현 전 검토가 필요하다.

실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`, 모델 기반 AI는 `NOT_TESTED`다. Safari·VoiceOver·실제 모바일 기기는 이번 Phase에서 검증하지 않았다.

## 2. 시작 Gate 증거

시작 기준 SHA `294e9ad7ef839929b0d2c287fb9d8cd1bcec712b`, Run `40883508051`을 확인했다.

- branch `main`; 시작 시 working tree clean
- `HEAD`, 로컬 `main`, `origin/main`, GitHub remote `main` 모두 기준 SHA
- `origin/main...HEAD`: behind 0 / ahead 0
- Run: 기준 SHA, `push / completed / success`
- Artifact: 0개
- 잠금 Python 설치, 전체 pytest, Linux TCP Syslog smoke·reliability·management, JSONL acceptance, restricted report smoke, Node·Chromium·axe, tracked-file invariant: 모두 성공
- `v0.4.0` tag 및 Release target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`

이는 시작 시점 CI 증거이며 이 설계 문서의 새 커밋을 검증한 CI 결과가 아니다.

## 3. 현재 입력 구조 분석

`app/api.py`는 `POST /api/v1/investigations`를 `create_local_endpoint(...)`에 연결한다. 이 endpoint는 `app/local_investigation_api.py`의 `_FIELDS` 및 `_SOURCES`에 정해진 `application_file`, `ssh_file`, `access_file` 세 파일을 각각 정확히 하나 요구한다. 누락, 중복, 알 수 없는 필드는 거부된다. 이 multipart 계약을 텍스트 입력을 위해 바꾸지 않는다.

현행 업로드 경계는 loopback/Host/Origin/forwarding-header 검증, 스트리밍 multipart 본문 96 KiB, 파일당 32 KiB, 합계 80 KiB, 한 줄 2048 bytes, 파일당 512줄, strict UTF-8, 허용된 제어문자만 허용, 비공백 및 source 형식 사전 확인을 수행한다. 요청 제한은 동시 처리 1건, 분당 6회, 업로드 timeout 10초, worker 분석 timeout 10초다. 임시 디렉터리는 0700, 파일은 0600과 `O_NOFOLLOW`로 생성되고 정상 경로에서 `TemporaryDirectory`로 정리된다. 자식 프로세스 종료·timeout도 관리한다. 예외와 오류 응답은 고정 코드/문구로 입력을 반향하지 않는다.

텍스트 입력에 이 보호가 자동 승계되지는 않는다. 현재 `_LocalLimit`은 `create_local_endpoint()` 호출 때 endpoint별 인스턴스로 만들어진다. 별도 endpoint가 별도 limiter를 만들면 업로드 경로의 제한을 우회할 수 있으므로, 36.8B는 두 입력 경로가 공유하는 하나의 admission/limiter 인스턴스를 설계·검증해야 한다. 단순히 현재 factory를 두 번 호출하는 구현은 허용하지 않는다.

현재 `frontend/index.html`의 `#local-form`은 세 파일 input을 필수로 표시하고, `frontend/app.js`의 `requestLocalInvestigation`은 세 파일을 확인한 뒤 `FormData`로 기존 endpoint에 POST한다. 기존 파일 입력과 명시적 submit 흐름은 그대로 보존한다. `app/web_ui.py`는 정적 asset에 160 KiB 상한을 적용하므로 브라우저 UI 변경 Phase에서도 이 상한을 유지해야 한다.

## 4. 사용자 시나리오

1. 분석가가 외부 로그 도구에서 필요한 로그 일부를 직접 선택·복사한다.
2. `내 로그 분석`에서 `텍스트 직접 입력`을 명시적으로 선택한다.
3. 애플리케이션·SSH·웹 접근 중 하나의 종류를 선택하고 텍스트를 붙여넣는다.
4. 제한 및 부분 로그의 의미를 확인한 뒤 `로그 분석하기`를 누른다.
5. 동일 로컬 서버가 입력을 검증하고 기존 분석 pipeline을 실행한다.
6. 결과는 기존 Dashboard와 조사 작업공간에서 확인한다. 입력 source와 부분 범위 안내는 결과 화면 및 다운로드 보고서에서도 보존한다.

Clipboard API를 호출하거나 clipboard를 자동 읽지 않는다. 사용자는 브라우저의 기본 붙여넣기 동작으로 입력한다.

## 5. 파일 업로드와 텍스트 입력 비교

| 항목 | 파일 업로드 | 텍스트 직접 입력 | 설계 결정 |
|---|---|---|---|
| 기존 사용 | 세 역할 파일 필요 | 한 source만 선택 | 두 경로 분리 |
| 전송 | multipart, 세 `UploadFile` | bounded JSON body | 혼합 요청 불허 |
| 검증 | 현재 서버 스트리밍 검증 | 서버의 별도 JSON·문자열 검증 필요 | 검증 핵심은 공유 함수로 추출 검토 |
| 임시 자료 | 0700/0600 임시 파일 | 기존 parser 호환을 위해 같은 방식 후보 | request cleanup 유지 |
| 분석 | 세 source pipeline | source config 한 개 | 기존 analyzer 호출, source 합성 금지 |
| 유지보수 | 기존 API/schema 유지 | 새 endpoint·request/error/scope 모델 필요 | 기존 endpoint의 필수 조건 불변 |

브라우저 검증은 즉시 피드백일 뿐이며, 서버 검증을 보안 권한으로 둔다.

## 6. 단일 source 분석 가능성

### 코드 근거

`app/main.py`의 `analyze(log_sources)`는 설정 목록을 `load_normalized_logs()`에 넘긴다. `app/analyzer/pipeline.py`는 전달된 설정만 순회해 기존 `get_parser(source)`와 `load_log_lines(path)`를 호출한 뒤 `detect_attacks(logs)`, `correlate_attacks(logs, result)`, `assess_risk(result)`를 실행한다. 입력 목록을 세 개로 고정하거나 누락 source에 빈 파일을 채우는 코드는 이 pipeline 경로에 없다. Correlation은 파싱된 event sequence를 받고, 존재하지 않는 source의 이벤트는 존재하지 않는다.

읽기 전용 합성 검증에서 각 기존 sample을 단일 source로 `analyze_with_source_role_snapshot`에 전달하고 기존 case projection, report projection, HTML renderer를 실행했다.

| 단일 source sample | 분석·사례 projection | 보고서 생성 | 관측 |
|---|---|---|---|
| `application` | 사례 1, 독립 관찰 2 | 성공 | sample fixture 결과에 한정 |
| `ssh` | 사례 1, 독립 관찰 0 | 성공 | sample fixture 결과에 한정 |
| `access` | 사례 0, 독립 관찰 2 | 성공 | 사례가 없다고 안전을 뜻하지 않음 |

분석 함수, source-role snapshot, case projection, report projection 및 HTML rendering이 repository sample로 단일 source 실행을 완료했다. 이는 실제 운영 로그에 대한 호환성 보장이나 모든 형식 변형의 coverage 증거가 아니다.

### 의미와 남은 Gate

- 미입력 source는 **누락된 source**이지 빈 정상 로그가 아니다. 빈 파일 또는 임시 placeholder를 만들지 않는다.
- 단일 source에서는 교차 source correlation이 성립할 수 없으며, 결과가 없다는 사실은 안전 판정이 아니다.
- `_local_response()`는 현재 범위와 source 개수를 API에 표현하지 않는다. 현재 `LocalInvestigationResponse`는 closed model이고 `local_context` 문구는 고정되어 있다. 텍스트 결과가 기존 UI와 보고서에서 파일 업로드 결과와 혼동되지 않게 하려면, 36.8B 전에 새 응답의 closed `input_scope` metadata와 HTML report의 고정 범위 안내를 설계·검증해야 한다.
- 제안: 새 텍스트 응답 envelope에 `input_scope` (`mode`, 선택된 `source`, 고정 `notice_code`)와 기존 `LocalInvestigationResponse` 형태의 `result`를 둔다. UI는 envelope를 검증하고 `result`를 기존 dashboard validator에 전달한다. checklist registry는 기존 typed inner response와 trusted cases를 계속 사용한 뒤, attach 완료한 응답을 envelope로 감싼다. 새 endpoint/model/OpenAPI는 제안이며 아직 계약이 아니다.
- 보고서도 같은 분석 projection에서 생성하되 텍스트 입력 전용 HTML에 고정 범위 안내를 추가한다. 원문 로그를 보고서에 포함하지 않으며 기존 파일 업로드 report는 바꾸지 않는다.
- `AnalysisSourceRoleSnapshot.from_events()`는 event의 실제 source로 주체별 role 집합을 만들고 하나의 허용 role이 확인된 때만 bind한다. 실제 case/checklist 연결은 36.8B에서 단일 source의 각 합성 fixture를 통해 registry까지 통합 검증해야 한다. Access sample처럼 case가 없는 경우 checklist 사례를 만들어내지 않는다.

**결론:** 기존 pipeline은 단일 source를 받으며 repository의 세 합성 sample에서 분석·case adapter·report 경로가 작동했다. 다만 범위 metadata 및 checklist registry가 포함된 endpoint 통합 시험 전까지 `single-source end-to-end contract = UNVERIFIED`로 둔다. 이는 설계를 막지는 않지만 36.8B의 필수 진입 Gate다.

## 7. API 설계 대안 비교

| 대안 | 장점 | 위험·비용 | 판정 |
|---|---|---|---|
| A. 기존 `POST /api/v1/investigations` 확장 | 경로 하나 | 세 파일 필수 및 response contract를 변경해야 하고 파일/텍스트 혼합, 누락 source 의미가 모호해짐 | 비권장. 기존 계약 유지 |
| B. `POST /api/v1/investigations/text` 신규 텍스트 전용 endpoint | 입력 종류와 source 하나가 명확하고 기존 multipart 소비자와 격리 | 별도 closed request/error/scope response schema와 공통 limiter·worker boundary 필요 | **권장** |
| C. 브라우저에서 가상 File 생성 후 기존 endpoint | 새 전송 형식처럼 보이지 않음 | 기존 endpoint는 세 `UploadFile`을 요구하므로 빈 파일·가짜 source 생성 또는 의미 왜곡이 필요. client-only 검증은 신뢰할 수 없음 | 거부 |

별도 path는 기존 요청 body와 혼합되지 않도록 하며, 동일 `classify_local_request`, query 거부, 공유 rate/concurrency admission, timeout, response bound 및 분석 worker를 재사용해야 한다. 독립 limiter를 생성해도 우회가 없다는 보장은 현재 없으므로 반드시 공유하도록 한다.

## 8. 권장 Request/Response 계약

아래는 **제안**이며 현재 route나 승인된 API schema가 아니다.

### Request 후보

```json
{
  "schema_version": 1,
  "source": "ssh",
  "log_text": "합성 SSH 로그 문자열"
}
```

- `Content-Type: application/json; charset=utf-8` (정확한 허용 문법은 구현 테스트에서 고정)
- 최상위 정확한 closed key set: `schema_version`, `source`, `log_text`
- `schema_version`은 bool이 아닌 정수 1, `source`는 `application | ssh | access`, `log_text`는 strict UTF-8 문자열
- JSON 중복 key 거부, 알 수 없는 key/중첩 object/array 거부, NaN/Infinity 거부
- 요청 query string 거부. 입력은 URL, header, filename에 넣지 않음.
- 텍스트와 파일은 한 요청에서 혼합하지 않음. 한 요청당 source 하나.

RFC 8259는 객체 member name의 uniqueness를 SHOULD로 규정하고 중복 시 receiver 동작이 예측 불가능할 수 있음을 설명한다. 이 보안 계약은 구현 단계에서 중복 key를 거부해 parser 간 해석 차이를 없앤다 ([RFC 8259 §4](https://www.rfc-editor.org/rfc/rfc8259#section-4)).

### Response 후보

새로운 text response envelope는 `input_scope`와 기존 검증 가능한 local result를 분리한다. `input_scope.source`는 사용자가 선택한 입력 분류일 뿐 분석에서 검증된 source role이 아니다. 분석 case의 role은 기존 source-role snapshot과 trusted-case binding을 통과한 결과만 체크리스트에서 표시한다. `input_scope`에는 raw text, 식별자, 파일 경로를 포함하지 않는다. 실패는 고정 error code/message/recovery action만 가진 별도 closed model을 사용하며 raw line, parser exception, path, request body를 반향하지 않는다.

새 route와 response/error schema는 구현 Phase에서 OpenAPI와 frontend validator에 함께 반영할 제안이다. 실제 경로 등록 전에는 계약 승인과 버전/호환성 review가 필요하다.

## 9. Parser/Analyzer 재사용 경계

| 방법 | 장점 | 위험·비용 | 권고 |
|---|---|---|---|
| 메모리에서 parser에 text 직접 전달 | 디스크 기록을 없앰 | 현재 `load_normalized_logs()`는 `source` + `path` 설정과 `load_log_lines(path)`를 사용. 세 parser의 공개 입력 경계가 path/line generator에 묶여 있어 새 stream adapter 또는 loader refactor가 필요 | 현 Phase에는 비권장; 향후 별도 loader 설계 후 선택 가능 |
| 0700 temp dir 안 0600 파일로 stage | 현재 loader/parser/worker를 그대로 재사용, source 1개만 전달 가능 | 처리 중 디스크에 민감 입력 기록, crash/강제 종료 후 cleanup 보장 한계 | **초기 권고**: 현재 경계와 동일한 보호·정리, 최대 10초 worker, 예외·취소 정리 테스트 필요 |

브라우저에서 로컬 HTTP 서버로 텍스트가 전송되며 브라우저 메모리에서만 처리되는 기능이 아니다. Stage는 strict UTF-8과 모든 byte/line/control/source 검증이 끝난 뒤에만 수행한다. Worker에는 원문 문자열을 전달하기보다 현재처럼 안전한 임시 경로 설정만 넘긴다. 종료 시 `TemporaryDirectory`를 닫고, 강제 프로세스/OS 종료 후 임시 잔존 가능성과 secure erase를 보장하지 않는 점은 사용자에게 알린다. 임시 경로·원문을 worker exception, log, IPC error로 반환하지 않는다.

## 10. 텍스트 입력 보안 정책

### 검증 순서

1. shared loopback request 검사: client loopback, forwarded header 거부, Host/Origin 일치, `sec-fetch-site: cross-site` 거부. Proxy header로 loopback 권한을 만들지 않는다.
2. query 거부, 정확한 JSON media type 및 strict UTF-8 JSON decode.
3. body를 chunk 단위로 최대 크기까지만 읽는다. `Content-Length`는 조기 거절 힌트일 뿐 실제 스트림 누적 제한도 적용한다.
4. duplicate/unknown key, 잘못된 schema/source/type/중첩 값 거부.
5. `log_text` UTF-8 byte 길이, 빈/공백 입력, 줄 수/줄 길이, NUL/control, line ending 및 source 형식 확인.
6. 검증 완료 후 임시 stage와 기존 분석 worker 실행.

요청 크기, string 크기, 작업 시간, 메모리·process·요청 횟수는 모두 제한해야 한다. 이는 무제한 자원 소비를 피하기 위해 payload, operation frequency, timeout 및 process/resource ceiling을 모두 제한하라는 OWASP API4 권고와 일치한다 ([OWASP API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)).

### 입력별 처리안

| 입력 | 정책 후보 |
|---|---|
| 빈 문자열/공백 | 거부; 빈 파일/source로 대체하지 않음 |
| 크기 | `log_text` UTF-8 최대 32 KiB; wire JSON body 최대 96 KiB |
| 줄 | 기존 업로드 기준을 우선 적용: 줄당 2048 bytes, 최대 512 lines; 구현에서 끝 개행 경계 테스트 |
| UTF-8 | 엄격한 decode/encode; invalid bytes, JSON escaped lone surrogate 거부 |
| 제어 문자 | 기존 `_stage_file`과 일치해 TAB/LF/CRLF만 허용; NUL, 기타 C0, DEL 및 CR 단독 거부 |
| source | allowlist 3개 외 거부; 잘못된 source/형식은 고정 오류 |
| 포맷 | 기존 `_compatible` 검사를 재사용 가능한 공통 검증 함수로 추출 검토; parser가 최종 해석, validator 복제 금지 |
| Unicode | 입력을 정규화하거나 confusable을 임의 치환하지 않음; 본문은 text node로만 표시; 시각적 혼동은 고지·검수하고 로그 의미를 조작하지 않음 |
| JSON 구조 | flat exact keys; 중복 key, 알 수 없는 key, 잘못된 타입/깊이 거부 |

상한 제안은 기존 파일 1개 상한과 같은 32 KiB, 기존 한 줄/줄 수 제한을 출발점으로 한다. 이는 기준선 재사용 제안이지 측정된 안전 최대치가 아니다. wire JSON 96 KiB는 multipart envelope의 상한을 빌린 보수적 제안이며 UTF-8 raw `log_text` 상한과 별도로 적용한다. 서버는 문자 수가 아니라 UTF-8 byte 수를 계산한다.

### 자원·격리

- 요청 rate/concurrency는 기존 업로드와 하나의 limiter를 공유: 현재 합성 로컬 설정 6회/60초, 동시 1건.
- 업로드/body receive timeout 10초, 분석 worker timeout 10초를 상향하지 않는다.
- 중복 submit 방지: UI pending 잠금 + server limiter. UI 잠금만 신뢰하지 않는다.
- worker는 기존 spawned process와 종료/kill 경계를 사용. 취소·timeout에서 temporary dir 정리를 확인한다.
- response는 현재 로컬 response 128 KiB 이하를 유지. 새 scope metadata와 고정 안내 포함 후 직렬화 결과도 제한.
- 외부 요청·LLM 호출 0, cross-origin 거부, loopback 외 접근 거부.

OWASP는 적절한 request body limits와 rate limit을 권고한다. 후보 수치는 이 프로젝트의 기존 synthetic local policy를 재사용하는 것이며 OWASP가 권고한 특정 수치가 아니다.

## 11. Privacy boundary

- 로그 본문을 `print`, application logger, audit event, traceback, exception, metrics label에 기록하지 않는다.
- URL query, route, history state, localStorage, sessionStorage, IndexedDB, cookie에 저장하지 않는다.
- Clipboard 자동 접근, autosubmit, 자동 분석, 외부 LLM/API, 외부 네트워크 전송 없음.
- validation 오류는 고정 code, 안전한 field id 및 안내만 반환; 입력 일부, line, account, IP, hostname, path, filename, credential, parser exception 금지.
- 결과와 HTML report는 기존 protected subject alias, case/timeline closed projection을 유지. raw log를 DOM/ARIA/data attribute 또는 HTML report에 넣지 않는다.
- raw log는 local HTTP request로 127.0.0.1 서버에 전달되고 worker 처리 중 temp file에 저장될 수 있다. 정상 종료 정리와 비정상 종료 잔존 가능성을 분명히 설명; secure erase를 주장하지 않는다.
- Browser text DOM은 사용자가 입력한 원문을 화면에 보이는 동안 메모리에 보유한다. 사용자가 화면을 떠나거나 모드를 바꿀 때/요청이 끝난 뒤 입력 지우기 정책을 정하고 명시적 지우기 동작을 제공한다. 성공 후에는 지우고 결과 범위 metadata만 유지한다. 오류 후 보존 여부는 사용자에게 보여주고 선택하게 하되, 기본 최소 보존은 오류 후에도 clear 후 재붙여넣기이다. JavaScript/OS 메모리의 물리적 secure erase는 보장할 수 없다.
- 비동기 응답은 분석 generation/snapshot identity와 현재 입력 mode를 대조해 이전 분석이 새 결과를 덮지 못하게 한다.

## 12. UI/UX 설계

`내 로그 분석`에서 두 mode를 `파일 업로드` / `텍스트 직접 입력`으로 선택한다. 기본 선택은 기존 파일 업로드로 두어 기존 사용 경로를 보존한다. 선택된 mode만 required validation과 submit payload에 포함한다. File upload mode는 기존 form/API byte-for-byte contract 유지.

Text mode에는 label이 연결된 `select` (세 source), label과 helper/error 연결된 multi-line `textarea`, 제한, local-only privacy notice, partial-scope notice, `지우기`, 명시 `로그 분석하기` 버튼을 둔다. Clipboard API 자동 read 금지. `aria-live=polite` 상태, 오류 시 field `aria-invalid`와 연계된 고정 도움말, visible focus, keyboard-only activation 유지.

모드 전환 동작 제안: 아직 전송되지 않은 다른 mode 입력이 있으면 폐기 확인을 받고, 승인 시 비활성 mode data를 clear한다. File input은 브라우저 보안 모델상 자동 복원하지 않는다. Text textarea는 사용자가 모드를 변경하지 않는 동안 validation error를 고치고 다시 제출할 수 있게 유지할 수 있으나, 명시적 취소/모드 전환/새 분석 성공/화면 떠남에서 clear한다. Pending 중 mode control과 submit을 disable한다. 이전 성공 결과를 요청 직전부터 보여주지 않고, generation을 교체해 이전 async 응답과 새 결과의 혼합을 막는다.

문구는 기존 36.6A–G dashboard/개요/Timeline 용어와 일치한다. 기존 조사 작업공간의 dashboard/navigation, checklist 의미, risk·review priority 구분을 변경하지 않는다. 320 CSS px, 200% equivalent reflow, 최소 44×44px target/8px 간격을 구현 gate로 한다. 새 UI는 `app/web_ui.py` 정적 JS 160 KiB 상한을 늘리지 않고 기존 vanilla JS 구조 안에서 검증한다.

## 13. 부분 로그 분석 안내

기본 고정 문구 후보:

> 입력한 로그 범위에서만 분석한 결과입니다. 다른 로그나 누락된 시간대에 발생한 활동은 포함되지 않을 수 있습니다.

결과 및 다운로드 보고서에 추가로 다음 의미를 유지한다.

- 다른 source를 제공하지 않았을 수 있고, 분석 범위는 선택된 단일 source와 제공된 줄에 한정된다.
- 다른 시점의 이벤트는 포함되지 않을 수 있다.
- 이 범위에서 탐지가 없거나 관계가 발견되지 않았다고 안전 또는 공격 경로 부재를 뜻하지 않는다.
- 탐지된 패턴은 침해 성공의 증거가 아니다.
- 성공 로그인은 침해 증명이 아니며, 로그 부재는 공격 실패 증명이 아니다.

문구는 limitation code나 risk를 새로 만들지 않는다. 사용자에게 input scope를 정확히 알리는 고정 metadata/notice다.

## 14. 오류 응답 및 복구 방법

새 closed error model은 후보로 `error_code`, 고정 `user_message`, 고정 `recovery_action`, boolean `retryable`, 제한된 `field`만 둔다. 기존 upload error model의 file-only `field` literal을 그대로 쓰지 말고 text model에서 `source | log_text | null` 중 하나로 제한하거나 field 자체를 생략한다.

| 오류 범주 | 제안 상태 | 복구 안내 |
|---|---|---|
| 잘못된 media type/JSON/schema/source | 400/415 | 입력 방식을 확인하고 지정된 source와 형식 사용 |
| 빈/공백/UTF-8/제어문자/형식 불일치 | 400 | 원문을 노출하지 않고 source·UTF-8 형식 확인 |
| body/text/line/line-count 초과 | 413 | 더 작은 범위의 로그를 명시적으로 다시 붙여넣기 |
| loopback/Origin 거절 | 403 | 직접 실행한 loopback UI 사용; proxy 우회 금지 |
| rate/concurrency 제한 | 429 | 현재 처리 종료 후 잠시 대기 |
| upload/analysis timeout | 503 | 입력은 정리하고 더 작은 범위로 수동 재시도 |
| parser/case/report/response 오류 | 4xx 또는 5xx 고정 mapping | 안전한 일반 안내만; traceback 및 원문 미노출 |

새 코드는 기존 API 오류 code 목록에 억지로 넣지 말고 새 endpoint의 closed error schema와 OpenAPI로 명시한다. 정확한 HTTP/code mapping은 구현 전 승인해야 한다.

## 15. 테스트 계획

모든 fixture는 `sample_logs/` 또는 테스트가 만든 synthetic text만 사용한다.

| 영역 | 계획된 검증 |
|---|---|
| 기존 호환성 | 세 파일 업로드 성공/error contract unchanged, 기존 endpoint OpenAPI, UI 기존 mode regression |
| 정상 입력 | application/SSH/access 각 synthetic line; 여러 줄; 마지막 LF 유무; single-source analysis; case/report; 같은 raw logs를 파일과 텍스트로 전달한 결과 의미 비교 |
| 제한 입력 | empty/whitespace, text 32 KiB 초과, JSON body 96 KiB 초과, 2048-byte line 초과, 512 lines 초과, malformed/wrong source, invalid format, control/NUL/DEL/CR-only, invalid UTF-8, escaped lone surrogate |
| JSON 경계 | 알 수 없는/누락/중복 field, duplicate JSON key, 중첩/배열/잘못된 타입/schema, 잘못된 Content-Type, JSON NaN/Infinity, body chunk로 나뉜 oversized stream |
| 네트워크 경계 | non-loopback, IPv4-mapped IPv6, forwarded headers, invalid Host/Origin, cross-site fetch metadata, query string, remote client |
| resource control | upload+text가 공유하는 rate/concurrency quota, body read timeout, analysis timeout, cancellation, repeated submit, worker terminate/cleanup, bounded response |
| 격리/개인정보 | concurrent request text mixing zero; canary in response/HTML/logger/error/repr zero; report raw input absent; temp mode 0700/0600, no-follow, cleanup after success/reject/timeout/cancel; crash orphan caveat |
| 파이프라인 의미 | supplied source only; absent source not represented by empty file; cross-source relation unavailable is explicit; missing detection/relation not safety; deterministic pipeline reused once; risk/case not recomputed by UI |
| source role/checklist | selected input kind distinct from validated source-role; role snapshot binds same analysis/projection; unmatched/mixed role `unknown`; case refs opaque; checklist explicit POST only and exact source/case binding |
| result/report scope | input_scope accurate; single-source and provided-range notice in dashboard/detail/report; existing file report unchanged; no raw text |
| Frontend | mode switching/clear policy, one source, manual paste, explicit submit only, pending double-submit block, safe failure, stale request generation guard, existing file mode retained |
| accessibility | keyboard/visible focus/label/error/live region, 44×44/8px, axe 0, 390/320, 200% equivalent, no overflow/external requests |

RED in later implementation should first cover endpoint and validation tests before production changes; API/schema mismatch or inability to bind scope safely is a hold, not a reason to weaken tests.

## 16. 기존 기능과의 호환성

- `POST /api/v1/investigations`의 세 파일 필수 multipart/API/OpenAPI/response 계약은 그대로 둔다.
- 기존 `requestLocalInvestigation` file path, 세 source validation, report 및 checklist behavior를 보존한다.
- 새 text API는 기존 `analyze_with_source_role_snapshot`, `project_investigation_cases_from_analysis`, `build_investigation_report_projection`, `render_investigation_report_html`를 재사용한다. 탐지·관계·risk 로직은 복제하지 않는다.
- 새 response scope는 checklist registry의 existing typed response에 붙인 뒤 envelope 처리하는 adapter boundary가 가능하다. 이 결합은 제안으로, 통합 테스트 전 `UNVERIFIED`.
- API는 로컬 보호 app에서만 등록하고 Linux Audit protected app에 공개 경로, temp path 또는 원문을 추가로 노출하지 않는다.
- 기존 HTML report는 파일 업로드 경로에서 유지. Text report만 범위 notice를 반영하는 구현이 필요하다.
- 36.6G `KEEP_LEGACY`와 기존 renderer rollback switch 유지. 텍스트 분석은 입력 경로이고 renderer 제거 근거가 아니다.

## 17. 남은 위험 및 불확실성

- **UNVERIFIED:** unit-level one-source success는 세 repository sample에서 보였지만 API → shared limiter → worker → `ChecklistRegistry.attach` → text envelope → report scope end-to-end는 미검증.
- **UNVERIFIED:** text response envelope와 HTML report에 scope metadata를 추가하는 model/validator shape, OpenAPI compatibility, asset budget 영향.
- **UNVERIFIED:** 현재 `assess_risk()`가 로컬 metadata를 읽는 방식과 단일 source에서 의미가 세 source와 동일한지; 수치/의미를 변경하지 않고 정확히 고지할 수 있는지 36.8B에서 검증.
- **UNVERIFIED:** access synthetic sample은 case가 0개이므로 사용자 단일 access-source에서 checklist 사례 UI가 없을 수 있음. 이를 성공 사례로 과장하지 말고 독립 관찰만 표시.
- 일부 parser는 source format validation이 shallow `_compatible()`을 통과한 뒤 실제 parser에서 event를 만들지 않을 수 있다. 성공한 빈 결과와 잘못된 형식의 구분, scope notice를 함께 검증해야 한다.
- 임시 파일은 정상 종료 cleanup이 가능하지만 강제 OS 종료 뒤 잔존과 secure deletion은 보장되지 않는다.
- 본문 96 KiB 및 텍스트 32 KiB는 기존 제한에서 보수적으로 가져온 candidate이지 완전한 threat measurement가 아니다. body streaming, UTF-8 expansion, deployed ASGI server behavior를 확인해야 한다.
- 단일-source 데이터로 계산한 risk/case는 입력범위의 결정적 기존 결과일 뿐 전체 조직 상태를 대변하지 않는다.

## 18. 후속 구현 Phase 계획

### Phase 36.8B — Backend Text Input Boundary

새 text-only endpoint, strict bounded JSON parser, shared local limiter/admission, shared validation helper, temp-file staging, worker 재사용, closed text response/error + input-scope metadata, text-specific scoped report, OpenAPI 및 합성 API/security tests. Single-source checklist binding, access case-zero, cleanup/error lifecycle를 구현 gate로 둔다.

### Phase 36.8C — Frontend Text Paste Input

파일/텍스트 선택, 단일 source 선택, textarea, limits/privacy notice, explicit submit, validation/error/live status, input mode clear lifecycle, generation guard, existing dashboard and current workspace consumption. 160 KiB asset ceiling 유지.

### Phase 36.8D — Security & End-to-End Validation

전체 regression, file-vs-text semantic equivalence, privacy canary, admission-bypass tests, malformed/oversized body, process cleanup, report scope, browser/axe, 320/390/200% reflow, Linux worker resource acceptance.

### Phase 36.8E — User Acceptance

격리된 합성 fixture로 실제 local production UI에서 한 source씩 붙여넣기, 기존 파일 upload regression, 부분 로그 의미 이해도와 실패 복구 흐름을 수용 검수. 사용자 응답과 자동 검증을 별도로 기록.

Phase split은 제안이며 36.8B의 실제 code boundary 조사에 따라 조정 가능하다.

## 19. 최종 설계 판정

`PHASE_36_8A_TEXT_PASTE_INPUT_DESIGN_LOCAL_CONDITIONAL_GO`

근거: 현 pipeline은 source config 목록을 받아 repository의 세 합성 source sample 각각을 단독 처리하고 case/report 경로까지 실행했다. 신규 text-only local endpoint와 shared admission boundary가 기존 multipart contract를 건드리지 않고 설계 가능하다. 구현은 아직 하지 않았다.

Conditional gate: Phase 36.8B 전 API scope response/report model 및 shared limiter boundary를 확정하고, 세 source별 worker→case/checklist registry end-to-end, API/OpenAPI, malformed input, cleanup, asset/UI 계획을 검증해야 한다. 통과 전 실제 데이터 이용이나 운영 판단에 적용하지 않는다.

## 20. 설계 근거 및 상태

프로젝트 사실은 시작 SHA의 소스와 합성 sample로 확인했다. 보안 자원 경계는 현재 업로드 상한과 로컬 endpoint의 정책을 기준으로 삼았다. 외부 근거는 무제한 자원 소비 예방(요청 크기, 동시성/빈도, timeout 및 자원 상한)과 JSON duplicate member 해석의 불일치 문제를 확인하는 보조 자료이며, 이 프로젝트의 구체적 상한은 기존 synthetic policy 기반 제안이다.

- [OWASP API Security Top 10 2023 — API4 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [RFC 8259 — The JavaScript Object Notation (JSON) Data Interchange Format, §4](https://www.rfc-editor.org/rfc/rfc8259#section-4)
- [Starlette Requests — request stream and form-data limits](https://www.starlette.dev/requests/)
- Repository source: `app/api.py`, `app/local_investigation_api.py`, `app/local_request_security.py`, `app/main.py`, `app/analyzer/pipeline.py`, `app/analyzer/incident_case_adapter.py`, `app/investigation_role_snapshot_36_4.py`, `app/investigation_checklist_api_36_3.py`, `app/models/investigation_sample_api.py`, `frontend/index.html`, `frontend/app.js`, `app/web_ui.py`.

Research Basis: OWASP API4는 요청 payload 크기, rate, timeout, memory/process 자원에 server-side limit을 요구한다. RFC 8259 §4는 중복 object member name의 receiver 동작이 예측 불가능할 수 있다고 설명한다. Starlette 문서는 request stream 및 multipart parser의 limit 경계가 서로 다름을 설명하므로 JSON endpoint도 직접 bounded streaming을 적용해야 한다.

Observable Evidence Mapping: source 선택은 `load_normalized_logs()` 설정과 각 parser에 들어가고, 파싱된 events만 `detect_attacks`/`correlate_attacks`/`assess_risk`로 전달된다. 제한된 경로 기반 adapter는 현재 loader와 worker가 소비하는 계약이다. 한 source 부재로 cross-source event가 생기지 않으며, 빈 탐지 결과는 안전 판정이 아니다.

Limitations: repository sample 세 개의 단일 source 실행은 형식 전체 coverage, 운영 로그의 성공, UI/API 통합, source role/checklist binding 또는 성능 보증이 아니다. `single-source end-to-end contract`와 report scope는 `UNVERIFIED`이며 Phase 36.8B 진입 조건이다.
