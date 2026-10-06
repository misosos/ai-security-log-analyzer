# Linux Audit API Boundary Design

## 1. 목적과 상태

이 문서는 Linux Audit 파일을 API로 받아 기존 pure parser, aggregate, collector와 immutable summary를 재사용할 때의 V1 입력·응답·privacy 경계를 정의한다. 현재 구현을 설명하는 부분과 후속 구현 제안을 구분한다. Phase 3Y-B에서 무인증 `/api/upload-test`는 public app과 OpenAPI schema에서 제거되었다. Phase 3Y-C의 bounded staging, Phase 3Y-D의 route-independent analysis orchestration, Phase 3Y-E의 strict response/error projection과 Phase 3Y-F의 default-disabled endpoint integration이 구현됐다.

V1 권고는 기본 비활성화된 전용 `POST /api/analyze-linux-audit`이다. 기존 `POST /api/analyze`, `AnalysisResponse`, `analyze(log_sources=None)`, CLI 및 Frontend contract는 변경하지 않는다. 인증과 resource control이 준비되지 않은 deployment에서는 endpoint를 활성화하지 않는다.

## 2. 현재 API 조사 결과

`app/api.py`의 `create_app(*, enable_linux_audit_api: bool = False)`가 `FastAPI` app을 만들고 module-level `app = create_app()`이 기존 `app.api:app` import를 보존한다. Exact bool만 허용하며 environment string, truthy value, mutable global toggle 또는 숨은 alias는 없다. 기본 app의 route는 다음 두 개다.

| Method | Route | 실제 동작 |
|---|---|---|
| GET | `/api/health` | `{"status": "ok"}` 반환 |
| POST | `/api/analyze` | application/SSH/access 파일을 각각 요구하고 `analyze(log_sources)` 결과를 `AnalysisResponse`로 projection |

Development/test가 명시적으로 `create_app(enable_linux_audit_api=True)`를 호출할 때만 repeatable multipart field `linux_audit_files`를 받는 `POST /api/analyze-linux-audit`가 한 번 등록된다. 기본 app에서 POST와 GET은 `404`이고 path와 Linux Audit schema는 OpenAPI에 없다. Enabled app에는 기존 health/analyze route도 각각 한 번 유지된다. 이 programmatic feature gate는 endpoint registration control일 뿐 authentication 또는 authorization이 아니다.

과거 `/api/upload-test`는 단일 upload를 임시 파일에 쓴 뒤 client filename, 신뢰할 수 없는 content type 및 실제 temporary path를 응답했다. Consumer가 없어 Phase 3Y-B에서 handler를 완전히 제거했으며 POST와 GET은 `404`이고 OpenAPI `paths`에도 존재하지 않는다. 개발용 upload 진단은 public HTTP endpoint가 아니라 `TestClient`와 private test helper로 수행한다.

`save_upload_to_temp()`는 `/api/analyze`가 계속 공유한다. 이 helper는 client filename의 suffix가 `.log` 또는 `.txt`인지 확인하고 `UploadFile.file.read()`로 전체 content를 메모리에 읽는다. Empty file과 10 MiB 초과 파일을 HTTP `400`으로 거부한 뒤 `NamedTemporaryFile(delete=False)`에 기록한다. `/api/analyze`는 생성된 path만 list에 넣고 `finally`에서 성공·분석 실패 시 삭제한다. 저장 도중 실패한 파일, process 종료 또는 강제 취소까지 cleanup을 보장하는 별도 abstraction은 없다.

`/api/analyze`의 multipart field는 `application_file`, `ssh_file`, `access_file`이며 Linux Audit field는 없다. `AnalysisResponse`는 `analysis_id`, `status`, IP summary, IP result list, arbitrary `global_correlation` dict와 nullable `ai_summary`를 포함한다. Builder는 detection evidence를 명시적으로 복사하지만 `correlation`, `risk_factors`, `global_correlation`은 dict로 전달한다. 현재 endpoint는 LLM 함수를 호출하지 않고 `ai_summary=None`을 반환한다.

Custom exception handler, 인증·인가, rate limit, request-wide size limit 또는 duplicate upload 판정은 없다. FastAPI의 기본 validation error 형식을 사용한다. `frontend/` 파일은 비어 있어 endpoint나 response에 대한 실행 가능한 Frontend 의존은 현재 없다. API tests는 response builder contract와 제거된 route, health/analyze 및 upload cleanup을 `TestClient`로 검증한다.

### 발견한 위험과 결함

1. Phase 3Y-B에서 `/api/upload-test`를 제거해 client filename, spoofable content type 및 실제 temporary path를 반환하던 public 공격 표면을 닫았다. Alias, feature flag 또는 대체 public test route는 두지 않는다.
2. `UploadFile` 자체는 spooled file이지만 현재 helper가 전체를 다시 `read()`하므로 파일 content가 메모리에 복제된다. Loader도 grouped event와 normalized logs를 메모리에 유지한다.
3. `/api/analyze`는 client filename extension만 검사하고 content type은 사용하지 않는다. 둘 다 신뢰 가능한 content 판별 신호가 아니다.
4. `global_correlation`은 고정 response model이 아닌 arbitrary dict다. 현재 builder test에서도 `source_instance`, `node`, Audit session ID, event ID와 timestamp가 그대로 보존된다. Linux Audit 결과를 기존 `AnalysisResponse`에 넣으면 신규 count-only privacy 정책과 충돌한다.
5. Enabled Linux Audit endpoint는 예상하지 못한 `Exception`을 fixed `INTERNAL_SERVER_ERROR`로 제한하지만 인증·request rate/concurrency 제한은 없다. 이 outer HTTP 경계는 `BaseException`이나 task cancellation을 성공 또는 error response로 바꾸지 않는다.

Phase 3Y-F는 Linux Audit endpoint의 bounded HTTP error 경계까지만 구현했다. 인증과 resource control은 deployment enablement의 선행 gate로 남는다.

## 3. API 형태 비교와 결정

| 후보 | 호환성 | Privacy·오류 경계 | 복수 입력·인증 | 복잡도와 migration |
|---|---|---|---|---|
| A. 기존 `/api/analyze`에 optional field | 기존 client가 field를 생략하면 호출은 유지되지만 response 확장이 필요 | 기존 arbitrary `global_correlation`과 Linux Audit count가 혼합되고 세부 scope 노출 위험 | 세 종류 필수 파일과 repeatable Audit 파일의 의미가 혼재 | 단기 파일 수는 적지만 기존 schema/client 회귀 범위가 큼 |
| B. 전용 `/api/analyze-linux-audit` | 기존 route와 `AnalysisResponse` 불변 | 별도 strict model, bounded error, feature gate를 독립 적용 | repeatable file, auth/rate policy를 endpoint 단위 적용 가능 | 작은 route/helper/model이 필요하지만 되돌리기 쉽고 privacy가 명확 |
| C. `/api/v1/analyze` 통합 | 명시적 version migration 가능 | 장기적으로 일관된 schema 가능 | 다양한 source를 확장하기 좋음 | 현재 client·schema를 새 버전으로 동시에 설계해야 해 V1 범위를 초과 |

V1은 후보 B를 선택한다. Linux Audit만으로 기존 IP analysis를 반환할 실익보다 `global_correlation` 상세 scope의 accidental exposure 위험이 크고, 기존 `/api/analyze`와 Frontend contract를 깨지 않으면서 endpoint-specific auth, size, cleanup과 fixed response를 테스트할 수 있기 때문이다. 후보 C는 source-neutral API 요구가 구체화될 때 별도 migration으로 검토한다.

## 4. Request contract

- Method/path: `POST /api/analyze-linux-audit`
- Encoding: `multipart/form-data`
- Repeatable field: `linux_audit_files`
- V1 file count: 최소 1, 최대 4
- V1 file content size: 각 최대 10 MiB
- V1 application-level content 합계: 최대 20 MiB
- Content: uncompressed strict UTF-8 Linux Audit text
- Archive, gzip, remote URL 및 directory upload: 지원하지 않음

4 files, 10 MiB/file, 20 MiB/request는 공식 Linux Audit 표준값이 아니라 현재 loader가 grouped events와 normalized logs를 메모리에 보관하는 점과 기존 API의 10 MiB file limit을 고려한 V1 운영 방어값이다. Named constants 또는 typed settings로 두어 운영 측정 후 변경하며 boundary test를 제공한다. Application 합계는 multipart envelope 전체 크기를 뜻하지 않으므로 reverse proxy/ASGI server에도 별도 full request limit, timeout, concurrency 및 rate limit이 필요하다.

`UploadFile.filename`, extension과 `content_type`은 신뢰하지 않고 response, source identity, temp path 또는 log metadata에 복사하지 않는다. V1은 filename extension allowlist를 security boundary로 사용하지 않는다. Known archive/compression input과 strict UTF-8 decode failure를 거부하고, parser가 해석할 수 있는 Audit structure를 실제 content contract로 사용한다.

`app/api_uploads.py`의 staging helper는 64 KiB fixed-size chunk로 읽어 per-file 및 aggregate byte count를 초과하는 즉시 중단한다. 전체 content나 decode된 전체 문자열을 메모리에 조립하지 않고 generated request-local file에 기록하면서 SHA-256, byte count와 incremental strict UTF-8 상태만 유지한다. Empty와 whitespace-only input은 `EMPTY_LINUX_AUDIT_FILE`로 거부하고 NUL-containing input은 plain-text contract에 맞지 않아 `UNSUPPORTED_LINUX_AUDIT_INPUT`으로 거부한다. Non-empty all-malformed input은 staging을 통과하며 `NO_ELIGIBLE_LINUX_AUDIT_EVENTS` 판정은 후속 loader/parser orchestration 책임이다. 개별 malformed line은 기존 loader/parser처럼 skip하고 유효 group은 계속 처리한다.

각 accepted input에는 순서대로 `api-linux-audit-1`, `api-linux-audit-2` 같은 invocation-local `source_instance`를 부여한다. 이는 host/node/cross-request identity가 아니며 response에 표시하지 않는다. Input order는 source isolation을 위한 결정론만 제공하고 arrival order 또는 causation이 아니다.

Chunk copy 중 SHA-256과 byte count를 계산해 동일 request 안에서 같은 content digest와 size를 가진 input은 duplicate로 거부한다. Digest는 request-local set에만 존재하며 staged result, log 또는 response에 반환하지 않는다. Silent deduplication과 request 간 cache는 사용하지 않는다. ZIP, gzip, bzip2, xz의 일반적인 leading signature와 tar의 `ustar` marker를 bounded prefix로 거부하지만 완전한 file-type 또는 polyglot 탐지를 주장하지 않는다.

## 5. Temporary file과 cleanup lifecycle

현재 loader가 filesystem path를 요구하므로 implemented staging helper는 request별 `TemporaryDirectory`를 사용한다. `input-1.audit`처럼 server가 생성한 basename만 사용하고 client filename, extension과 content type을 validation이나 path에 사용하지 않는다. File permission은 process 전용 `0600`으로 제한한다.

```text
request accepted
→ request-scoped temporary directory
→ bounded chunk copy + digest + strict input checks
→ load_normalized_logs(sources) 정확히 1회
→ analysis products와 explicit projection 생성
→ response model validation
→ finally/context exit에서 모든 file과 directory cleanup
```

Helper가 소유한 directory cleanup은 정상 context 종료, staging validation failure, caller body의 parser/collector/summary 모의 failure와 request cancellation 경로에서 `finally`로 실행한다. Cleanup 오류를 성공으로 삼키지 않으며 path 없는 고정 내부 오류로 바꾼다. Process kill, host crash 및 storage failure까지 in-process `finally`가 절대 보장하지는 않으므로 startup stale-artifact cleanup과 OS-level temporary storage policy가 운영 보완책이다.

Uploaded path는 server가 즉시 안전하게 생성하므로 CLI의 user path symlink/TOCTOU contract와 동일하지 않다. 그럼에도 file creation과 later loader open 사이의 filesystem 상태 변화 가능성을 완전히 제거한다고 주장하지 않는다.

## 6. Internal orchestration

CLI `main()`을 호출하거나 stdout을 parsing하지 않는다. 구현된 route-independent orchestration은 다음 pure producer와 하나의 normalized logs list를 재사용한다.

```text
bounded upload reader
→ request-scoped temp sources
→ load_normalized_logs(sources)  # 정확히 1회
→ 같은 normalized logs list object
→ aggregate_process_execution_observations(logs)
→ collect_shared_memory_execution_observations(logs)
→ summarize_shared_memory_execution_observations(shared_observations)
→ collect_session_process_co_observations(logs)
→ summarize_session_process_co_observations(relations, shared_observations)
→ immutable scalar-only LinuxAuditApiAnalysis
→ 후속 explicit Pydantic response builder
→ cleanup
```

`app/analyzer/linux_audit_api.py`는 staged input을 explicit Linux Audit source config로 투영하고 `load_normalized_logs()`를 정확히 한 번 호출한다. 모든 aggregate/collector에는 같은 normalized logs list object를 전달하고, shared-memory observation tuple도 overall summary와 session-process summary에 동일 객체로 재사용한다. 기존 producer가 반환한 mutable aggregate와 immutable summary의 exact type, key, integer 및 cross-count invariant를 검증한 뒤 16개 non-negative integer만 `LinuxAuditApiAnalysis`에 명시적으로 복사한다. Event, context, observation, relation, path 또는 scope identity는 결과에 보관하지 않는다.

Loader/parser 결과가 비어 있으면 이 orchestration이 `NO_ELIGIBLE_LINUX_AUDIT_EVENTS`(future HTTP 422)를 소유한다. Valid lifecycle-only event나 process observation이 없는 valid event set은 eligible input이며 fixed zero process shape를 반환할 수 있다. Producer shape 또는 count invariant가 깨지면 `LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR`(future HTTP 500)로 제한하고 내부 exception text를 복사하지 않는다. 개별 malformed line이 있어도 하나 이상의 normalized event가 있으면 기존 loader/parser 정책대로 처리한다. Process observation 부재는 execution 또는 attack 부재를 뜻하지 않는다.

V1 public response에는 IP results와 existing `global_correlation`을 포함하지 않으므로 `_analyze_normalized_logs()`를 호출하지 않는다. Enabled endpoint는 staging context가 열린 동안 synchronous orchestration을 Starlette `run_in_threadpool()`에서 정확히 한 번 실행해 async event loop의 filesystem parsing block을 피한다. Orchestration 성공 후에만 content/path/identity와 무관한 UUID4를 만들고 strict builder를 한 번 호출한다. CLI와 API는 loader/parser 및 pure aggregate/collector/summary를 공유하되 orchestration과 presentation builder는 분리하며 LLM, risk 또는 Frontend를 호출하지 않는다.

`stage_linux_audit_uploads()`의 async context는 orchestration과 projection이 끝날 때까지 유지되고 success, known validation, orchestration/projection failure, unexpected exception 및 cancellation exit에서 owned temporary directory를 정리한다. Request multipart `UploadFile` spool은 endpoint가 전역 보관하거나 조기 close하지 않으며 FastAPI/Starlette request lifecycle이 response 후 닫는다. Route는 spool path를 읽거나 응답하지 않는다.

필요한 최소 helper는 bounded upload copy/validation, request-scoped temporary lifecycle, Linux Audit summary orchestration, explicit response projection이다. Generic source registry, CLI reuse layer, serializer framework 또는 evidence DTO는 만들지 않는다.

## 7. Response allowlist

`app/models/linux_audit_api.py`에는 기존 `AnalysisResponse`와 분리된 Pydantic v2 response/error model 및 projection builder가 구현되어 있다. 모든 model은 frozen, `extra="forbid"`, strict이며 count는 bool, string, float coercion 없이 exact non-negative integer만 허용한다. Zero도 omission하지 않고 같은 fixed shape에서 `0`으로 반환하며, zero는 activity 또는 attack 부재를 의미하지 않는다.

```json
{
  "analysis_id": "12345678-1234-5678-9abc-def012345678",
  "status": "completed",
  "process_telemetry": {
    "observation_count": 0,
    "outcome_counts": {"success": 0, "failure": 0, "unknown": 0},
    "argv_completeness_counts": {"complete": 0, "incomplete": 0},
    "path_completeness_counts": {"complete": 0, "incomplete": 0}
  },
  "shared_memory_review": {
    "observation_count": 0
  },
  "session_process_review": {
    "session_co_observation_count": 0,
    "process_observation_count": 0,
    "outcome_counts": {"success": 0, "failure": 0, "unknown": 0},
    "shared_memory_observation_count": 0,
    "sessions_with_shared_memory_observation_count": 0
  }
}
```

`analysis_id`는 builder caller가 actual `UUID`로 명시하며 builder가 생성하거나 현재 시간·randomness를 읽지 않는다. Status는 `Literal["completed"]`다. Builder는 `LinuxAuditApiAnalysis` exact type만 받고 위 scalar와 fixed nested keys를 하나씩 직접 복사한다. Process outcome/argv/path 합, overall shared-memory 상한, session outcome 합과 overall/session/linked cross-count invariant를 독립적으로 재검증한다. Invalid bool·음수·불변식은 clamp나 zero 치환 없이 `LINUX_AUDIT_RESPONSE_PROJECTION_ERROR`로 제한한다.

`asdict()`, `vars()`, `__dict__`, arbitrary dict passthrough, generic `model_validate()`, generic dataclass/Pydantic serialization 또는 recursive serialization로 internal object를 투영하지 않는다. Pydantic validation detail의 location, input value와 내부 message도 public error body로 복사하지 않는다. `model_dump(mode="json")`과 `model_dump_json()`은 canonical UUID를 포함한 동일 fixed shape를 안정적으로 직렬화한다. 이 model을 `app/api.py`가 import하지 않으므로 현재 OpenAPI, `/api/health`와 `/api/analyze` schema는 변하지 않는다.

기본 응답에는 `NormalizedEvent`, process/session/shared-memory object, detection evidence, argv, PROCTITLE, raw records, executable, PATH/CWD, PID/PPID, UID/GID/AUID/session ID, source_instance, node, event ID, timestamp, uploaded filename/path, temporary path, exception text, `results` 또는 `global_correlation`을 포함하지 않는다.

Count는 observation occurrence의 bounded aggregate이며 unique process, 동일 인간, malware, attack, incident, compromise 또는 causation을 뜻하지 않는다. 전체 shared-memory count와 session-linked count는 다를 수 있고 후자만 전자를 넘지 않아야 한다.

## 8. Privacy, LLM과 Frontend 경계

Linux Audit API route는 Gemini 또는 다른 LLM provider를 호출하지 않는다. Raw evidence뿐 아니라 process/session aggregate count도 별도 privacy·provider 승인 전에는 `build_llm_input()`, `generate_security_summary()` 또는 `generate_overall_summary()`에 전달하지 않는다. Prompt restriction은 data selection boundary를 대신하지 못한다.

API response builder와 LLM input selection은 별도 allowlist다. Detailed evidence endpoint는 만들지 않는다. Existing deterministic canary를 raw/context에 둔 fixture로 response JSON, bounded error, protected log capture와 LLM mock 호출 여부를 검사한다. Provider network call은 test에서 수행하지 않는다.

Frontend files는 현재 비어 있고 신규 endpoint를 소비하지 않는다. V1 API 추가가 Frontend 자동 rendering을 승인하지 않으며 별도 UI privacy review 전에는 연결하지 않는다.

## 9. Error contract

Error response는 고정 shape `{"error": {"code": "...", "message": "..."}}`만 사용한다. Filename, basename, raw content, temp path, exception text, object repr와 traceback은 넣지 않는다.

| 범주 | HTTP | code | bounded message |
|---|---:|---|---|
| multipart field 누락 | 422 | `MISSING_LINUX_AUDIT_FILES` | `At least one Linux Audit file is required.` |
| 파일 개수 초과 | 413 | `LINUX_AUDIT_FILE_COUNT_EXCEEDED` | `Linux Audit file count limit exceeded.` |
| 파일별 크기 초과 | 413 | `LINUX_AUDIT_FILE_TOO_LARGE` | `A Linux Audit file exceeds the size limit.` |
| content 합계 초과 | 413 | `LINUX_AUDIT_REQUEST_TOO_LARGE` | `Linux Audit upload size limit exceeded.` |
| empty/whitespace-only file | 400 | `EMPTY_LINUX_AUDIT_FILE` | `A Linux Audit file is empty or contains only whitespace.` |
| strict UTF-8 decode 실패 | 400 | `INVALID_LINUX_AUDIT_ENCODING` | `Linux Audit input must be valid UTF-8.` |
| archive/compression 등 unsupported | 415 | `UNSUPPORTED_LINUX_AUDIT_INPUT` | `Linux Audit input format is not supported.` |
| duplicate content | 409 | `DUPLICATE_LINUX_AUDIT_FILE` | `Duplicate Linux Audit input is not allowed.` |
| all-malformed/no normalized event | 422 | `NO_ELIGIBLE_LINUX_AUDIT_EVENTS` | `No eligible Linux Audit events were found.` |
| collector/summary/response contract 실패 | 500 | `LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR` | `Linux Audit analysis could not be completed.` |
| response projection contract 실패 | 500 | `LINUX_AUDIT_RESPONSE_PROJECTION_ERROR` | `Linux Audit response could not be created.` |
| 예상하지 못한 server failure | 500 | `INTERNAL_SERVER_ERROR` | `The request could not be completed.` |

구현된 error projection은 `LinuxAuditUploadValidationError`, `LinuxAuditAnalysisValidationError`, `LinuxAuditResponseProjectionError` 및 fixed `LinuxAuditUnexpectedServerError`의 exact type과 고정 code/status/message 조합만 허용한다. 변조된 known error는 user-controlled text를 복사하지 않고 fixed projection error로 축소하며, enabled route의 outer `except Exception`은 unknown error text를 복사하지 않고 fixed unexpected-server error를 투영한다. HTTP status는 frozen internal carrier에 두며 JSON body에는 포함하지 않는다.

Expected input/contract 오류를 `200` empty result나 safe zero로 바꾸지 않는다. Endpoint-specific handler는 optional multipart container를 empty tuple staging contract로 넘겨 missing-field error를 안정화하고 나머지 기존 route error contract는 바꾸지 않는다.

Server log allowlist는 request correlation ID, route, status, stable error code, file input index, accepted file count와 bounded byte count, exception class category다. Client filename/path, content, hashes, Audit identity와 exception string은 기록하지 않는다. Expected errors에는 traceback을 남기지 않는다. Unexpected programmer error의 traceback은 승인된 protected sink와 access audit/retention이 준비된 경우에만 서버 내부에 보관하며 response에는 절대 포함하지 않는다.

## 10. 인증·인가와 운영 경계

현재 API에는 authentication, authorization, CSRF policy, rate limit 또는 access audit가 없다. 따라서 module-level default app은 endpoint를 등록하지 않고 test/development code에서만 `create_app(enable_linux_audit_api=True)`로 명시적으로 enable한다. 이 feature gate는 인증이 아니며 production enablement를 승인하지 않는다. Production enablement gate는 적어도 authenticated operator identity, endpoint authorization, request rate/concurrency limit, TLS termination, upload access audit, temporary storage monitoring과 retention/deletion policy다.

Count-only response도 resource consumption과 조직 활동량을 노출할 수 있으므로 무인증 public exposure를 승인하지 않는다. Detailed forensic evidence는 count-only 권한과 별개이며 RBAC, purpose limitation, access audit, export control, retention 및 deletion이 선행되기 전에는 endpoint 자체를 만들지 않는다. Raw upload는 response 후 보존하지 않는 것이 V1 기본 정책이다.

`/api/upload-test`의 filename/content type/temp path 응답은 Phase 3Y-B에서 public app으로부터 제거되었다. 이 제거는 신규 endpoint의 feature gate, 인증·인가 또는 resource control을 대신하지 않는다.

## 11. 구현 테스트 계획

FastAPI `TestClient`와 monkeypatch를 우선 사용하고 실제 network server나 LLM provider를 호출하지 않는다.

1. `/api/health`, `/api/analyze`와 `AnalysisResponse` 회귀, 제거된 `/api/upload-test`의 `404`와 OpenAPI 부재 확인
2. Feature disabled 기본 상태와 explicit test enable
3. 단일/repeatable `linux_audit_files`, 최대 count 및 input ordering
4. Deterministic invocation-local source_instance와 request 간/concurrent request 격리
5. Existing session fixture 및 session-linked fixture count acceptance
6. Empty, whitespace-only, all-malformed, partial malformed, invalid UTF-8, archive input
7. Exactly-at/one-byte-over per-file and aggregate size, count boundary와 oversized early stop
8. Exact/aliased filename과 무관한 content duplicate 판정
9. Success, validation, loader/parser, collector/summary, response validation 및 cancellation cleanup
10. Fixed response key set, exact scalar type, invariants와 deterministic repeated request
11. Filename/path/temp path, raw/argv/executable/scope/event identity 및 canary 비노출
12. Stable error status/code/message, no underlying exception/traceback, protected log allowlist
13. LLM functions/provider가 호출되지 않음
14. `analyze()` 기존 signature/keys, CLI 출력, existing IP detection/correlation/risk 불변
15. Input event/context/observation/relation mutation 없음
16. Multiple and concurrent request temp/source state isolation
17. Frontend files와 public contract 불변
18. Full regression

## 12. Rollout 단계와 non-goals

1. 완료: `/api/upload-test`를 public app에서 제거
2. 완료: bounded upload/temp lifecycle 및 internal validation error model을 route와 격리해 구현·테스트
3. 완료: route-independent Linux Audit summary orchestration과 immutable scalar-only internal result 구현
4. 완료: Strict Pydantic response/error projection, invariant validation 및 known-error mapping
5. 완료: Default-disabled endpoint integration, threadpool boundary와 success/failure cleanup acceptance
6. 완료: Endpoint canary, LLM/API/CLI isolation 및 concurrent request acceptance
7. 운영 resource 측정 후 count/size/concurrency limit 조정
8. 별도 승인 후에만 Frontend 또는 LLM consumer 검토

V1 non-goals는 archive/gzip/URL/directory ingestion, raw log retention, detailed evidence download, asynchronous job queue, real-time ingestion, cross-request deduplication, risk/ATT&CK verdict, Gemini summary, 기존 `/api/analyze` migration과 Frontend integration이다.

## 13. 공식 근거

접근일: 2026-10-06

- FastAPI, *Request Files*, `UploadFile`, multiple uploads, multipart sections.
  https://fastapi.tiangolo.com/tutorial/request-files/
  `UploadFile`가 spooled file과 file-like/async interface를 제공하고 multiple file field를 지원한다는 구현 선택에 반영했다. Application-specific size, duplicate, auth 또는 privacy 정책은 보장하지 않는다.
- Starlette, *Requests — Request Files*.
  https://www.starlette.io/requests/#request-files
  Multipart form/file parsing과 parser-level limits를 구현 전에 installed version에 맞춰 검증할 근거다. Loader memory, business count limit 또는 cleanup lifecycle을 대신 보장하지 않는다.
- Python Software Foundation, *tempfile — Generate temporary files and directories*, `NamedTemporaryFile`, `TemporaryDirectory`.
  https://docs.python.org/3/library/tempfile.html
  Secure generated names와 context-managed cleanup 선택에 반영했다. Host crash, forced termination 또는 application의 `delete=False` cleanup을 절대 보장하지 않는다.
- OWASP, *File Upload Cheat Sheet*, File Upload Protection, Filename Safety, User Permissions, Upload and Download Limits.
  https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
  Filename/content type 불신, generated filename, authorization, storage 분리와 size limit에 반영했다. 특정 4/10/20 limit이나 Audit content의 진위를 보장하지 않는다.
- OWASP API Security Project, *API4:2023 Unrestricted Resource Consumption*, “How To Prevent”.
  https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/
  Upload size, operation count, rate/resource limit 필요성에 반영했다. 이 repository에 적합한 수치나 parser 안전성을 정하지 않는다.
- OWASP, *Logging Cheat Sheet*, Data to exclude, Protection, Disposal.
  https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
  Session ID, path, secrets, raw data의 response/server-log 최소화와 access/retention 경계에 반영했다. Linux Audit field semantics나 correlation causation을 보장하지 않는다.
- NIST, *SP 800-92: Guide to Computer Security Log Management*, September 2006.
  https://csrc.nist.gov/pubs/sp/800/92/final
  Log management infrastructure, protection, retention과 operational process 분리에 반영했다. Step-by-step FastAPI implementation이나 endpoint schema를 제공하지 않는다.
- Red Hat, *RHEL 8 Security hardening — Auditing the system*.
  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening
  Linux Audit record/event와 security telemetry 역할의 근거다. Uploaded log의 trust, 완전성, 동일 인간 또는 공격 인과관계를 보장하지 않는다.
- Linux Audit Project, *Linux Audit field dictionary*.
  https://raw.githubusercontent.com/linux-audit/audit-documentation/main/specs/fields/field-dictionary.csv
  `auid`, `ses`, UID/PID와 outcome field 의미의 근거다. ID의 global/cross-run uniqueness를 보장하지 않는다.

## 14. 알려진 한계와 다음 구현 우선순위

이 설계는 인증 system, rate limiter, proxy limit, crash-safe cleanup, malware scanning, storage encryption 또는 access audit을 구현하지 않는다. Upload content는 untrusted이고 parsing success가 completeness/authenticity를 보장하지 않는다. Fixed count도 unique process, 동일 인간, attack, incident 또는 compromise를 뜻하지 않는다.

다음 구현 우선순위는 (1) production authentication/authorization 및 resource gate, (2) TLS/access audit/retention·deletion 운영 경계, (3) 별도 승인 이후 deployment enablement 검토다. Module-level default app은 Linux Audit endpoint를 등록하지 않으며, 명시적으로 enabled된 route도 LLM, CLI, risk 또는 Frontend에 연결되지 않는다. 이 programmatic feature gate만으로 production enablement gate가 충족되지는 않는다.
