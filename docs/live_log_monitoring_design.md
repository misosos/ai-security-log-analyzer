# v0.2.0 Phase 11 — bounded 로컬 로그 모니터링 설계

상태: **Phase 12~13.1 내부 live tail·parse·detection·worker, Phase 14 bounded publication/replay buffer, Phase 14.1 loopback 읽기 전용 status/SSE, Phase 14.2 단일 source CLI·bounded 자동 polling 구현; 사용자 live UI는 미구현** (2026-10-12). `v0.1.0`의 파일 업로드·분석 계약과 공개 Release는 변경하지 않는다. 사용자 표시명은 **로컬 로그 실시간 확인**을 우선한다. 여기서 ‘실시간’은 polling 기반의 추가분 관찰이며 즉시 처리, 무유실, SIEM·EDR, 침해 판정을 보장하지 않는다. 이 문서의 후속 분석 한도에 남긴 `TO_BE_BENCHMARKED`는 현재 개발용 기본값이 아니다.

### Phase 14.2 현재 CLI 및 자동 polling lifecycle

`uv run python -m app.local_web --monitor-config /absolute/path/to/live-monitor.json`을 실행할 수 있다. `--no-browser`와 `--port 8123`을 함께 사용할 수 있다. 설정은 기존 `load_live_monitor_config(Path)`의 닫힌 JSON(`schema_version: "1"`, `source.role: application|ssh|access`, `source.path: 절대 경로`, `start_policy: "FROM_END"`)을 그대로 사용한다. 안전한 [예시](examples/live-monitor.json)는 실제 경로가 아니므로 자신의 절대 경로로 바꾸어야 한다. 설정 파일은 실행자 소유이며 group/world 접근을 허용하지 않아야 한다. Source와 모든 parent 경로는 symlink가 아니어야 한다. 브라우저에서 source 경로를 선택하거나 설정하지 않는다. CLI 인자에 넣은 config 경로는 OS process list 또는 shell history에 노출될 수 있으므로 비밀 경로를 사용하지 않는다.

런처는 서버 bind 전에 config를 정확히 한 번 읽고 regular source를 `FROM_END`로 열어 session → accumulator → publication을 소유하는 worker → service → runner → live-enabled 앱을 만든다. 실패하면 열린 FD를 닫고 브라우저·서버를 시작하지 않는다. 기본 명령은 기존과 같고 live endpoint가 비활성이다. Config 모드에서는 기존과 같이 브라우저를 열 수 있지만 첫 화면에 live 결과 UI는 아직 없으며 status/SSE는 기술 검증용이다. `/api/health`는 기존 `{"status":"ok"}`만 반환하며 live 정상 여부의 증명이 아니다.

Runner는 서버 FastAPI lifespan의 asyncio loop에서 task 정확히 하나로 동작한다. 별도 worker thread·per-event task·executor job은 없으며 동기 `worker.step()`을 같은 loop에서 순차 호출한다. 기존 한 poll 최대 4,096 byte, chunk 1,024 byte, queue 32 item/16KiB, lease 최대 16 record/4,096 byte 및 이번 단계의 history 256 event/256KiB 개발 상한을 근거로 소규모 loopback 전용으로 제한한다. 이는 운영 성능 SLA가 아니다. 개발 기본 polling 간격은 0.5초이며 탐지 시간 창·threshold가 아니다. 다른 실행 주기를 CLI에서 받지 않는다. 이 선택은 lock 없이 단일 caller 계약을 유지하지만, step 중 event loop가 잠시 지연될 수 있다. Bench 결과를 운영 환경에 일반화하지 않는다.

각 iteration은 안전한 `NO_DATA` 또는 `PROCESSED` 결과만 받아 다음 poll을 기다린다. Publication `published_total`이 증가했을 때만 payload 없는 `notify_change()`로 SSE를 깨운다. Event·raw detector 결과는 runner에 보관하지 않는다. 알림 실패는 이미 완료된 queue ack·detection·publication을 되돌리지 않고 live runner를 terminal `FAILED`로 봉쇄한다. Worker `DEGRADED`는 자동 resume하지 않고 `LIVE_RUNNER_DEGRADED`, `FAILED`는 `LIVE_RUNNER_FAILED` 고정 code와 재시작 안내를 status/SSE에 표시한 뒤 step을 중지한다. 일반 sample·로컬 업로드·Linux Audit API는 live 오류와 무관하게 계속 제공한다. 새로운 복구 API는 없다.

Lifespan shutdown, cancellation, Ctrl+C에서는 runner stop → 최대 5초 task 대기 → 필요 시 cancel → service/worker/session close 순서로 정리한다. 런처의 서버 join 상한은 기존 7초다. Timeout은 고정 `LIVE_SHUTDOWN_TIMEOUT`으로 나타내되 강제 프로세스 종료 뒤 완전 cleanup이나 Python 메모리 secure erase는 주장하지 않는다. Rotation·truncation·source 소실·queue/history overflow와 partial line의 기존 fail-closed 의미를 유지하고 추측 병합·자동 재시도·중단 중 추가분 복구를 하지 않는다. Process crash/restart 뒤 checkpoint와 replay는 없다. Correlation·risk·case·Linux Audit live·LLM·hosted 노출 및 사용자 live UI도 아직 없다.

개발 microbenchmark (2026-10-12, 이 작업 머신의 Python 3.12·합성 application 줄; 운영 SLA 아님): `tracemalloc`을 켠 빈 worker step 100회 median 1.394ms/p95 1.586ms, 16줄 한 step 26.248ms, peak traced allocation 94,894 byte였다. 16줄을 tail만 polling했을 때 resident queue는 16 item/1,040 byte로 기존 32 item/16KiB 상한 아래였다. 실제 0.5초 cadence에서 append→publication notification의 한 표본은 512.9ms였다. 활성 runner와 병행한 TestClient status 30회 p95 1.951ms/max 3.81ms, service close 한 표본은 0.647ms였다. CPU/RSS·운영 p99·지속 고속 부하는 이 작은 실험으로 보장하지 않는다. History 256 event/256KiB는 batch prefix 재계산의 event-loop stall과 메모리를 bounded하게 두기 위한 **개발용 상한**이며 초과 시 조용한 eviction 없이 runner를 중단한다.

### Phase 14.1 현재 loopback status/SSE 전송 경계

기본 `create_app()`에서는 `GET /api/v1/live/status`와 `GET /api/v1/live/events`가 고정 `404 LIVE_MONITORING_NOT_ENABLED`다. 앱 생성 시 exact `LiveMonitoringService` 한 개를 명시적으로 주입해야만 읽기 전용 경계가 활성화된다. 요청으로 session·source path를 만들거나 config를 변경하지 않으며 API는 파일을 열거나 worker `step()`을 호출하지 않는다. Phase 14.1 당시 런처는 service를 주입하지 않았지만 Phase 14.2에서는 명시적 `--monitor-config`를 사용한 경우에만 주입한다. 새 POST/PUT/DELETE endpoint와 브라우저 `EventSource`는 없다.

공통 로컬 요청 검사는 실제 peer `127.0.0.1` 또는 `::1`, Host `127.0.0.1` 또는 `[::1]`(선택적 port), 동일 Origin만 허용한다. `Forwarded`·`X-Forwarded-For`·`X-Real-IP` 및 관련 forwarding header, cross-site 요청은 거부한다. CORS·cookie/credential 인증을 추가하지 않는다. Loopback은 다른 로컬 process나 사용자를 인증하지 못하므로 hosted/public 배포 경계가 아니다. 오류는 고정 code·한국어 안내·복구 행동·retryable만 포함한다. Status는 명시적 닫힌 Pydantic 모델의 안전한 상태·역할·session ID·revision·event/eviction/gap count·상한만 반환하며 `no-store`·`nosniff`를 적용한다.

SSE 응답은 `text/event-stream; charset=utf-8`이며 `snapshot`, `observation_changes`, `replay_gap`, `service_status`, `heartbeat`, `stream_end`의 닫힌 event allowlist만 인코딩한다. 각 field는 LF와 빈 줄로 끝나고 `data`는 결정적 한 줄 UTF-8 JSON이다. Observation change에만 Phase 14 event ID를 붙인다. Heartbeat는 15초 개발 주기, 고정 상태만 보내며 ID·clock·개인정보가 없다. 실제 reverse proxy용 keepalive 보장은 아니다. 최초 연결은 안전 snapshot 다음 retained event 전부, 재연결은 **표준 `Last-Event-ID` header**를 Phase 14 `replay_after()`에 그대로 전달한 결과를 보낸다. Query cursor·cookie는 받지 않는다. Gap이면 고정 `replay_gap`과 최신 snapshot을 보낸 뒤 연결을 종료한다. 후속 UI는 자동 재연결 폭주를 막는 별도 정책이 필요하다.

Service는 정확히 한 worker와 buffer에 한 번만 연결되고 process-local·memory-only다. 상태는 worker의 `READY/RUNNING_STEP/DEGRADED/FAILED/STOPPING/STOPPED`와 service close를 안전하게 매핑한다. 명시적 `notify_change()`는 payload 없는 condition 알림만 전달한다. Stream은 깨어날 때마다 bounded publication buffer를 다시 조회하며 별도 client queue나 raw 복사본을 무제한 보관하지 않는다. Spurious wakeup, 여러 change 한꺼번에 도착, client별 독립 cursor를 허용한다. 최대 동시 SSE 연결은 개발용 2개다. 느린 client의 cursor가 eviction되면 replay gap이며, publish는 client를 기다리지 않는다. Disconnect·cancel·generator 오류에서 slot을 반환한다. Service close는 worker/FD를 닫고 기존 stream에 `stream_end`를 보내며 새 연결을 거부한다. Stream 시작 뒤 HTTP status는 변경할 수 없어 내부 오류는 가능한 경우 고정 `LIVE_STREAM_FAILED` 종료 event로 보낸다.

SSE는 읽기 전용 전송 형식이지 보안 경계나 무유실·exactly-once 보장이 아니다. Process crash/restart 뒤 replay가 사라지고 여러 worker/process 간 일관성은 없다. 원래 계정·IP·HTTP path/query·raw line·argv·source path·내부 exception은 status/SSE/error/OpenAPI에 넣지 않는다. Trusted tail/parse/detection 내부에는 raw 값이 남을 수 있다. 이번 단계는 correlation·risk·case·Linux Audit live·LLM·영구 저장·hosted 노출을 구현하지 않는다.

### Phase 14 현재 내부 publication/replay 계약

`LivePublicationBuffer(accumulator, max_items=32, max_bytes=16384)`는 process-local·memory-only이며 정확히 한 `LiveDetectionAccumulator`의 **committed** `LiveDetectionChangeSet` identity만 받는다. Proposal, raw event/detection, dict, 타 session change, 중복·누락 revision은 고정 오류다. `publish()`는 detector·diff를 다시 실행하지 않는다. 변화가 없는 완료 revision은 event 없이 latest revision만 전진한다. 의미 있는 change에는 안전한 `LivePublicationEvent` 하나를 부여한다. Frozen event에는 session/event ID, detection revision, `DETECTION_CHANGE`, created/updated/no-longer-matches 수, active observation 수와 Phase 13.1의 안전한 change tuple만 있다. IP·account·path/query·raw evidence·event timestamp·lease ID는 없다. 직렬화는 UTF-8 JSON의 정렬된 key와 고정 separator이며, 실제 직렬화 byte 길이를 budget에 사용한다. Phase 14 단독 단계에는 SSE의 `data:` framing과 HTTP response model이 없었고, 현재는 위 Phase 14.1 읽기 전용 경계가 있다. 브라우저 수신은 여전히 없다.

Session ID `LIVE-SESSION-000001`과 event ID `LIVE-EVENT-000001-000001`은 현재 process의 단조 정수에서만 만들며 clock·UUID·randomness·IP·account·hash를 사용하지 않는다. Event 번호는 게시 순서이고 detection revision과 별개다. 재시작 뒤 같은 번호가 나올 수 있어 전역 identity가 아니다. Event ID에 session 번호를 포함하므로 다른 session의 replay 요청을 고정 `FOREIGN_SESSION` gap으로 분류한다.

개발 기본값은 **32 item·16,384 serialized bytes**의 이중 상한이다. 기존 합성 sample investigation API 응답은 이 환경에서 41,067 bytes이고, 5개 인증 실패의 첫 CREATED 및 다음 UPDATED change의 안전 JSON event는 각 420 bytes로 측정했다. 약 39개 단일-change event가 byte 상한에 들어가므로 item 상한 32가 먼저 걸리는 사례가 있으며, change 수가 많으면 byte 상한이 먼저 걸린다. 이는 개발용 합성 측정이며 운영 throughput·RSS·p95/p99 근거가 아니다. Buffer는 tuple 기반 고정 상한이고 오래된 event부터 제거한다. `evicted_total`과 earliest/latest ID가 바뀌며 조용한 삭제나 정상 0건으로 포장하지 않는다. 단일 event가 상한보다 크면 잘라내지 않고 `EVENT_TOO_LARGE`로 거부하고 `rejected_oversized_total`을 올린다. Python 객체 overhead는 JSON byte 예산과 별개로 남는 한계다.

`replay_after(None)`은 `INITIAL`과 현재 안전 snapshot 및 보유한 bounded event 전부를 반환한다. 현재 buffer에 남은 event ID라면 그 다음부터 `REPLAY`하며 최신 ID면 빈 tuple이 정상이다. 제거된 ID는 `EVICTED_EVENT_ID`다. 다른 session, 미래/형식 오류, 존재하지 않은 ID, 닫힌 buffer는 event가 없는 `GAP`과 고정 code·복구 문구 및 최신 안전 snapshot을 반환한다. 이때 최신 snapshot부터 다시 시작해야 하며 과거 event 복구나 무유실을 주장하지 않는다. Gap 수는 안전한 누적 counter다. Close는 반복 가능하고 보유 event를 폐기하며 이후 publish를 거부하고 replay는 `BUFFER_CLOSED` gap이다. 이미 caller가 보유한 event 객체나 Python 메모리를 secure erase하지 않는다.

Worker의 순서는 `poll → lease → parse → detection prepare/prevalidate → queue ack → detection commit → publication → worker safe result`다. Queue ack와 detection commit 및 publication은 진정한 원자적 transaction이 아니고 exactly-once 보장도 없다. Detection commit 이후 publication 실패는 rollback·lease release·자동 재게시 없이 terminal `PUBLICATION_FAILED_AFTER_DETECTION_COMMIT`으로 처리하고 `potentially_unpublished_revision_count`를 올린다. 게시 후 worker 집계 실패는 별도 `WORKER_AGGREGATE_FAILED_AFTER_PUBLICATION` terminal code다. 두 경우 close만 허용한다. Worker snapshot의 publication snapshot은 안전한 count·상한·ID·revision만 담는다. Raw event/detector는 buffer에 들어오지 않고 trusted accumulator 내부에만 있다. Process crash/restart 후 replay 복구는 없고 여러 worker/process 사이 공유·일관성도 없다. Phase 14 당시에는 자동 polling loop, API route, SSE endpoint, frontend, CLI monitor flag, correlation/risk/case, Linux Audit live 및 LLM이 없었다. 현재 status/SSE 경계는 위 Phase 14.1 계약을 따른다.

## 0. Phase 12에서 실제 구현된 내부 core

Phase 12 tail core는 `app.live_monitoring`의 `load_live_monitor_config(Path) -> LiveMonitorConfig`, `open_live_tail_session(LiveMonitorConfig) -> LiveTailSession`, `poll_once() -> int`, `snapshot() -> LiveTailSnapshot`, `close() -> None`을 제공한다. Phase 12.2에서는 안전하지 않은 `take_records()`를 제거하고 `lease_records(max_records, max_bytes)`, `acknowledge_lease(lease)`, `release_lease(lease)`를 추가했다. 동기식 단일 source·명시적 poll step이며 core 자체는 clock/sleep·background task/thread·parser/detector·CLI flag·HTTP route·SSE·frontend·LLM을 사용하지 않는다. `close()`는 반복 호출 가능하고 열린 FD를 닫으며 partial과 미완료 resident record를 폐기하고 `abandoned_on_close_count`에 기록한다. 서버 영구 저장은 없다. `LiveTailRecord.payload`와 `LiveRecordLease.records`에는 trusted parser용 원문 한 줄이 존재할 수 있으나 `repr`/`str`에는 나오지 않는다. 일반 JSON/FastAPI encoder에 내부 객체를 전달하지 않는다. `LiveTailSnapshot`에는 고정 역할·상태·signed-64 count/queue/ownership/오류 code만 있으며 path·account·IP·request·offset/inode·payload는 없다.

Phase 12.1의 별도 내부 함수 `parse_live_records(source_role, tuple[LiveTailRecord, ...]) -> LiveParseBatch`는 `application`·`ssh`·`access`만 받는다. 기존 batch loader와 공유하는 `preprocess_log_line()`의 `strip()` 후 빈 줄은 `IGNORED`; 나머지는 기존 parser registry와 timezone을 사용하고 `normalize_to_utc()`를 적용한다. Parser가 `None`을 반환하면 `IGNORED`, event를 반환하면 `PARSED`, 예상 가능한 `ValueError`/`IndexError`는 고정 reason code의 `REJECTED`다. 특히 SSH의 지원하지 않는 문구가 기존 parser에서 `event_type=None`인 `NormalizedEvent`를 반환한다면 live에서도 **PARSED**이지 임의로 무시하지 않는다. Batch pipeline은 일부 malformed application/SSH 줄에서 예외를 전파하지만, live adapter는 같은 parser 예외를 줄별 `REJECTED`로 바꾼다. 이는 control-flow 보호이지 parser 의미 변경이나 batch 성공 주장이 아니다.

입력은 정확한 tuple·`LiveTailRecord` runtime type·단일 role·엄격히 증가하는 sequence를 요구한다. Gap은 허용하고 정렬·재번호 부여는 하지 않는다. 모든 입력 record에는 순서가 같은 하나의 outcome이 있으며 공백 record도 `IGNORED` outcome으로 남는다. Frozen outcome의 `event`는 repr에서 빠지지만 직접 접근하면 account·IP·HTTP path/query·raw를 포함할 수 있는 **trusted internal** 값이다. Rejected/ignored outcome은 원문을 보관하지 않는다. Adapter는 파일 I/O, detector, correlation, risk, case, HTML, LLM을 실행하지 않으며 공개 snapshot·API/OpenAPI에 연결되지 않는다. 단일 lease의 예상 밖 내부 오류는 부분 성공 없이 고정 batch error로 fail closed하며 상위 caller가 `release_lease()`를 명시적으로 호출해야 한다. `PARSED`·`IGNORED`·`REJECTED`가 모두 완성된 batch는 전체 ack할 수 있다. Parser가 ownership을 직접 제어하지 않으며 향후 detector·projection까지 성공한 뒤 ack할지는 상위 worker 정책이다. 자동 retry/backoff, retry limit, 프로세스 crash 복구, exactly-once는 없다. 따라서 현재 core와 adapter를 운영 실시간 기능으로 사용할 수 없다.

### Phase 12.2 ownership 계약

한 session에는 active lease가 최대 하나다. Queue는 resident record를 FIFO로 보유하고 lease는 맨 앞 prefix의 처리 권한만 부여한다. `resident items/bytes = available items/bytes + leased items/bytes`; lease 중에도 32건·16KiB budget은 감소하지 않는다. Ack만 전체 prefix를 제거하고 acknowledged count를 올린다. Release는 queue를 물리적으로 이동하지 않아 원래 prefix를 즉시 available로 되돌리며, 그 사이 append된 기록보다 앞선다. 개별 기록의 lease 시도 횟수는 내부에서 증가하고 snapshot은 최대 시도 횟수와 release 총수만 보여 준다. 첫 lease는 attempt 1이며 재lease는 2 이상이다. 임의 retry 상한은 정하지 않았다. Lease ID는 session-local 단조 증가 정수이고 다른 session 구분자는 process-local 단조 증가 정수다. UUID·clock·randomness·객체 identity는 ID 생성에 쓰지 않는다. Caller가 내부 필드에 악의적으로 직접 접근하는 것은 신뢰 경계 밖이다.

`lease_records()`는 `RUNNING`에서만 가능하며 빈 queue는 `None`을 반환한다. Limit은 bool 제외 양의 정수·설정 상한 이내다. 첫 record조차 byte limit에 담지 못하면 고정 오류다. Ack/release는 exact active lease의 role·ID·count·byte·sequence·payload가 일치해야 하고 partial ack는 없다. Stale/foreign/forged/중복 settlement는 고정 오류다. 내부 ownership 일관성이 깨져 release 검증 자체가 실패하면 세션을 `FAILED`로 전환한다. `close()`는 암묵적 ack가 아니며 available+leased를 abandoned로 기록하고 세션이 보유한 raw 참조를 제거한다. Close 시에도 ownership 불일치가 발견되면 FD와 queue를 정리한 뒤 고정 `CLOSE_INVALID_OWNERSHIP`을 남긴다. Snapshot의 `queue_item_count`·`queue_byte_count`는 전체 resident 수이고 `available_*`·`leased_*` 합과 일치한다. `active_lease`, `acknowledged_record_count`, `released_lease_count`, `max_attempt_count`, `abandoned_on_close_count`는 안전한 집계이며 sequence 목록·payload·lease ID는 포함하지 않는다. Caller가 이미 들고 있는 lease 객체의 raw 참조와 Python 메모리의 secure erase까지 보장하지 않는다. 이 core는 single-threaded explicit-step 계약이며 동시 호출 안전성을 주장하지 않는다. 향후 async worker는 호출을 직렬화해야 한다. 이 변경은 미공개 v0.2 내부 계약만 바꾸며 v0.1 public API·CLI에는 영향이 없다.

실제 JSON config는 top-level exact `schema_version`, `source`, `start_policy`다. `source`는 exact `role`, `path`이며 **정확히 한 source**만 받는다. Role은 `application`·`ssh`·`access`; `FROM_END` 외 정책과 Linux Audit는 거부한다. Config는 4096바이트 이하 strict UTF-8 JSON, 중복·unknown key와 NaN/Infinity 거부, 실행 사용자 소유의 owner-only regular file이다. Config와 source 경로의 각 성분을 `O_NOFOLLOW` 가능한 플랫폼에서 no-follow dir-fd로 열고, 최종 FD를 `fstat`해 regular file인지 확인한다. Source는 읽기 가능하고 group/world writable이면 거부한다. 플랫폼이 `O_NOFOLLOW` 등 필요한 경계를 제공하지 않으면 `UNSAFE_PLATFORM`으로 fail closed한다. 원본 파일의 권한은 바꾸지 않는다.

세션 open 시 열린 FD를 EOF로 이동한다. open **이후** 첫 poll 전 append는 읽지만 기존 줄은 읽지 않는다. LF로 끝난 줄만 queue에 넣고 CRLF의 마지막 CR과 LF는 제거한다. 멀티바이트 UTF-8은 byte로 모았다가 완성 줄을 strict decode한다. NUL·control/binary·invalid UTF-8과 초과 길이는 고정 오류로 `FAILED`에 들어간다. Queue overflow, truncation, replacement/rotation, 경로 소실·symlink swap·권한 상실도 자동 병합 없이 `FAILED`이며, 수락된 record 수와 fixed warning을 snapshot에 남긴다. **읽었지만 enqueue하지 못한 줄은 성공 count에 넣지 않는다.** Overflow 뒤에는 offset 재시도를 추측하지 않고 세션 종료·재시작을 요구하며, 재시작은 `FROM_END`라 gap이 있을 수 있다. 크기만으로 판별할 수 없는 빠른 copytruncate·inode 재사용 등은 남은 위험이다.

| 개발 상한 | 값 | 선정 근거 |
|---|---:|---|
| config 전체 | 4096 bytes | 한 source·닫힌 JSON schema만 허용; 경계 테스트 고정 |
| 한 번의 read chunk | 1024 bytes | 최대 줄 2048보다 작은 고정 chunk로 partial/multibyte 경계를 시험 |
| 한 poll의 read / record | 4096 bytes / 16건 | 명시적 호출마다 처리량 제한; 실제 반복 loop는 없음 |
| 한 줄 / partial | 각각 2048 bytes | 기존 로컬 업로드의 줄 상한과 동일한 보수적 입력 범위; LF 전 raw byte 기준(마지막 CR 포함) |
| queue | 32건 + UTF-8 payload 합계 16384 bytes | 작은 로컬 실험용; item과 byte 제한을 각각 독립 테스트 |
| 모든 count/revision/sequence | signed 64-bit nonnegative | bool-as-int 거부, 넘치면 fixed `COUNTER_LIMIT` |

기존 합성 fixture 측정: application 17줄·973바이트·최장 64바이트, SSH 6줄·459바이트·최장 67바이트, access 4줄·569바이트·최장 155바이트. 기존 업로드 API는 파일당 최대 512줄·한 줄 2048바이트다. 개발 환경 Python 3.12에서 155바이트 synthetic 줄 1600건을 100회 append/poll/drain한 1회 측정은 약 0.286초·tracemalloc peak 7849바이트였고, 2048바이트 경계 줄 800건은 약 1.131초·peak 22519바이트였다. 이는 작은 단일 실행 관찰이며 운영 처리량·peak RSS·p95/p99 지연 보장이 아니다. Queue의 16KiB는 payload 합계이며 Python 객체 overhead는 포함하지 않으므로 향후 운영 한도는 별도 benchmark가 필요하다.

### Phase 12.3 단일 caller worker 계약 (당시 계약)

이 절은 Phase 12.3의 parser-only 기준을 기록한다. **현재 정상 경로는 아래 Phase 13.1의 detection-aware worker**이며 이 생성자와 detector 미연결 설명은 현재 실행 계약이 아니다.

`LiveProcessingWorker(session, max_lease_records, max_lease_bytes)`는 정확한 `LiveTailSession` 한 개에 한 번만 연결된다. `step()`은 한 번의 `poll_once()` 후 available prefix를 최대 한 번 lease하고, 기존 adapter로 parse한 전체 batch의 role·outcome 수·sequence 순서·상태별 count를 확인한 뒤에만 전체 ack한다. `REJECTED`도 예상된 완료 결과라 ack하고 집계한다. Queue가 비어 있으면 parser/lease/ack 없이 `NO_DATA`이며 partial byte가 있어도 안전 판정을 뜻하지 않는다. 반환되는 frozen `LiveWorkerStepResult`와 `snapshot()`은 고정 상태·count·오류 code만 보유한다. Parsed event나 lease를 보관·반환하지 않는다. Trusted worker-local event는 step 안에만 있고 detector·case에 전달하지 않는다. 한 step의 work는 lease 상한과 기존 poll 상한으로 제한된다.

Worker 상태는 `READY → RUNNING_STEP → READY`(정상), `RUNNING_STEP → DEGRADED`(parse·batch 불변식 실패 후 release 성공), `RUNNING_STEP → FAILED`(poll·lease·ack·release 실패), `DEGRADED → READY`(명시적 `resume_after_degraded()`), `READY/DEGRADED/FAILED → STOPPING → STOPPED`(close)다. `DEGRADED`에서 자동 step·retry는 없고 resume 전에 active lease가 없고 session이 RUNNING임을 확인한다. FAILED에서는 close만 허용한다. Poll의 truncation·rotation/replacement·source unavailable·symlink/permission·UTF-8/NUL/줄 길이·queue overflow와 기타 tail 오류는 기존 session이 terminal FAILED로 전환하므로 모두 worker 고정 `POLL_FAILURE → FAILED`로 매핑한다. 이 과정에서 원래 tail code는 privacy-safe session snapshot에 남는다. Ack/release 실패는 가능한 경우 session도 terminal FAILED로 전환하고 FD를 닫되 lease를 자동 정산하지 않는다. Ack 실패에는 release를 시도하지 않고, release 실패에도 재시도·queue 추측 복구를 하지 않는다. Close는 ack가 아니며 남은 resident 기록은 session의 abandoned count에만 반영된다. Worker가 session을 닫고 FD를 정리한다.

단일 worker binding은 두 번째 worker 생성만 runtime에서 거부한다. 신뢰된 내부 caller가 session 메서드를 직접 혼용하거나 여러 thread에서 동시에 호출하는 것을 완전하게 차단하는 동시성 장치는 없다. 호출자는 worker에 session을 넘긴 뒤 직접 조작하지 않아야 하며, 향후 async loop는 직렬화해야 한다. Worker는 명시적 step만 제공하고 sleep·timer·background thread/task·자동 polling·CLI·SSE·UI·LLM·detector·상관분석·risk·case·HTML을 실행하지 않는다. Process memory 밖 persistence와 crash recovery는 없고 exactly-once도 보장하지 않는다.

### Phase 13 bounded detection accumulator (당시 독립 계약)

이 절은 Phase 13의 worker 미연결 기준을 기록한다. **현재 ack/commit 순서는 아래 Phase 13.1 계약**을 따른다.

`LiveDetectionAccumulator(source_role, max_history_records, max_history_bytes)`는 application·SSH·access 중 한 역할의 **내부 단일 caller** 계약이다. `prepare(LiveParseBatch)`는 exact batch·역할·sequence·outcome 수를 재검증하고 PARSED event 전부를 기존 committed tuple 뒤에 같은 입력 순서로 붙인다. IGNORED/REJECTED는 history에 넣지 않고 안전한 count만 후보에 반영한다. Event raw의 strict UTF-8 byte 길이를 합해 두 상한을 동시에 검사한다. 상한은 caller가 명시하며 이 단계에서 운영 기본값을 정하지 않는다. 초과 시 전체 proposal을 고정 `HISTORY_LIMIT_EXCEEDED`로 거부하고 committed state를 바꾸지 않는다. 과거 event의 rolling eviction이나 일부 new event만 commit하는 방식은 없다. **오래된 실패 1건+최근 실패 5건**에서 기존 batch detector가 전체 min/max를 보므로 최근 60초만 남기면 의미가 바뀔 수 있다.

상한을 통과한 candidate history는 기존 `detect_attacks(list(history))` 한 번으로 평가한다. 기존 `summarize_ip_failures`, Brute Force, Password Spray-like, Path Traversal 및 네 웹 관찰 함수의 threshold·ordering·evidence를 복제하거나 수정하지 않는다. Result의 subject set, feature/detection slot, `DetectionResult`/`Evidence` typed 구조를 검증한다. Frozen `LiveDetectionProposal`에는 trusted raw history/result가 `repr`에서 제외되어 있지만 명시적으로 접근하면 account·IP·HTTP path/query·raw가 존재할 수 있다. `safe_summary()`와 `snapshot()`만 고정 type별 detection count·subject count·history count/byte·입력 outcome count를 제공하며 raw subject·evidence·timestamp 목록을 포함하지 않는다. 일반 JSON/FastAPI encoder에 내부 proposal이나 accumulator를 전달하지 않는다.

`prepare()`는 committed history·detection·revision을 변경하지 않고 active proposal 하나만 예약한다. PARSED가 0건인 batch는 detector를 재실행하지 않는 유효 proposal이며 ignored/rejected 누적만 commit한다. `abort()`는 committed snapshot을 그대로 유지하고 같은 batch의 명시적 재시도를 허용한다. `commit()`은 exact active owner/proposal ID·revision·role·history byte/count·detection invariant를 재검증한 뒤 history·raw detection·집계를 함께 적용하고 revision을 정확히 1 올린다. Foreign/stale/forged/double settlement는 고정 오류다. 내부 `NormalizedEvent`와 detector dictionary는 mutable Python 객체이므로 악성 내부 코드의 직접 변조나 Python 메모리 secure erase는 이 계약의 보호 범위가 아니다. 단일 caller가 trusted proposal을 공유·변조하지 않는 것이 전제다. Process crash 후 복구나 exactly-once 보장은 없다.

각 prefix에서 같은 ordered event list를 batch `detect_attacks()`에 전달했을 때 전체 subject·feature·detection/evidence 구조가 동일해야 한다. 기존 batch의 입력 순서 민감성(예: Path Traversal 단일 slot의 마지막 일치)은 live가 임의로 고치지 않고 같은 순서를 보존한다. 이번 단계는 탐지를 publish하지 않는다. 같은 탐지가 각 prefix에서 반복 계산됨 → publication identity와 revision 계약 필요 → **Phase 13.1에서 설계**한다. Accumulator는 `LiveProcessingWorker`, lease ack/release, correlation, risk, case, CLI, API, SSE, UI, LLM, HTML에 연결되지 않는다. 후속 통합의 open decision은 `detection prepare 성공 → queue ack 성공 → detection commit` 사이에서 ack 후 commit 실패가 발생하면 소유권을 어떻게 terminal 처리할지다. 이번 단계에서 worker의 ack 순서를 바꾸거나 이를 해결했다고 주장하지 않는다.

### Phase 13.1 현재 내부 처리 계약

`LiveProcessingWorker(session, detection_accumulator, max_lease_records, max_lease_bytes)`는 정확히 한 source role의 새 session과 빈 `LiveDetectionAccumulator`를 각 하나씩 소유한다. 둘의 role이 다르거나 accumulator에 이전 committed history·active proposal이 있으면 거부한다. 둘 이상의 worker가 같은 session/accumulator를 공유할 수 없다. 신뢰된 caller의 직접 settlement 혼용이나 동시 thread 호출까지 막는 lock은 없으므로 단일 caller 계약이다. Parser-only worker 우회 경로는 없다. CLI·API·SSE·UI·correlation·risk·case·HTML·LLM은 호출하지 않는다.

한 `step()`은 `poll → lease → parse → batch invariant → detection prepare → proposal prevalidate → queue ack → commit_prepared → 안전 집계` 순서다. `prepare()`에서 whole-prefix detector 실행, observation diff·ID 할당, safe summary, 다음 frozen committed state와 snapshot을 모두 만든다. `prevalidate()`는 ack 전에 exact active proposal과 count·byte·detection·observation 계약을 검사한다. `commit_prepared()`에는 detector·정렬·raw byte 계산·ID 생성·publication diff·깊은 validation이 없고 사전 준비한 state 참조를 교체한다. Ack가 **point of no return**이다. Queue와 accumulator 사이에 진정한 원자적 transaction은 없으며 exactly-once, process crash recovery, Python secure memory erasure를 보장하지 않는다.

Ack 이전 실패는 active proposal이 있으면 abort한 다음 lease를 release하여 원래 FIFO 순서를 복구하고 worker를 `DEGRADED`로 둔다. 자동 retry는 없고 명시적 `resume_after_degraded()`가 필요하다. Abort/release 자체가 실패하면 `FAILED`이며 ownership을 추측해 ack하지 않는다. Ack 실패는 proposal만 abort하고 release를 추측하지 않으며 고정 `ACK_FAILURE`로 terminal `FAILED`다. Ack 호출에서 이미 정산된 것이 확인된 뒤 예외가 발생하거나, ack 후 commit이 실패하면 ack를 되돌리거나 release·재시도하지 않는다. 마지막으로 확인된 accumulator 참조를 유지하고 terminal로 봉쇄하되 queue record를 복구했다고 주장하지 않는다. `DETECTION_COMMIT_FAILED_AFTER_ACK`, `post_ack_commit_failure_count`, `uncommitted_after_ack_record_count`를 안전 snapshot에 기록하고 close만 허용한다. 이 상태는 **일부 로그가 탐지 상태에 반영되지 않았을 수 있는 terminal integrity failure**다. 기대된 `REJECTED`는 처리 완료이므로 정상 ack되고, PARSED가 0건이어도 완료 proposal revision은 1 증가한다.

Observation의 내부 key는 trusted subject와 승인된 detection slot이고, 공개 가능한 ID는 session-local 단조 정수 `LIVE-OBS-000001` 형태다. IP·account·hash·clock·UUID를 ID에 넣지 않는다. 최초 활성화는 `CREATED`, canonical `DetectionResult`(활성 여부·type·evidence 순서/type/value/source/UTC time/range) 변화는 같은 ID의 `UPDATED`, 현재 prefix에서 조건이 사라지면 `NO_LONGER_MATCHES_CURRENT_RESULT` 상태와 `NO_LONGER_MATCHES` change를 기록한다. 이는 공격 해결·안전 판정이 아니다. 같은 session에서 재등장하면 기존 ID의 revision을 올려 `UPDATED`로 표시한다. Process 재시작 뒤 ID 지속성·공격자 identity는 주장하지 않는다. Proposal에서 생성한 change set은 frozen 안전 scalar만 담고 최신 committed 1개만 보관한다. Phase 14 bounded replay buffer와 Phase 14.1 읽기 전용 SSE 경계가 현재 연결됐지만 사용자 live UI는 후속 단계다.

Worker step result는 accumulator revision, created/updated/no-longer-matches 건수와 active observation 건수만 더한다. IP·account·HTTP path/query·raw evidence는 trusted history·detection·subject slot key에만 있을 수 있으며 step result/snapshot/오류/repr로 넘기지 않는다. `NO_DATA`는 revision·observation count를 바꾸지 않는다. `close()`는 session FD와 accumulator의 보유 raw 참조를 정리하고 active proposal을 commit하지 않는다. Safe worker count는 남지만 이는 서버 영구 저장이나 secure erase가 아니다.

## 1. 현재 계약, 목표와 관찰 가능한 근거

현재 `app.local_web`은 `127.0.0.1` 전경 서버이며 `--port`, `--no-browser`만 받는다. 샘플·3파일·Linux Audit 업로드는 각각 **일회성** 분석이다. `load_normalized_logs()`는 파일 전체를 읽어 list를 만든다. registry는 application/SSH의 naive 시각을 `Asia/Seoul`로, access의 명시적 offset을 UTC로 정규화한다. `NormalizedEvent.raw`, account, HTTP path/query 및 Linux Audit 실행 문맥은 trusted 내부 값이다. 공개 경계는 별도 allowlist projection이다. `detect_attacks()`는 IP별 단일 detection slot을 갖고, 인증 실패 전체의 min/max가 60초 이내인지 본다. Brute Force는 실패 5건·단일 계정, Spray-like는 4건·3계정, Web Scanning-like는 60초 안의 요청 6건·distinct target 6개·4xx 3건을 요구한다. 인증 실패→성공 및 Brute Force→성공은 60초의 가까운 후속 성공을 택한다. Path Traversal은 새 웹 탐지의 bounded canonicalizer와 달리 기존 반복 percent decode를 사용한다. **이 차이를 live 설계가 몰래 바꾸지 않는다.**

| 소스 역할 | 현재 parser가 실제로 볼 수 있는 것 | live에서 보존할 의미/공백 |
|---|---|---|
| application authentication | 줄별 timestamp, event type, account, source IP | 초 단위 원본 시각·KST 규칙 유지; malformed line은 현재 parser가 예외를 낼 수 있음 |
| SSH authentication | 지원하는 Failed/Accepted 문구, account, source IP | 미지원 문구는 event type이 없을 수 있음; 수집 성공=탐지 성공 아님 |
| NCSA access | offset 있는 timestamp, method, 분리된 path/query, status | request target은 내부에서만 사용; 200은 공격 성공 증거 아님 |
| Linux Audit | 다중 record grouping, execution context | 별도 역할; 1차 live 구현에서 보류하며 IP 사례와 결합 금지 |

전체 설계가 목표로 하는 흐름은 `명시적 로컬 설정 → 파일 identity 검증 → bounded tail → 완전한 줄 framing → typed parser → bounded queue → 결정적 micro-batch → privacy-safe projection → bounded 메모리 replay → SSE → 접근 가능한 UI`다. Phase 12는 이 중 파일 검증·tail·완전 줄 queue·안전 snapshot까지만 구현한다. 탐지는 관찰 후보, correlation은 인과관계가 아니며 Linux 분류는 인증·웹 사례와 합치지 않는다. LLM은 live 경로에서 **호출하지 않는다**. 파일 내용·분석 결과·checkpoint의 서버 영구 저장도 없다.

## 2. 사용자 흐름과 구성 계약

Phase 14.2에서 `uv run python -m app.local_web --monitor-config /absolute/path/to/live-monitor.json` 명령을 구현했다. 기본 실행은 계속 기존 UI만 제공한다. 후속 UI는 config 없는 상태에서 `모니터링 비활성`과 시작 방법을 보이고, 브라우저에서 모니터링 경로를 지정하거나 config를 수정하지 않는다. 전경 서버는 계속 `127.0.0.1` 한 process·한 worker로 두고 `Ctrl+C`로 수집까지 중지한다. 브라우저 file input으로 장기 tail path를 선택하지 않는다. 다운로드·업로드 UI는 기존 기능으로 남는다.

Phase 12 내부 core의 Config는 UTF-8 JSON 단일 local regular file, exact-key typed schema다. 실제 계약은 다음과 같다.

```json
{
  "schema_version": "1",
  "start_policy": "FROM_END",
  "source": {"role": "application", "path": "/absolute/example/auth.log"}
}
```

예시 경로는 형식 설명일 뿐 실제 소스나 권장 위치가 아니다. Phase 12는 `source` 한 개만 받으며 role은 `application`·`ssh`·`access` 중 하나다. `linux_audit`와 여러 source는 **거부**한다. 후속 단계의 1~3개 source 확장은 별도 schema migration 및 identity 중복 테스트가 필요하다. Poll 간격과 `source_id`는 config에 없으며 현재는 자동 polling loop도 없다. 후속 UI 표시명은 역할별 고정 한국어 이름만 사용하며 path, basename, path hash, inode/offset을 공개하지 않는다. Unknown/누락 key, 중복 JSON key, 상대 경로, `..` 경로 성분, symlink, FIFO/device/socket/directory, 불가한 소유·권한은 고정 오류로 fail closed한다. 설정 파일은 실행 사용자 소유·group/world 접근 금지(0600 또는 그보다 제한적)로 하고, 소스는 읽기 가능하면서 group/world writable이 아니어야 한다. 소스 소유자는 실행 사용자 또는 OS 관리 계정일 수 있으므로 일률적 0600을 강제하지 않는다. 권한 상승·`sudo`·임의 경로 자동 검색은 없다. Parent symlink도 dir-fd 기반 단계별 no-follow open 및 `fstat()` 검증으로 거부한다. OS가 필요한 no-follow 검증을 제공하지 않으면 모니터링을 거부한다. 경로는 API/UI/일반 오류·로그에 넣지 않는다. CLI argument의 config 경로가 OS process list·shell history에 보일 수 있음은 **후속 CLI**의 잔여 위험으로 고지한다.

`FROM_END`만 V1에서 허용한다. 검증·open한 파일의 시작 시점 EOF를 offset으로 잡고 **그 뒤 append된 완전한 줄만** 처리한다. `FROM_START`와 persistent checkpoint는 보류한다. 재시작 시 다시 끝에서 시작하므로 중단 동안의 append는 놓칠 수 있고, 후속 UI에는 `재시작 이후 추가분만 관찰`을 표시해야 한다. Core는 clock을 읽지 않으며 event timestamp도 생성하지 않는다. 내부 상태는 `STARTING → RUNNING`으로 시작한다.

화면 상태는 `모니터링 비활성 / 시작 준비 / 실행 중 / 일시 중지 / 입력 지연 / 일부 입력 오류 / queue pressure / 관찰 유실 가능성 / 중지 완료 / 복구 필요`를 구분한다. 마지막 처리 시각(없으면 `아직 없음`), 처리한 줄 수, 새 조사 후보 수, queue 깊이/상태, 완전성 경고, 규칙 기반·LLM 비호출, 저장 정책과 `Ctrl+C` 중지 방법을 표시한다. 상태가 좋아 보인다고 안전을 뜻하지 않는다.

## 3. 구성 요소와 파일 수명주기

| 경계 | 책임 | 금지 |
|---|---|---|
| supervisor | 승인 파일만 열고 reader/worker/SSE를 시작·취소·join, 고정 상태/오류 수집 | 디렉터리 재귀 검색, `/var/log` 전체 검색, 홈 자동 검색, sudo, 자동 source 추가, 원격 수집 |
| tail reader | 열려 있는 FD의 새 byte를 chunk로 읽고 offset·partial buffer·rotation 감지 | unbounded `read()`, filename 재해석, FIFO/device 열기, 무음 skip |
| parser dispatch | 완전한 UTF-8 줄을 기존 역할 parser로 보내고 UTC typed event 생성 | loader 재호출, detector 판단, raw 예외 출력 |
| queue + analysis | bounded typed event 전달, 승인된 event-time micro-batch, 기존 detector 의미 검증 | 전체 파일 매 이벤트 재분석, event별 LLM, 무한 history |
| projection + publisher | allowlist DTO, bounded replay, same-origin SSE | raw line/event/account/path/query/argv, 내부 repr, 영구 결과 저장 |

파일 identity는 open FD의 `(st_dev, st_ino)`와 `fstat` mode를 내부에서 사용하고, path의 `lstat`/재open 결과와 비교한다. macOS/Linux POSIX filesystem에서 이 값은 합리적인 근접 identity지만 inode 재사용·network filesystem·동시 교체를 완벽히 판별하지 못한다. 파일을 `O_NOFOLLOW | O_NONBLOCK`으로 열고 regular file을 `fstat`한 뒤 사용한다. 경로 확인과 open 사이의 TOCTOU는 dir-fd 검증과 open 뒤 재검증으로 줄이지만 0으로 만들지는 못한다. 지원하지 않는 filesystem/OS에서는 시작 거부가 기본이다.

| 감지 상황 | reader 전이와 bounded 동작 | 완전성 안내 |
|---|---|---|
| 같은 identity, size 증가 | offset부터 chunk를 읽되 완전한 줄만 queue에 확정 | poll 지연 가능 |
| 같은 identity, size < offset (`copytruncate` 등) | `SOURCE_TRUNCATED`로 `FAILED`, 자동 seek/replay 없음 | truncate 전 미읽은 byte 유실 가능 |
| path가 새 identity로 교체/rename 후 재생성 | `SOURCE_REPLACED`로 `FAILED`, 새 파일 자동 병합 없음 | swap 사이 append의 중복·유실 가능 |
| path 소실/권한 변경/symlink swap | fixed code로 `FAILED`, descriptor 닫기 | 재시작 시 gap 가능 |
| rotation 시 partial line | `FAILED` 상태에서 parser에 전달하지 않음; 명시적 `close()`에서 폐기 | partial 유실 가능 |
| 동일 timestamp 또는 내용 재등장 | 줄마다 별도 물리 기록으로 처리; raw 동등성만으로 dedup하지 않음 | rotation 중복 가능성 표시 |

Phase 12는 다른 source가 없는 단일 세션이다. 열린 FD와 path의 `(device,inode)` identity를 내부에서만 비교하며 새 파일을 자동 열지 않는다. 파일 identity 재사용, 크기가 offset과 같아질 때의 copytruncate, 두 poll 사이 여러 rotation은 탐지 불가능할 수 있으므로 **exactly-once / no-loss 보장 없음**. 자동 재개와 multi-source 격리는 후속 설계다.

줄 framing은 raw byte chunk를 source-local bounded partial buffer에 넣고 LF(`\n`)가 끝난 줄만 처리한다. CRLF는 마지막 CR 하나만 제거한다. EOF의 미완성 줄은 다음 poll까지 보존한다. UTF-8 multibyte가 chunk 경계에서 갈려도 **완성 byte line을 strict decode**하므로 깨지지 않는다. 현재 byte 상한은 Section 0과 같다. invalid UTF-8, NUL, 명백한 binary, 너무 긴 줄은 `FAILED`와 fixed code로 멈춘다. Phase 12에는 parser가 없으므로 parser 실패/의도적 무시 수치를 아직 만들지 않는다. 잘못된 줄을 조용히 버리고 `정상 0건`으로 표시하지 않는다. partial은 repr/log/error에 포함하지 않으며 SSE 자체가 없다.

## 4. 3단계 backpressure와 분석 의미

| 구간 | bounded 한도 | 꽉 찼을 때 / 복구 |
|---|---|---|
| Phase 12 reader → trusted complete-line queue | 32 item + 16384 UTF-8 payload bytes, 한 chunk의 미처리 잔여도 최대 1024 bytes | 원자적 enqueue 실패 시 `QUEUE_OVERFLOW`·`FAILED`; 받아들인 sequence만 processed count. FD는 닫고 자동 offset 재시도는 **하지 않음**. 이미 읽은 초과 줄은 유실 가능성이 고정 경고로 보임 |
| analysis → live projection replay | event count + 총 UTF-8 byte cap `TO_BE_BENCHMARKED` | 오래된 공개 frame을 퇴출하되 수집 사실은 버리지 않음. 이어지는 browser는 replay gap + 최신 snapshot. 버퍼 압력이 지속되면 새 publication을 pause하고 `DEGRADED`; 결과를 정상 0건으로 표시하지 않음 |
| SSE → browser | 연결 수 + 각 연결의 frame/item/byte cap + send timeout `TO_BE_BENCHMARKED` | 느린 연결만 종료; server-side session은 계속. 재접속하면 replay 또는 gap/snapshot. storm은 접속 거부/고정 warning; producer를 무한 대기시키지 않음 |

모든 count는 bool 제외 nonnegative signed 64-bit 범위이며 초과는 고정 `COUNTER_LIMIT`로 거부한다. Phase 12 queue는 동기식이며 비동기 `put()` timeout이나 worker slot은 없다. Queue memory는 항목 수와 payload byte 수로 제한하지만 Python 객체 overhead를 포함하지 않는다. 후속 async 경로에서도 `asyncio.Queue(maxsize=0)`은 금지한다. 공개 replay frame과 놓친 원본 line의 count는 향후 서로 구분하고 후자가 추정치이면 `unknown`으로 표시한다.

기존 detector는 batch 전체의 min/max와 per-IP 단일 slot을 사용한다. 따라서 단순히 60초 rolling deque를 넘기면 batch의 범위 선택이 달라질 수 있다. `detect_web_observations()`의 subject 요청 상한 4096, legacy traversal의 반복 decode, raw account/target이 남는 `NormalizedEvent`도 별도 gate다. 세 대안을 비교한다.

| 분석 방식 | 장점 | 결정성·메모리·의미 위험 | 결정 |
|---|---|---|---|
| 이벤트마다 전체 pipeline 재실행 | 코드 재사용 | 파일 I/O·메모리 무한 증가, 이전 결과 변동, event별 비용 | no-go |
| bounded micro-batch + 기존 pure 단계 재사용 | 기존 threshold/관계/위험도 재사용 가능 | event-time window 구성·중복 case revision 검증 필요; batch 동등성 없으면 오표시 | **권장 후속 단계**, 동등성 gate 필수 |
| detector별 incremental state machine | 처리량 우수 | 7개 웹/인증 detection과 auth correlation을 재구현하는 의미 변경 위험 | 성능 측정 뒤 별도 단계 |

분석 worker는 source별 reader sequence와 canonical UTC event time으로 bounded reorder buffer를 만들고, watermark/allowed lateness는 `TO_BE_BENCHMARKED`로 남긴다. 시스템 clock은 watermark와 혼합하지 않는다. 동일 timestamp는 source role·source-local sequence로 안정 정렬하되 이 순서가 endpoint 선택 의미를 바꾸면 relation을 내지 않는다. 재전송 ID는 `(internal file generation, byte span, role)`을 내부에서만 사용하고 **같은 로그 줄 내용/시각만으로는 중복 제거하지 않는다**. late/out-of-order/far-future/past event가 허용된 버퍼를 넘으면 `DEGRADED`, gap/late count와 재검토 요구를 표시한다. Brute/Spray/Web Scanning 60초와 기존 auth 관계 60초, Path Traversal/개별 웹 관찰의 event-local 필요 history를 일람표로 테스트하되 threshold/window를 바꾸지 않는다. 위험도·case는 원래 pipeline과 같은 bounded fact set에서만 만든다. closest-success 정책, Spray case no-go, 웹 독립 관찰, Linux 분리 유지. raw global correlation은 live case에 적용하지 않는다. 현재 pipeline의 global 범위를 보존할 수 없으면 그 output을 **미지원**으로 표시한다.

후속 단계에서는 한 번 공개한 관찰을 자동으로 다른 사실로 덮어쓰지 않고, 비교 가능한 fact key와 증가 revision의 `case_revision`으로 변경·철회를 명시한다. Phase 12–12.2는 이 publication을 하지 않는다. 종료 때 미완성 줄은 추측해 전달하지 않고 미완료 resident record는 abandoned로 계산한다. Detector·case publication은 배치 동등성, bounded memory, privacy test가 통과한 다음 단계에서만 켠다. 현재 UI에는 live 상태 자체가 없다.

## 5. process-local session 및 SSE 계약

V1은 **단일 process-local session**이다. 영구 DB/offset/result가 없고 다중 worker 간 공유도 없다. Config를 받은 launcher가 소유하고 browser는 session을 시작하거나 path를 바꿀 수 없다. Server restart는 새 generation/offset이다. Public session ID는 필요 없으므로 노출하지 않는다. Worker 내부에는 bounded typed event와 필요한 raw account/target이 TTL 동안 잠시 존재할 수 있으나 public `LiveSessionSnapshot`에는 저장하지 않는다. 원본 줄·account·query·argv·파일 경로·credential·cookie/token은 session DTO·replay에 없다. Python 메모리 완전 삭제, crash 후 정리, 다른 로컬 사용자에 대한 격리는 보장하지 않는다.

| 상태 | 진입 조건 | 허용 전이 |
|---|---|---|
| `CREATED` | config 미적용 | `STARTING`, `FAILED` |
| `STARTING` | 파일 검증/reader 준비 | `RUNNING`, `DEGRADED`, `FAILED`, `STOPPING` |
| `RUNNING` | reader/worker 정상 | `PAUSED`, `DEGRADED`, `STOPPING` |
| `PAUSED` | 후속 operator 수집 pause를 위한 상태; reader offset 유지. **V1의 브라우저 표시 pause는 여기에 진입하지 않음** | `RUNNING`, `DEGRADED`, `STOPPING` |
| `DEGRADED` | source 오류·queue pressure·gap 가능성 | 조건 해결 시 `RUNNING`, operator 조치 시 `PAUSED`, `STOPPING`, `FAILED` |
| `STOPPING` | Ctrl+C/종료 요청; 새 analysis 성공으로 표기 금지 | `STOPPED`, `FAILED` |
| `STOPPED` | task/FD/connection 종료 확인 | 종결 |
| `FAILED` | unrecoverable 또는 shutdown deadline 위반 | 종결/새 process에서만 재시작 |

Session 속성은 monotonic revision, 시작·마지막 활동의 UTC 시각, 상태, role tuple, 처리/거부 줄 수, queue 깊이, overflow/gap indicator, 마지막 처리 시각, bounded warning, privacy-safe 관찰 count다. 상태는 결과 확정·완전성의 증거가 아니다. 브라우저 `pause updates`는 화면 반영만 멈추고 server tail 중단과 다르며 별도 문구를 쓴다. V1 수집 시작·중지는 CLI 실행/`Ctrl+C`만 지원한다. Browser mutation endpoint를 만들지 않으므로 다른 local site의 CSRF 시작/중지 문제를 줄인다. 후속 browser pause/stop API가 필요하면 Origin/Host/CSRF token 검증과 local-process 접근 위협을 별도 설계해야 한다. 키보드로 UI의 표시 pause/resume 및 터미널 Ctrl+C가 가능해야 한다.

후속 SSE 후보는 `GET /api/v1/live/status`, `GET /api/v1/live/events` 두 개만이다. `POST /api/v1/live/start`/`stop`은 V1 **없음**. Config 없이 status는 고정 비활성 DTO, events는 고정 거부다. 모든 요청은 peer IP를 Python `ipaddress`로 loopback 검증하며 없는/invalid client, IPv4-mapped IPv6, forwarding header, 외부 Host/Origin 우회는 fail closed한다. Launcher는 `127.0.0.1`, proxy header 비신뢰, CORS 비활성, no redirects to remote. Same-origin `Origin`/Fetch Metadata가 있는 요청은 정확히 검증하되, header 부재나 loopback 자체가 악의적 로컬 프로세스에 대한 인증은 아니다. 다른 로컬 사용자/프로세스가 loopback port에 접근할 수 있으므로 live SSE에 개인정보-safe DTO만 싣고, OS 사용자 격리가 필요한 환경에서는 V1 no-go다.

`/status`는 no-store의 typed snapshot. `/events`는 `text/event-stream; charset=utf-8`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, 연결 수·시간·frame cap과 disconnect cleanup. Proxy buffering을 끄도록 설계하되 reverse proxy/hosted는 지원하지 않는다. Heartbeat는 comment 또는 `heartbeat`의 revision/고정 상태만 포함한다. EventSource reconnect는 브라우저가 `Last-Event-ID`를 보낼 수 있지만 전송·수신 정확성을 보장하지 않는다. Event ID는 비밀이나 audit ID가 아닌 process generation + 증가 sequence, 문법·길이를 정확히 검증한다. Transport generation은 process마다 달라도 **분석 의미/순서에 사용하지 않는다**.

`Last-Event-ID`가 현재 replay의 연속 범위 안이면 `id` 다음 frame부터 재전송한다. 처음 연결처럼 ID가 없으면 정상 `snapshot`, 옛 generation·너무 오래된 ID·ahead ID면 `replay_gap` warning을 포함한 최신 `snapshot`을 보내고 완전성 재확인을 요구한다. Gap을 0건으로 바꾸지 않는다. Reconnect 폭주/느린 client는 연결 단위 제한 후 종료. Browser가 끊겨도 수집은 계속; 서버 종료 시 terminal frame을 보내고 FD/task를 정리한다.

| event | exact public data 의미 (모두 schema `"1"`, revision, UTC 시각, 고정 kind 포함) | 사용 시점 |
|---|---|---|
| `snapshot` | 상태, role별 fixed label, bounded count/queue, completeness flag, 현재 승인된 case/관찰 projection | 첫 연결, replay gap, 재접속 동기화 |
| `observation` | 고정 type·fact ID·risk/confidence·승인된 scalar만, raw 제외 | 동등성 검증 후에만 |
| `case_revision` | case ID·old/new revision·typed 공개 projection 또는 명시적 철회 | 동등성 검증 후에만 |
| `status` | 상태 전이, 마지막 처리 시각, role별 count | bounded coalescing |
| `warning` | 고정 code, 영향 역할, 복구 행동, 완전성 flag | gap/queue/rotation/오류 |
| `heartbeat` | 고정 heartbeat·revision만 | 연결 유지; 개인정보 없음 |
| `terminal_error` | 고정 code, 종료 상태, 재시작 행동 | 재시도 불가 오류 |

`id`는 data event에만 주고 heartbeat가 revision을 증가시키지 않도록 한다. JSON은 explicit Pydantic/typed allowlist에서만 만들고 raw analysis, `jsonable_encoder(raw)`, exception text 전달 금지. Frame별 byte cap과 `Last-Event-ID` 길이·형식 cap은 benchmark/테스트로 확정한다. `retry:`는 bounded 고정값을 측정 뒤 선택하며 client가 임의 rapid reconnect하지 못하게 server connection rate도 제한한다.

모든 data frame은 정확히 `schema_version: "1"`, `kind: 고정 enum`, `revision: 0..2^63-1의 정수(bool 제외)`, `emitted_at_utc: canonical UTC`, `payload: kind별 닫힌 typed DTO`의 5개 JSON key를 갖는다. `id`는 별도의 SSE field로만 전송하며 JSON payload에 복제하지 않는다. `snapshot` payload는 `state`, `roles`(고정 role ID·display label tuple), `processed_line_count`, `rejected_line_count`, `queue_depth`, `gap_possible`, `last_processed_at_utc`, `observation_count`, `bounded_warnings`의 exact key를 갖는다. `status`는 같은 집계에서 변경된 revision의 **전체** 값이지 임의 patch가 아니다. `warning`/`terminal_error`는 고정 `code`, 영향 `role` 또는 `null`, `recovery_action`, `retryable`, `gap_possible`만 허용한다. `observation`과 `case_revision` payload는 기존 공개 case projection의 고정 필드만 재검증해 구성하고 새 raw key를 전파하지 않는다. `heartbeat`는 comment-only를 우선하여 JSON event도 revision도 만들지 않는다. 범위 밖/unknown enum·추가 key·bool-as-int·잘못된 UTC는 frame 전체 거부다.

## 6. 접근 가능한 live UI와 개인정보

새 결과는 목록에 곧바로 삽입하지 않는다. 짧고 낮은 빈도의 `aria-live="polite"` 상태 count와 **새 결과 N건 보기** native button만 갱신한다. 사용자가 누르면 검증된 batch를 append하고 기존 읽기 위치·focus·Timeline DOM 순서를 유지한다. 자동 scroll/focus/re-sort/삭제, 이벤트별 screen reader announcement, countdown/autoplay/animation은 없다. `업데이트 표시 일시 중지`/`다시 표시`는 keyboard-only로 조작되며 **서버 수집은 계속**임을 명시한다. 실제 수집 종료는 터미널 `Ctrl+C`; UI에는 고정 방법을 표시한다. 연결 끊김, `DEGRADED`, queue pressure, 유실 가능성, 빈 결과(`안전함 아님`)을 색상 이외 텍스트로 표시한다. Visible focus, semantic headings/landmarks, table caption/`th scope`, reduced motion, 좁은 화면과 200% 확대를 수동 확인한다. WCAG 2.2 AA 준수를 자동으로 주장하지 않는다.

공개 DTO/SSE/UI/log/OpenAPI/metrics/shutdown에는 전체 source path·basename·account·HTTP path/query·Linux exe/argv/CWD·raw line·partial line·credential·cookie/token·내부 exception/repr가 없어야 한다. 운영 log는 고정 source role, 전이, signed-64 count, fixed code, queue depth, duration/revision만. 오류는 fixed code·한국어 복구 행동·retryable과 완전성 flag이며 raw exception chaining을 public/log에 남기지 않는다. Python 내부 parser/worker의 trusted state에는 join을 위한 계정·target이 TTL 동안 남을 수 있고, memory dump/debugger/악성 내부 코드는 보호 범위 밖이다. Browser close 후에도 bounded worker state는 세션 종료까지 남으므로 ‘저장하지 않는다’는 **영구 저장 없음**으로만 표현한다.

Canary 계획: 서로 다른 합성 account, HTTP path/query, credential, exe/argv/CWD, config source path, filename, partial line, parser exception을 넣고 SSE/status/UI DOM/browser console/stdout/stderr/application log/error/model repr/OpenAPI/metrics/shutdown을 전부 검색한다. 원문·부분 segment·URL-encoding·JSON-escaped 형태를 검사한다. Known private path를 테스트 오류 diff에도 넣지 않는다. `NormalizedEvent.raw` 자체를 generic serializer나 logger에 전달하는 테스트는 반드시 실패해야 한다.

## 7. 위협 모델 (예방 / 탐지 / bounded failure / 잔여 위험)

| 위협 | 예방 | 탐지·bounded failure | 잔여 위험 |
|---|---|---|---|
| 악의적 local producer, 무한 append, 긴 줄, 고정 partial | chunk·line·partial·rate/queue cap | source pause + fixed warning | FD backlog 증가/유실 가능 |
| invalid UTF-8, NUL/binary, parser 예외 반복, crafted percent encoding | 완전 줄 strict decode, typed dispatch, web target bound; legacy traversal 별도 gate | 오류 count 및 `DEGRADED`; 반복 예외 budget 초과 시 source 중단 | parser CPU 폭주를 hard-stop하려면 별도 process 필요 |
| 빠른 rename rotation, copytruncate, replacement, inode 재사용 | fstat/path identity, bounded drain, no-follow 재open | rotation/gap warning, 재open budget 초과 시 pause | poll 사이 변경·copytruncate 데이터 유실/중복 |
| symlink swap, TOCTOU, FIFO/device 등록, 권한 상실 | absolute path, dir-fd no-follow, open 뒤 regular/owner/permission 확인 | 안전 검증 불가면 reject/degraded | filesystem·OS별 race 완전 제거 불가 |
| queue exhaustion, high-cardinality IP/account/target, 미래/과거 timestamp | item+byte+subject+history+lateness cap | pressure/gap 또는 fail closed; 정상 0건 금지 | 합성 benchmark 밖 load는 지원 안 함 |
| 느린 browser, reconnect storm, 많은 local 연결 | 연결/frame/replay cap·rate, browser 표시 batch | 느린 client 종료·snapshot/gap | loopback의 다른 local process가 자원 소모 가능 |
| disk full, source disappearance, shutdown 중 append | 원본 변경/서버 기록 없음, FD close·bounded drain | `DEGRADED`/terminal warning | writer 또는 OS의 데이터 손실은 통제 못 함 |
| server crash, browser close | 전경 process, in-memory only, restart FROM_END | 다음 시작에 restart-gap 안내 | crash 중 append 누락, secure memory erasure 없음 |
| 다른 로컬 사용자/포트 포워딩/hosted 노출 | loopback bind·peer 검사·same-origin, CORS off, privacy-safe DTO | 고정 접근 거부·연결 제한 | loopback은 사용자 인증이 아님; 공유 host와 공개 노출 no-go |

## 8. 대안 비교와 Phase 12 최소 수용 범위

| 선택 | 대안의 비용/위험 | V1 결정 |
|---|---|---|
| 변화 감지 | Linux inotify는 플랫폼 종속·event coalescing/overflow, Apple FSEvents는 디렉터리 계층/latency, 외부 watcher는 새 dependency | **portable polling**. identity 재검증을 항상 하고 latency는 측정 전 미보장 |
| 처리 | 전파일 재실행은 unbounded; incremental state machine은 의미 drift; micro-batch는 bounded state와 parity 필요 | 순차적으로 **bounded tail/status → 동등성 검증된 micro-batch** |
| session | 여러 session은 ownership·리소스 증가; DB는 영구 민감 state | **단일 process-local session** |
| 시작 | FROM_START는 초기 backlog; checkpoint는 저장/복구 | **FROM_END only**, 재시작 gap 명시 |
| UI 전달 | polling은 반복 요청, WebSocket은 양방향 공격면, SSE는 일방향·replay 관리 필요 | **SSE**와 읽기 전용 status; mutation endpoint 없음 |

다음 표는 각 대안을 개인정보(P), 결정성(D), 유실/중복(L), 접근성(A), 구현·운영 부담(C/O) 축으로 비교한 결정 기록이다. `낮음/높음`은 측정치가 아니라 상대 설계 부담이다.

| 영역·대안 | P / D / L / A / C·O 핵심 차이 |
|---|---|
| 감지: polling | path는 서버 내부만; 명시적 poll step으로 D 우수; poll 사이 L 가능; UI는 coalesced update 가능; C·O 낮음 |
| 감지: inotify | path 이벤트 취급 주의; 커널 event coalescing/overflow로 L 완전 해결 안 됨; Linux 전용 C·O 상승; A 자체 효과 적음 |
| 감지: FSEvents | 디렉터리 계층 metadata 주의; latency/coalescing으로 L 가능; macOS 전용 C·O 상승; A 자체 효과 적음 |
| 감지: 외부 watcher | dependency·권한·path 처리 확대; 이벤트 순서 D/유실 L 재검증 필요; C·O 높음, A 직접 효과 없음 |
| 처리: 전파일 재실행 | raw 파일 반복 접촉(P), 지속 비용(C·O) 무한; 중복 publication(L), 읽기 위치(A) 교란; D도 rotation에 취약 |
| 처리: bounded micro-batch | raw TTL을 제한(P); event-time 정렬/parity로 D 증명 가능; late/gap L 경고 필요; 사용자 batch 반영(A); C·O 중간 |
| 처리: incremental state machine | 최소 raw retention 가능(P)하지만 별도 규칙 D drift 위험; 재시작 L 복잡; UI revision(A), C·O 최고 |
| 세션: 단일 process-local | raw 상태 한 곳(P), revision D 단순; crash L은 남음; UI 상태 A 단순; C·O 낮음 |
| 세션: 다중 | session 간 raw/권한 격리(P)·ordering(D)·gap(L) 어려움; UI 구분(A)·C·O 상승 |
| 세션: persistent DB | 삭제/backup(P)·checkpoint D/L 설계 필요; 재개 UI(A) 유리할 수 있으나 C·O 높음 |
| 시작: FROM_END | 기존 raw 재처리(P) 최소; 재시작 gap(L) 명시; D 간단, UI(A) 설명 필요, C·O 낮음 |
| 시작: FROM_START | 과거 raw backlog(P)·유실/중복(L) 경계 복잡; D 정렬 필요, UI(A) 초기 지연; C·O 높음 |
| 시작: checkpoint | 영구 offset/identity(P)와 atomicity(D/L) 필요; 재개 UI(A) 유리하나 C·O 높음 |
| 전달: polling | 반복 status 접촉(P), revision D 단순, gap L 비교 필요; UI(A) batch 가능; C·O 낮음 |
| 전달: SSE | 공개 DTO만(P), ID/revision D·replay L 필요; 조용한 UI(A) 적합; C·O 중간 |
| 전달: WebSocket | 양방향 입력 공격면(P), message order D·replay L 별도; UI(A) 이점 제한, C·O 높음 |

Phase 12의 **당시 실제 구현 범위**는 application/SSH/access 중 명시된 **1개 source**, `FROM_END`, 단일 동기식 session, regular-file/identity gate, 명시적 `poll_once()`, chunk·완전 줄 framing, bounded trusted-record queue와 개인정보 안전 snapshot이었다. Parser와 detector는 tail core에서 호출하지 않는다. 당시 CLI flag·자동 polling loop·status API·SSE·browser UI·Ctrl+C 연결은 없었다. 이후 Phase 12.1~14.1에서 parser·detector·읽기 전용 status/SSE를 순서대로 추가했지만 자동 polling과 UI는 여전히 없다. `observation/case_revision`은 별도 gate가 필요하며 화면에 `탐지 동작 중`이라고 표시하지 않는다. Linux live parsing은 다중 record framing·privacy 한도를 별도 설계한 후에만 추가한다.

No-go: unbounded queue/list/history, raw event SSE, browser arbitrary path, recursive watch, silent overflow, rotation 추측 병합, 기존 threshold·risk·case 변경, input-order dependence, canary 노출, shutdown 후 task/thread/FD 잔존, 실제 sleep에 의존하는 test, hosted/public collector, event별 LLM. 기존 Path Traversal 반복 decoding을 live에서 bounded하게 실행할 수 있는지 입증 전에는 web 관찰 publication도 no-go다.

## 9. benchmark 및 구현 전 테스트 계획

Benchmark는 fixed synthetic inputs와 동일 머신·Python/OS metadata를 기록하고 저속 정상, 순간 burst, 지속 고속, 긴 줄, 많은 IP/account/distinct target, Linux multi-record burst(후속), 느린 SSE client, disconnect/reconnect를 사용한다. 측정: lines/s, bytes/s, parser/detector/correlation throughput, queue peak bytes, per-subject state peak, SSE frame 크기, browser DOM render cost, append→관찰 p50/p95/p99 latency, shutdown latency, rotation recovery. 평균뿐 아니라 peak RSS/tracemalloc와 p95/p99를 기록한다. 이 수치로 poll interval, chunk/line/partial, source count, queue item+byte, subject/history, replay/frame/connection, enqueue/send/shutdown timeout을 정하고 **한도 바로 아래/정확히/초과**를 고정 테스트한다. 합성 benchmark를 운영환경 탐지율/지연 보장으로 일반화하지 않는다.

결정적 fake clock·fake filesystem/explicit `poll_step()`를 사용해 실제 장시간 sleep 없이 다음을 시험한다: 한 줄 append, 여러 줄 append, partial UTF-8, newline 없는 partial, 긴 partial, invalid UTF-8, NUL/binary, truncation, rename rotation, copytruncate, 소실/재출현, 권한 상실, symlink swap, 중복 timestamp, 역순 timestamp, 정확한 detector 경계, queue full, slow consumer, SSE disconnect/reconnect·replay 성공·gap, cancellation, graceful shutdown, 강제 worker 예외, privacy canary, event/file permutation, UTC/KST, no leaked task/thread/FD. 동일한 합성 이벤트를 현재 batch pipeline과 live candidate에 넣어 detection endpoint/count, closest-success, risk, case rule/revision, independent 관찰과 JSON order를 비교한다. Late event가 한도를 넘는 경우는 **불완전 경고**여야 하며 parity 성공으로 포장하지 않는다. Actual filesystem integration test는 temporary file+rotation을 별도로 수행한다.

## 10. 연구 근거, 프로젝트 정책, 남은 한계

확인일: 2026-10-11. 아래 자료는 **인터페이스·실패 방식의 근거**이며 queue 숫자, polling 주기, 탐지 임계값의 외부 권위가 아니다.

| 공식 1차 자료 | 설계에 반영한 관찰 |
|---|---|
| [WHATWG Server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html) | `text/event-stream`, `id`/`Last-Event-ID` 재연결, heartbeat·replay gap 고려 |
| [Python 3.12 asyncio Queue](https://docs.python.org/3.12/library/asyncio-queue.html), [Task cancellation](https://docs.python.org/3.12/library/asyncio-task.html) | nonzero `maxsize`, `put` 대기/timeout, cancellation `try/finally`·task join |
| [Starlette StreamingResponse](https://www.starlette.io/responses/) | async iterator로 SSE를 내보내되 연결 해제·slow consumer는 별도 구현/검증 필요 |
| [Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html), [Apple File System Events](https://developer.apple.com/documentation/coreservices/file_system_events) | 플랫폼별 notification이 달라 portable polling 선택; 변경 통지는 정확한 line 카운트가 아님 |
| [logrotate manual](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) | copytruncate 자체에도 손실 구간이 존재하므로 no-loss 주장 금지 |
| [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final), [SP 800-61 Rev.3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | 로그 관리와 조사 보조라는 범위; 관찰을 사고·침해 확정으로 과장하지 않음 |
| [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | 입력 유래 민감값과 log injection을 운영 로그에 재출력하지 않는 경계 |

**Observable Evidence Mapping:** 파일 byte 증가·완전 LF 줄·parser가 만든 UTC event만 detector 입력 후보가 된다. IP·account join은 trusted bounded worker에서만, 웹 target은 bounded canonicalization/기존 승인 pattern 판단에만, Linux argv/path는 후속 별도 분류에만 쓴다. SSE에는 승인된 count/type/time/risk/confidence/limitation만 projection한다. Writer가 기록하지 않았거나 rotation 중 잃은 byte, 사용자 의도·공격 성공·인과관계·파일 유출은 이 telemetry로 성립하지 않는다.

**남은 한계:** 현재 batch detector는 live window semantics가 정의되어 있지 않고 Path Traversal decode는 반복형이다. Phase 12에서 bounded tail/status까지만 구현하고 관찰 publication은 parity·privacy·성능 gate까지 보류한다. Polling과 process-local memory는 crash·rotation·다른 local user·OS permission 문제에 대해 완전성/격리를 보장하지 않는다. 외부 인증·tenant isolation·배포 보호가 없으므로 hosted/public exposure는 계속 no-go다.
