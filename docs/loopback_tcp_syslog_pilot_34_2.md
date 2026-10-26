# Phase 34.2 — bounded loopback TCP Syslog pilot

## 판정과 범위

Phase 34.2는 한 역할(application 또는 SSH)의 **합성 입력 loopback pilot**으로만 `CONDITIONAL_GO`다. 이 조건부 판정은 자동 원격 수집, 실제 사용자 로그, 조직 운영, 공개 API/SSE/UI 게시를 승인하지 않는다. IPv4 `127.0.0.1` 또는 IPv6 `::1` 중 하나의 고정 loopback literal에 high port로 bind하며, port 0은 test-only 구성에서만 허용한다. UDP, newline framing, TLS/mTLS, 외부 interface, access, cross-source, checkpoint, disk spool, 재연결, AI/LLM/embedding은 지원하지 않는다. Exactly-once나 무유실도 보장하지 않는다.

`app/log_collection/runtime.py`는 Phase 34.1의 immutable core config, incremental octet-counting decoder, bounded queue를 재사용한다. listener는 runtime의 내부 synthetic-pilot API에서만 시작한다. source role은 application/SSH 중 하나로 고정되고, 최대 연결은 2개다. peer address는 읽거나 분석 주체로 쓰지 않는다. 같은 연결의 frame은 wire order대로 enqueue되며 연결 간 처리 순서는 event loop의 도착·처리 scheduling 순서다.

## 구현 계약

Runtime config는 닫힌 `tcp-syslog-runtime/v1` dataclass다. 허용 필드는 schema version, source role, `ipv4`/`ipv6` family 선택, port, connection limit, idle/read timeout, 기존 parser timezone(`Asia/Seoul`), fixed startup mode와 frame/buffer/queue 상한이다. wildcard, hostname, 임의 bind 주소, access, bool-as-int, privileged port, unknown fields와 test-only가 아닌 port 0은 거부한다. 주소는 family 선택에 따라 코드의 고정 literal로만 결정된다. Config repr/error는 원문·경로·주소를 싣지 않는다.

이 구성은 수신 경계와 기존 file runtime 사이의 **migration/compatibility**를 분리한다. File config, checkpoint, event schema, publication epoch는 재사용하거나 변경하지 않는다. 동일 role의 file monitor와 TCP listener를 함께 켜지 않는 단일 synthetic runtime 후보로 제한한다.

각 connection은 독립 decoder를 가진다. read 크기는 4096 byte 이하, decoder 입력은 configured buffer 이하, complete frame은 최대 8192 byte, prefix는 최대 6자리다. Runtime config는 queue를 최대 256 event/1 MiB로 제한하고, parser/analysis history는 최대 256 record/256 KiB다. Core의 event·byte 상한은 모두 enqueue 전에 확인된다. 이 고정 queue가 **backpressure** 경계다. Queue full은 해당 연결을 종료하고 listener를 새 연결에 닫은 `DEGRADED` 상태로 둔다. 이때 이미 accepted된 queue item은 processor가 마무리하거나 stop 시 dropped로 계상한다. Partial frame, malformed length, invalid UTF-8, NUL/control, oversized payload는 정상 record가 아니며 connection decoder를 폐기한다. Idle/read timeout은 고정 category로만 집계된다.

완성한 text frame은 기존 `parse_live_records` adapter와 role parser를 거쳐 기존 detection·correlation·risk·case accumulator에 전달된다. Parser rejection은 parsed event와 별도 count다. 분석 commit이 끝난 후 detector history 안의 parser 원문은 원래 UTF-8 byte 수를 보존하는 공백으로 덮어쓰므로 history byte budget은 유지되고 raw line은 장기 상태에 남지 않는다. 이 adapter는 existing file worker/checkpoint/publication을 사용하지 않는다. 결과는 `internal_analysis_summary()`에서만 합성 테스트가 읽으며 API, SSE, UI, report, checkpoint 또는 persistent store로 게시되지 않는다. 새 listener 시작은 UUID 기반 process-local ephemeral epoch를 만들지만 snapshot이나 output에 넣지 않는다.

Safe status에는 schema, source role, transport enum, lifecycle state, count/limit, UTC start/last-success time, 고정 error category와 next-action category만 포함된다. Raw frame, payload hash, account, IP, hostname, source/bind port/address, path, credential, rationale, exception text와 object repr는 제외된다. Connection limit 초과는 payload를 읽지 않고 socket writer를 닫는다. Listener bind 충돌은 `PORT_IN_USE`, 기타 bind 실패는 `BIND_FAILED`다.

Lifecycle는 `STARTING → LISTENING → DEGRADED/FAILED/STOPPING → STOPPED` 계약으로 제한된다. Startup은 config/core/analysis 준비 후 bind하고 나서만 LISTENING을 표시한다. Stop은 accept close, connection/processor cancel 및 join, writer close, bounded queue close, analysis reference cleanup, listener wait-closed를 시도한다. Cleanup 하나가 실패해도 나머지를 계속 시도하며 마지막 상태는 `SHUTDOWN_FAILED` category일 수 있다. 반복 stop은 안전하다. Bind 실패와 runtime failure의 예외는 고정 코드만 표시한다.

## 위협·실패 모델

Loopback은 인증이 아니다. 같은 UID 또는 로컬의 악성 process는 임의 frame을 주입할 수 있고 payload에 적힌 host/IP는 송신자를 증명하지 않는다. Framing은 prefix overflow, leading-zero, sign/whitespace, oversized declaration, invalid UTF-8/control, incomplete EOF를 거부한다. StreamReader의 bounded limit와 `read(n)`은 추가 transport buffering을 제한하지만 Python object overhead와 OS socket buffers를 byte-for-byte RSS 상한으로 보장하지 않는다. Slow partial frame은 read/idle timeout과 decoder byte cap으로 종료한다. 이 timeout·queue/history 상한은 프로젝트 pilot engineering limits이며 표준 권고나 운영 SLA가 아니다.

Malformed frame·parser rejection·queue overload·analysis failure는 성공으로 표시하지 않는다. Accepted는 validation과 queue admission 완료를 뜻한다. Queue admission 뒤 분석 실패는 rollback을 주장하지 않고 `FAILED`로 멈춘다; queue에서 꺼냈지만 분석이 실패한 item은 dropped count에 반영한다. 재연결은 새 decoder를 만든다. 재시작은 새 volatile epoch이며 이전 frame 복구/재게시, duplicate 탐지, 재처리를 보장하지 않는다. Stop 중 처리되지 않은 queue item은 처리 완료가 아니다. Crash, SIGKILL, 전원 장애 후의 메모리 정리나 수신 연속성은 보장하지 않는다. Listener가 내려간 downtime 동안의 이벤트 유실은 복구하지 않는다.

No raw message logging, metrics labels, spool, dead-letter, packet capture, trace, checkpoint 또는 CI artifact를 생성하지 않는다. 개인정보가 될 수 있는 account/IP 및 raw bytes/text는 decoder, queue와 parser call 경계에서 bounded memory에 잠시 존재한다. Parser 결과가 trusted internal analysis state에 포함하는 account/IP 등은 기존 구조와 동일한 분석 메모리 범위에서만 존재하며 새 public projection은 만들지 않는다. Swap, crash dump, same-UID malware와 host compromise는 잔여 위험이다. Prompt-injection 문자열은 일반 payload data이며 도구·파일·네트워크/AI 동작을 실행하지 않는다.

### Research basis

- [RFC 6587](https://www.rfc-editor.org/rfc/rfc6587.html) describes legacy Syslog over TCP framing; octet counting uses a decimal message length, one space, then exactly that many octets. Its Historic status and security discussion do not establish this unauthenticated loopback pilot as a secure remote transport. RFC 5424 with TLS is outside this phase.
- [Python 3.12 asyncio streams](https://docs.python.org/3.12/library/asyncio-stream.html) documents `start_server`/StreamReader limits and flow control. The application still enforces its own frame, connection, queue and history limits; the library limit is not claimed as a total process-memory cap.
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) recommends sanitizing event data and avoiding sensitive data in logs. This runtime emits fixed categories/counts and omits raw frames and peer identity.
- The parser mapping is based on the repository's existing `parse_live_records`/application and SSH parser contracts, not inferred Syslog hostname identity. The existing deterministic analysis pipeline remains authoritative.

### Observable evidence mapping

| Pilot input | Existing parser path | What this phase can establish | Limitation |
|---|---|---|---|
| Complete octet-counted UTF-8 frame | Existing application parser | The parser recognized the existing application event fields; the existing detector/correlation/risk/case summaries may update in memory | No authenticated sender, persistence, delivery guarantee or public publication |
| Complete octet-counted UTF-8 frame | Existing SSH parser | The parser recognized the existing SSH event fields; the same existing deterministic analysis summaries may update in memory | Payload host/IP is not sender identity; no cross-source correlation |
| Malformed/incomplete/oversized frame | No parser call | A bounded framing rejection count/category | No raw payload diagnostic; rejected content is not evidence |
| Role-incompatible complete frame | Existing parser rejection outcome | A parser-rejected count, distinct from accepted parsed events | Does not establish a security event |

Detection remains evidence of observed telemetry, not confirmed compromise; correlation is not causation. The pilot's parser-compatible input is the repository's existing log line format carried as a Syslog frame. A full RFC 5424 envelope adapter is not introduced.

## Verification

Start gate: `1c19e35d5465e8cdfde42455c4b1e205ff541477`, push CI run `40269516954`, completed/success. CI recorded Ubuntu 24.04 locked install, 2785 passed/2 existing warnings, Phase 33.5 Linux smoke, Chromium/axe 14 states and 0 external requests; artifact count 0. v0.4.0 tag and Release target remained `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

This change adds an Ubuntu workflow subprocess smoke, but this local change has not yet run at a new SHA in GitHub Actions. Therefore Ubuntu execution of the new listener smoke is **NOT_TESTED** in this record; the prior run predates the listener. Local macOS focused tests and subprocess smoke are reported separately. No CI artifacts upload the synthetic input or runtime output.

`tests/smoke_tcp_syslog_34_2.py` starts four separate child processes: application and SSH each run once with SIGINT and once with SIGTERM. Each uses an isolated temporary HOME/private directory, sends five failed and one successful synthetic authentication record plus one parser-rejected record, exercises a split frame and a batched write, waits for analysis, then verifies graceful shutdown and immediate port rebind. It prints only a fixed completion marker with role and counts. CI runs this script under Ubuntu 24.04 as a separate step after full pytest.

Local focused runtime tests cover closed config/port/bind, status privacy, both parsers, partial and multiple frames, analysis result parity, parser/framing rejection, third-connection rejection, idle timeout, listener release/idempotent stop, ephemeral epochs, queue overload, sanitized injected bind/parser/queue/cleanup failures, and repeated-run analysis determinism. Existing Phase 34.1 property tests cover random bytes, arbitrary frame chunking, caps and UTF-8/control validation. Full project regression and required browser/privacy checks are run before commit and their actual results are reported separately.

Local macOS 15.7.7 arm64 / Python 3.12.7 regression evidence: pre-change baseline **2785 passed / 2 existing warnings**; final suite **2809 passed / 2 existing warnings**. Phase 34.1/34.2 and 34.0/34.1 documentation focused suite: **84 passed**; repeated standalone subprocess smoke: `TCP_SYSLOG_SMOKE_COMPLETE roles=2 subprocesses=4 synthetic=1`. Evaluation-focused **36 passed** includes the repository assertions for synthetic boundary corpus 79/79, Linux process corpus 21/21, and risk/case 70/70. `npm ci --ignore-scripts --no-audit --no-fund` succeeded; Chromium/axe reported 14 states and 0 external requests. `uv sync --locked --dev`, `uv lock --check`, Python compile, Node syntax, `git diff --check`, and changed-file secret/private-path scan passed. The browser and package checks do not constitute Safari or Ubuntu listener evidence.

The test-only manual benchmark is `tests/benchmark_tcp_syslog_runtime_34_2.py`. It separates server start, connect, send-to-queue admission, parser/analysis, status snapshot and graceful close for application/SSH at 1, 32 and 256 frames. It uses one warm-up and three samples, reports median/p95/max and synthetic payload bytes, with OS/architecture/Python. One local run on macOS 15.7.7 arm64 / Python 3.12.7 measured parser+analysis median/p95/max:

| Role | Frames | Median (ms) | p95 (ms) | Max (ms) |
|---|---:|---:|---:|---:|
| application | 1 | 5.661 | 5.676 | 5.676 |
| application | 32 | 12.901 | 13.090 | 13.090 |
| application | 256 | 954.679 | 957.412 | 957.412 |
| SSH | 1 | 5.666 | 5.695 | 5.695 |
| SSH | 32 | 11.726 | 12.024 | 12.024 |
| SSH | 256 | 967.834 | 977.728 | 977.728 |

At 256 frames, queue admission median was 4.465 ms (application) and 5.022 ms (SSH); server start median was 0.145–0.178 ms, connect 0.267–0.311 ms, status 0.008–0.015 ms and graceful close 0.195–0.269 ms across roles/sizes. Each cell has only three measured samples. These are developer observations, not a production SLA or worst-case guarantee; benchmark output excludes payload content.

`tests/soak_tcp_syslog_runtime_34_2.py` ran locally on that macOS host with a slow partial connection, fast 32-frame producer, second connection with four paced frames, 20 malformed reconnect attempts, and shutdown, for each role. Application and SSH each reported 36 accepted/parsed/analyzed frames, 21 rejected frames (20 malformed plus one incomplete), peak queue 32 events/2656 bytes and 32 events/3040 bytes respectively, below 256 events/1 MiB; process-wide peak RSS observations were 38,797,312 and 38,928,384 bytes. FD count was 7 before and after, listener released and connection tasks 0. Elapsed times were 270.351 ms and 278.878 ms. This is a short synthetic development soak, not long-duration/operational evidence.

## Compatibility and remaining gates

No public API/OpenAPI/SSE/UI, schema 2/3, subject alias, lexical guidance, restricted report, file monitoring v1/v2/v3, checkpoint, dependency or `uv.lock` contract changes. The Phase 33.5 report remains synthetic-only; it is not connected to this listener. Embedding remains production `NO_GO`; local LLM remains `STORAGE_SETUP_BLOCKED`; Gemini remains unconnected.

Phase 34.2 local synthetic pilot alone may be `CONDITIONAL_GO` after local and new-SHA CI verification. Real user logs and organization use remain `NO_GO`. Remote collection remains `NO_GO` until a separately designed authenticated, encrypted transport/collector gate. Exactly-once, no-loss, restart recovery, long-duration soak, production memory/SLA, arbitrary syslog variants, real-user acceptance, IPv6 availability on every target, crash/power-loss cleanup and hostile same-UID isolation are not claimed.
