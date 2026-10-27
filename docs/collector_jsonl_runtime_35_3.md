# Phase 35.3 — bounded JSON Lines collector runtime

검증 기준: **2026-10-26**, local macOS development environment. 시작 SHA `b37b4c063d4d0b2be0a2fa544d3c5e6e23ef2279`; exact push CI `40339602044` 성공(전체 pytest 2,905 passed, 기본 TCP smoke, Linux reliability 80-run, management smoke, restricted report, axe 14 states, artifact 0). This is synthetic-only evidence; it does not approve user data or operations.

## Scope and decision

`app/log_collection/jsonl_runtime.py` adds a separate IPv4/IPv6 loopback listener that reuses the Phase 35.2 incremental JSON Lines decoder and bounded queue. Each runtime is fixed to one `application` or `ssh` role and routes each validated payload through that role's existing `parse_live_records` adapter and the existing deterministic detection and analysis accumulators. There is no role fallback. User account metadata is not loaded; analysis uses an empty metadata tuple.

No Vector binary, socket outside loopback, public API/SSE/UI/HTML, parser rule, checkpoint, publication, durable replay, management CLI, shared collection lock, or external process is used. Runtime results remain in bounded in-memory accumulators and the status contains counts only. This synthetic runtime is `GO` only for the bounded Ubuntu acceptance scope recorded in [Phase 35.3A](collector_jsonl_runtime_linux_acceptance_35_3a.md). Actual Vector integration remains `NOT_TESTED`; actual user data and organizational operation remain `NO_GO`.

실제 사용자 자료와 조직 운영은 계속 `NO_GO`이며, 이 단계에서 **Vector 실행**, 설치, 외부 process, public API 연결은 하지 않았다.
공개 API, SSE, UI에는 연결하지 않았다.

## Runtime contract

Closed immutable config schema is `collector-jsonl-runtime/v1`. Allowed hosts are exactly `127.0.0.1` and `::1`; hostnames (including `localhost`), wildcard, mapped, private, and link-local addresses are rejected. Port 0 is test-only; other ports are 1024–65535. Connection limit is 1–2. Read chunk is at most 4,096 bytes. The Phase 35.2 decoder continues to enforce 65,536-byte record and connection buffer, 8,192-byte UTF-8 payload, 32 records per feed, and the queue enforces 256 events/1 MiB. Analysis history is capped at 256 records/256 KiB. These are project test bounds, not resource or service guarantees.

States are `CREATED`, `STARTING`, `RUNNING`, `DEGRADED`, `FAILED`, `STOPPING`, `STOPPED`; invalid transitions are rejected. Fixed error categories use the `JSONL_RUNTIME_` prefix. `EADDRINUSE` is classified through `errno.EADDRINUSE`; other bind failures collapse to `BIND_FAILED`. Status excludes endpoint, payload, collector alias, sequence hint, host identity, paths, hashes, and internal exception text.

Each connection owns a decoder and bounded reader. Completed lines are counted as received; only core-validated envelopes increment validated; successful queue admission is separate. A queue-full event is rejected and closes that connection; it is never silently dropped or acknowledged. Queue consumption is a single bounded synchronous step per item and connection handlers yield after each admission. Parser unrecognized and infrastructure failures are separate. A pipeline infrastructure failure stops new collection; it does not roll back already committed analysis. Queue items remaining during stop are counted as processing drops before queue cleanup. No retry, dedup, replay, checkpoint, or exactly-once behavior is claimed. `sequence_hint` and `retry_hint` do not affect processing order or identity.

## Pipeline and privacy

### Analysis parity

The exact `source_role` configured at runtime is required in every envelope. The existing parser adapter receives one `LiveTailRecord` with the queue receipt ID; parser rejection does not trigger a different parser. Detector proposal, analysis proposal, prevalidation, and commits use the existing in-memory accumulators. No publication adapter is created. Once analysis commits, the retained normalized event's raw field is replaced with a same-size whitespace placeholder to maintain existing history byte accounting. The accumulator's public-safe analysis snapshot contains only existing ordinal summaries/counts. Runtime status exposes only stage counts and bounded history counts.

The payload, collector alias and sequence hint exist transiently in decoder/queue/parser memory. They are not serialized into runtime errors, repr, status or logs. Account/IP/hostname may naturally be present in trusted analysis state, as in the existing internal pipeline, but are not added to this runtime's status or any public projection. No restricted report or lexical guidance call is made. Memory overwrite is not secure erase; process memory, swap, crash dumps and host compromise remain outside this contract.

## Faults, lifecycle, and resource limits

The runtime prepares the queue consumer before opening the listener. Bind failure closes the worker and listener resources and reports only a fixed category. A third connection is closed without reading. Per-connection malformed input, invalid role/schema, timeout, and incomplete EOF close that connection; other clients can continue. Stop closes the listener, closes/cancels connection tasks, cancels the consumer, accounts and clears queued work, and closes both accumulators; repeated stop is safe. Cleanup attempts continue across independent resources. This does not promise recovery from process crash, SIGKILL, power loss, or interpreter failure during cleanup.

No shared collection lock is acquired in this phase. Until a later management integration explicitly unifies locks, concurrent operation with a file monitor or Phase 34 TCP collector is not approved. Tests use only fresh synthetic runtimes and loopback sockets.

## Research Basis

This change does not alter parser, detector, correlation, risk, or case rules. It reuses existing role-specific parsing and analysis contracts. Python's official asyncio streams documentation describes `start_server` reader limits, bounded `read(n)`, writer close/`wait_closed`, and stream flow control; the runtime uses bounded `read(n)`, a configured stream limit, explicit timeouts, and close/wait cleanup. These API descriptions are not proof of OS-level memory caps or delivery guarantees: [Python asyncio streams](https://docs.python.org/3/library/asyncio-stream.html). Documentation checked 2026-10-26.

## Observable Evidence Mapping

| Observable input | Existing path reused | What this phase establishes | What it does not establish |
|---|---|---|---|
| One valid JSONL record with fixed `application` role | application parser registry → deterministic accumulators | the configured parser/analysis path can process a bounded synthetic record | authenticity of the sender or completeness of source logs |
| One valid JSONL record with fixed `ssh` role | SSH parser registry → deterministic accumulators | same role-specific path for synthetic SSH format | remote-source identity or operational SSH coverage |
| Invalid/role-mismatched JSONL envelope | Phase 35.2 decoder | fixed rejection without payload in status/error | Vector serialization compatibility |
| Analysis infrastructure exception | runtime failure path | no success count is added; collection stops and cleanup is attempted | transaction rollback or replay |

Detection remains evidence-based; parser recognition is not attack confirmation. Analysis snapshots and status counts do not establish compromise or safety.

## Validation and benchmark

TDD 확인: 최초 runtime 계약 테스트는 구현 전 `app.log_collection.jsonl_runtime` 부재로 collection 실패했다. Fault test에서 queue-full 뒤 `wait_until_processed()`가 실제로 `READ_TIMEOUT`으로 잘못 보고되는 것도 재현했고, 고정 `QUEUE_FULL`을 즉시 반환하도록 수정했다. 최종 runtime/core/documentation focused suite는 **51 passed**; 별도 subprocess smoke는 application/SSH, SIGINT/SIGTERM 각 조합을 수행해 `COLLECTOR_JSONL_RUNTIME_SMOKE_PASS roles=2 subprocesses=4 synthetic=1 leaks=0`를 출력했다. 전체 pytest는 **2,930 passed, 기존 warning 2개**다. 기존 합성 평가도 79/79 scenarios, Linux 21/21, risk 70/70 및 case 70/70으로 유지됐다. Warning은 Starlette/httpx 및 AnyIO deprecation이다. `uv sync --locked --dev`, `uv lock --check`, Python compile, Node syntax, `npm ci`, Chromium·axe 14 states (`external_requests=0`), `git diff --check`와 변경 파일 경로/credential scan도 통과했다. Dependency와 `uv.lock`은 변경하지 않았다.

Benchmark: `tests/test_collector_jsonl_runtime_35_3.py`; subprocess harness: `tests/smoke_collector_jsonl_runtime_35_3.py`; optional benchmark: `tests/benchmark_collector_jsonl_runtime_35_3.py`; documentation contract: `tests/test_collector_jsonl_runtime_35_3_documentation.py`. Benchmark uses synthetic application/SSH payloads, 2 warmups and 9 samples per role/size (1, 32, 256), then 2 warmups and 9 samples for start/stop, malformed refusal, queue full, two-connection fairness and bind-fault cleanup. The end-to-end rows include listener send, parse, analysis, and close. Median/p95/max are milliseconds; this small development measurement is not an operational SLA or worst-case bound.

Local benchmark environment: Python 3.12.7, macOS Darwin arm64. Representative application / SSH results (median / p95 / max ms):

| Case | Application | SSH |
|---|---:|---:|
| 1 record end-to-end | 0.756 / 0.839 / 0.839 | 0.685 / 0.755 / 0.755 |
| 32 record burst | 8.567 / 8.979 / 8.979 | 8.656 / 9.501 / 9.501 |
| 256 record burst | 95.792 / 99.322 / 99.322 | 96.691 / 99.198 / 99.198 |
| start and stop | 0.164 / 0.178 / 0.178 | 0.170 / 0.181 / 0.181 |
| malformed refusal | 0.622 / 0.651 / 0.651 | 0.647 / 0.671 / 0.671 |
| queue full | 0.678 / 0.838 / 0.838 | 0.642 / 0.692 / 0.692 |
| two connection fairness | 1.576 / 1.633 / 1.633 | 1.631 / 2.549 / 2.549 |
| bind-fault cleanup | 0.053 / 0.057 / 0.057 | 0.054 / 0.075 / 0.075 |

Synthetic payload size was 81 bytes for application and 94 bytes for SSH. RSS was not measured by this benchmark. These numbers are local observations only; Linux and Vector measurements remain `NOT_TESTED`.

The bounded Ubuntu subprocess acceptance for this JSONL runtime passed in exact push run `40452774780`; see [the Linux reliability acceptance record](collector_jsonl_runtime_linux_acceptance_35_3a.md). It does not verify Vector, egress isolation, long-duration operation, filesystem durability, Linux IPv6, or operational delivery guarantees.

## Limitations

- Vector is not installed or run; its native RFC 6587 incompatibility, custom framing uncertainty, checksum-only provenance acceptance, and three `UNRESOLVED` credential-shaped findings remain unchanged.
- TLS/mTLS, authentication, remote collection, disk buffer, durable replay, exactly-once and lossless delivery are unsupported.
- Public API/SSE/UI, management CLI, shared collection lock, and file-monitor coordination are not implemented.
- Actual logs, organizational operation, and production use remain `NO_GO`.
- Actual Vector integration remains `NOT_TESTED`; actual user data and organizational operation remain `NO_GO`.
