# Phase 35.3A — JSON Lines runtime Linux reliability acceptance

**Status before push:** `PENDING_REMOTE_CI`; Ubuntu 24.04 result was then `NOT_TESTED`.
**Final status:** `GO` for the bounded synthetic Ubuntu 24.04 JSONL runtime acceptance scope only. Vector integration, user data, organizational operation, and remote collection remain `NOT_TESTED` or `NO_GO` as specified below.
**Evidence date:** 2026-10-27. This record describes synthetic-only tests and
does not approve actual user data or organizational operation (`NO_GO`).

## Scope and gate evidence

The start gate was checked at `8879f91d1864daa268249d4123aa69088145417e` on
`main`; the working tree was clean, local `main` equaled `origin/main`, and
`origin/main...HEAD` was `0 behind / 0 ahead`. Push run
[40446328246](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40446328246)
for this exact SHA completed successfully. Its full regression reported
**2,930 passed, 2 existing warnings**. SSH checkpoint ownership, unified
monitoring, TCP Syslog smoke, 80-run TCP reliability, TCP management, restricted
report, report benchmark, Chromium/axe, and tracked-file checks all completed
successfully. The run had **0 artifacts**. `v0.4.0` and its Release still point
to `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

That run predates the Phase 35.3A workflow step. The new Ubuntu JSONL runtime
acceptance therefore remains **`NOT_TESTED`** until a push run for the new SHA
executes the named step and emits the required marker.

## Harness and bounded matrix

`tests/accept_collector_jsonl_runtime_35_3a.py` runs eight scenarios five times
for each of `application` and `ssh`: readiness with a processed record, SIGINT,
SIGTERM, normal stop, immediate stop after start, shutdown with one accepted
record held before analysis, malformed-record recovery followed by shutdown,
and queue-full followed by shutdown. The target is 40 child processes per role,
80 matrix runs total, without automatic retries.

Each child receives a fresh temporary `HOME` and temporary directory with
private permissions. It opens a fresh IPv4 loopback runtime on an OS-assigned
ephemeral port. Readiness is a complete, exact JSON marker written to a private
temporary file using write, flush, file `fsync`, and atomic replace; the marker
contains only schema and `RUNNING` state. The port is handed to the parent on an
inherited private pipe, never through stdout, stderr, status, or the marker.
Signals are sent only after the parent validates the atomic readiness marker.
Child stdout/stderr are captured, scanned for synthetic canaries and temporary
or repository paths, and never echoed on failure.

Every child verifies a `STOPPED` result, no active connection, listener,
connection task, worker, closing task, pending task, queued event, or queued
byte, a reaped child, and same-port rebind. The rebind probe uses the runtime's
`SO_REUSEADDR` setting. This same-port **port reuse** probe is a local check of that configuration, not a
claim that the option removes `TIME_WAIT` or guarantees reuse on every system.
Linux `/proc/self/fd` counts are used only when available; no unrelated system
socket or process is inspected or changed.

The queue-full case holds the worker at a test-only boundary, admits exactly
256 records, rejects the overflow record, observes `DEGRADED` and the fixed
`JSONL_RUNTIME_QUEUE_FULL` result from `wait_until_processed()`, then verifies
shutdown accounts the 256 pending records as dropped. The pending-record case
similarly checks one accepted but unprocessed record is not counted as analyzed.
Malformed input must close only that connection; a subsequent valid connection
must still complete analysis. No raw message is written to the marker, result,
status, output, or CI log.

## Additional Linux checks in the harness

After the subprocess matrix, each role gets bounded loopback checks for two
simultaneous connections, a rejected third connection, progress on one peer
while another holds a partial record, a split UTF-8 code point, and 30 serial
connect/disconnect cycles. The harness preflight gives the pure decoder, for
each role, exactly 32 records in one feed (success) and a **33-record** feed
(terminal refusal with no partial acceptance). This pure-core check is distinct
from TCP segmentation: a socket write is not assumed to map to one `read()` call.

Each role then starts a fresh runtime for an isolated **256-record** synthetic
soak. Expected counts are received/validated/queued/parser-recognized/analyzed
256, rejected/malformed/dropped 0. Queue and analysis history must stay within
their configured event and byte limits. The harness verifies runtime stop,
file descriptor count does not increase when `/proc` is available, and the
port can be rebound. These are small synthetic development observations, not
an operational SLA, worst-case load test, or delivery guarantee.

The harness has no dependency on the real runner `HOME`, logs, config, or
checkpoint. It does not run Vector, modify the RFC 6587 listener, create a
spool, or call the parser except through the existing JSONL runtime. It checks
IPv4 loopback. IPv6 loopback on Ubuntu remains **`NOT_TESTED`** by this harness.
Existing unit tests retain test-only bind/task/parser/analysis/cleanup fault
injection; the Linux acceptance run does not claim to inject every such fault.

## Workflow and safe output

The new step is named **`Verify collector JSONL runtime on Linux`**, has a
five-minute timeout, asserts Linux, and invokes the harness after full pytest
and existing TCP Syslog checks but before Node/Chromium setup. It does not use
`continue-on-error`, retry, or upload artifacts. Success is exactly:

```text
COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0
```

Failure output is restricted to role, scenario, fixed stage/category, safe
numeric counts, and completed matrix count. No child stdout/stderr, endpoint,
port, path, payload, account, IP, hostname, credential, or internal exception
text is emitted. Temporary input and runtime state are not artifacts.
Workflow contract tests are in `tests/test_collector_jsonl_runtime_linux_ci_35_3a.py`;
documentation contracts are in
`tests/test_collector_jsonl_runtime_linux_acceptance_35_3a_documentation.py`.

## Local verification and remaining limits

On 2026-10-27, macOS 15 / Python 3.12.7 / arm64 completed the final local
`--local-dry-run`: the 80 subprocess matrix and both roles' connection,
reconnect, UTF-8, 32/33-feed, 256-record soak, cleanup, and port-reuse checks
passed; the harness emitted
`COLLECTOR_JSONL_LOCAL_DRY_RUN_PASS roles=2 runs=80 synthetic=1 leaks=0`.
The final end-to-end harness took about 60.5 seconds. This checks harness portability
and local runtime behavior only; it does not count as Linux acceptance. There
were earlier test-harness-only iteration failures before the final run: the
port probe initially did not match the listener's `SO_REUSEADDR` setting, the
stress records shared one runtime's 256-entry history with its soak, and an
immediate-stop child could finish before its progress file existed. The probe
now matches the runtime option, soak starts a fresh runtime, and the initial
progress record is published before stop. These were corrected in test-only
code; no production defect was found or changed. No failed case was retried
within a matrix run.

## Exact Ubuntu acceptance result

The Phase 35.3A commit `5cdf941291204a48edace62a25c1e1fbe3350a75` was pushed
to `main`. Exact push run
[40452774780](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40452774780)
completed successfully on 2026-10-27. It ran the full regression (**2,934
passed, 2 existing warnings**), SSH checkpoint ownership and unified
monitoring, existing TCP Syslog smoke/reliability/management, restricted
report and benchmark, Node/Chromium/axe, and tracked-file immutability. The
dedicated **`Verify collector JSONL runtime on Linux`** step ran after full
pytest and TCP steps and before Node. Its exact completion marker appeared
once:

```text
COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0
```

Artifact count was **0**. The `v0.4.0` tag and Release still target
`eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

The passing harness definition fixes eight first-attempt scenarios × five
repetitions for each of application and SSH: readiness, SIGINT, SIGTERM,
normal stop, immediate stop, pending accepted record, malformed recovery, and
queue-full shutdown. Thus the marker represents 40 subprocess runs per role,
80 total, without retries. The same invocation also passed two-connection
progress/third-connection refusal, partial-record fairness, 30 reconnects per
role, split UTF-8, exact 32/33 decoder boundaries, and an isolated 256-record
soak per role. Queue-full assertions covered 256 accepted, overflow rejected,
`DEGRADED`, fixed `JSONL_RUNTIME_QUEUE_FULL`, and all 256 queued records
accounted as dropped on shutdown. The soak assertions required 256 received,
validated, queued, parser-recognized, and analyzed; rejected, malformed, and
dropped were zero.

The harness verified child reap, closed listener/worker/connection tasks,
empty queue, same-port rebind, and no positive `/proc/self/fd` delta when
available (the file descriptor check is an aggregate, not a published count).
It sampled peak RSS privately, but the CI output did not retain
numeric RSS or FD baselines; the marker's `leaks=0` is the checked aggregate,
not a general resource cap. The runner filesystem/mount type was not recorded.
The harness uses IPv4 loopback; Linux IPv6 remains `NOT_TESTED`. These checks
are short synthetic CI observations, not a long soak, operational SLA, or
delivery guarantee.

This phase does not add production features. Account privilege metadata remains
unavailable to the JSONL runtime; arbitrary account metadata is not accepted.
Vector and actual collector integration, actual user data, organizational
operation, remote collection, TLS/mTLS, durable spool/replay, and exactly-once
or lossless delivery remain unsupported; **durable replay** is not provided.
A process crash, SIGKILL,
power loss, long-duration operational load, and IPv6 Linux listener behavior
are not established here.

Local macOS validation remains separately identified above and is not used as
the Ubuntu result. JSONL runtime의 합성 Ubuntu 수용 범위만 `GO`입니다.
Phase 35.3A is **`GO` only for the tested bounded synthetic Ubuntu acceptance
scope**. Actual Vector integration remains `NOT_TESTED`; actual user data,
organizational operation, and remote collection remain `NO_GO`.
