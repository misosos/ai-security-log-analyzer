# Phase 34.3A — Ubuntu bounded reliability acceptance

## 후속 원격 확인 — Phase 34.4 시작 SHA

앞서 준비한 reliability step은 SHA `746c6d517fc27ca9a32b728b57df57c9912b2596`의 push CI run `40282366828`에서 실행되어 성공했다. 해당 run의 전체 pytest는 **2819 passed, 기존 warning 2개**였고, reliability 표식은 `TCP_SYSLOG_LINUX_RELIABILITY_PASS roles=2 runs=80 synthetic=1 leaks=0`이었다. Ubuntu basic smoke, Node·Chromium·axe, tracked-file 불변 검사도 통과하고 artifact는 0개였다. 따라서 **기존 34.3A Ubuntu synthetic bounded reliability 범위는 `CONDITIONAL_GO`**로 갱신한다. 이것은 Phase 34.4에서 추가한 CLI management smoke를 실행한 증거가 아니며, 그 smoke는 새 commit CI 전 `NOT_TESTED`다. 실제 사용자 자료·조직 운영·원격 수집은 계속 `NO_GO`다.

## Scope and gate

This record covers synthetic-only Ubuntu 24.04 reliability checks for the existing loopback TCP Syslog pilot. It adds no production behavior and does not authorize actual user data, organization operation, or remote collection.

The start SHA was `32e9ff9efb3068a97c7056bee84cc87b1d63d564`, on clean `main`, equal to `origin/main` with behind/ahead `0/0`. Push run [40279634934](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40279634934) was completed/success for that exact SHA. Its full regression reported **2818 passed, 2 warnings**. The existing Ubuntu pilot step succeeded with `TCP_SYSLOG_SMOKE_COMPLETE roles=2 subprocesses=4 synthetic=1`; Chromium/axe reported 14 states and 0 external requests; tracked-file immutability passed; artifact count was 0. The v0.4.0 tag object remained `855a92827a605805b62c627ed719958620150ec4`, peeled target and Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

That gate is evidence for the prior basic smoke only. The new bounded reliability step has not run on a new SHA yet and is therefore **NOT_TESTED** until the commit containing it receives push CI.

## New bounded CI step

Workflow step: `Verify bounded TCP Syslog reliability on Linux`, after full pytest and the basic listener smoke, before Node installation. It asserts Linux and directly runs `uv run python tests/accept_loopback_tcp_syslog_34_3.py --linux-bounded`. Its step timeout is five minutes; the workflow job remains bounded by its existing 15-minute timeout. The mode is synthetic-only, uses a fresh temporary HOME/runtime and OS-assigned loopback port for each child, performs no user HOME/log search, and creates no packet capture, trace, report, or upload artifact. Child stdout/stderr is captured and never replayed. Failure output is restricted to role/scenario/stage, a fixed category, and counts; success emits only:

`TCP_SYSLOG_LINUX_RELIABILITY_PASS roles=2 runs=80 synthetic=1 leaks=0`

The reliability matrix runs 40 first-attempt subprocess cycles per role: readiness 10; SIGINT 5; SIGTERM 5; normal stop 5; startup stop 5; valid frame processing stop 5; malformed-frame stop 5. It does not retry failed cases. Every cycle checks exit/result state, no active connection or task, listener release, runtime FD delta, subprocess reap, immediate port reuse, and temporary directory removal. CI fails closed if the run count, cycle outcomes, cleanup, concurrency, queue, or soak contract differs.

The same bounded step checks two concurrent connections, third-connection rejection, peer progress while another connection holds a partial frame, independent malformed/reconnect handling, 30 rapid connect/disconnect cycles per role, queue overload without silent drop, and a 256-frame application and SSH soak. It records and validates accepted/rejected/parsed/parser-rejected/analyzed/dropped counts, queue peaks, connection/task bounds, FD baseline, listener cleanup, port reuse, elapsed time, and process-observed peak RSS internally; it prints none of those detailed values to CI logs on success.

## Evidence status

| Check | Before new SHA push CI |
|---|---|
| Previous Ubuntu basic smoke, application + SSH | PASS at run `40279634934` |
| New Ubuntu 80-cycle first-attempt matrix | NOT_TESTED |
| New Ubuntu concurrency and rapid reconnect | NOT_TESTED |
| New Ubuntu 256-frame soak per role | NOT_TESTED |
| Local portable bounded harness | PASS on macOS 15.7.7 arm64 / Python 3.12.7; Ubuntu-only mode rejects non-Linux |
| macOS 140-cycle matrix, concurrency, reconnect, soak | Prior Phase 34.3 evidence; see [acceptance record](loopback_tcp_syslog_acceptance_34_3.md) |

The earlier macOS application readiness one-off and Phase 34.2 SSH/SIGTERM one-off remain `UNEXPLAINED_NON_REPRODUCED`. They are not treated as resolved and must not be erased by a rerun.

## Local preparation run

On macOS 15.7.7 arm64 / Python 3.12.7, `uv run python tests/accept_loopback_tcp_syslog_34_3.py --bounded` passed **80/80 first attempts** (40 per role), with zero categorized failures and zero cleanup failures. This exercises the same bounded repetition and concurrency/soak assertions, but is not Ubuntu evidence. Application and SSH each also passed two-connection progress, third-connection rejection, partial-frame peer progress, independent malformed/reconnect recovery (7 cases), 30 rapid reconnects, bounded queue overload (accepted 1/rejected 1, queue depth 1), and 256-frame soak (accepted/parsed/analyzed 256, rejected/parser-rejected/dropped 0). Both roles ended with active connections/tasks at zero, FD baseline unchanged, listener released, and port reuse successful. In the final local bounded run, SIGINT shutdown (5 samples per role) measured app median/p95/max 60.440/61.960/61.960 ms and SSH 57.672/65.510/65.510 ms; SIGTERM measured app 58.745/60.817/60.817 ms and SSH 58.054/64.643/64.643 ms. Soak took 435.253 ms (application) and 432.717 ms (SSH); process-wide peak RSS observations were 41,566,208 and 41,811,968 bytes. These are small macOS synthetic observations, not operational targets. The existing macOS unexplained one-off failures remain unresolved.

The new Linux step has a five-minute hard timeout and no sleep-based polling; readiness and state checks use deadlines. This is a conservative upper bound for added CI time, not a measured duration. Overall workflow job timeout remains 15 minutes. Linux duration, RSS, and its reliability result are pending the new SHA CI.

## Boundaries

The Ubuntu result, when available, will establish only bounded synthetic reliability on the GitHub-hosted Ubuntu runner and exercised filesystem. It will not establish production stability, all-filesystem behavior, long-duration operation, no-loss, exactly-once delivery, crash/power-loss recovery, remote authentication, or real-data privacy compliance. Public API/SSE/UI, file-monitoring v1/v2/v3, checkpoints, subject aliases, lexical guidance, restricted reports, detection/risk/case behavior, dependencies, and `uv.lock` remain unchanged. Actual user data, organization operation, unauthenticated remote collection, exactly-once, and no-loss remain **NO_GO**.
