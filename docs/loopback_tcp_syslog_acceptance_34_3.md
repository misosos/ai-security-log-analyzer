# Phase 34.3 — loopback TCP Syslog 반복성·자원 정리 수용 기록

## 후속 상태 — Phase 34.3A 및 34.4

Phase 34.3A의 bounded Ubuntu reliability는 시작 SHA `746c6d517fc27ca9a32b728b57df57c9912b2596`의 push CI run `40282366828`에서 80회 역할별 matrix가 성공했다. 이후 Phase 34.4 CLI management도 SHA `961e279c19ae848d405724cc09d71bfba5cfbb38`의 push CI run `40308485200`에서 Ubuntu subprocess smoke로 통과했고, Phase 34.5에서 합성 CLI 안내 10개 항목의 사용자 이해도를 수용 검수했다. [Phase 34.4 기록](loopback_tcp_syslog_management_34_4.md) 및 [34.5 수용 기록](loopback_tcp_syslog_management_acceptance_34_5.md). 실제 자료·조직 운영·원격 수집은 계속 `NO_GO`다.

## 판정 범위

합성 loopback application/SSH pilot의 반복 종료·재시작·동시성·bounded resource 정리만 **CONDITIONAL_GO**다. 실제 사용자 로그·계정·설정·checkpoint, 외부 interface, 인증 없는 원격 수집과 조직 운영은 계속 **NO_GO**다. 이 기록은 운영 처리량, SLA, 무유실 또는 exactly-once를 보장하지 않는다.

## 시작 gate와 원격 CI 증거

- 시작 SHA: `b3bec0833dde77f672ccebad42633b90efed3ed6`
- branch `main`, clean working tree, local main = origin/main, ahead/behind 0
- 정확한 SHA의 push run [40274877704](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40274877704): `completed/success`
- Ubuntu 24.04 전체 회귀: **2814 passed, 2 warnings**
- 별도 `Verify bounded loopback TCP Syslog pilot on Linux` 단계: success
- CI 로그 완료 표식: `TCP_SYSLOG_SMOKE_COMPLETE roles=2 subprocesses=4 synthetic=1`
- Node·Chromium·axe: 14개 상태 통과, `external_requests=0`
- tracked file 불변 검사 통과, CI artifact **0개**
- v0.4.0 tag와 공개 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

이는 해당 SHA에서 application/SSH subprocess smoke를 Ubuntu에서 실행한 원격 CI 증거다. 아래의 34.3 반복 lifecycle matrix와 soak는 **macOS 로컬**에서만 실행했다. 확장 Ubuntu 반복 matrix는 **NOT_TESTED**다.

### Phase 34.2 errno 실패 이력 정정

이전 SHA `a0ad520c70748552e159c4abfacb2267c83fcf1f`의 run [40272852172](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40272852172)은 **1 failed, 2808 passed, 기존 warning 2개**였다. 테스트가 일반 bind 실패로 `OSError(98, ...)`를 넣었지만 Ubuntu의 errno 98은 `EADDRINUSE`여서 production이 올바르게 `PORT_IN_USE`를 반환했다. 이는 테스트의 OS별 숫자 errno 가정이었으며 production listener·privacy·analysis 결함이 아니다. 해당 run에서는 Linux smoke와 benchmark가 실행되지 않았다.

수정 SHA `b3bec0833dde77f672ccebad42633b90efed3ed6`의 run `40274877704`는 위의 Ubuntu 회귀·listener smoke를 통과했다. Phase 34.2 기록에서 이 errno 실패와 무관한 run ID가 잘못 연결됐던 항목도 바로잡았다.

## 로컬 반복 subprocess matrix

검증 harness: [`tests/accept_loopback_tcp_syslog_34_3.py`](../tests/accept_loopback_tcp_syslog_34_3.py). macOS 15.7.7 arm64, Python 3.12.7에서 각 cycle은 새 0700 임시 directory/HOME, port 0으로 선택한 새 loopback port, application 또는 SSH 합성 frame만 사용했다. 각 child는 고정 완료 표식만 stdout에 출력했고 stderr는 비어 있었다. child는 runtime 전후 FD count, listener 상태, connection/closing/processor task, queue 상태를 반환했으며 parent는 child reap 후 같은 port bind를 확인했다.

최종 matrix 실행은 **140/140 첫 시도 통과**, 분류된 cycle failure 0, 임시 directory cleanup 실패 0이었다.

| 역할 | SIGINT | SIGTERM | 정상 stop | 시작 직후 | frame 처리 중 | malformed 후 stop | 합계 |
|---|---:|---:|---:|---:|---:|---:|---:|
| application | 10/10 | 20/20 | 10/10 | 10/10 | 10/10 | 10/10 | 70/70 |
| SSH | 10/10 | 20/20 | 10/10 | 10/10 | 10/10 | 10/10 | 70/70 |

모든 cycle에서 제한 시간 내 child 종료/reap, `STOPPED`, active connection 0, connection/closing task 0, processor 완료, queue 0, runtime 소유 FD 차이 0을 확인했다. process 종료 후 선택 port를 즉시 다시 bind할 수 있었다. 정상 stop은 임시 stop marker를 통해 child가 직접 `runtime.stop()`을 부르는 흐름이다. 처리 중 종료는 test-only parser delay에서 입력 처리를 시작한 뒤 신호를 전달했다. `SIGINT`와 `SIGTERM`의 matrix 횟수는 각 위 표와 같으며 frame 처리 중 10회는 두 신호를 번갈아 사용했다.

### 첫 시도 오류 기록

검증 harness를 처음 실행한 한 차례는 140 cycle 루프 뒤 parent 프로세스가 repository import 경로를 설정하지 않아 concurrency 단계에서 중단됐고, 그 실행은 신뢰 가능한 결과 요약을 남기지 못했다. 다음 harness 버전에서는 전체 matrix가 **139/140**이었고 `application:normal:listener_readiness` 1건이 실패했다. 그 실행의 cycle 출력은 민감한 stderr/stdout 대신 고정 단계 category만 집계했다. 이 단계 실패의 정확한 원인은 확정하지 못했다.

test-only readiness marker를 임시 파일에서 atomic replace로 게시하도록 보강한 최종 실행에서는 동일 범주 실패가 재현되지 않았고 140/140이 첫 시도에 통과했다. 따라서 이 관측은 **UNEXPLAINED_NON_REPRODUCED**로 남긴다. 이는 production listener 결함이 확인됐다는 뜻이 아니며, 최초 실패를 성공으로 바꾸어 세지 않았다.

Phase 34.2 macOS smoke에서 관찰된 SSH/SIGTERM 단발 실패도 원인이 확인되지 않았다. 이번 matrix의 SSH SIGTERM 20회와 SSH processing/malformed 종료 cycle은 모두 첫 시도 통과했지만, 기존 단발 관측은 **UNEXPLAINED_NON_REPRODUCED**로 남기며 운영 보장으로 확대하지 않는다.

## 종료 지연 관측

신호 또는 stop 요청 시점부터 child가 종료되어 parent가 `communicate()`로 reap할 때까지 측정했다. 같은 로컬 macOS/Python 실행의 표본은 각 cell 10회 또는 20회이며, 아래 값은 ms다. p95는 작은 표본에서의 nearest-rank 관측치다. 측정 범위에는 이후 별도 수행한 port rebind probe 시간이 포함되지 않는다.

| 역할/종료 경로 | n | median | p95 | max |
|---|---:|---:|---:|---:|
| application SIGINT | 10 | 59.659 | 63.516 | 63.516 |
| application SIGTERM | 20 | 59.369 | 61.123 | 67.842 |
| application 정상 stop | 10 | 60.872 | 63.175 | 63.175 |
| application 시작 직후 stop | 10 | 57.119 | 59.168 | 59.168 |
| application frame 처리 중 종료 | 10 | 107.811 | 109.762 | 109.762 |
| application malformed 후 종료 | 10 | 60.390 | 63.145 | 63.145 |
| SSH SIGINT | 10 | 58.853 | 64.256 | 64.256 |
| SSH SIGTERM | 20 | 58.750 | 63.055 | 65.645 |
| SSH 정상 stop | 10 | 63.138 | 81.745 | 81.745 |
| SSH 시작 직후 stop | 10 | 58.247 | 63.951 | 63.951 |
| SSH frame 처리 중 종료 | 10 | 106.517 | 108.965 | 108.965 |
| SSH malformed 후 종료 | 10 | 59.752 | 64.503 | 64.503 |

이 표는 운영 SLA가 아닙니다. 이 작은 합성 개발 표본은 worst-case latency 또는 다른 OS/filesystem의 동작을 보장하지 않는다.

## 연결·과부하·malformed 반복

application과 SSH 각각에 대해 다음을 실행했다.

- 동시 connection 2개와 connection task 최대 2개가 진행됨. 세 번째 연결은 payload를 읽지 않고 거부됨.
- 첫 연결에 partial frame prefix를 둔 동안 두 번째 연결의 16 frame burst가 처리됐고, 이후 첫 연결 frame도 처리됨. 관찰된 starvation은 없었다.
- rapid connect/disconnect 100회가 제한 시간 안에 끝났고 각 cycle 뒤 active connection은 0으로 돌아왔다.
- invalid prefix, oversized length, incomplete EOF, invalid UTF-8, NUL control, parser 부적합 record를 각각 1회 전송했다. framing 오류는 rejected count를 증가시키고 해당 연결만 닫았다. parser 부적합은 parser-rejected count로 분리됐다. 각 경우 뒤 정상 record가 처리되어 listener 상태는 `LISTENING`으로 유지됐다.
- 각 role에서 max queue event 1로 실제 connection handler의 admission을 포화시켰다. 첫 frame만 accepted/queued, 두 번째는 rejected, 상태는 `DEGRADED`, queue는 event limit 1이었다. 조용한 drop은 없었다.

각 role의 privacy 확인에서 status JSON/repr에는 합성 account/IP가 없었다. subprocess stdout은 고정된 cycle 완료 표식만, stderr는 빈 값이었다. 기존 full regression은 public API/SSE/UI/HTML/guidance/restricted-report privacy 계약을 포함한다. 원격·production endpoint는 열지 않았다.

## Bounded soak와 자원

각 role당 **256 frame**을 한 loopback connection에서 전송했다(사용자 상한 1,000 이하). synthetic records는 기존 role parser를 통과했고, public publication 없이 기존 내부 결정적 분석만 수행했다.

| 측정 | application | SSH |
|---|---:|---:|
| sent / accepted / parsed / analyzed | 256 / 256 / 256 / 256 | 256 / 256 / 256 / 256 |
| rejected / parser-rejected / dropped | 0 / 0 / 0 | 0 / 0 / 0 |
| peak queue events / bytes | 256 / 21,248 | 256 / 24,320 |
| queue limits | 256 / 1 MiB | 256 / 1 MiB |
| main runtime active connections/tasks peak | 2 / 2 | 2 / 2 |
| soak connection/task peak | 1 / 1 | 1 / 1 |
| main runtime FD before / after stop | 7 / 7 | 7 / 7 |
| soak FD before / after stop | 8 / 8 | 8 / 8 |
| listener sockets before stop / task count after | 1 / 0 | 1 / 0 |
| listener released and port rebind | yes | yes |
| process-wide observed peak RSS | 41,713,664 bytes | 41,893,888 bytes |
| soak elapsed | 439.859 ms | 416.591 ms |

RSS는 Python process의 `getrusage` high-water observation이며 runtime 전용 allocation 측정이 아니다. `tracemalloc`로 전체 native/socket memory를 계측하지 않았다. queue event peak는 허용 상한에 정확히 닿았으며 byte cap은 넘지 않았다. 이 값은 짧은 synthetic 개발 관측치다.

## 회귀와 변경 경계

최종 CI gate SHA `b3bec0833dde77f672ccebad42633b90efed3ed6`에서 전체 pytest **2814 passed / warning 2개**, Phase 34.2 Ubuntu subprocess smoke 성공, Chromium/axe와 tracked-file 검사가 성공했다. 이 단계의 macOS 회귀는 수용 문서·test-only harness 계약 검사를 포함해 별도로 기록한다.

검증 대상은 기존 runtime 및 공개 경계의 불변 확인이다. API/OpenAPI, SSE, UI, schema 2/3, file monitoring/checkpoint, lexical guidance, restricted report, detection·relation·risk·case 의미, dependency와 `uv.lock`은 변경하지 않는다. TCP 분석 결과는 자동 게시되지 않고, checkpoint·disk spool·이전 epoch recovery를 만들지 않는다.

## NOT_TESTED와 남은 위험

- Phase 34.3의 140회 반복 matrix·100 connect cycles·256 frame soak는 macOS에서만 수행했다. Ubuntu에서 같은 확장 반복/soak는 **NOT_TESTED**다.
- macOS와 Ubuntu 이외의 OS, IPv6 loopback availability의 모든 target, 긴 기간 soak, 실제 사용자 로그, 원격 수집과 조직 운영은 검증/승인하지 않았다.
- SIGKILL, process crash, 전원 차단, 실제 OS socket/accept 실패, 실제 ENOBUFS/ENOSPC, kernel-level connection flood, hostile same-UID process의 격리는 테스트하지 않았다.
- 인증 없는 원격 수집, TLS/mTLS, UDP, access role, cross-source correlation, exactly-once, 무유실, automatic replay/recovery는 **NO_GO / 미지원**이다.
- 계정·IP 등 원문은 기존 parser/analysis의 bounded in-memory processing 동안 존재할 수 있다. swap/core dump와 host compromise 위험은 해결하지 않았다.
- embedding production 통합은 NO_GO, local LLM은 STORAGE_SETUP_BLOCKED, Gemini 연결은 없다.

합성 local 반복성 범위만 **CONDITIONAL_GO**다. 기록된 두 unexplained non-reproduced 이력과 Ubuntu 확장 matrix 미실행을 한계로 유지한다. 실제 사용자 자료·원격 수집·조직 운영은 계속 **NO_GO**다.

Phase 34.3A는 Ubuntu 24.04의 대표 bounded repetition을 위한 별도 CI step을 추가한다. 새 SHA의 CI 전 상태는 [Phase 34.3A 기록](loopback_tcp_syslog_linux_reliability_34_3a.md)과 같이 **PENDING_REMOTE_CI / NOT_TESTED**다. macOS의 기존 140회 matrix와 측정치는 Ubuntu 결과로 간주하지 않는다.

### Phase 34.4B smoke harness finding

Push run `40299125326` at `70c4971cd75b48cd7b789f3d0ab10345152904d6` passed SSH checkpoint ownership and full pytest (**2855 passed / 2 existing warnings**) but failed the later TCP smoke for application/SIGTERM. The subsequent Ubuntu reliability, management, restricted-report and Node/axe steps were skipped. The old smoke wrapper collapsed every failure to one generic exception, so that CI log cannot establish the inner stage or exception.

Two local macOS pre-fix mixed matrices recorded three first-attempt failures at the broad listener-readiness boundary across 180 signal runs. The deterministic failing regression demonstrated that a parent can observe the ready file between file creation and its content write. After changing the harness to atomically publish a complete private marker, the post-fix signal matrix passed application/SIGTERM 50/50, application/SIGINT 20/20 and SSH/SIGTERM 20/20, plus 20 normal stops and 8 startup/readiness/processing/malformed boundary cycles. The existing bounded acceptance harness then passed 80/80 lifecycle cases, with zero temp cleanup failures, and its two-role concurrency, rapid reconnect, malformed recovery, overload and 256-frame soak checks. The smoke and acceptance results include process reap, pipe drain, listener release, port reuse, runtime task cleanup and FD baseline checks. This does not prove that the specific Ubuntu run failed at the same inner operation: its details were lost, Linux is unavailable locally, and the changed SHA has not run in Ubuntu CI. Therefore the run-specific Ubuntu cause remains **NOT_TESTED** pending the next CI execution. No production listener change was made. The prior macOS SSH/SIGTERM single failure remains `UNEXPLAINED_NON_REPRODUCED`.
