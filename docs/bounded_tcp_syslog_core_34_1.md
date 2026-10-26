# Phase 34.1 — bounded TCP Syslog pure core

## 후속 상태 — Phase 34.2

[Phase 34.2](loopback_tcp_syslog_pilot_34_2.md)는 이 pure decoder/queue를 loopback-only application/SSH 합성 pilot에 연결했다. 별도 프로세스 smoke는 macOS와 Ubuntu CI run `40274877704`에서 확인했다. Phase 34.3의 확장 반복 matrix는 macOS local에서만 확인했으며 Ubuntu 확장 matrix는 NOT_TESTED다. 실제 사용자 자료·조직 운영과 원격 수집은 NO_GO다. 34.1의 순수 framing/queue 계약은 변경하지 않았다. [Phase 34.3 수용 기록](loopback_tcp_syslog_acceptance_34_3.md).

Phase 34.3A의 Ubuntu bounded matrix는 별도 CI step으로 준비 중이며 새 SHA push CI 전까지 `NOT_TESTED`다: [검증 계획·기록](loopback_tcp_syslog_linux_reliability_34_3a.md).

**판정: `CONDITIONAL_GO` — 순수 framing/config/queue core만 검증했다. 자동 수집은 `NOT_IMPLEMENTED`이며 실제 socket을 열지 않았다.** 이 구현은 loopback listener, parser, 분석 pipeline, 공개 API/SSE/UI, 파일 monitor, checkpoint와 연결되지 않는다.

## 범위와 계약

새 dependency·lockfile 변경 없이 `app/log_collection/{models,framing,queue}.py`에 네트워크 비의존 core를 추가했다. Config는 immutable `tcp-syslog-config/v1`이며 role은 `application`/`ssh`, transport는 `tcp_syslog_octet_counting`, bind scope 후보는 `loopback_only`로 닫힌다. 숫자 필드는 bool을 포함한 비정수·0·범위 초과를 거부한다. Prefix는 최대 6자리, payload는 최대 8192 bytes, `max_connection_buffer_bytes`는 최대 `max_frame_bytes + max_prefix_digits + 1` (기본 최대 8199 bytes)다. `max_queue_events`는 256, `max_queue_bytes`는 1 MiB 이하에서 event 수와 UTF-8 payload byte를 함께 검사한다. 이는 bounded core 계약이지 운영 적합성이나 RSS 상한 주장이 아니다.

RFC 6587 octet-counting 하위 문법은 ASCII decimal length, ASCII space 하나, 정확한 payload bytes다. 0, leading zero, 부호, whitespace 변형, 비숫자, prefix/frame 상한 초과는 고정 category로 terminal reject한다. Payload는 strict UTF-8이고 C0/DEL, NUL을 거부한다. trim이나 Unicode normalization을 하지 않는다. Prompt injection처럼 보이는 문자열도 payload data일 뿐 어떤 동작도 실행하지 않는다. Incomplete EOF는 event가 되지 않는다. 여러 frame과 분할 입력을 지원하며 malformed frame 후 decoder는 terminal이다.

Closed result/status 표현에는 frame 수, buffer/queue byte/count, state, 고정 오류 category와 고정 next-action만 포함한다. `ValidatedFrame`과 `QueueItem`만 내부 payload를 보유하며 repr은 내용 없이 byte 수만 표시한다. Queue admission은 FIFO이며 상한 초과 시 부분 enqueue/eviction 없이 reject한다. `accepted`는 queue 삽입 완료, `rejected`는 입력/admission 거부, `dequeued`는 queue 제거, `dropped`는 close 때 폐기된 accepted 항목을 센다. 이 in-memory core는 durable delivery, exactly-once, 무유실을 보장하지 않는다.

상태 전이는 `STARTING → READY|FAILED`, `READY → DEGRADED|FAILED|STOPPED`, `DEGRADED → FAILED|STOPPED`, `FAILED → STOPPED`, `STOPPED → STOPPED`만 허용한다. `active_connections`는 DTO 계약 검사용 수동 core state일 뿐 실제 connection 상태가 아니다. drop은 기본 0이며 명시적 폐기에서만 증가한다. close는 반복 호출 가능하고 queue가 남긴 payload 참조를 정리한다. 메모리의 secure erase는 보장하지 않는다 (`memory의 secure erase` 보장 없음).

## 오류와 개인정보 경계

오류 category는 `INVALID_CONFIG`, `INVALID_PREFIX`, `PREFIX_TOO_LONG`, `FRAME_TOO_LARGE`, `CONNECTION_BUFFER_FULL`, `INVALID_UTF8`, `FORBIDDEN_CONTROL`, `INCOMPLETE_FRAME`, `DECODER_CLOSED`, `INTERNAL_FAILURE`, `QUEUE_FULL`, `QUEUE_CLOSED`, `INVALID_STATE`로 고정한다. 예외는 입력값이나 내부 예외 문구를 이어 붙이지 않는다. Status에는 raw payload/hash, account, IP, hostname, port, bind 상세, 경로, credential이 없다. 별도 로그·spool·dead-letter를 만들지 않는다.

## 검증과 한계

시작 gate는 SHA `3182edda9b0336bcefdf776ab1b30bec1a32bfe3`, push CI run `40267678512`의 completed/success였다. 해당 CI는 Ubuntu 24.04 locked install, 전체 pytest 2730 passed/기존 warning 2개, Phase 33.5 Linux smoke, Chromium·axe 14 states/external requests 0, tracked-file 불변을 확인했고 artifact는 0개였다. v0.4.0 tag/Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`을 유지했다.

수정 전 로컬 전체 pytest 기준선도 **2730 passed, 기존 warning 2개**였다. 신규 계약 테스트는 구현 전 `ModuleNotFoundError: app.log_collection`으로 실패했고, 구현 후 core focused 테스트 **53 passed**, 새 문서 계약과 Phase 34.0 문서 계약 포함 focused **60 passed**, 전체 문서 계약 **308 passed**, 전체 pytest **2785 passed, 기존 warning 2개**였다. `uv sync --locked --dev`, `uv lock --check`, `npm ci`, Chromium·axe 14 states/external requests 0, Python compile과 Node syntax 검사가 통과했다. 기존 합성 평가 `79/79`, Linux `21/21`, risk/case `70/70`을 확인했으며 UTC와 Asia/Seoul 출력은 byte-equivalent였다. `git diff --check` 및 dependency/lockfile 불변 검사가 통과했다. Property 검사는 Hypothesis로 임의 byte feed가 buffer cap을 넘지 않는지, 유효 UTF-8 payload의 모든 단일 split에서 결과가 동일한지 검증한다. Fault 테스트는 append/decode/admission/snapshot/cleanup 경계를 통해 고정 오류와 참조 정리를 확인한다.

`tests/benchmark_tcp_syslog_core_34_1.py`는 일반 pytest에서 자동 실행되지 않는 순수 in-process 합성 benchmark다. 실행 시 warmup 2회, 측정 20회, median/p95/max, Python·OS·architecture, payload 크기와 queue/frame의 payload byte budget을 출력한다. Python object overhead/RSS는 이 byte budget에 포함되지 않는다. 수치는 개발용 합성 관측값이며 운영 SLA가 아니다.

로컬 개발 측정 (Python 3.12.7, Darwin arm64; warmup 2, 표본 20, ms):

| 작업 | Payload | Median | p95 | Max |
|---|---:|---:|---:|---:|
| decoder 생성 | 0 B | 0.0003 | 0.0006 | 0.0010 |
| 단일 frame | 512 B | 0.0396 | 0.0405 | 0.0423 |
| 1-byte chunk feed | 512 B | 0.6980 | 0.7080 | 0.7155 |
| 32 frame batch | 32 B 합계 | 0.0512 | 0.0525 | 0.0527 |
| 최대 frame | 8192 B | 0.6144 | 0.6219 | 0.6370 |
| queue enqueue/dequeue | 512 B | 0.0819 | 0.0824 | 0.0843 |
| malformed prefix reject | 0 B | 0.0013 | 0.0014 | 0.0018 |
| close cleanup | 512 B partial | 0.0028 | 0.0030 | 0.0035 |

이 작은 표본은 한 macOS 개발 환경의 관측값이며 Linux/Ubuntu 성능, 운영 처리량, 최악 지연 또는 SLA를 대표하지 않는다. RSS는 측정하지 않았다.

Phase 34.1 당시에는 실제 socket, TCP 송수신, Ubuntu network, slowloris timing, connection flood, soak, parser/analysis integration을 수행하지 않았다 (`NOT_TESTED`). Phase 34.2는 별도 [Ubuntu CI run `40274877704`](loopback_tcp_syslog_pilot_34_2.md)에서 합성 loopback smoke를 통과했다. Phase 34.3 확장 반복/soak는 macOS local only이며 Ubuntu 확장 matrix는 NOT_TESTED다. 공개 API·SSE·UI, v1/v2/v3 file runtime, checkpoint, schema 2/3, detection/relation/risk/case, lexical guidance, restricted-report 계약, Gemini/embedding/LLM은 변경하지 않았다. 원격 수집은 인증·암호화 전까지 `NO_GO`; AI parser 제안은 별도 gate 전까지 `NO_GO`다.

## Research Basis, Observable Evidence Mapping, Limitations

Research basis는 [RFC 6587](https://www.rfc-editor.org/rfc/rfc6587.html)의 octet-counting framing이다. 해당 RFC는 Historic이며 이 설계는 TCP 전송 보안이나 sender authentication을 제공하지 않는다. Observable evidence는 length prefix, exact byte count, UTF-8 validity와 금지 control 여부뿐이다. 이 core는 Syslog 의미, 송신자 정체, 공격 성공, parser 호환성을 판정하지 않는다. 6-digit/8192-byte/queue 상한은 프로젝트의 시험 가능한 engineering limits이며 RFC 보장이나 운영값이 아니다. Python byte/string copy, OS buffering, swap, core dump와 host compromise는 보장 범위 밖이다.
