# Phase 35.2 — Collector JSON Lines Adapter Pure Core

Phase 35.3 후속: 이 core는 별도 synthetic loopback runtime에서 재사용되어 기존 role-specific parser와 결정적 in-memory analysis에 연결되었다. Ubuntu 별도 프로세스 신뢰성 검증은 [Phase 35.3A Linux acceptance 기록](collector_jsonl_runtime_linux_acceptance_35_3a.md)에 있으며 새 SHA push 전까지 `PENDING_REMOTE_CI` / `NOT_TESTED`다. Vector·실제 자료·조직 운영은 계속 미지원/`NO_GO`다.

검증 기준일: **2026-10-26**. 이 변경은 external collector 전용 JSON Lines envelope의 순수 decoder·검증·bounded queue·safe status DTO만 제공한다.

## Pure Core Scope

- Production module: `app/log_collection/jsonl_adapter.py`
- Unit/property tests: `tests/test_jsonl_adapter_35_2.py`
- Opt-in synthetic benchmark: `tests/benchmark_jsonl_adapter_35_2.py`
- **순수 core만 구현했다.** There is no listener. Socket, Vector binary, 외부 process, filesystem, parser/analysis pipeline을 실행하거나 연결하지 않았다.
- Existing Phase 34 RFC 6587 decoder/runtime/management 계약은 변경하지 않았다. Public API, SSE, UI, restricted report, guidance와 checkpoint/publication에도 연결하지 않았다.

## Closed Envelope

JSON Lines record 하나는 UTF-8 JSON object 한 개와 실제 LF delimiter 한 개다. Stream read/write 경계는 record 경계가 아니다. JSON string 안의 `\\n` escape는 JSON parsing 뒤 newline 문자가 되며 payload control-character 검사에서 거부된다. CRLF, BOM, 빈 줄, leading/trailing 바깥 whitespace, partial EOF/partial close는 자동 보정하지 않고 거부한다.

정확히 아래 key만 허용하고 모두 필수다.

```json
{
  "schema_version": 1,
  "source_role": "application",
  "payload": "synthetic log line",
  "collector_instance_alias": "collector-1",
  "sequence_hint": null,
  "retry_hint": false
}
```

`schema_version`은 bool이 아닌 integer `1`; role은 adapter config와 동일한 `application` 또는 `ssh`; payload는 non-empty string; alias는 1–64 ASCII letter/digit/underscore/hyphen; sequence는 null 또는 1–64자 bounded ASCII opaque hint; retry는 정확한 boolean이다. Alias는 collector가 부여하는 표시용 alias일 뿐 hostname이나 sender 인증이 아니다. Sequence hint는 exactly-once ID가 아니며 retry hint는 보증이 아니다. 임의 metadata map을 받지 않는다.

Duplicate key, extra/missing key, NaN/Infinity와 float overflow, bool-as-int, 잘못된 type/schema/role은 fixed error category로 거부한다. Byte input은 strict UTF-8 decode한다. BOM, invalid UTF-8, unpaired surrogate, NUL 및 C0/DEL payload control은 거부한다. Unicode normalization, trim, truncation, 추론은 하지 않는다.

## Limits

| Limit | Default and hard cap | Meaning |
|---|---:|---|
| JSON line | 65,536 bytes | LF delimiter 포함 |
| payload | 8,192 UTF-8 bytes | 문자가 아닌 encoded bytes |
| per-decoder retained buffer | 65,536 bytes | LF를 기다리는 단일 partial line |
| results per `feed` call | 32 records | 반환 tuple memory를 제한; LF가 33개 이상인 feed call 전체를 parsing 전에 terminal 거부 |
| queue | 256 records | event count limit |
| queue byte budget | 1,048,576 bytes | payload+alias+sequence의 UTF-8 byte 합 |
| alias / sequence hint | 각 최대 64 ASCII bytes | metadata cardinality와 각 item bound |

모든 정수 config bound는 bool과 float를 거부한다. Line max는 delimiter를 포함하며 `max_connection_buffer_bytes >= max_record_bytes`, `max_record_bytes >= max_payload_bytes + 128`이어야 한다. Byte budget은 Python object/deque allocator overhead 또는 process RSS 자체를 세지 않는다. Item count와 각 문자열 길이도 제한되어 있으나 이 accounting을 RSS hard cap으로 표현하지 않는다. Queue가 가득 차면 enqueue 전체를 거부하며 eviction/partial enqueue를 하지 않는다.

## Validation and Errors

Decoder는 LF까지 모인 record만 parse하고 완성 전에는 반환하지 않는다. 여러 record를 순서대로 반환할 수 있고 UTF-8 multibyte sequence가 chunk 사이에 나뉘어도 연결한다. Record 또는 buffer 상한 초과, syntax/schema/role/payload 오류는 현재 decoder를 terminal로 만든다. 잘못된 line 뒤의 bytes를 재동기화해 계속 읽지 않는다. EOF의 partial line은 `INCOMPLETE_RECORD`; 반복 close는 안전하고 이후 feed는 `DECODER_CLOSED`다.

고정 category는 `INVALID_UTF8`, `INVALID_JSON`, `DUPLICATE_KEY`, `UNKNOWN_FIELD`, `INVALID_SCHEMA`, `ROLE_MISMATCH`, `FORBIDDEN_CONTROL`, `PAYLOAD_TOO_LARGE`, `RECORD_TOO_LARGE`, `INCOMPLETE_RECORD`, `DECODER_CLOSED`, `FEED_EVENT_LIMIT`, `QUEUE_FULL`, `QUEUE_CLOSED`, `INTERNAL_FAILURE`다. Error text/repr에는 category 외 입력·예외가 없다. Syntax/schema 오류가 같은 feed 앞쪽의 valid record 뒤에 오면 그 valid prefix와 category를 반환할 수 있다. 그러나 33개 이상 LF delimiter가 한 feed에 포함되면 사전 검사로 그 feed 전체를 거부해 partial acceptance를 막는다. 호출자는 그 경우 feed를 bounded batch로 나눠야 한다.

## Queue and Status

Queue item은 trusted internal payload, role, sequence receipt ID, alias/sequence/retry metadata, byte count만 갖는다. Receipt ID는 enqueue가 성공한 때만 증가한다. Queue는 FIFO다. 거부된 enqueue는 rejection counter만 증가시키고 기존 item, byte usage, 다음 ID를 보존한다. `accepted`는 queue admission 완료, `rejected`는 명시적 거부, `dequeued`는 queue에서 꺼낸 수다. Close는 미처리 항목을 완료로 표시하지 않고 제거하며 dropped로 센다. Repeated close는 안전하다. Durable queue, retry/replay, exactly-once, 무유실 의미는 없다.

Safe snapshot에는 fixed schema/role/transport/state, event·byte counts와 limits, fixed error/next-action만 있다. Payload, alias, sequence, source identity, 경로, hash는 status/JSON/repr에 없다. Snapshot은 내부 계약이고 public API/SSE/UI projection이 아니다.

## Privacy Boundary

Payload는 완성된 validated internal envelope와 queue item에서만 소비자가 사용할 수 있다. Decoder/result/event repr, status, exception, logger에서 payload/alias/sequence를 숨긴다. Core 자체는 logging, network, filesystem, AI, parser 또는 analysis 호출을 하지 않는다. Test canaries는 모두 명시적 합성값이며 test failure assertion은 입력 object 전체를 출력하지 않고 고정 category/counter만 검사한다. Restricted report와 lexical guidance로 자동 전달되지 않는다.

## Benchmark

Opt-in benchmark: `tests/benchmark_jsonl_adapter_35_2.py`; **8 warm-up / 51 samples**, Python 3.12.7, macOS Darwin arm64. 각 수치는 ms이며 sample은 로컬 합성 in-process 관측이다.

| Case | Payload bytes | Record bytes | Queue-accounted bytes | Median | p95 | Max |
|---|---:|---:|---:|---:|---:|---:|
| ASCII | 15 | 162 | 0 | 0.0500 | 0.0632 | 0.0645 |
| Korean | 15 | 162 | 0 | 0.0642 | 0.0652 | 0.0735 |
| 1-byte UTF-8 chunk feeds | 4 | 151 | 0 | 0.4442 | 0.4525 | 0.4551 |
| 32-record batch | 224 | 4,928 | 0 | 1.7940 | 1.8113 | 2.0967 |
| Maximum line | 8,192 | 65,536 | 0 | 21.9700 | 22.2291 | 22.7170 |
| Refusal | 0 | 3 | 0 | 0.0150 | 0.0187 | 0.0191 |
| Queue enqueue/dequeue | 15 | n/a | 30 | 0.0114 | 0.0120 | 0.0124 |

Queue-accounted bytes는 payload+alias+sequence byte 합이며 Python object overhead는 포함하지 않는다. 이 작은 표본은 운영 SLA, 최악 지연, Linux 성능 또는 Vector 성능이 아니다.

## Verification

검증 명령은 `uv run pytest -q tests/test_jsonl_adapter_35_2.py`, `uv run python tests/benchmark_jsonl_adapter_35_2.py`, `uv run pytest -q`다. Property tests는 canary-free fixed byte alphabet의 generated byte sequences와 fixed synthetic payload corpus를 사용해 chunk widths, 모든 UTF-8 multibyte split 위치, concatenated records와 bounds를 검사한다. Hypothesis가 실패 예제를 출력해도 입력 문자열이나 identifier canary가 포함되지 않는다. 32-record batch는 성공하고 33 LF batch는 아무 record도 부분 수락하지 않고 terminal 거부한다. UTC 및 Asia/Seoul에서 safe status/error serialization이 동일한지 확인한다. Phase 34 core/runtime/management/privacy 및 API/SSE/UI/restricted report/guidance regression은 전체 pytest에 포함된다.

최종 macOS 개발 환경 검증: adapter focused **26 passed**; Phase 34 core/runtime/management, restricted-report fault/privacy 및 Schemathesis 함께 **154 passed**; 전체 문서 계약 **333 passed**; 전체 pytest **2,905 passed, 기존 warning 2개**. UTC 및 Asia/Seoul adapter 반복은 각각 **26 passed**. 합성 평가는 authentication/web **79/79**, Linux Audit **21/21**, risk **70/70**, case **70/70**. `uv sync --locked --dev`, `uv lock --check`, Python compile, Node syntax, `npm ci`, Chromium·axe 14 states (`external_requests=0`), `git diff --check`가 통과했고 dependency/lockfile 변경은 없다.

Benchmark는 ASCII, 한국어, 1-byte chunk, 32-record batch, maximum line, rejection, queue enqueue/dequeue를 8 warm-up과 51 sample로 측정한다. 결과는 Python/OS/architecture, payload/record byte, median/p95/max를 출력한다. 이는 작은 로컬 합성 in-process 관측치이며 **operational SLA**, 운영 처리량, worst-case latency 또는 Vector 성능으로 해석하지 않는다.

## Limitations

- Linux 실행은 현재 변경 SHA의 CI 전까지 **`NOT_TESTED`**다. Local unit test는 socket/OS stream 실행이 아니다.
- Vector 0.60.0 및 external process 연동, JSONL serializer wire parity, listener/connection lifecycle는 **`NOT_TESTED`**다.
- Vector provenance는 checksum-only isolated pilot 조건부 수용 상태이며, credential 형태 scan의 미분류 `UNRESOLVED` 3건은 유지한다. 이 core 구현은 Vector 실행 승인이 아니다.
- 실제 사용자 자료·조직 운영은 `NO_GO`; remote collection, TLS/mTLS adapter, spool, parser/pipeline/public API 연결은 이 단계 범위 밖이다.
- Queue byte metric은 data bytes만 세며 전체 interpreter memory, secure erase, durable persistence를 보장하지 않는다.
