# Phase 16.4 로컬 live 조사 분석 통합 감사 (2026-10-13)

판정 범위는 **단일 application source의 로컬 v0.2 후보**다. 검증 시작점은 `main`의 `4fe77397d8cf8b843a67bf8e44d20a159a9592b3`, 깨끗한 작업 트리, 원격 main과 일치, CI run `38351546443` completed/success였다. 변경 전 `uv run pytest -q`는 **1,981 passed, 기존 의존성 경고 2개**였다. 아래 `PASS`는 열거한 자동/실제 증거 범위에서만 통과했다는 뜻이며, 모든 운영 입력의 안전성이나 무유실을 뜻하지 않는다. `PARTIAL`과 `NOT_TESTED`를 PASS로 승격하지 않는다.

## 요구사항 추적성

| Phase 11~16.3 계약 | 판정 | production 근거 | 검증 근거와 한계 |
|---|---|---|---|
| 단일 source 닫힌 config·절대 경로 | PASS | `app/live_monitoring/config.py` | `tests/test_live_monitor_config.py` |
| symlink·비정상 파일 거부 | PASS | config·`core.py` no-follow/open 검증 | config·tail reader 경계 테스트 |
| `FROM_END`의 기존 줄 미처리 | PASS | `core.py` session open | `test_from_end_skips_existing_and_catches_append_before_first_poll`, 실제 socket smoke |
| partial line·strict UTF-8 | PASS | `core.py` | `tests/test_live_tail_reader.py`의 partial/invalid 경계 |
| queue item/byte 이중 상한 | PASS | `core.py` | `test_queue_item_limit_exact_then_visible_overflow`, byte 대응 테스트 |
| lease/ack/release FIFO | PASS | `core.py` | `tests/test_live_record_lease.py`, `tests/test_live_record_ownership.py` |
| parser 동등성 | PASS | `parser_adapter.py`의 기존 parser 재사용 | `tests/test_live_parser_equivalence.py`; malformed 줄은 live에서 REJECTED라는 명시적 제어 흐름 차이 |
| detector prefix 동등성 | PASS | `detection_accumulator.py` | `tests/test_live_detection_equivalence.py` |
| application analysis prefix 동등성 | PASS | `analysis_accumulator.py` | `tests/test_live_analysis_prefix_parity.py`, worker integration; SSH/access 분석은 범위 밖 |
| ack 전/후 실패 계약 | PASS | `worker.py` | `test_individual_fault_boundary` 25개 ID, 아래 추가 경계; process crash 원자성은 미보장 |
| publication batch의 두 event 일괄 교체 | PASS | `publication.py:prepare_batch`/`commit_prepared` | `tests/test_live_analysis_publication.py` 직렬화·상한·swap fault; Python process crash는 미보장 |
| observation→analysis event 순서 | PASS | `publication.py`, `service.py` | `test_batch_event_order_replay_and_private_values`, 실제 SSE socket smoke |
| 단일 replay cursor·명시적 gap | PASS | `publication.py:replay_after` | buffer/HTTP/SSE/Node 테스트; eviction 이후 무유실 아님 |
| 개인정보 안전 DTO·직렬화 | PASS | `publication.py` allowlist, `http.py` response model | canary tests, 실제 status/SSE/OpenAPI smoke; trusted 내부 원문은 남음 |
| UI 공통 pending 32개/16KiB | PASS | `frontend/live-monitoring.js` | Node item·byte overflow 테스트; 실제 Safari overflow 조작은 NOT_TESTED |
| staged apply·pause/resume | PARTIAL | `frontend/live-monitoring.js` | Node 통과, Safari WebDriver는 staged 버튼과 pause toggle만 확인; pause 중 서버 계속 처리 수동 확인 없음 |
| focus/scroll 보존 | PARTIAL | JS에 강제 focus/scroll 없음 | Node 계약 확인; 실제 Safari keyboard-only·scroll 수동 검증 없음 |
| shutdown/FD/port/task 정리 | PARTIAL | runner/service/worker close | TestClient lifespan·실제 SIGINT/port 해제 통과; 모든 OS FD·EventSource zombie의 직접 계측 없음 |

## 하나의 application runtime 흐름

기존 `observation_changes`와 새 `analysis_changes`는 공통 `LIVE-EVENT-*` cursor에서 순서대로 전송된다.

`tests/test_live_launcher.py::test_same_running_runtime_commits_cases_and_transmits_safe_analysis`는 config→tail→detection→analysis→worker→publication→service→runner→FastAPI lifespan을 **동일 process**에서 구성한다. 기존 줄의 ack 0에서 시작해 합성 실패 5건·성공 1건을 append하고 detection/analysis revision 2 일치, `failed_to_successful_login`와 `brute_force_to_successful_login`, risk 1건 이상, `CASE-BRUTE-SUCCESS-01`의 exact-endpoint supporting relation 1건, resident 0/active lease·proposal 없음, 기존 observation과 새 analysis SSE, status/OpenAPI·wire의 canary 비노출, FD close를 확인한다. `tests/smoke_live_analysis_16_3.py`는 실제 loopback socket/CLI·SIGINT에서 health/status/snapshot/두 event/replay/gap/port 해제를 확인한다. 이 socket script는 외부 process의 trusted relation 상세를 직접 읽지 않으므로 동일-process 테스트와 증거 범위를 구분한다. Safari WebDriver에서는 버튼 전 네 목록이 비어 있고 버튼 뒤 네 목록에 항목이 생기는 것을 확인했다. 추가 UPDATED·NO_LONGER_MATCHES, pause 중 append·서버 지속 처리와 실제 keyboard-only는 이 Safari run에서 확인하지 않았다.

## Replay·복구와 실패 경계

`tests/test_live_publication_buffer.py`는 최초/정상/최신 ID의 빈 replay, 오래된·미래·외부 session·잘못된 ID, item/byte eviction, close gap을 각각 검사한다. `tests/test_live_http.py`는 `Last-Event-ID`·gap 종료·동시 연결 제한을, `tests/test_live_sse_stream.py`는 느린 client gap·cursor 독립성·slot 반환을 검사한다. `tests/live_monitoring_ui_behavior.cjs`는 연속 오류 뒤 수동 재연결, gap에서 stale/목록 폐기·자동 재연결 금지, 33번째 pending 및 16KiB 초과 시 폐기 없이 오류·status 재조회, terminal 문구를 검사한다. Analysis snapshot의 **category별 256 item / 128KiB**는 `test_snapshot_item_limit_is_pre_ack_without_truncation`과 `test_snapshot_size_failure_is_pre_ack`에서 monkeypatch 한계로 각각 fail-closed를 확인했다. 실제 최대 합성 256-subject snapshot은 26,307B였으며 128KiB 근접 실사용 일반화는 하지 않는다.

Phase 16.2의 독립 25 fault ID와 queue/D/A/P revision 표는 [보강 기록](live_analysis_16_2_verification.md)에 있다. 이번 단계는 observation serializer, analysis serializer, snapshot projection의 예외를 각 독립 case로 주입했다. 모두 ack 0·lease release 1·FIFO available 5·D/A revision 0·publication 0·active proposal 없음·안전 오류로 끝났다. 두 event의 합산 byte 초과도 ack 전에 전체 거부했다. Publication swap **전** failure는 두 event 모두 없고 D/A만 확정된 terminal 상태였다. Swap **직후** exception은 두 event가 모두 보이지만 worker가 `FAILED`로 terminalize되고 같은 revision을 다시 처리하지 않았다. 두 event 중 하나만 게시된 상태는 관찰하지 않았다. 기존 25 fault ID는 poll/lease/parse/각 proposal/abort/release/ack/각 commit/summary/notify/close를 포함한다. SSE encoder의 bad type·LF 등 경계는 `tests/test_live_http.py`, frontend malformed analysis는 Node에서 검증한다. 극단적 interpreter 종료·MemoryError는 테스트하지 않았고 원자적 transaction이라 주장하지 않는다.

| Phase 16.3 추가 fault point | 판정 | 독립/가장 가까운 검증 |
|---|---|---|
| observation 직렬화 실패 | PASS | `test_batch_prepare_faults_release_without_partial_publication[observation_serialization]` |
| analysis 직렬화 실패 | PASS | 같은 test의 `[analysis_serialization]` |
| 두 event 합산 byte 초과 | PASS | `test_two_event_combined_byte_cap_rejects_before_ack` |
| batch prepare 직후 예외 | PASS | `test_prepare_return_boundary_does_not_leave_active_proposal[publication]` |
| ack 직후 예외 | PASS | `test_individual_fault_boundary[16_after_queue_ack]` |
| detection commit 후 예외 | PASS | `[18_after_detection_commit]` |
| analysis commit 후 예외 | PASS | `[20_after_analysis_commit]` |
| publication swap 전 예외 | PASS | `test_batch_commit_swap_failure_has_no_partial_publication` |
| publication swap 직후 예외 | PASS | `test_fault_after_batch_swap_keeps_both_events_and_never_retries` |
| runner notify 실패 | PASS | `test_fault_point_24_runner_notify_change_is_terminal_without_reprocessing` |
| SSE encoding 잘못된 입력·LF | PASS | `test_connection_limit_close_and_safe_encoder`, `test_sse_encoder_rejects_serialized_newline_without_leaking_payload`; 실제 transport 예외 전체는 이 테스트 범위 밖 |
| snapshot projection 예외 | PASS | `test_batch_prepare_faults_release_without_partial_publication[snapshot_projection]` |

## 개인정보 및 브라우저 범위

Node UI 동작 테스트는 relation/case의 `NO_LONGER_MATCHES`, risk의 `NO_LONGER_PRESENT`를 같은 ID의 다음 revision에 단계적으로 반영하고 “더 이상 일치/포함되지 않음”으로 표시하는 것도 확인했다. 이는 실제 공격 종료·해결·안전의 증명이 아니다.

Account, 예약 IP, source filename/path와 내부 exception canary는 unit의 safe dataclass repr/serialization, 실제 status·snapshot·observation/analysis SSE, replay, OpenAPI, CLI stdout/stderr에서 부재를 검사했다. Node는 malformed payload의 private key를 거부하고 DOM text에 원문을 쓰지 않음을 확인한다. Safe DTO의 `asdict`는 allowlist 구조 자체를 확인하지만 모든 가능한 원문 조합에 대한 증명은 아니다. Trusted parser event, detector evidence, correlation/case 내부 state에는 원문이 필요하며 공개 경계와 혼동하면 안 된다. 실제 브라우저 console 전체, IndexedDB/clipboard/download에 대한 Safari 수동 관찰은 `NOT_TESTED`; 코드·Node 저장/unsafe DOM sink 검사만 수행했다.

Safari **18.6 (20621.3.11.11.3)** WebDriver에서 실제 loopback server의 영역 표시, status, native EventSource, snapshot, 새 결과 버튼, 적용 전/후 네 영역, pause/restart 버튼, 개인정보 비노출을 확인했다. 이것은 개발자 자동 walkthrough이며 사용자 연구, keyboard-only, VoiceOver, 실제 200% 확대, 320px, Safari console/CSP network panel 검사를 대신하지 않는다. 이 항목들은 `NOT_TESTED`이고 WCAG 2.2 AA 준수 주장을 하지 않는다.

## 성능 — 개발용 합성 측정

`uv run python -m tests.benchmark_live_analysis_16_4`; uv Python 3.12, 같은 account·예약 IP의 합성 application 실패 `N-1`건과 마지막 성공 1건, 앞선 record는 16줄 이하 step으로 확정하고 **마지막 한 줄 step**을 측정했다. Prefix마다 warm-up 2, 표본 12, `perf_counter_ns`, 아래 본표는 `tracemalloc` **꺼짐**. 모든 prefix에서 마지막 결과는 detection 1/relation 2/risk 1/case 1. 수치는 운영 SLA가 아니다.

| prefix / encoded raw bytes | 구간 | median / p95 / max (ms) |
|---|---|---|
| empty / 0 | worker step | 0.557 / 0.737 / 0.737 |
| 16 / 1,070 | worker / detection prepare / analysis prepare | 3.273 / 3.795 / 3.795 ; 0.294 / 0.397 / 0.397 ; 1.523 / 1.854 / 1.854 |
| 64 / 4,286 | worker / detection prepare / analysis prepare | 4.526 / 5.563 / 5.563 ; 0.422 / 0.547 / 0.547 ; 2.498 / 3.541 / 3.541 |
| 128 / 8,574 | worker / detection prepare / analysis prepare | 5.570 / 6.149 / 6.149 ; 0.562 / 0.785 / 0.785 ; 3.502 / 4.164 / 4.164 |
| 256 / 17,150 | worker / detection prepare / analysis prepare | 7.764 / 8.963 / 8.963 ; 0.921 / 1.043 / 1.043 ; 5.171 / 6.273 / 6.273 |
| 256 | publication prepare / commit / ack 후 전체 | 0.292 / 0.315 / 0.315 ; 0.009 / 0.013 / 0.013 ; 0.066 / 0.107 / 0.107 |

Runner 0.5초 polling 중 status HTTP 40회는 median/p95/max **2.524/3.973/5.861ms**였고 worker와 겹친 요청 3회였다. Worker close 12회는 **0.132/0.174/0.174ms**. 별도 같은 256-prefix 측정에서 safe JSON event serialization **0.049/0.059/0.059ms**, snapshot size 1,367B, 두-event batch 839B, 다양화 256-subject snapshot 26,307B였다. `tracemalloc` 켠 이전 Phase 16.2 동일 fixture prepare median 21.975ms/peak 31,912B와 tracing 없는 이번 5.171ms를 직접 성능 회귀로 비교하지 않는다. 실제 append→SSE는 socket smoke의 단일 표본이며 분포나 p95가 아니다. 입력 복잡도·브라우저 렌더링·지속 부하·p99를 보장하지 않는다.

## 판정과 릴리스 경계

검증 명령 결과: 변경 전 `1,981 passed`, live 집중 `368 passed`, 변경 후 전체 `1,989 passed`; 두 의존성 deprecation 경고는 변경 전후 동일하고 새 경고는 없었다. 인증·웹 합성 평가 **79/79**, 별도 Linux 합성 평가 **21/21**. UTC와 `Asia/Seoul`에서 동일 focused 25개가 각각 통과했다. `uv lock --check`, 변경 Python `py_compile`, `node --check`, Node live 동작 테스트, `git diff --check`, 변경 문서의 개인 경로/canary scan, live JS의 unsafe DOM/storage/remote URL scan은 통과했다. 같은 fixture의 반복 측정은 시간 수치가 아니라 결과·revision·event 순서의 결정성을 확인한다. Safari와 실제 socket smoke는 synthetic 데이터만 사용하고 임시 디렉터리와 listener를 종료했다.

추가 동일 절차 재실행(표본 12, warm-up 2, tracing 없음)에서 256-prefix safe snapshot UTF-8 JSON 생성은 median/p95/max **0.119/0.145/0.145ms**였다. 실제 loopback socket smoke의 append→`analysis_changes` 수신은 **43.516ms, 단일 표본**이었다. 후자는 OS scheduling·runner cadence의 영향을 받으므로 p95나 SLA로 일반화하지 않는다. 두 반복 측정의 시간값은 표본 변동이 있어 위 표와 직접 합산하지 않는다.

**CONDITIONAL GO** — 현 단일 application·loopback·합성 계약에서 batch parity, FIFO 실패 처리, 두-event 원자적 buffer swap, 명시적 gap, 개인정보 safe DTO, 현재 개발 상한과 정상 종료가 확인됐다. 256-prefix worker p95는 0.5초 polling 간격 아래였으나 운영 SLA가 아니다. v0.2에 포함할 후보는 이 단일-source 로컬 분석·bounded replay·단계적 UI에 한정한다. 릴리스 전 실제 Safari keyboard-only, 200% 확대·최소 폭, console/CSP와 gap·terminal·pause 중 append를 사람이 확인해야 한다. 확인되지 않은 OS 전체 FD/task/zombie stream 계측도 남아 있다. 이 미확인 항목은 현재 범위의 조건이며 PASS가 아니다. SSH/access live analysis, cross-source, 영구 저장, crash recovery, exactly-once, hosted 제공은 v0.2 이후로 보류한다. 탐지는 침해 확정이 아니고 관계는 인과관계가 아니며 risk 하향·NO_LONGER는 안전/해결을 뜻하지 않는다.

## Phase 17 후속 검수 연결

[Phase 17 수용성 기록](live_monitoring_acceptance_17.md)은 실제 loopback 정상·오류 종료 뒤 listener/process FD/임시 자료 정리와 Safari 18.6 WebDriver·HTTP/SSE 재검증을 추가한다. WebDriver는 사람의 keyboard-only, 실제 200% 확대 또는 Web Inspector 관찰을 대신하지 않는다. 이 미완료 항목은 Phase 17에서 별도 `BLOCKED`/`NOT_TESTED`로 남겨 v0.2 릴리스 실행 gate와 구분한다. Phase 16.4의 당시 판정을 사후에 PASS로 재해석하지 않는다.

2026-10-14 **Phase 17.1 후속 수동 검수**에서 사용자는 실제 Safari keyboard-only, 200% 페이지 확대, 가능한 최소 창 너비, Web Inspector의 주요 live 연결·결과 적용, pause 중 append와 terminal 안내를 각각 `PASS`로 확인했다. 실제 Safari replay gap은 안전한 주입 방법이 없어 `NOT_TESTED`이고 정확한 CSS viewport 수치·VoiceOver 상세·종료 뒤 Network zombie 요청도 미확인이다. 결과와 환경별 증거는 위 Phase 17 문서의 후속 절을 우선하며, Phase 16.4 당시의 `PARTIAL`·`NOT_TESTED`를 소급 수정하지 않는다.
