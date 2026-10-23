# Phase 32.2 — bounded multi-source publication, API, SSE

**범위:** 당시 32.2 구현은 [32.1A private v3 설정](multi_source_private_config_32_1.md)과 [32.1B 내부 runtime](multi_source_runtime_32_1b.md)을 내부 launcher로 검증했다. **Phase 32.3 후속 구현**은 해당 schema 3 publication을 production `--monitor` 및 역할 선택 UI에 연결했다. 32.2 자체의 설계·테스트 범위는 변하지 않으며 사용자 수용은 아직 NOT_TESTED다. 단계 구분과 후속 gate는 [32.3 구현 기록](multi_source_user_monitoring_32_3.md)을 참조한다.

## 기존 단일 source 공개 계약과 확장 이유

단일 source status는 닫힌 `LiveStatusResponse` schema_version `2`이며 단일 source_role, worker/publication state, detection·analysis revision, 집계, 고정 오류, 32 item·16 KiB replay 상한을 보낸다. SSE는 snapshot, observation_changes, analysis_changes, replay_gap, service_status, heartbeat, stream_end를 사용한다. Observation→analysis는 한 worker step 안에서 순서를 지킨다. event ID는 세션별 `LIVE-EVENT` 전역 cursor 형태지만 단일 source 세션에만 속한다. Buffer eviction은 gap으로 알리고 최신 snapshot 재조회가 필요하다. 단일 source 분석 projection은 131072 byte와 category별 256 item 상한이다. 기존 frontend validator는 schema `2`와 정확한 필드·enum만 수용한다. Schema `2`를 두 역할로 재해석하면 기존 클라이언트의 단일 revision·source 전제를 깨므로 내부 두 역할 transport에만 schema `3`을 사용한다. 기존 화면은 schema `3`을 안전하게 거부하고 Phase 32.3에서 별도 수용 계약을 만든다.

## v3 안전한 snapshot과 publication

`PairStatusResponse`는 닫힌 DTO다. 전체 service_state와 application·SSH 각 역할의 role, service_state, detection_revision, analysis_revision, observation/relation/risk/case count, checkpoint_available 불리언, 안전한 last_step_code를 제공한다. 한 역할이 DEGRADED/FAILED이면 전체 상태도 READY/RUNNING이 아니다. 경로·파일명·identity·offset·계정·IP·hostname·raw line·evidence·rationale·내부 예외·실제 checkpoint/lock 이름은 DTO와 OpenAPI에 없다. Trusted runtime 내부에는 원본이 남을 수 있다.

기존 source별 publication proposal과 worker의 ack 경계를 그대로 사용한다. Ack 전에 source event projection·직렬화와 두 event 합계 16 KiB 검사를 완료하고, ack 뒤 source commit 다음에 global pair buffer를 commit한다. Event에는 schema `3`, source_role, 역할별 detection_revision·analysis_revision와 source 비식별 세션의 단조 증가 global event_id가 포함된다. 한 step의 observation_changes가 analysis_changes보다 먼저 간다. 각 역할의 correlation·risk·case는 자체 analysis accumulator에서만 온다. 두 역할의 publication은 원자적 transaction이 아니다. 다른 역할의 확정 결과를 되돌리거나 자동 재게시하지 않는다.

Global replay는 32 item·16 KiB를 넘지 않는다. Status DTO는 비식별 session/event ID 형식과 남은 event의 연속 ID 범위·count 일치를 검증한다. Eviction은 `EVICTED_EVENT_ID` gap이며 사라진 event의 역할을 추적해 영향을 받을 수 있는 역할을 포함한다. 입증할 수 없는 malformed/foreign/future/unknown cursor gap은 두 역할 모두를 포함한다. Gap frame은 `stale:true`와 최신 snapshot 재조회 안내를 보내며 stream을 닫는다. 같은 event ID는 cursor 이후에 다시 적용하지 않는다. URL query나 browser storage에 cursor를 넣는 경로는 만들지 않았다. SSE slot은 최대 2개이며 frame/snapshot은 JSON을 완전 직렬화한 다음 보낸다. 131072 byte status snapshot 상한을 적용한다.

준비 실패는 기존 worker의 proposal abort·lease release 뒤 전체 scheduler DEGRADED/FAILED 중단으로 이어진다. Commit·notify 등 ack 이후 실패는 rollback하지 않으며 전체를 정상으로 표시하지 않는다. 일반 HTTP 오류·SSE 종료에는 고정 code와 일반 문구만 사용한다. 서비스 종료 시 두 runtime worker와 publication, SSE slot 및 listener를 정리한다. 이는 crash 이후 exactly-once·무유실이나 두 source transaction을 뜻하지 않는다. Phase 32.3은 기존 닫힌 DTO를 production 런처와 UI에서 소비하며 schema 2 경로를 별도로 유지한다.

## 재현과 검증

수정 전 `tests/test_multi_source_publication_32_2.py`는 pair publication 모듈 부재로 collection 실패했다. 추가 fault 테스트는 초기 runner notify 예외와 cycle 실패 뒤 notify 예외가 원문 canary를 전파하는 결함을 각각 재현했고, 고정 `PAIR_RUNNER_FAILED` terminal 상태로 수정했다. Serializer에 사적 필드를 주입한 수정 전 테스트도 공개 projection 누출을 재현해 observation·analysis의 닫힌 허용 필드 검사로 막았다. DTO의 비식별 session/event ID 검사 누락도 수정 전 실패를 확인한 뒤 보완했다. 합성 application·SSH 파일을 쓰는 production runtime 테스트는 역할별 revision, 한쪽만 변경·양쪽 변경·idle, global ID, 순서, eviction gap, ack 전 projection·합산 byte 실패, ack 후 application·SSH swap 실패와 부분 batch 부재, snapshot byte 상한의 안전한 HTTP 오류, DTO와 HTTP privacy를 확인한다. `tests/smoke_multi_source_publication_32_2.py`는 실제 loopback socket에서 health/status/OpenAPI/SSE snapshot, 양쪽 append·event 순서, mixed replay, eviction gap, source identity 교체 뒤 terminal 상태, 종료 후 listener/FD 정리를 확인한다. `frontend/live-monitoring.js`는 그대로이며 schema `3`은 기존 단일 source validator가 거부한다.

개발용 benchmark 명령은 `env PYTHONPATH=. uv run python tests/benchmark_multi_source_publication_32_2.py --warmup 2 --samples 10`이다. 각 표본은 새로운 합성 파일·private 설정·runtime을 만들고 종료 뒤 소유 FD, lock, queue, lease, proposal, SSE slot을 확인한다. 출력은 case별 n, median/p95/max ms, median payload byte다. p95는 nearest-rank 값이다. 이는 개발 머신의 관측치이며 운영 SLA·최악 지연·실제 사용자의 체감 속도 보장이 아니다.

| 합성 macOS 측정 | n | median ms | p95 ms | max ms | median payload byte |
|---|---:|---:|---:|---:|---:|
| 두 역할 status snapshot | 10 | 0.296 | 0.358 | 0.358 | 1149 |
| 초기 SSE snapshot | 10 | 0.857 | 1.153 | 1.153 | 1173 |
| application publication | 10 | 4.940 | 6.490 | 6.490 | 1023 |
| SSH publication | 10 | 4.873 | 5.989 | 5.989 | 1007 |
| 두 역할 연속 publication | 10 | 10.503 | 13.233 | 13.233 | 2030 |
| mixed replay | 10 | 0.035 | 0.123 | 0.123 | 1504 |
| replay gap 생성·조회 | 10 | 209.883 | 223.170 | 223.170 | 30 |
| status HTTP 응답 | 10 | 2.372 | 3.348 | 3.348 | 1161 |

`replay_gap` 값은 application append와 40 scheduling cycle로 eviction을 만든 뒤 gap을 조회하는 전체 합성 작업이다. `successive_pair_publication`은 하나의 cycle에서 application·SSH step 두 개와 이어지는 idle cycle의 합성 계측이다. Payload byte는 해당 측정이 생성하거나 반환한 safe JSON/frame의 중간값이다.
`status_http`는 ASGI TestClient를 거친 HTTP 응답 계측으로 TCP stack·실제 browser 수신 지연을 포함하지 않는다. 별도 loopback socket smoke는 기능 검증이며 latency 표본이 아니다.

## 남은 경계

Phase 32.3 전까지 v3 일반 사용자 `--monitor`, setup/show/reset/delete UX, production 두 역할 화면·필터·탐색 및 Safari 수용은 없다. 자동 rotation/copytruncate, 두 파일 세대 replay, cross-source correlation·risk·case, source 무제한 추가, 두 source 원자적 transaction, exactly-once·무유실은 지원하지 않는다.
