# Phase 21 — 동일 파일 bounded checkpoint 계약

상태: 단일 `application` source의 기본 private v2 설정에 구현된 경계. 이 문서는 기존 `FROM_END`와 worker transaction을 바꾸지 않는 복구 계약을 정의한다.

후속 Phase 21.1은 [관찰 가능한 파일 크기 감소의 fail-closed 검사](live_rotation_21_1.md)를 추가했다. 자동 rotation 추종이나 checkpoint 세대 전환은 여전히 없다.

## 현재 확정 지점 감사

`LiveTailSession._offset`은 `os.read` 직후 증가하므로 완성되지 않은 줄과 아직 큐에 있는 줄도 포함한다. `_partial`과 `_pending_chunk`는 메모리 전용이다. `acknowledge_lease()`는 FIFO queue prefix를 제거하지만 detector나 publication을 확정하지 않는다. Worker는 detection/analysis/publication proposal을 ack 전에 준비하고, ack → detection commit → analysis commit → publication commit → worker summary 순서로 확정한다. Runner 알림은 그 뒤이다. Ack 후 실패에 rollback이나 자동 재처리는 없다. Close는 미완료 queue record를 abandoned로 세고 FD·partial을 해제한다.

Detection/analysis의 PARSED history는 256건/256KiB이며 silent eviction을 하지 않는다. Worker의 detection/analysis revision은 처리한 비어 있지 않은 lease마다 함께 증가한다. 현재 모든 시작은 파일 EOF부터이고, 종료 시 offset·history·publication replay·session-local ID는 사라진다.

## checkpoint 의미와 상한

`committed_offset`은 **마지막으로 완전히 확정된 LF 줄 바로 다음 byte**다. 읽기 offset, UTF-8 문자 index, partial 끝 또는 단순 queue ack 위치가 아니다. 첫 시작에서 checkpoint anchor는 현재 EOF이며 기존 줄을 처리한 의미가 아니다. 정상 step은 publication과 worker summary까지 확정한 뒤에만 checkpoint를 준비·원자 교체하고, 그 뒤 runner에 새 publication을 알린다. Checkpoint write 실패는 이미 확정된 메모리/publication을 취소하지 않으며 terminal failure다. 다음 시작은 마지막 유효 checkpoint에서 다시 읽으므로 중복될 수 있다. Exactly-once·무유실은 보장하지 않는다.

Checkpoint는 private 위치의 닫힌 v1 JSON이다. config v2의 source ID·role·timezone·policy, 원본 파일의 private `(device,inode)` identity, 시작 anchor와 확정 byte offset, 원본 file size, write sequence, 완료한 lease별 record 수, PARSED history 수·byte 수, 안전한 의미 검증값만 저장한다. 로그 원문·경로·계정·IP·query·event/detection/case 객체 및 이들 원문 hash를 넣지 않는다. 첫 anchor부터 확정 offset까지의 replay는 256 완성 줄 및 256KiB로 제한한다. PARSED history가 그보다 먼저 기존 상한에 닿으면 기존대로 fail closed한다. 범위를 넘은 뒤 anchor를 임의로 전진시키지 않는다.

## 복구

기본 private v2 설정의 `BOUNDED_REPLAY_V1`에서만 활성화한다. 기존 `DISABLED`, 명시적 `--monitor-config`, v1은 기존 `FROM_END`다. Checkpoint가 없으면 EOF anchor를 검증하고 초기 checkpoint를 쓴 뒤 시작한다. Checkpoint가 있으면 소유자·0700/0600·symlink·schema·config binding·source identity·size·LF 경계·replay 상한을 검사한다. 저장된 lease 크기대로 기존 parser → detector → analysis를 재실행한다. 재생은 기존 publication을 만들거나 브라우저에 과거 변경을 재전송하지 않으며 새 session의 publication buffer만 열린다. 재생 직후 안전한 detection/analysis 결과를 checkpoint의 의미 검증값과 비교한다. 일치하지 않으면 서버를 열지 않는다. 완료 후 tail은 현재 EOF가 아니라 확정 byte offset부터 시작한다. 중지 중 추가된 완성 줄은 정상 새 step으로 처리한다. 재시작 후 public ID 연속성은 약속하지 않는다.

안전한 projection의 canonical 검증은 공개 민감값을 만들지 않지만, 동일한 안전 표시값으로 투영되는 서로 다른 원문을 구별하는 암호학적 원문 무결성 증명은 아니다. 같은 inode가 재사용되거나 같은 길이로 과거 바이트가 변경되는 잔여 위험이 있다. 파일 identity mismatch, size 감소, 잘림·교체·rotation 징후, 안전 의미 mismatch는 자동 추측 없이 fail closed한다.

동일 기본 설정은 private advisory lock을 한 프로세스가 독점한다. PID 문자열은 권한 증거가 아니다. Lock·FD는 종료 또는 crash 시 OS가 해제하지만, crash 복구 전체를 보장한다는 뜻은 아니다. 설정 삭제는 연결된 checkpoint도 검사·삭제하여 고아 checkpoint를 정상으로 취급하지 않는다. 두 파일 삭제는 단일 원자 transaction이 아니므로 부분 실패는 고정 오류로 보고한다. 원본 로그는 삭제하지 않는다.

## 실제 스키마와 저장 경계

| 필드 | 의미 | 공개 경계 |
|---|---|---|
| `schema_version`, `config_schema_version`, `source_id`, `source_role`, `start_position`, `parser_timezone`, `checkpoint_policy` | 닫힌 config binding (`1`, `2`, `SOURCE-000001`, `application`, `FROM_END`, `Asia/Seoul`, `BOUNDED_REPLAY_V1`) | 역할·정책만 안전 요약 |
| `file_device`, `file_inode` | 열린 regular file의 private identity | 비공개 |
| `replay_start_offset`, `committed_offset`, `committed_file_size` | 원본 파일의 byte 경계와 확인 당시 크기 | 비공개 |
| `write_sequence`, `batches` | 확정된 순차 lease의 수와 각 완성 줄 수; 동일 prefix의 재실행 순서 | 비공개 |
| `history_count`, `history_bytes`, `partial_line_present` | PARSED prefix 검증값과 미완성 줄 존재 여부 | `--show`는 bounded 건수만 |
| `semantic_digest` | 안전한 detection·analysis snapshot을 정렬 JSON으로 직렬화한 SHA-256 검증값 | 비공개 |

JSON은 unknown/duplicate key, bool-as-int, 음수, 잘못된 version·enum, 8192 byte 초과를 거부한다. 원본 로그 byte나 원래 계정/IP의 hash는 저장하지 않는다. 이 digest는 동일한 안전한 표현을 갖는 서로 다른 private join key를 식별하지 못한다. 따라서 동일 inode의 in-place 수정이나 inode reuse를 완전히 검출하는 무결성 보증이 아니다. Private 원본 로그 파일과 checkpoint를 다른 사용자가 수정할 수 없는 권한 경계가 전제되며, 잔여 위험은 운영 무유실 약속으로 해석하지 않는다.

기본 설정의 사용자 전용 디렉터리에 `checkpoint-source-000001.json`과 advisory lock 파일을 둔다. 디렉터리는 `0700`, 두 파일은 `0600` 및 현재 사용자 소유여야 한다. Symbolic link와 비정상 타입을 거부한다. 저장은 같은 디렉터리의 private 임시 파일에 결정적 UTF-8 JSON 한 줄을 쓰고 flush/fsync한 뒤 원자적 replace·디렉터리 fsync·post-read 검증을 수행한다. 이전 또는 새 완전한 checkpoint만 유효하며, replace 이후 오류는 rollback으로 보고하지 않는다. 임시 파일은 실패 시 정리하지만 OS 수준 secure erase나 모든 filesystem crash 보증을 주장하지 않는다. Lock 파일은 설정 삭제 뒤에도 안전한 고정 이름의 빈 관리 artifact로 남을 수 있으며 원본 로그나 checkpoint는 아니다.

## 실패와 재시작 의미

| 경계 | 현재 process | durable 위치와 다음 재시작 |
|---|---|---|
| 최초 checkpoint 쓰기 전·중 실패 | 서버 시작 거부 | 이전 checkpoint 없음; 다음 시도도 안전 검증 필요 |
| parse/detection/analysis/publication prepare 실패 | abort, lease FIFO release, `DEGRADED` | 이전 checkpoint 유지 |
| queue ack 실패 | worker `FAILED`, rollback 추측 금지 | 이전 checkpoint 유지; 이미 제거됐을 수 있는 record 수 불명 |
| ack 뒤 detection/analysis/publication/summary 실패 | terminal `FAILED`, rollback·자동 재게시 없음 | 이전 checkpoint 유지; 재시작 시 bounded 중복 가능 |
| publication/summary 뒤 checkpoint prepare·write 실패 | terminal `FAILED`, 이미 게시된 event 취소 불가 | 이전 또는 새 완전한 checkpoint; bounded 중복 가능 |
| checkpoint 확정 뒤 runner notification 실패 | runner terminal, 같은 revision 재처리 금지 | 새 checkpoint 유지; 알림이 유실됐을 수 있음 |
| 재생 중 schema/권한/identity/boundary/parser/의미 검증 실패 | 서버 시작 거부, `FROM_END` fallback 없음 | 원본과 private 자료 수동 확인 필요 |

Checkpoint는 queue와 분석·publication보다 앞서지 않는다. 현재 프로세스의 확정 상태와 disk checkpoint는 실패 순간 일시적으로 다를 수 있다. 이전 checkpoint 이후에 원본 파일에 남은 줄을 다시 읽으므로 중복 가능성이 있다. 파일이 rotation·truncation·교체됐거나 재생 구간이 사라지면 자동으로 병합하지 않고 fail closed하므로 gap 가능성도 있다. 재시작된 새 session의 public ID와 과거 SSE cursor는 이어지지 않는다. `--show`는 `FIRST_START`·`RECOVERABLE`·`NEEDS_REVIEW`·`DISABLED` 중 안전한 상태만 보여주며 offset·inode·digest를 보여주지 않는다. 실행 중 기본 설정 삭제는 lock 때문에 거부한다. 승인 삭제는 config 뒤 checkpoint 순서라 두 번째 삭제 실패 시 orphan checkpoint가 남고 새 setup은 이를 거부한다. 백업·Time Machine·crash dump의 보존과 삭제는 이 기능이 통제하지 않는다.

## 개발용 성능 관찰과 범위

Darwin/macOS, Python 3.12.7, 로컬 임시 filesystem(종류 미확인), 합성 application 입력, prefix마다 warm-up 1회·측정 3회, replay 구간에서 `tracemalloc` 사용. 256 완성 줄/16,956 encoded byte에서 replay 전체 median 183.1ms, p95/max 183.1ms, parser 재생 median 65.1ms, detection 45.3ms, analysis 41.3ms, safe digest 0.8ms, peak tracked memory 약 295KiB였다. 같은 규모의 정상 worker step median 4.7ms, checkpoint update median 1.3ms, 상태 HTTP median 1.3ms(별도 30회), 종료 median 1.6ms, checkpoint JSON 565 byte였다. 1/16/64/128/256 구간의 전체 replay median은 각각 11.4/16.5/47.2/82.9/183.1ms였다. 소규모 합성 입력 측정이며 운영 SLA나 rotation 대응 성능이 아니다. Linux와 Windows는 이 단계에서 실제 검증하지 않았다. Phase 21.1에서 rotation/truncation 정책과 OS별 실패 경계를 별도로 검증해야 한다.
