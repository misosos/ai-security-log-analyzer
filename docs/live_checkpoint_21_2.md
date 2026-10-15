# Phase 21.2 — checkpoint 소유권·원자 교체 장애 경계

상태: 기본 private v2 설정의 단일 `application` checkpoint에서 **관찰 가능한 잠금 이름 교체**를 ack 전에 거부한다. 원자 교체 직후 실패의 재시작 의미를 합성 fault injection으로 검증했다. 공개 API·SSE·UI, checkpoint 스키마, 분석 규칙, 저장 자료는 바꾸지 않았다.

## 소유권 계약

Manager는 기존 advisory `flock`을 유지하면서 잠금 경로의 `lstat` 의미와 열린 잠금 FD의 device/inode/owner/mode를 비교한다. 시작·복구, **빈 step을 포함한 poll 전**, checkpoint 쓰기 전, 매 step의 checkpoint 사전 검증에서 비교한다. 이름이 삭제·symlink·다른 inode로 바뀌면 고정 `CHECKPOINT_UNSAFE`로 fail closed한다. Poll 전이면 worker는 고정 `POLL_FAILURE`로 terminal `FAILED`; poll 이후 사전 검증에서 발생하면 proposal abort → FIFO lease release → `DEGRADED`이며 queue ack, detection/analysis/publication commit, checkpoint 갱신은 없다. Ack 뒤 쓰기에서 발견되면 이미 확정된 상태를 rollback하지 않고 terminal `FAILED`다.

이는 **검사 시점의 identity** 보장이다. 같은 권한의 로컬 프로세스가 검사 사이에 잠금 이름을 교체할 수 있으므로 악의적인 동일 사용자에 대한 절대적 단일 프로세스 보장이나 분산 transaction을 주장하지 않는다. Lock 파일을 자동 삭제하거나 재생성해서 추측 복구하지 않는다. 설정·checkpoint 경로, inode, offset, 원문 예외는 공개 오류에 넣지 않는다.

## 교체 후 실패·재시작

정상 순서: queue ack → detection commit → analysis commit → publication commit → worker summary → checkpoint temp write/fsync → atomic replace → parent fsync → strict post-read → runner notify. Checkpoint 이전에 browser publication state가 앞설 수 있다. `os.replace` 이후 실패가 발생해도 worker는 `CHECKPOINT_FAILED_AFTER_PUBLICATION`으로 terminal이며 이미 ack·확정된 revision을 되돌리거나 자동 재게시하지 않는다.

| 주입 위치 | 현재 process | 디스크 checkpoint | 재시작 의미 |
|---|---|---|---|
| replace 전 write/fsync 실패 | terminal; revision은 메모리에서 앞설 수 있음 | 이전 유효 버전 | 원본 bounded 구간을 다시 읽을 수 있어 중복 가능성 |
| replace 직후 parent fsync 실패 | terminal; rollback 없음 | 새 완전 버전이 관찰될 수 있으나 전원 손실 내구성은 입증하지 못함 | strict 검사로 유효한 버전만 재생; 과거 publication 억제 |
| replace 후 strict post-read 실패 | terminal; rollback 없음 | 새 버전 또는 손상 상태 | 유효하면 재생, 손상되면 fail closed; 과거 publication 억제 |
| checkpoint 완료 뒤 runner notify 실패 | terminal; checkpoint는 앞서 있음 | 새 유효 버전 | 새 session snapshot은 재구성하나 알림의 exactly-once는 보장 안 함 |

합성 테스트에서 parent fsync·post-read 오류 후에는 새 파일이 완전하게 남았고, 재시작에서 detection/analysis revision을 재구성하며 이전 publication을 재전송하지 않았다. 실제 전원 차단, filesystem별 crash consistency, 복구 중 원본 변조는 이 테스트로 검증되지 않았다. 이전 checkpoint 뒤 publication이 사용자에게 보였는지 여부도 확정할 수 없으므로 중복·gap 가능성을 유지한다. Raw log, 계정, IP, path, query의 새로운 보존은 없다.

## 검증 범위와 다음 gate

macOS 합성 regular file에서 idle poll 전·poll 후·ack 뒤 잠금 이름 교체, ack 전 FIFO 복구, 원자 교체 후 두 장애점, 재시작 replay, 기존 전체 회귀를 검사했다. 실제 Linux 및 OS 전원 차단 실험은 `NOT_TESTED`다. Safe projection digest는 서로 다른 trusted 계정/IP join 값을 항상 구별하지 못하고, 파일의 truncate·재성장이 두 관찰 사이에 끝나면 크기 검사만으로 알 수 없다. 다음 gate는 실제 프로세스 종료·다시 시작과 HTTP/SSE 사용자 흐름, Linux 파일시스템·rotation 환경, 동시 부하 성능을 별도로 검증해야 한다. 자동 rotation handoff·무유실·exactly-once는 여전히 no-go다.

개발 benchmark 재실행 조건은 Darwin/Python 3.12.7, 합성 256 event·16,956 byte, warm-up 1회·표본 3개다. Replay 전체 median/p95/max는 61.2/62.2/62.2ms, checkpoint update는 0.5/0.6/0.6ms였다. `worker_step` median 1.9ms는 **최대 16 record인 step들의 중앙값**이며 256 event 단일 step이 아니다. Status HTTP는 replay 종료 뒤 측정됐다. 동시 부하나 전원 차단 성능·운영 SLA는 이 값으로 주장하지 않는다.
