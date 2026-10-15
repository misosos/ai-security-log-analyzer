# Phase 21.1 — 관찰 가능한 로그 축소의 fail-closed 경계

상태: 단일 `application` source의 기존 `FAIL_CLOSED` 정책을 강화했다. 자동 rotation 추종, 새 파일 연결, checkpoint 재설정 또는 과거 세대 병합은 구현하지 않았다.

## 결정과 근거

Phase 21까지 tail은 경로의 `(device, inode)`가 바뀌거나 열린 파일의 크기가 **현재 읽기 offset보다 작아진 경우** 중단했다. Checkpoint에서 복구하면 읽기 offset보다 파일 크기가 클 수 있다. 그 사이 관찰했던 파일이 줄어도 새 크기가 offset 이상이면 다음 줄을 읽어 서로 다른 구간을 한 prefix로 취급할 수 있었다. 수정 전 실패 테스트 `test_observed_shrink_above_read_offset_fails_before_polling_more`가 이를 재현했다.

이 단계는 열린 regular file에서 관찰한 최대 `st_size`를 trusted session 메모리에만 보관한다. Poll 전후 identity 검사에서 현재 크기가 이전에 관찰한 크기보다 작으면 `SOURCE_TRUNCATED`로 terminal 실패한다. 검사 중 크기가 커지면 관찰값을 갱신한다. 크기 검사는 UTF-8 문자 수가 아닌 원본 byte 수다. 새 필드는 public snapshot·API·SSE·UI·checkpoint JSON·`repr()`에 들어가지 않는다. Queue ack, detection/analysis commit, publication, checkpoint 순서는 바뀌지 않는다.

[Python 3.12의 `os.stat_result.st_size`](https://docs.python.org/3.12/library/os.html#os.stat_result)는 regular file의 byte 크기다. [logrotate의 `copytruncate` 설명](https://man7.org/linux/man-pages/man5/logrotate.conf.5.html)은 복사와 truncate 사이에 기록 유실 창이 있을 수 있다고 밝힌다. 이 자료는 관찰 가능한 축소를 중단해야 하는 근거이지, 모든 rotation을 복구할 수 있다는 근거가 아니다. 256건/256KiB와 0.5초 polling은 프로젝트 정책이며 외부 문서가 정한 값이 아니다.

## 상태·실패 계약

| 상황 | 관찰 근거 | 동작 | 남은 한계 |
|---|---|---|---|
| rename 후 같은 경로에 새 파일 | 경로 identity 불일치 | 기존 `SOURCE_REPLACED`, terminal | 옛 FD의 미완료 줄을 자동 drain하지 않음 |
| symlink·삭제로 교체 | 열린 경로 검사 실패 | 기존 고정 오류, terminal | 원본을 추측해 찾지 않음 |
| 관찰한 크기보다 축소, 새 크기는 read offset 이상 | `st_size` high-water 감소 | 새 `SOURCE_TRUNCATED`, ack·checkpoint 전 중단 | 이미 확정된 과거 revision은 rollback하지 않음 |
| poll 중 축소 | poll 후 재검사에서 크기 감소 | `SOURCE_TRUNCATED`, lease 없음 | queue에 이미 들어간 미확정 record는 close 시 abandoned 처리 |
| restart 시 checkpoint보다 작은 파일 | private checkpoint size/identity 검사 | 시작 거부 | `FROM_END` fallback 없음 |
| 두 검사 사이 truncate 후 기존 크기 이상 재성장 | 현재 stat만으로 세대 변화 증명 불가 | 탐지 보장 없음 | 조용한 복구를 보증하지 않음; 후속 generation 설계 필요 |
| 동일 inode의 제자리 내용 변경 | 안전 snapshot digest가 같을 수 있음 | 정확한 private join 무결성 보장 없음 | 원문 hash를 checkpoint에 추가하지 않음 |

오류는 원래 경로·inode·offset·로그 줄을 포함하지 않는다. 실패를 탐지 0건·안전 상태로 해석하지 않는다. 자동 retry·새 세대 연결·checkpoint 삭제를 수행하지 않는다. 사용자는 원본 로그와 설정을 수동 확인한 뒤 별도 승인된 복구 절차가 마련될 때까지 모니터링을 다시 시작할 수 없다. Checkpoint 파일을 직접 편집해 우회하는 방식은 지원하지 않는다.

## 검증과 다음 단계

- 수정 전 실패 → 수정 후 통과: 축소 후 크기가 read offset보다 큰 경우.
- 단위: poll 전 축소, poll 도중 축소, 고정 오류·terminal 상태·FD 종료.
- 통합: worker/checkpoint에서 축소 뒤 추가 ack·detection/analysis/publication revision·checkpoint write가 없음.
- 기존 rename·symlink·partial·restart 거부, Phase 16 fault matrix, 전체 회귀를 유지한다.
- 다음 gate는 여러 파일 세대의 identity·old-writer 종료·partial line·bounded drain·durable generation을 증명해야 한다. 그 전에는 rename handoff, copytruncate 병합, 중단 중 회전된 파일 탐색, 무유실·exactly-once 주장은 no-go다.

실제 운영 로그나 Linux rotation daemon과의 end-to-end 검증은 수행하지 않았다. macOS 합성 regular file에서 검증했고 Linux·Windows 실제 실행은 별도 확인이 필요하다. 최소권한 별도 collector, 다중 source, authenticated remote collector 역시 보류다.

Phase 21 개발 benchmark를 변경 후 다시 실행했다(Darwin, Python 3.12.7, 합성 256줄·16,956 byte, warm-up 1회·표본 3개). Bounded replay median/p95는 64.9/69.3ms, checkpoint update는 0.6/0.6ms였다. 이 benchmark의 `worker_step` median 2.0ms는 **최대 16줄인 여러 step의 중앙값**이지 256줄 단일 step이 아니며, status HTTP는 재생 완료 후 측정됐다. 따라서 이전 다른 조건의 수치와 직접 비교하거나 동시 부하·운영 SLA를 주장하지 않는다.
