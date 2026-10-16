# Phase 21.7 — 승인 기반 새 분석 epoch 준비

상태: **기본 private v2 `application` 설정에서 구현됨.** `--reset-checkpoint`는 fail closed로 중단된 모니터링을 자동 복구하지 않는다. 사용자가 분석 연속성 포기를 이해하고 `y/yes`로 승인한 경우에만 연결된 derived checkpoint JSON **하나**를 삭제한다. Config·원본 로그·lock·parent·sibling 파일은 삭제하지 않으며 서버를 자동 시작하지 않는다. 기존 checkpoint v1 형식, detection·correlation·risk·case, API·SSE schema는 바꾸지 않았다. Rotation/copytruncate 자동 handoff와 두 세대 replay는 계속 NO-GO다.

## 사용 방법과 사용자 의미

먼저 실행 중인 기본 모니터링을 정상 종료한다. 파일 교체·축소·checkpoint identity 불일치의 원인을 확인한 뒤 trusted 로컬 터미널에서 다음을 실행한다.

```bash
uv run python -m app.monitor_setup --reset-checkpoint
uv run python -m app.local_web --monitor
```

첫 명령은 안전한 결과 단절 안내를 표시하고 `y/yes`만 승인한다. 공백·대소문자는 정규화하지만 다른 입력·EOF는 취소(종료 0)다. 승인 전에는 삭제하지 않는다. 성공 뒤에도 두 번째 명령은 사용자가 직접 실행한다. 다음 시작은 현재 파일의 **FROM_END**이므로 기존 줄과 중단 기간의 줄을 분석하지 않는다. 이전 탐지·관계·위험도·조사 사례 prefix, session-local ID 및 SSE replay cursor는 새 epoch에 이어지지 않는다. 이것은 누락된 기록의 복구, 무유실 또는 exactly-once가 아니다. 실패·취소는 안전한 0건 판정이 아니다. UI의 “최신 상태로 다시 연결”은 동일 runtime의 표시 복구일 뿐 이 CLI reset을 실행하지 않는다.

CLI는 계정·IP·source/config/checkpoint 원본 경로, inode·offset, 로그 줄, 내부 예외를 출력하지 않는다. Terminal의 입력·process list·scrollback 등 기존 로컬 경계는 별개다. 색상이나 자동 진행·timeout 없이 결과와 복구 행동을 읽은 뒤 한 번 승인한다.

## 삭제 전후 계약

1. 기본 경로의 private parent(현재 사용자, `0700`)와 닫힌 config v2(일반 파일, 현재 사용자, `0600`)를 열린 FD·경로 identity로 검증한다. 사용자 지정 `--output`과 명시적 `--monitor-config`는 대상이 아니다.
2. Config가 `BOUNDED_REPLAY_V1`인 경우에만 기존 checkpoint lock을 독점 획득한다. 활성 모니터링이나 다른 reset이 lock을 보유하면 `CHECKPOINT_RESET_ACTIVE`로 거부한다. Lock은 승인 대기부터 결과 확인까지 보유한다.
3. 연결된 checkpoint 하나가 실제로 있어야 한다. `O_NOFOLLOW`로 regular file을 열고 owner·`0600`·8192 byte 상한·중복/unknown field 없는 checkpoint v1 schema와 config binding을 검증한다. Approval 전에 파일 identity `(device,inode,mode,owner,size,mtime,ctime)`를 기록한다.
4. 승인 후 config guard·lock identity를 재검증한다. Checkpoint를 다시 열어 schema와 path/FD identity를 재검증하고, 승인 전 identity와 같을 때만 고정 이름 `checkpoint-source-000001.json` 하나를 열린 private directory FD 기준으로 `unlink`한다. 디렉터리 `fsync`와 대상 부재를 확인한다. 확인 실패는 성공이라고 보고하지 않는다.
5. Config, source, lock, parent와 sibling 파일은 불변이다. Recursive 삭제, glob, 임의 경로, checkpoint에 저장된 경로를 삭제 대상으로 사용하지 않는다. 부재·손상·symlink·권한 오류는 자동으로 무시하거나 고치지 않는다.

`CHECKPOINT_RESET_MISSING`·`UNSAFE`·`CHANGED`·`ACTIVE`는 검증 실패(종료 3), unlink 또는 삭제 후 검증 실패는 종료 4, 성공·명시 취소는 종료 0이다. 고정 오류에는 경로·로그·내부 예외가 없다. `fsync` 같은 **삭제 이후** 실패에서는 파일이 이미 제거됐을 수 있으므로 rollback·성공을 모두 주장하지 않고 수동 확인을 안내한다. Reset은 secure erase가 아니며 backup·filesystem snapshot·Time Machine·crash dump에 이전 checkpoint metadata가 남을 수 있다.

## Race·장애·개인정보 경계

승인 대기 중 같은 내용의 새 checkpoint inode로 교체해도 identity mismatch로 삭제를 거부한다. Config 교체 역시 guard가 거부한다. 두 협력적 reset 또는 monitor/reset의 동시 실행은 advisory lock으로 직렬화한다. Lock 이름 교체는 기존 manager의 identity 검사로 거부한다. 하지만 POSIX `unlink(name, dir_fd=...)`에는 portable한 inode 조건부 CAS가 없다. **최종 검사 직후** 같은 UID의 비협력적 프로세스가 private 이름을 바꾸는 TOCTOU까지 원자적으로 막는다고 주장하지 않는다. `flock`도 advisory다. 이 한계는 [Python `os` 문서](https://docs.python.org/3.12/library/os.html)와 [Linux `flock(2)`](https://man7.org/linux/man-pages/man2/flock.2.html)의 primitive 범위와 구분한 프로젝트 판정이다.

Checkpoint 파일 자체에는 기존 승인된 private identity·offset·safe semantic digest가 있었을 수 있다. Reset 성공 후 현재 checkpoint 이름은 없지만 열린 FD, filesystem 잔존 블록, backup과 crash dump의 완전 삭제를 보증하지 않는다. Public API·SSE·UI에 epoch reset용 새 필드를 추가하지 않는다. 새 `--monitor` 프로세스는 빈 accumulator와 새 publication session으로 시작하며, 최초 checkpoint는 현재 EOF anchor를 기록한다. 이때 원본 파일을 수정하지 않는다.

## 검증과 남은 한계

macOS의 합성 regular file에서 승인·취소, active lock, 같은 내용의 inode 교체, config 교체, symlink·malformed·missing checkpoint, 동시 reset, 삭제 뒤 `fsync` 장애와 실제 CLI→loopback 서버 종료→파일 교체→재시작 거부→reset→새 FROM_END 시작을 검증했다. 이후 [Phase 21.8 Linux 감사](live_checkpoint_epoch_reset_21_8_linux_audit.md)는 시작 코드의 Ubuntu CI 전체 회귀와 신규 명시적 Linux CI gate를 분리해 기록한다. Old SSE cursor와 새 session의 gap 의미는 기존 transport 테스트에 의존하며 이번 단계의 Safari 수동 테스트는 없다. 전원 차단, 같은 UID의 악의적 최종-nanosecond swap, secure erase는 NOT_TESTED 또는 보장 밖이다. 자동 rotation, copytruncate, 두 세대 분석 연속성은 [Phase 21.6 gate](live_rotation_21_6.md)대로 계속 NO-GO다.
