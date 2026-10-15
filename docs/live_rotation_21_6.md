# Phase 21.6 — 두 파일 세대 복구 가능성 검증

상태: **설계·실패 재현만 수행. Production handoff는 NO-GO.** 현재 checkpoint v1, config, worker, publication, API·SSE·UI는 변경하지 않았다. 자동 rename rotation, copytruncate, truncation 복구를 제공한다고 해석하지 않는다. 현재 지원 범위는 같은 `application` regular file의 bounded replay다.

## 코드와 재현으로 확인한 현재 경계

- `LiveTailSession._probe_identity()`는 설정 경로와 열린 FD의 `(st_dev, st_ino)` 및 관찰된 크기를 검사한다. Worker는 ack 직전에도 검사한다. 이 검사는 관찰 가능한 교체·축소를 중단하지만 writer 수, 마지막 기록 여부, 같은 inode의 truncate·재성장을 증명하지 않는다.
- Checkpoint v1은 단일 `file_device`·`file_inode`, 하나의 `replay_start_offset`→`committed_offset`, `committed_file_size`, lease별 `batches`, 안전한 의미 digest를 저장한다. 재시작은 **현재 설정 경로 하나**를 열어 그 파일에서만 재생한다. 열린 old FD는 프로세스 종료 뒤 재사용할 수 없고 inode만으로 이전 파일을 안전하게 다시 열 수 없다.
- 새 테스트는 (1) old FD의 EOF 이후 old writer append, (2) rotated 원본이 남아 있어도 새 설정 경로의 다른 identity를 checkpoint가 거부, (3) old partial line과 new 첫 줄의 결합 거부, (4) copytruncate 뒤 같은 identity·크기로 재성장한 파일을 metadata만으로 구분할 수 없음을 재현한다. (4)는 **OS 관찰의 한계**이지, production의 안전한 copytruncate 처리 증거가 아니다.
- 기존 256 완성 record / 256 KiB replay와 256 parsed event / 256 KiB analysis history는 프로젝트 정책이다. 두 세대의 **합산** 범위가 상한을 넘거나 이전 파일을 다시 열 수 없으면 일부를 버리거나 `FROM_END`로 전환하지 않고 중단해야 한다.

## Old writer 종료: 증명 가능한가?

일반적인 외부 writer에 대해 reader가 한 번 관찰한 EOF, 일정 시간 크기 불변, `st_nlink`/PID 상태, `lsof` 결과, rename 이벤트, Linux `IN_CLOSE_WRITE`, macOS FSEvents 알림은 **quiescence(이후 old FD에 기록이 없다는 보장)**를 증명하지 못한다. Writer가 FD를 계속 보유하거나 다시 열 수 있고, watcher에는 지연·유실·race가 있다. Source를 읽는 권한만 가진 현재 도구는 writer를 정지시키거나 확인 응답을 강제하지 않는다.

미래 rename-only pilot의 조건부 후보는 **관리되는 writer/rotator 프로토콜**이다: old writer의 쓰기 중지·FD close 확인, 해당 세대에 다시 쓰지 않는다는 계약, old 파일의 마지막 LF/partial 처리 결정, 새 generation open 전후 identity 재검증, 실패 시 terminal 중단. 프로토콜 바깥의 writer가 접근 가능한 환경에서는 이 증거도 약하다. Linux inotify 또는 Apple FSEvents는 상태를 다시 검사하라는 힌트로만 쓸 수 있다. 현재 범용 로그 파일에 이러한 협력 계약이 없으므로 자동 handoff는 NO-GO다.

## 두 세대 bounded durable replay의 최소 후보

| 후보 private 필드·계약 | 목적 | 지금 저장 여부 | 승인 전 조건 |
|---|---|---|---|
| `generation_order` 및 generation별 고정 ID | old→new 입력 순서 고정; timestamp 재정렬 금지 | 없음 | batch-prefix parity와 ID 비공개 |
| generation별 `file_device`, `file_inode` | 다시 연 파일과 세대 binding 확인 | **한 세대만** | inode reuse·교체 TOCTOU의 잔여 위험 명시 |
| generation별 `replay_start_offset`, `committed_offset`, 확인 크기 | 각 세대의 LF byte boundary, 합산 상한 검증 | **한 세대만** | partial line·UTF-8·CRLF 정책, 256/256 KiB 합산 상한 |
| old generation의 안정적 재접근 locator | 재시작 후 old raw 원본을 다시 열기 | 없음 | 경로라면 개인정보 관련 metadata 저장 확대 승인; 권한·symlink·owner·identity 검증 |
| 세대를 가로지르는 `batches`와 safe semantic digest | parser→detection→analysis 입력 순서와 결과 검증 | 단일 세대만 | 기존 full-prefix 의미 동등성, 과거 publication 억제 |

이 표는 **구현 스키마가 아니다**. Dynamic rotated path를 checkpoint에 기록하는 안은 source 경로의 추가 저장이다. 보존 기간 후보는 checkpoint가 유효한 동안부터 사용자가 config와 연결 checkpoint를 삭제하거나 명시적으로 승인한 epoch가 끝날 때까지이며, 현재 구현에는 TTL이 없다. 삭제 후에도 filesystem backup·Time Machine·crash dump는 통제하지 못한다. Locator, inode, offset, digest는 trusted private 파일에만 두고 `repr()`·오류·일반 로그·status·SSE·UI·OpenAPI에 내보내지 않아야 한다. Raw 로그 복제나 원문/hash/account/IP/query를 checkpoint에 넣는 것은 후보가 아니다.

대안은 (a) 협력적 rotator가 **고정 private archive 위치와 불변성**을 보증해 checkpoint에 dynamic path를 넣지 않는 방식, (b) 사용자가 분석 연속성 상실을 이해하고 명시적으로 새 epoch를 시작하는 방식, (c) 현재처럼 fail closed 유지다. (a)도 세대별 identity·offset 저장과 old 원본의 실제 보존·권한 검증이 필요하다. (b)는 기존 failed-login prefix를 버려 batch 의미가 달라지므로 자동 fallback이 아니다. 단순 glob/이름 패턴으로 old 파일을 찾지 않는다.

## TOCTOU·partial line·copytruncate

미래 reader는 old/new 각 경로에 대해 `lstat`→`O_NOFOLLOW` 읽기 전용 open→`fstat`와 parent binding 재검증을 해야 하지만 모든 외부 writer race를 원자적으로 봉쇄하지 못한다. 각 generation의 완료 LF만 ack·committed boundary가 될 수 있다. Old partial을 new 첫 줄과 잇지 않으며, old partial을 보류·폐기·오류 중 무엇으로 다룰지 사용자에게 알리는 별도 계약이 필요하다. 중지 중 old partial이 완성됐는지 알 수 없는 경우 자동 진행하지 않는다.

`copytruncate`는 rename과 다르게 같은 identity에서 길이를 줄인다. 축소 후 다음 probe 전에 원래 크기 이상으로 재성장하면 현 `(device,inode,size)` 검사로 세대 변화를 놓칠 수 있다. 파일 내용 fingerprint를 추가해도 probe 사이에 사라진 byte를 되살리지 못한다. 따라서 copytruncate 자동 병합은 별도 NO-GO이며, 관찰된 truncation은 지금처럼 fail closed한다.

## Crash window와 미래 acceptance gate

| 지점 | 실패 시 필요한 의미 | 현재 상태 |
|---|---|---|
| old drain proposal 전·ack 전 | abort·FIFO release, 세대 간 줄 혼합 없음 | old/new handoff 미구현 |
| old ack 후 detection/analysis 전 | rollback·자동 재처리 주장 금지, 잠재 gap 표시 | 미구현 |
| old publication 후 dual-generation checkpoint 전 | 이미 보인 SSE 취소 불가; 재시작 중복·gap 가능 | 미구현 |
| 두 세대 checkpoint 원자 교체 중 | 이전 또는 새 **완전한** 문서만 유효, hybrid 금지 | v1의 한 세대만 검증 |
| checkpoint 후 new 첫 ack 전 | old archive 재접근, new identity, 세대 순서 재검증 | 미구현 |
| new 첫 ack 후 다음 checkpoint 전 | 두 세대 replay, safe 의미 parity, 과거 publication 억제 | 미구현 |
| old 원본 제거·권한 변경·symlink 교체·합산 상한 초과 | 새 파일만 `FROM_END`로 시작하지 않고 fail closed | 미래 테스트 필요 |

Queue ack, detection/analysis/publication commit, checkpoint 원자 교체, 외부 writer의 rename·close는 하나의 transaction이 아니다. Exactly-once·무유실을 주장하지 않는다. Ack 뒤 checkpoint 전 장애에는 중복 가능성이 있고, 원본 세대가 사라지면 gap이 가능하다. 현재 same-file fault matrix를 두 세대 보증으로 확대 해석하지 않는다.

## 판정과 연구 근거

- **GO:** 현재 same-file bounded checkpoint와 관찰 가능한 교체·축소의 fail-closed 유지; Phase 21.6 설계·합성 실패 재현.
- **CONDITIONAL GO 후보:** 협력적 writer/rotator의 close·불변 archive 계약, 합산 bounded replay, 두 세대 crash matrix, 개인정보 metadata 승인 및 macOS/Linux 실제 검증이 모두 있는 좁은 rename-only pilot.
- **NO-GO:** 범용 외부 writer의 종료 추측, EOF/watch 알림만으로 handoff, copytruncate 병합, 이전 원본이 없는 재시작, 부분 history eviction, public 경계의 경로·identity·offset 노출.

[Python 3.12 `os` 문서](https://docs.python.org/3.12/library/os.html)는 FD와 경로 metadata 검사 primitive의 근거다. [Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)는 close 알림과 queue overflow를 명시하고, [Apple FSEvents](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html)는 알림 지연·유실 뒤 재검사를 요구한다. [logrotate의 copytruncate](https://man7.org/linux/man-pages/man5/logrotate.conf.5.html)는 copy와 truncate 사이 기록 유실 창을 명시한다. 이 자료들은 프로젝트의 256/256 KiB 상한이나 writer quiescence를 정해 주지 않는다.

macOS의 synthetic regular file 재현만 직접 PASS다. 실제 Linux logrotate, macOS FSEvents watcher, 협력적 rotator, 여러 세대 crash/power-loss, Safari 수동 복구는 NOT_TESTED다. Production checkpoint 형식·동작을 바꾸기 전에 위 필드의 정확한 집합·목적·보존 기간·노출 경계와 대안에 대한 사용자 승인이 필요하다.
