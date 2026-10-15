# Phase 21.5 — rotation handoff 안전성 gate

상태: **설계·계약 검증만** 완료했다. 현재 production은 단일 `application` source의 동일 regular file만 bounded checkpoint로 복구한다. Rename rotation, copytruncate 및 여러 파일 세대의 자동 handoff는 여전히 **NO-GO**다. Config/checkpoint 스키마, tail·worker·publication, API·SSE·UI, 분석 규칙을 변경하지 않았다.

## 현재 구현에서 입증되는 범위

`LiveTailSession`은 열린 FD와 설정 경로의 `(device, inode)`를 비교하고, 현재 읽기 offset 또는 이전에 관찰한 크기보다 축소되면 중단한다. `LiveProcessingWorker`는 proposal 생성 후 queue ack 직전에 한 번 더 검사한다. 기본 v2 checkpoint는 **한 파일 identity**와 그 파일 안의 **하나의 연속된 replay_start_offset→committed_offset 구간** 및 batch partition만 저장한다. 재시작 시 현재 설정 경로로 연 FD에서 그 구간을 다시 읽는다. 저장된 raw 로그 복사본이나 이전 세대 파일 검색 기능은 없다. 256 parsed event/256 KiB의 분석 history·replay 상한은 이 프로젝트의 개발 정책이다.

검증 테스트는 rename 전에 열린 old writer가 rename 후에도 **old FD에 새 완성 줄을 쓸 수 있는** 합성 상황을 만든다. 현재 collector는 새 경로를 열거나 old FD를 조용히 drain하지 않고 `POLL_FAILURE`/terminal `FAILED`로 멈춘다. Queue ack, detection·analysis revision, publication, checkpoint는 전진하지 않는다. 이는 데이터가 모두 복구됐다는 뜻이 아니라 **근거 없는 세대 결합을 하지 않는다**는 뜻이다.

## 전이 판정

| 관찰 | 현재 동작 | 자동 handoff 판정 | 필요한 추가 근거 |
|---|---|---|---|
| 같은 identity, 관찰된 크기 비감소 | 기존 bounded 처리 | 현 계약 내 GO | LF boundary·queue/history 상한 유지 |
| 경로 identity 변경, old FD에 unread 또는 partial line | fail closed | NO-GO | old writer 종료, 미완성 줄 정책, 이전 세대 durable replay |
| old FD가 일시적으로 EOF | fail closed | NO-GO | EOF는 old writer 종료 증거가 아님 |
| 새 경로가 먼저/나중에 생성되거나 old writer가 계속 append | fail closed | NO-GO | 세대 순서·양쪽 writer quiescence 입증 |
| old writer 종료가 입증되고 old 세대가 완성 LF에서 끝남 | 아직 fail closed | CONDITIONAL GO 설계 후보 | 두 세대 bounded 재접근·checkpoint schema·crash matrix 검증 |
| copytruncate 또는 동일 inode의 빠른 truncate·재성장 | 관찰된 축소면 중단, 관찰 못 하면 판별 불가 | NO-GO | byte-level 세대 증거 없이는 무유실 주장 불가 |
| 중지 중 rotation, 이전 파일 소실, 빠른 다중 rotation | checkpoint identity 불일치로 시작 거부 | NO-GO | 안전한 이전 세대 재접근·누락 범위 판단 근거 |

**Partial line은 파일 세대를 넘어 이어 붙이지 않는다.** Old FD에 남은 줄을 읽을지, 마지막 미완성 줄을 어떻게 알릴지, 새 세대의 첫 줄과 시간 순서를 어떻게 정할지는 별도 typed 상태 계약이 필요하다. Timestamp 정렬로 기존 batch 입력 순서 의미를 바꾸지 않는다. 단순한 파일명 패턴 검색, inode만으로 generation 추측, old EOF 한 번 관찰, watcher 알림 하나로 handoff를 승인하지 않는다.

## 미래 handoff의 최소 계약과 장애 창

미래의 rename-only pilot을 검토하려면 다음이 모두 필요하다: (1) old writer quiescence의 **검증 가능한 증거**, (2) old FD의 완성 줄과 partial line의 명시적 처리, (3) old/new 세대의 identity와 순서를 고정한 typed proposal, (4) 둘 모두를 재시작 시 다시 열 수 있는 **bounded durable replay** 근거, (5) 전체 prefix에 대한 기존 parser·detector·correlation·risk·case 동등성, (6) queue/history/publication 한도 초과 시 fail closed, (7) 개인정보 안전한 UI gap·복구 안내. 새 private checkpoint에 두 세대의 identity/offset을 보관한다면 이는 저장 metadata 확대이므로 별도 승인·권한·retention 검토 없이 구현하지 않는다. Raw 로그 복사, glob으로 rotated file 탐색, 웹에서 경로 변경은 후보가 아니다.

| 장애 창 | 필요한 미래 계약 | 현재 판정 |
|---|---|---|
| old drain의 ack 전 | proposal abort·FIFO release; partial 혼합 금지 | 미구현 |
| old ack 후 detection/analysis/publication 전 | rollback·자동 재처리 주장 금지; 잠재 gap 집계 | 미구현 |
| old publication 후 세대 checkpoint 전 | 이미 보인 결과 취소 불가; 재시작 중복·gap 명시 | 미구현 |
| 세대 checkpoint 후 new FD 활성화 전 | 새 파일을 안전하게 재열고 identity 재검증 | 미구현 |
| new 첫 ack 후 checkpoint 전 | 두 세대 replay와 revision parity, 부분 게시 금지 | 미구현 |

파일 rename과 외부 writer 종료는 collector의 queue ack·checkpoint와 원자적 transaction이 아니다. 정상 종료·crash·전원 차단의 모든 창에서 exactly-once 또는 무유실을 약속하지 않는다. 명시적으로 승인받은 **새 분석 epoch**에서 이전 history를 버리는 대안도 기존 분석 연속성이 깨지므로 자동 fallback으로 넣지 않는다.

## 개인정보·자원·사용자 경계

원본 로그, 계정, IP, source/config path, inode·offset 및 이전 세대의 파일 내용은 trusted 내부에만 존재할 수 있다. Public status/SSE/UI/오류/일반 로그에는 safe 고정 상태·복구 행동만 허용한다. 새 세대 ID를 IP·계정·경로·hash로 만들지 않는다. 두 세대를 동시에 보관할 경우 FD 수, queue 32 item/16 KiB, parsed history 256/256 KiB, publication 32 event/16 KiB, checkpoint byte budget을 다시 측정·검증해야 하며 한도 도달 시 일부 세대를 조용히 버리지 않는다. 현재는 추가 FD·raw retention·checkpoint metadata를 만들지 않는다.

사용자에게 현재 제공하는 의미는 **“로그 파일 교체 감지 — 자동으로 이어 읽지 않습니다. 설정과 원본을 확인한 뒤 모니터링을 다시 시작하십시오.”**다. 실패를 탐지 0건·안전·해결로 표현하지 않는다. 다시 시작해도 동일-file checkpoint identity 불일치는 무언의 `FROM_END`로 넘어가지 않는다.

## Research basis와 검증 한계

- [Python 3.12 `os.fstat`·`stat_result`](https://docs.python.org/3.12/library/os.html)는 열린 FD와 경로의 metadata를 따로 검사할 수 있는 근거다. `(device, inode)`만으로 모든 content generation이나 old writer 종료를 증명한다는 자료는 아니다.
- [logrotate의 `copytruncate`](https://man7.org/linux/man-pages/man5/logrotate.conf.5.html)는 copy와 truncate 사이의 기록 유실 창을 명시한다. 이 프로젝트의 byte/record 상한을 정하지 않는다.
- [Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)는 inode 기반 watch와 queue overflow 가능성을 설명한다. [Apple FSEvents](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html)는 dropped-event flag와 지연 가능성을 설명한다. 둘 다 알림을 재검사 신호로만 사용할 수 있으며 ack된 byte의 완전성 증거는 아니다.

macOS 합성 regular file의 old-writer rename 거부와 기존 fail-closed 테스트만 **PASS**다. 실제 Linux logrotate, Apple FSEvents 기반 collector, copytruncate 재성장, 중지 중 다중 rotation, Safari 수동 복구, 전원 차단 뒤 두 세대 복구는 **NOT_TESTED**다. 이 미검증 범위를 자동 handoff 구현의 통과 증거로 사용하지 않는다. 다음 구현 단계는 세대 metadata 저장 확대의 승인 여부와 old-writer quiescence 증거를 먼저 결정해야 한다.
