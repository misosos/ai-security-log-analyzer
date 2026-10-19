# Phase 26.0 — 동일 SSH 파일의 bounded checkpoint 복구

**판정: macOS 구현·검증은 CONDITIONAL GO, Ubuntu 원격 CI는 후속 확인.** 기존 `BOUNDED_REPLAY_V1`의 닫힌 checkpoint schema를 변경하지 않고 단일 SSH source 역할만 확장했다. 기존 application v2 checkpoint는 그대로 읽고 재작성하지 않으며, 명시적 v1 SSH `--monitor-config`는 종전처럼 매번 `FROM_END`다. 새 기능은 **private 기본 위치의 명시적으로 작성·검증된 v2 SSH config**에서 `--monitor`로 실행할 때만 활성화된다. 설정 마법사는 여전히 application 전용이고 SSH config 생성·수정 UI는 이번 단계에 없다. 기존 설정을 자동 migration하거나 덮어쓰지 않는다.

## 변경 전 증거와 역할 차이

시작 SHA `0bf42dbfc36cc09cbb07211c21ed969b5fe41c76`의 GitHub Actions CI는 성공, 로컬 전체 기준선은 2,308 passed·기존 deprecation 경고 2개였다. 수정 전 새 테스트의 v2 SSH load·재시작·reset 3건은 모두 `LiveMonitorConfigV2`가 `source_role=ssh`를 `INVALID_CONFIG`로 거부해 실패했다. 이는 기존 경로의 실제 부재를 고정한 증거이며 테스트 편의를 위해 parser·detector 의미를 바꾸지 않았다.

| 구분 | application | SSH |
|---|---|---|
| parser/timezone | 기존 application parser, `Asia/Seoul` | 기존 SSH parser, `Asia/Seoul` |
| ignored/rejected | 공백은 ignored; 예상 가능한 parser 실패는 rejected | 같은 live adapter 계약. timestamp는 기존 parser의 초 단위이며 microseconds 문자열은 지원하지 않음 |
| event type | application 인증 의미 | 지원하지 않는 SSH 문구도 timestamp가 유효하면 `event_type=None`인 PARSED event일 수 있음 |
| LF/길이 | 완성 LF 줄, 최대 2048 bytes인 기존 tail 계약 | 같은 tail·queue·UTF-8 경계. raw SSH 줄은 checkpoint에 복사하지 않음 |
| 분석 | 기존 인증·file-access 지원 범위 | 기존 실패→성공, brute→성공, risk, generic/brute case만; file-access/cross-source/Spray case 추가 없음 |
| config | setup wizard가 private 기본 v2 생성 | private 기본 v2를 사용자가 명시적으로 준비해야 함. Wizard는 여전히 거부 |
| 기존 실행 | 기본 `--monitor`에서 checkpoint 가능 | v1 `--monitor-config`는 checkpoint 없이 `FROM_END` |

## Public·internal 계약

닫힌 v2 config의 고정 source ID `SOURCE-000001`, 단일 source, `FROM_END`, `Asia/Seoul`, `FAIL_CLOSED` 및 `BOUNDED_REPLAY_V1`을 유지한다. SSH의 표시 별칭만 고정 `SSH 로그 1`로 허용한다. `--monitor`는 기존 기본 resolver와 0700 parent·0600 config 검증 뒤 SSH runtime을 구성한다. `--monitor-config` 경로의 기존 v1/v2 명시적 실행은 checkpoint를 만들지 않는다. Browser/API에서 source path를 정하거나 설정을 바꾸지 못한다. `--show`는 role·checkpoint enabled/existence·안전한 recovery 상태만, `--reset-checkpoint`는 종료된 기본 monitor의 연결 checkpoint **한 개**만 `y/yes` 승인 뒤 삭제한다. Config·원본 로그·parent/sibling은 삭제하지 않는다. 활성 advisory lock, 승인 대기 중 교체, malformed/unsafe checkpoint는 거부한다. Reset은 secure erase가 아니며 다음 실행은 현재 EOF의 새 분석 epoch다.

Private checkpoint JSON의 필드 집합·schema version 1은 Phase 21과 동일하다. 이미 있던 `source_role` 필드에 `ssh`만 추가 허용하고 읽을 때 **config role과 정확히 대조**한다. `file_device`/`file_inode`, `replay_start_offset`/`committed_offset`, `batches`, history count/bytes, safe detection·analysis snapshot digest도 기존 의미 그대로다. SSH 계정·IP·hostname·filename·원본 path·raw line·evidence/rationale 또는 그 원문 hash의 새 저장은 없다. Config 자체에는 기존 계약대로 source path가 저장된다. Trusted 원본 파일·메모리의 reconstructed event에는 원문이 있을 수 있다. Private checkpoint identity/offset/digest는 status·SSE·UI·일반 오류·`repr()`에 표시하지 않는다.

처음에는 파일 EOF에 빈 checkpoint를 쓴다. 이후 `poll → lease → parse → detection/analysis/publication prepare·검증 → queue ack → detection commit → analysis commit → publication commit → worker summary → checkpoint atomic persist`의 기존 순서를 유지한다. 실패가 ack 전이면 proposal abort와 FIFO lease release 후 degraded, ack 뒤면 rollback·자동 재처리 없이 terminal failure다. Checkpoint write 실패 시 이미 전달된 안전 publication을 취소하지 않는다. Replay는 원본 파일의 bounded 완성 줄을 저장된 lease batch 크기로 기존 SSH parser·detector·analysis에 다시 적용하고 안전 digest를 검증한다. 이전 SSE event를 생성·재게시하지 않으며 다음 append부터 새 session publication이다. Session-local ID 연속성은 보장하지 않는다.

Replay 한계는 기존과 동일한 최대 256 완성 줄·256 KiB이며 PARSED history는 256 event·256 KiB에서 fail closed다. Offset은 완성 LF 다음 **byte**이지 UTF-8 문자 index나 partial 끝이 아니다. Malformed/unknown checkpoint, role binding 오류, 권한·symlink·identity·size·LF·UTF-8·semantic mismatch, 범위 초과, lock 경합은 `FROM_END`로 조용히 fallback하지 않는다. Rename rotation·copytruncate·file shrink·source 교체를 추측 병합하지 않는다. 같은 inode의 in-place rewrite나 reuse는 기존 safe semantic digest만으로 완전히 입증할 수 없는 잔여 위험이다. 강제 종료의 무유실·exactly-once도 아니다.

## 검증 범위와 한계

합성 SSH prefix별로 uninterrupted worker, checkpoint 종료·재시작, 기존 batch detection/correlation/risk/case projection을 비교한다. 실패 5건과 threshold 직전, 실패→성공, brute→성공, ignored/rejected, 유효 timestamp이나 `event_type=None`, 중복, out-of-order, 다중 계정을 포함한다. 재시작 전 partial LF 줄은 확정하지 않고 다음 시작에서 완성된 경우에만 한 번 처리한다. 기존 SSH parity suite가 nearest success·후보 동률·정확한 60초 경계/초과와 Spray case no-go를 계속 담당한다. 이 신규 기능은 microseconds 해석을 추가하지 않는다. Role mismatch·malformed·semantic mismatch·wrong mode·symlink·file replace/shrink, lock contention, checkpoint write fault와 reset 승인 중 교체를 별도 검사한다. Application checkpoint·v1 SSH 및 명시적 v2 SSH의 checkpoint 없는 `FROM_END`, safe status/SSE 회귀도 유지한다.

macOS에서 실제 전경 `--monitor --no-browser` 프로세스로 기존 줄 제외 → 실패 append → 정상 종료 → 중단 중 성공 append → 동일 파일 재시작·관계/사례 생성 → `--show` → 승인 reset → 새 `FROM_END` epoch → 종료·listener/임시 자료 정리를 합성 파일과 임시 HOME으로 검증한다. 즉시 같은 포트 재bind는 OS의 `TIME_WAIT` 때문에 거부된 실행이 있어 재시작 smoke는 새 loopback port를 쓰고 **활성 listener 부재**를 검사한다. 이는 listener FD 잔존과 `TIME_WAIT`를 구분한 것이다. macOS의 local filesystem에서 0700/0600·advisory lock·atomic replace를 검사했지만 네이티브 Ubuntu의 SSH checkpoint focused·두 process lock·restart·reset은 push 이후 CI gate로 남긴다. Windows 지원은 주장하지 않는다.

개발용 성능은 synthetic SSH 99-byte line, 1/16/64/128/256 records, 각 warm-up 1회·측정 3회, macOS 로컬 임시 filesystem에서 측정했다. 측정 wrapper를 통한 parser/prepare 타이밍은 계측 overhead를 포함하며 운영 SLA가 아니다. 256줄은 이미 record 한계에 도달하므로 이후 append step을 성공 성능으로 측정하지 않았다. 평가 79/79·21/21·risk/case 70/70은 기존 합성 corpus 일치도이지 실제 로그 탐지율이 아니다. Vector/Fluent Bit 자동 대체는 Phase 25.1 NO-GO이며 이번 변경에 포함되지 않는다.

Private 기본 디렉터리와 checkpoint 권한은 각각 0700/0600이다. 개발용 전체 복구 시간의 median/p95/max (ms)는 1줄 3.764/3.870/3.870, 16줄 5.218/5.332/5.332, 64줄 10.957/12.021/12.021, 128줄 18.020/18.963/18.963, 256줄 38.142/40.701/40.701이었다. 표본이 3개뿐인 로컬 개발 측정이므로 p95는 운영 백분위나 지연 상한이 아니다. 256줄 입력은 25,344 bytes이며, 이때 checkpoint load 0.140/0.147/0.147, file pread 0.030/0.066/0.066, parser 8.442/8.889/8.889, detection prepare 10.476/10.585/10.585, analysis prepare 13.764/15.069/15.069, safe digest 0.165/0.194/0.194, status 0.107/0.113/0.113 ms였다. 각 내부 단계는 별도 계측이므로 합산을 전체 복구 시간으로 해석하지 않는다.
