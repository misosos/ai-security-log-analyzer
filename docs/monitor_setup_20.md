# Phase 20·20.1 — 로컬 application 모니터링 설정 마법사와 기본 설정 관리

Phase 30.1 현재 사용법: 마법사에서 `1` 애플리케이션 로그인 로그 또는 `2` SSH 인증 로그를 명시적으로 선택한다. 예전 `application` 입력도 허용한다. 두 역할 중 하나의 파일만 private v2 설정에 저장하고, 기존 설정은 덮어쓰지 않는다. SSH dry-run은 기존 parser로 최대 4,096 byte·완성 16줄·줄당 2,048 byte를 검사해 인증 실패·성공 기록·기타 기록·무시·형식 미확인의 **건수만** 보여 준다. 형식 검사 결과는 탐지율이나 침해 여부를 뜻하지 않는다. 성공 후 기본 실행 명령은 `uv run python -m app.local_web --monitor`다. 명시적 `--output` 기능은 유지하지만 해당 config 경로를 안내 출력에 다시 표시하지 않는다. 상세 경계는 [SSH 설정 구현](monitor_setup_ssh_30_1.md)을 본다. 아래 Phase 20·21·26 설명은 각 시점의 기존 계약과 이력을 기록한다.

Phase 21 갱신: 아래 Phase 20/20.1 당시 설명의 `checkpoint_policy=DISABLED`·"config 하나만 삭제"·"file lock 없음"은 기존 설정에만 해당한다. 새 설정은 `BOUNDED_REPLAY_V1`이며 기본 `--monitor`에서 동일 파일 bounded checkpoint를 사용한다. `--show`는 checkpoint 상태/이력 건수도 안전하게 표시한다. 승인 삭제는 연결 checkpoint도 검사해 config 먼저, checkpoint 다음으로 지운다. 활성 모니터링이 lock을 가진 동안 삭제는 거부된다. 두 파일 삭제는 원자적이지 않고 부분 실패 시 수동 확인이 필요하다. 명시적 `--monitor-config`와 기존 `DISABLED` 설정은 재시작 때 기존 `FROM_END`다. 자세한 현재 계약은 [Phase 21 문서](live_checkpoint_21.md)를 우선한다.

Phase 21.7 갱신: [새 분석 epoch reset](live_checkpoint_epoch_reset_21_7.md)은 기본 checkpoint JSON 하나만 별도 `--reset-checkpoint` 명령으로 승인 삭제한다. Config 삭제 명령과 다르며 설정·원본 로그는 유지한다. 자동 rotation 복구는 아니다.

Phase 26.0 갱신: [SSH 동일 파일 복구](ssh_checkpoint_recovery_26_0.md)는 사용자가 명시적으로 준비한 private 기본 v2 SSH config의 `BOUNDED_REPLAY_V1`만 추가한다. 이 문서의 Phase 20 마법사 생성·dry-run 절차는 여전히 **application 전용**이다. `--show`·`--reset-checkpoint`는 SSH 기본 v2도 안전한 역할 요약과 연결 checkpoint 하나의 승인 reset만 처리한다. 명시적 v1 SSH `--monitor-config`는 재시작마다 `FROM_END`다.

상태: **구현됨**. 다음 명령은 trusted 로컬 CLI이며 브라우저·웹 API·detector·LLM을 실행하지 않는다.

```bash
uv run python -m app.monitor_setup
uv run python -m app.monitor_setup --output /absolute/path/to/monitoring.json --no-color
uv run python -m app.monitor_setup --show
uv run python -m app.monitor_setup --delete
uv run python -m app.local_web --monitor
```

기본 저장 위치는 macOS의 사용자 `Library/Application Support/ai-security-log-analyzer/monitoring.json`, Linux의 `$XDG_CONFIG_HOME/ai-security-log-analyzer/monitoring.json` 또는 사용자 `.config` 아래다. Setup과 launcher는 같은 resolver를 사용하며 cwd·저장소 위치를 탐색하지 않는다. `--output`은 절대 경로만 받는다. 기존 설정 파일은 덮어쓰지 않는다. 기본 설정은 별도 명령 `uv run python -m app.local_web --monitor`로 **사용자가 직접** 시작한다. 기존 명시적 `--monitor-config <절대-경로>`도 유지하며 사용자 지정 `--output`은 그 명령으로 실행한다. v1 config와 v2 config를 기존 loader가 모두 읽지만 `--monitor`는 private 기본 위치의 v2만 허용한다. `--monitor`가 없으면 live는 자동 활성화되지 않는다.

## 사용자 흐름과 승인

1. 새 줄만 읽고, 기존 줄을 분석하지 않으며, trusted 내부 메모리에는 원문이 존재할 수 있다는 안내를 읽는다.
2. `y` 또는 `yes`로 계속 진행한다. 다른 응답은 취소(종료 0)다.
3. 역할 `application`을 정확히 입력한다. SSH/access/Linux Audit는 이 마법사에서 지원하지 않는다.
4. 절대 경로의 일반 로그 파일을 입력한다. 경로는 shell로 실행되지 않는다. 터미널 drag-and-drop의 **정확히 하나의 바깥쪽 인용 부호**만 제거하며 환경변수·`~`·glob·URL·shell 문법을 해석하지 않는다.
5. 제한된 기존 샘플의 안전한 count를 확인한다. 이것은 **형식 확인**이지 기존 줄의 live 분석·결과 확정이 아니다.
6. schema 2, application, `FROM_END`, `Asia/Seoul`, 안전한 저장 위치 설명과 검사 수치를 확인한다. 원본 줄·계정·IP·source path는 미리보기에 없다.
7. `이 설정을 저장하시겠습니까? [y/N]`에 `y`/`yes`만 승인이다. 앞뒤 공백·대소문자는 정규화하지만 그 외 값은 승인하지 않는다. 취소 시 config·임시 파일은 없다.
8. 성공 후 시작 명령을 **실행하지 않고** 표시한다. 기본 저장이면 경로 없는 `--monitor`만 안내한다. 명시적 `--output`일 때에만 마지막 대화형 안내에 shell-quoted config 절대 경로를 포함한다. 이는 터미널 scrollback에 남을 수 있으므로 공유하지 않는다. `--output` 자체는 OS 프로세스 목록/셸 기록에 남을 수 있다.

## 기본 설정 조회·삭제·실행

`--show`는 기본 v2 config 하나의 존재·schema·application 역할·enabled·`FROM_END`·timezone·checkpoint/rotation 정책·권한 적합·현재 source 사용 가능 여부만 출력한다. 원본 JSON, source/config 경로, 파일 identity, 로그는 출력하지 않는다. 기본 설정이 없으면 `uv run python -m app.monitor_setup`을 안내하고 서버를 띄우지 않는다. 조회 순간의 source 사용 가능 여부는 앞으로의 처리를 보증하지 않는다.

`--delete`는 **기본 config 파일 하나만** 대상으로 한다. Private parent `0700`, 소유자·파일 `0600`, regular/non-symlink, 최대 4096B, 정확한 v2 schema, 열린 FD와 경로 identity를 승인 전과 직전에 검사한다. 승인 질문에 `y`/`yes`만 허용한다. 취소·EOF는 삭제 없이 종료 0이다. 손상된 파일·잘못된 권한은 자동 고치거나 지우지 않는다. 설정 하나만 `unlink`하며 원본 로그·parent·sibling·사용자 지정 `--output` 파일은 삭제하지 않는다. 설정 삭제는 secure erase가 아니고 backup·Time Machine 자료도 지우지 않는다. 실행 중 설정을 지워도 이미 열린 source의 처리가 즉시 멈추지 않는다. 재사용하려면 마법사를 다시 실행한다.

`--monitor`는 같은 resolver에서 기본 경로를 찾아 private parent/file와 v2 schema를 먼저 검증한 뒤 기존 runtime을 구성한다. 누락·손상·권한 오류에는 sample-only 서버로 fallback하지 않는다. `--monitor-config`와 동시 사용은 CLI 오류다. 명시적 `--monitor-config`는 기존 v1/v2 경로 계약을 유지하며, 기본 설정 전용 `0700` parent/`0600` file 규칙을 그 경로에 소급 적용하지 않는다.

검사와 unlink 사이에는 OS가 제공하는 단일 **조건부 unlink-by-inode** 연산이 없다. 열린 parent/파일 FD, `O_NOFOLLOW`, 반복 identity 검사로 확인 가능한 교체는 거부하지만 같은 사용자 권한의 비협조 프로세스가 마지막 검사 직후 경로를 바꾸는 극단적 race까지 원자적으로 차단한다고 주장하지 않는다. File lock은 도입하지 않았다. 동시에 두 삭제를 하면 하나만 성공하며 나머지는 누락 또는 identity 변경으로 실패한다. Setup과 삭제가 경쟁할 때도 자동 덮어쓰기·재생성은 하지 않는다. Source 파일이 교체되면 조회는 순간 상태만 표시하고, 실제 실행은 기존 안전 열기 경계에서 다시 검증한다.

## 입력·저장 계약

`app.live_monitoring.config.LiveMonitorConfigV2`는 [Phase 19의 닫힌 v2 JSON](local_collector_v030_design.md#3-제안-config저장삭제-계약)만 허용한다. `source_id=SOURCE-000001`, `source_role=application`, `display_alias=애플리케이션 로그 1`, `enabled=true`, `start_position=FROM_END`, `parser_timezone=Asia/Seoul`, `checkpoint_policy=DISABLED`, `rotation_policy=FAIL_CLOSED`로 생성한다. `enabled=false`는 v2 문서로 읽을 수 있으나 runtime 시작은 고정 `SOURCE_DISABLED`로 거부한다. Unknown key·중복 key·다중 source·bool-as-int·상대 경로·다른 enum·secret field는 거부한다. Trusted dataclass의 `source_path`는 `repr`에서 제외하지만 내부 직접 접근에는 존재하며 safe DTO로 직렬화하지 않는다.

Source 검사에는 `lstat`→기존 descriptor 기반 `_open_regular`→`fstat`·path identity 비교를 사용한다. 승인 뒤 재검사할 때 `(device,inode,size,mtime_ns,ctime_ns)`가 바뀌면 저장 전에 `SETUP_SOURCE_CHANGED`로 거부한다. macOS/Linux에서 필요한 `O_NOFOLLOW` 등의 안전 기능이 없으면 지원한다고 가장하지 않고 거부한다. 원본 파일은 읽기 전용으로 열며 수정하지 않는다.

Dry-run 개발용 상한은 **4,096 byte·완성 줄 16개·줄 2,048 byte**다. 기존 live parser adapter를 사용해 `PARSED/IGNORED/REJECTED`만 집계한다. NUL/제어 문자·binary signature·invalid UTF-8·너무 긴 줄은 고정 오류로 중단한다. 검사가 byte cap에서 끝나면 미완성 끝 조각은 parser로 전달하지 않는다. 빈 파일 또는 완성 줄이 없는 파일은 형식 미확인 경고 후 명시 승인으로 생성 가능하지만 “안전함”이나 parser 호환 확인으로 표현하지 않는다. 샘플의 일부 줄만 확인했다는 한계를 `sample_limited` safe count로 추적한다.

저장 파일은 deterministic key order의 UTF-8 JSON, 마지막 LF 1개, 최대 4,096 byte다. 새 private 디렉터리는 `0700`, 임시·최종 config는 owner `0600`으로 검증한다. 같은 디렉터리의 `O_EXCL|O_NOFOLLOW` 임시 파일을 완전히 쓰고 `fsync`한 뒤 `os.link`로 no-clobber 게시한다. `os.replace`는 덮어쓰기 때문에 사용하지 않는다. 게시 뒤 v2 및 기존 runtime loader로 재검증하고 parent를 `fsync`한다. 저장 실패는 알려진 임시 파일과 게시한 최종 파일을 정리하려 시도하며, 정리 실패 시 성공이라고 주장하지 않는다. OS 파일 시스템 crash 내구성·macOS ACL/볼륨 정책은 별도 검증이 필요하다.

## 고정 오류·종료

오류는 `MonitorSetupError(code, 고정 한국어 설명, 복구 행동, retryable)`로 제한한다. 경로·로그·OS 예외 원문은 `str/repr`에 포함되지 않는다. 주 코드: `SETUP_INVALID_INPUT`, `SETUP_UNSUPPORTED_ROLE`, `SETUP_PATH_MISSING`, `SETUP_PERMISSION_DENIED`, `SETUP_SYMLINK_REJECTED`, `SETUP_NOT_REGULAR_FILE`, `SETUP_SOURCE_CHANGED`, `SETUP_UNSUPPORTED_OS`, `SETUP_BINARY_INPUT`, `SETUP_INVALID_UTF8`, `SETUP_LINE_TOO_LONG`, `SETUP_UNSUPPORTED_FORMAT`, `SETUP_OUTPUT_EXISTS`, `SETUP_OUTPUT_SYMLINK`, `SETUP_UNSAFE_PARENT`, `SETUP_SAVE_FAILED`, `SETUP_POST_WRITE_FAILED`, `SETUP_INTERNAL_FAILED`.

| 종료 코드 | 의미 |
|---|---|
| 0 | 생성·조회·삭제 성공 또는 명시적 취소 (`CANCELLED` 별도 safe result) |
| 2 | 역할·경로 등 사용자 입력 오류 |
| 3 | source 또는 기본 config 안전 검증 실패 |
| 4 | config 저장·삭제 실패 |
| 1 | 예상 밖 내부 실패, traceback 없이 고정 메시지 |

## 남은 범위

Config 수정·덮어쓰기와 사용자 지정 `--output` 자동 삭제, checkpoint, rotation 자동 복구, 다중 source, 별도 collector/IPC, 서비스 설치, 웹 설정 화면, 원격 수집은 없다. 설정 생성 후에도 프로세스 재시작 중 유실 가능성과 `FROM_END` 의미는 기존 v0.2 경계 그대로다. 마법사의 안전한 출력만으로 원본 로그나 OS crash dump의 보안성을 보장하지 않는다. 실제 검증은 macOS이며 Linux 안전 API/권한/파일 시스템별 no-clobber·unlink 동작은 별도 실행 검증 전 지원 완료로 주장하지 않는다.
