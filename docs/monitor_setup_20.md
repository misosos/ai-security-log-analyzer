# Phase 20 — 로컬 application 모니터링 설정 마법사

상태: **구현됨**. 다음 명령은 trusted 로컬 CLI이며 브라우저·웹 API·detector·LLM을 실행하지 않는다.

```bash
uv run python -m app.monitor_setup
uv run python -m app.monitor_setup --output /absolute/path/to/monitoring.json --no-color
```

기본 저장 위치는 macOS의 사용자 `Library/Application Support/ai-security-log-analyzer/monitoring.json`, Linux의 `$XDG_CONFIG_HOME/ai-security-log-analyzer/monitoring.json` 또는 사용자 `.config` 아래다. `--output`은 절대 경로만 받는다. 기존 설정 파일은 덮어쓰지 않는다. 실시간 수집 자체는 별도 명령 `uv run python -m app.local_web --monitor-config <생성된-config-절대-경로>`로 **사용자가 직접** 시작한다. v1 config와 v2 config를 기존 loader가 모두 읽으며, v2는 application 단일 source로만 변환된다.

## 사용자 흐름과 승인

1. 새 줄만 읽고, 기존 줄을 분석하지 않으며, trusted 내부 메모리에는 원문이 존재할 수 있다는 안내를 읽는다.
2. `y` 또는 `yes`로 계속 진행한다. 다른 응답은 취소(종료 0)다.
3. 역할 `application`을 정확히 입력한다. SSH/access/Linux Audit는 이 마법사에서 지원하지 않는다.
4. 절대 경로의 일반 로그 파일을 입력한다. 경로는 shell로 실행되지 않는다. 터미널 drag-and-drop의 **정확히 하나의 바깥쪽 인용 부호**만 제거하며 환경변수·`~`·glob·URL·shell 문법을 해석하지 않는다.
5. 제한된 기존 샘플의 안전한 count를 확인한다. 이것은 **형식 확인**이지 기존 줄의 live 분석·결과 확정이 아니다.
6. schema 2, application, `FROM_END`, `Asia/Seoul`, 안전한 저장 위치 설명과 검사 수치를 확인한다. 원본 줄·계정·IP·source path는 미리보기에 없다.
7. `이 설정을 저장하시겠습니까? [y/N]`에 `y`/`yes`만 승인이다. 앞뒤 공백·대소문자는 정규화하지만 그 외 값은 승인하지 않는다. 취소 시 config·임시 파일은 없다.
8. 성공 후 시작 명령을 **실행하지 않고** 표시한다. 이 마지막 대화형 안내에만 shell-quoted config 절대 경로를 포함한다. 이는 터미널 scrollback에 남을 수 있으므로 공유하지 않는다. `--output` 자체는 OS 프로세스 목록/셸 기록에 남을 수 있다.

## 입력·저장 계약

`app.live_monitoring.config.LiveMonitorConfigV2`는 [Phase 19의 닫힌 v2 JSON](local_collector_v030_design.md#3-제안-config저장삭제-계약)만 허용한다. `source_id=SOURCE-000001`, `source_role=application`, `display_alias=애플리케이션 로그 1`, `enabled=true`, `start_position=FROM_END`, `parser_timezone=Asia/Seoul`, `checkpoint_policy=DISABLED`, `rotation_policy=FAIL_CLOSED`로 생성한다. `enabled=false`는 v2 문서로 읽을 수 있으나 runtime 시작은 고정 `SOURCE_DISABLED`로 거부한다. Unknown key·중복 key·다중 source·bool-as-int·상대 경로·다른 enum·secret field는 거부한다. Trusted dataclass의 `source_path`는 `repr`에서 제외하지만 내부 직접 접근에는 존재하며 safe DTO로 직렬화하지 않는다.

Source 검사에는 `lstat`→기존 descriptor 기반 `_open_regular`→`fstat`·path identity 비교를 사용한다. 승인 뒤 재검사할 때 `(device,inode,size,mtime_ns,ctime_ns)`가 바뀌면 저장 전에 `SETUP_SOURCE_CHANGED`로 거부한다. macOS/Linux에서 필요한 `O_NOFOLLOW` 등의 안전 기능이 없으면 지원한다고 가장하지 않고 거부한다. 원본 파일은 읽기 전용으로 열며 수정하지 않는다.

Dry-run 개발용 상한은 **4,096 byte·완성 줄 16개·줄 2,048 byte**다. 기존 live parser adapter를 사용해 `PARSED/IGNORED/REJECTED`만 집계한다. NUL/제어 문자·binary signature·invalid UTF-8·너무 긴 줄은 고정 오류로 중단한다. 검사가 byte cap에서 끝나면 미완성 끝 조각은 parser로 전달하지 않는다. 빈 파일 또는 완성 줄이 없는 파일은 형식 미확인 경고 후 명시 승인으로 생성 가능하지만 “안전함”이나 parser 호환 확인으로 표현하지 않는다. 샘플의 일부 줄만 확인했다는 한계를 `sample_limited` safe count로 추적한다.

저장 파일은 deterministic key order의 UTF-8 JSON, 마지막 LF 1개, 최대 4,096 byte다. 새 private 디렉터리는 `0700`, 임시·최종 config는 owner `0600`으로 검증한다. 같은 디렉터리의 `O_EXCL|O_NOFOLLOW` 임시 파일을 완전히 쓰고 `fsync`한 뒤 `os.link`로 no-clobber 게시한다. `os.replace`는 덮어쓰기 때문에 사용하지 않는다. 게시 뒤 v2 및 기존 runtime loader로 재검증하고 parent를 `fsync`한다. 저장 실패는 알려진 임시 파일과 게시한 최종 파일을 정리하려 시도하며, 정리 실패 시 성공이라고 주장하지 않는다. OS 파일 시스템 crash 내구성·macOS ACL/볼륨 정책은 별도 검증이 필요하다.

## 고정 오류·종료

오류는 `MonitorSetupError(code, 고정 한국어 설명, 복구 행동, retryable)`로 제한한다. 경로·로그·OS 예외 원문은 `str/repr`에 포함되지 않는다. 주 코드: `SETUP_INVALID_INPUT`, `SETUP_UNSUPPORTED_ROLE`, `SETUP_PATH_MISSING`, `SETUP_PERMISSION_DENIED`, `SETUP_SYMLINK_REJECTED`, `SETUP_NOT_REGULAR_FILE`, `SETUP_SOURCE_CHANGED`, `SETUP_UNSUPPORTED_OS`, `SETUP_BINARY_INPUT`, `SETUP_INVALID_UTF8`, `SETUP_LINE_TOO_LONG`, `SETUP_UNSUPPORTED_FORMAT`, `SETUP_OUTPUT_EXISTS`, `SETUP_OUTPUT_SYMLINK`, `SETUP_UNSAFE_PARENT`, `SETUP_SAVE_FAILED`, `SETUP_POST_WRITE_FAILED`, `SETUP_INTERNAL_FAILED`.

| 종료 코드 | 의미 |
|---|---|
| 0 | 생성 성공 또는 명시적 취소 (`CANCELLED` 별도 safe result) |
| 2 | 역할·경로 등 사용자 입력 오류 |
| 3 | 안전한 source 검사 실패 |
| 4 | config 저장·검증 실패 |
| 1 | 예상 밖 내부 실패, traceback 없이 고정 메시지 |

## 남은 범위

Config 삭제·수정, checkpoint, rotation 자동 복구, 다중 source, 별도 collector/IPC, 서비스 설치, 웹 설정 화면, 원격 수집은 없다. 설정 생성 후에도 프로세스 재시작 중 유실 가능성과 `FROM_END` 의미는 기존 v0.2 경계 그대로다. 마법사의 안전한 출력만으로 원본 로그나 OS crash dump의 보안성을 보장하지 않는다. 실제 검증은 macOS이며 Linux 안전 API/권한/파일 시스템별 no-clobber 동작은 별도 실행 검증 전 지원 완료로 주장하지 않는다.
