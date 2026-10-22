# Phase 32.1A — 두 로그용 private v3 설정

**구현 범위:** `create_monitor_pair_config(application, ssh, output)`는 application 로그와 SSH 로그의 절대 경로를 각 하나씩 검증한 뒤 닫힌 private v3 JSON 설정을 저장한다. `load_live_monitor_pair_config(path)`는 해당 설정을 private parent와 file descriptor로 읽어 역할·checkpoint 연결을 검증한다. 이는 내부 Python 계약이며 CLI 마법사, `--monitor`, worker, API·SSE·UI의 두 source 실행 지원을 뜻하지 않는다. [Phase 32.0 설계](bounded_multi_source_monitoring_32_0.md)의 나머지 scheduler·publication·사용자 검수는 미구현이다.

| v3 항목 | 값과 보존 목적 |
|---|---|
| `schema_version` | 고정 `3`; v1/v2 loader와 구분한다. |
| `sources` | 정확히 application 다음 SSH 순서의 두 entry. 동일 역할·세 번째 source·access·Linux Audit은 거부한다. |
| `source_path` | 역할마다 서로 다른 절대 로컬 파일 경로 하나. Private 설정에만 저장하며 공개 결과나 오류에 표시하지 않는다. 같은 file identity의 hardlink도 생성 시 거부한다. |
| `source_role`, `source_id`, `display_alias` | 역할 선택과 비식별 고정 ID·표시명. 계정·IP·경로를 ID에 인코딩하지 않는다. |
| `enabled`, `start_position`, `parser_timezone` | `true`, `FROM_END`, `Asia/Seoul`로 고정한다. |
| `checkpoint_policy`, `rotation_policy` | `BOUNDED_REPLAY_V1`, `FAIL_CLOSED`로 고정한다. 향후 복구 동작의 요구 계약이며 이 단계에서 복구를 실행하지 않는다. |
| `checkpoint_name`, `checkpoint_lock_name` | 역할별 고정 비식별 파일명. Application은 `checkpoint-application-v3.json`과 `checkpoint-application-v3.lock`, SSH는 `checkpoint-ssh-v3.json`과 `checkpoint-ssh-v3.lock`을 연결한다. 임의 경로나 경로 hash를 허용하지 않는다. 이 단계에서 checkpoint·lock 파일을 만들지 않는다. |

생성 시 source symlink·비정상 파일·권한·교체를 기존 descriptor 검사로 확인하고 SSH 소유권/parent 정책을 재사용한다. 출력 parent는 0700, 설정 파일은 0600이며 임시 파일을 fsync한 뒤 no-clobber 링크로 게시하고 다시 읽어 검증한다. 기존 설정과 v2/v3 남은 checkpoint가 있으면 덮어쓰지 않는다. 두 source의 inode가 같으면 거부한다. 설정 로드는 private parent·일반 파일·소유권·0600·size≤4096 byte·UTF-8·중복 JSON key·닫힌 field 집합을 확인한다. `repr`과 고정 오류에는 source/config 경로, 원문, 계정, IP를 넣지 않는다. Backup·snapshot의 안전한 완전 삭제는 보장하지 않는다.

**호환성:** 기존 v1 명시적 설정, 단일 source v2 설정·마법사·checkpoint 복구·관리 명령은 변경하지 않았다. 기존 `load_live_monitor_config`와 `app.local_web --monitor`는 v3를 `UNSUPPORTED_SCHEMA`로 거부한다. v3의 checkpoint 이름은 연결 metadata일 뿐 기존 `LiveCheckpointManager`의 v2 file format이나 고정 source ID를 재사용하지 않는다. 역할별 checkpoint manager, 두 source scheduler, source별 reset/delete 선택, 공개 status·SSE·UI는 후속 수정 전 실패 테스트와 함께 구현해야 한다. v3 설정을 현재 제품의 실행 가능한 다중 source 기능으로 안내하지 않는다.

**NO-GO 유지:** cross-source correlation, 자동 rotation/copytruncate 복구, exactly-once·무유실 보장, PentAGI 등 외부 실행 도구 연결. 이번 설정 파일의 경로는 사용자가 명시적으로 삭제할 때까지 private 영역에 남을 수 있으므로 공유·artifact 업로드 대상이 아니다.

**후속 단계:** Phase 32.1B는 내부 두 source runtime·역할별 checkpoint와 bounded scheduler를 검증한다. Phase 32.2는 publication·API·SSE 계약, Phase 32.3은 setup 관리 UX·UI·실제 사용자 검증을 각각 별도 gate에서 다룬다. 이번 단계는 어느 후속 기능도 구현하거나 사용자 지원 기능으로 선언하지 않는다.
