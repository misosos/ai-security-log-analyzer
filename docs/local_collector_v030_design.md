# v0.3.0 안전한 로컬 설정·Collector 설계 (Phase 19)

상태: Phase 19는 **설계만** 수행했다. 이후 Phase 20에서 단일 application source 설정 마법사 core와 v2 reader를, Phase 20.1에서 기본 설정 조회·삭제와 `--monitor` 실행을 구현했다. 아래 표의 `현재`는 공개 v0.2.0 감사 당시 계약이고, `제안` 중 구현된 범위는 [설정 마법사 사용·검증 문서](monitor_setup_20.md)를 우선한다. 탐지·관계·위험도·사례 의미와 v0.2.0 릴리스 노트는 변경하지 않는다. 재시작 복구·rotation 자동 추종·다중 source·권한 분리 collector는 후속 gate다. 따라서 이 최소 단위만으로 실무 무유실 수집을 주장하지 않는다.

## 1. 현재 코드 감사와 사용자 문제

| 항목 | 확인한 현재 계약과 근거 | 남은 문제 |
|---|---|---|
| 사용자 동작 | [README](../README.md), [예시 JSON](examples/live-monitor.json)을 복사하고 두 절대 경로·소유자 전용 config 권한을 직접 설정한 뒤 `python -m app.local_web --monitor-config ...` 실행 | 초보 사용자는 JSON, 권한, 경로 오류를 직접 해결해야 함 |
| config | [`config.py`](../app/live_monitoring/config.py): `{"schema_version":"1","source":{"role":"application|ssh|access","path":"/absolute/..."},"start_policy":"FROM_END"}`의 닫힌 스키마, 최대 4,096B, UTF-8·중복 키·unknown key 거부 | Linux Audit live 역할은 없음. 설정 마법사·지속 checkpoint 없음 |
| 파일 검증 | config load 시 owner·0600 상당 권한 검증 후 source 일반 파일·symlink·group/other write 거부; `openat` 계열 `dir_fd`, `O_NOFOLLOW`, `fstat`; tail open과 각 poll에서 identity 재검증 | 설정 입력과 실제 open 사이 교체는 재확인 필요. 해당 OS 플래그 미지원 시 fail closed |
| 시작·tail | [`core.py`](../app/live_monitoring/core.py): 열린 파일의 EOF로 이동하는 `FROM_END`, 완성 줄만, strict UTF-8·NUL/oversize 거부. poll당 4,096B/16줄, 줄·partial 각 2,048B | 기존 줄 미처리. 재시작 중 append는 복구되지 않음 |
| 소유·분석 | [`parser_adapter.py`](../app/live_monitoring/parser_adapter.py)는 기존 parser를 재사용. [`detection_accumulator.py`](../app/live_monitoring/detection_accumulator.py)와 [`analysis_accumulator.py`](../app/live_monitoring/analysis_accumulator.py)는 전체 prefix를 유지; analysis는 application만. [`worker.py`](../app/live_monitoring/worker.py)는 단일 session·detection·publication 및 application analysis를 한 caller에서 처리 | 두 번째 source/runner를 공유할 수 없음. Trusted history에는 원문 subject가 존재 |
| 트랜잭션 | parse → detection/analysis/publication prepare → queue ack → 각 commit; ack 이후 rollback/자동 재처리 없음 | queue ack와 분석·publication 확정은 원자적이지 않음 |
| 한계 | queue 32항목/16KiB, PARSED prefix 256건/256KiB; [`publication.py`](../app/live_monitoring/publication.py) replay 32 event/16KiB, analysis snapshot 256개/범주·128KiB | queue/history 초과는 silent eviction이 아니라 fail closed; replay eviction은 gap 표시 |
| 런타임 | [`runner.py`](../app/live_monitoring/runner.py) 0.5초 단일 event-loop caller, [`service.py`](../app/live_monitoring/service.py) 읽기 전용 status/SSE·동시 2개, [`local_web.py`](../app/local_web.py) loopback 전경 실행 | 자동 OS 서비스·IPC·프로세스 간 공유 없음 |
| 공개 경계 | [`frontend/live-monitoring.js`](../frontend/live-monitoring.js)는 안전한 status/SSE exact schema·bounded staged apply. config path는 trusted `LiveMonitorConfig.path`에, source path는 같은 객체·열린 FD와 내부 검증에만 존재하며 공개 DTO에 없음 | loopback은 다른 로컬 프로세스/사용자를 인증하지 않음; 공개 DTO에서 원문을 제거해 피해를 제한 |
| 종료·rotation | close 시 FD·queue·partial·trusted state 정리; path identity 변경 `SOURCE_REPLACED`, 관찰된 size 감소 `SOURCE_TRUNCATED`로 terminal. 새 파일을 추측해 이어 읽지 않음 | rename/copytruncate 자동 추종 없음. size 감소 전에 재성장하면 size만으로 truncate를 판별할 수 없음 |

현재 상태는 process-local·memory-only다. 재시작하면 tail offset, partial, queue/lease, detection·analysis prefix, session-local ID, publication replay와 UI cursor가 사라진다. 원본 로그는 외부 파일로 남지만 **복구 기준점은 없다**. 현재 경로의 `dir_fd`·`O_NOFOLLOW`·`fstat`와 POSIX 소유권 검사 때문에 macOS/Linux 계열에 의존하며 Windows 지원은 검증하지 않았다. [v0.2.0 릴리스 범위](releases/v0.2.0.md)의 SSH/access live는 detection-only이고 Linux Audit는 일회성 업로드다.

## 2. 사용자 유형과 범위 결정

| 사용자 | 제안 흐름 | v0.3 최소 단위 |
|---|---|---|
| A 초보 로컬 | 터미널에서 한 명령 → 역할 선택 → 파일 확인 → 안전 미리보기·승인 → 저장 → 실행 방법 | **포함: application 1개**. JSON 직접 작성 없음 |
| B 개발자·소규모 운영 | 이후 source 목록을 코드로 관리, `dry-run`·진단, 상태·rotation/위치 확인 | 설계만; 다중 source·durable 위치·서비스화는 Phase 21~24 |
| C 중앙·기업 | 원격 agent, 중앙 서버, mTLS, tenant isolation, 장기 저장·알림 | v0.3 범위 밖. hosted 보안성을 주장하지 않음 |

권장 명령은 **`uv run python -m app.monitor_setup`**이다. 웹 launcher와 별개 trusted CLI라서 브라우저 route/권한을 늘리지 않는다. `app.local_web --setup-monitoring`은 웹 서버와 설정 write 권한을 같은 진입점에 섞어 역할이 불명확하다. Phase 20에서 v2 reader migration을 완료했고 Phase 20.1에서 기본 config 하나의 `--show`·`--delete` 및 launcher `--monitor`를 연결했다. 기존 명시적 `--monitor-config`는 v1과 v2를 모두 읽는다.

### 마법사 단계·사용자 문구 (제안)

1. “로그 파일 연결: 선택한 파일의 새 줄만 로컬에서 분석합니다. 원문은 공개 화면에 표시하지 않습니다.” 개인정보·권한·백업 잔존 안내.
2. “로그 유형 선택” — v0.3 최소 단위는 “애플리케이션 인증 로그”만 선택 가능. SSH/access는 기존 수동 설정에서 detection-only이며 마법사 선택지는 후속 검증 전 비활성.
3. “로그 파일 경로 입력” — 절대 경로를 CLI 프롬프트로 받는다. shell 명령에 경로를 넣지 않는다.
4. descriptor 기반 읽기 권한·owner/모드·일반 파일·symlink/device/socket·파일 identity 검사.
5. bounded sample: 설정 단계에서 승인 전 **읽기 전용으로 최대 4,096B/16줄, 각 줄 2,048B** 검사; strict UTF-8/NUL 검사, 기존 parser로 형식 통계만 산출. 내용 자체는 화면·로그에 출력하지 않음. 빈 파일은 허용하고 “형식 미확인; 새 줄로 확인” 경고 후 명시 승인. 샘플 검사는 실제 수집이 아니며 타임존/불완전 줄은 추측하지 않음.
6. “새 로그부터 모니터링 (`FROM_END`): 시작 전에 있던 줄은 처리하지 않습니다. 재시작 중 기록도 자동 복구하지 않습니다.”
7. 안전 미리보기: schema 버전, source 역할, 선택한 공개 별칭, 시작 정책, 검사 결과 code·개수, 설정 파일 권한만. **원래 경로·파일명·로그 예문은 미리보기·오류·stdout/stderr에 미표시**.
8. “이 파일에 대한 읽기와 private 설정 저장을 승인합니까?” 기본값 `아니요`; 승인 전 저장·서버 시작 없음.
9. private·원자적 저장 후 저장 결과는 고정 code/설명만 보여준다.
10. 저장된 설정을 다시 안전하게 load하고 descriptor identity·bounded dry-run을 재검사한다. 미리보기와 달라졌으면 시작 금지.
11. 경로를 명령줄 인자로 출력하지 않는 기본 실행은 Phase 20.1의 `app.local_web --monitor`가 담당한다. 명시적 `--output`은 기존 `--monitor-config`의 절대 경로를 비공개 로컬 안내로만 제공하고, 공유 터미널 기록·스크린샷에 경로가 남을 수 있음을 고지한다.
12. 즉시 실행은 별도 재확인 후 foreground만; 기본값은 실행 명령 안내. 관리자 권한, password/API key 입력, `sudo`, shell 실행 없음.

| 고정 오류 code | 상황·복구 행동 (원문 미포함) |
|---|---|
| `SETUP_PATH_MISSING` | 파일이 없음 → 로컬 파일 존재 여부 확인 |
| `SETUP_PERMISSION_DENIED` | 읽기/저장 권한 없음 → 사용자 소유와 읽기 권한 확인; 관리자 비밀번호 요구 금지 |
| `SETUP_SYMLINK_REJECTED` | 입력/상위/저장 대상 symlink → 일반 파일·private 디렉터리 선택 |
| `SETUP_NOT_REGULAR_FILE` | directory/device/socket → 일반 로그 파일 선택 |
| `SETUP_UNSUPPORTED_FORMAT` | bounded parser sample이 역할 형식과 불일치 → 로그 유형 확인; 원문 표시 금지 |
| `SETUP_EMPTY_SOURCE` | 빈 파일 → 새 줄이 올 때까지 형식 미확인; 승인 후 진행 가능 |
| `SETUP_BINARY_INPUT` | NUL/binary → UTF-8 텍스트 로그 선택 |
| `SETUP_INVALID_UTF8` | decoding 실패 → UTF-8 source 선택 |
| `SETUP_LINE_TOO_LONG` | bounded sample 줄 초과 → 입력 형식 조정; 잘라서 정상 처리 금지 |
| `SETUP_CONFIG_EXISTS` | 설정 대상 존재 → 덮어쓰기 금지; 명시적 삭제/새 profile 사용 |
| `SETUP_SAVE_DENIED` | private 저장 위치 불가 → owner·권한 확인, 기존 파일 불변 |
| `SETUP_DUPLICATE_ROLE` | 역할 중복 → v0.3은 한 application source만 유지 |
| `SETUP_DUPLICATE_SOURCE` | 같은 파일 identity 중복 → 기존 연결 확인 |
| `SETUP_SOURCE_CHANGED` | 확인 중 교체 → 작업 취소·다시 선택 |
| `SETUP_DRY_RUN_CHANGED` | dry-run 중 rotation/truncation → 저장은 완료되었어도 실행 금지·재검증 |
| `SETUP_UNSUPPORTED_OS` | 필수 안전 파일 API 없음 → 해당 OS 미지원, 우회 금지 |

### 파일 선택 방식

| 방식 | 사용자 편의 | 보안 | 이식성 | 구현 복잡도 | 결정 |
|---|---|---|---|---|---|
| CLI 절대 경로 입력 | 보통 | trusted CLI에서 검증 가능; 화면 echo·기록 주의 | macOS/Linux 높음 | 낮음 | **v0.3 기본**: 프롬프트, shell에 raw path 인자 금지 |
| CLI drag-and-drop 경로 | 높음 | shell 인용/escape·공백·개행 문제; paste도 path로만 취급 | 터미널별 차이 | 중간 | 입력 편의로만 허용, shell 실행/해석 없음 |
| OS native file picker | 높음 | OS grant 범위 확인 필요, headless fallback 필수 | OS별 다름 | 높음 | 후속 optional, mockable picker adapter와 CLI fallback |
| 브라우저 file input | 높음 | 업로드용 선택이지 지속적인 tail 권한이 아님 | 높음 | 중간 | **no-go**: 장기 source로 전용 금지 |
| 브라우저 경로 문자열 | 높음 | 로컬 웹에 임의 파일 읽기 권한 부여 | 높음 | 낮음 | **no-go**: start/config API 생성 금지 |

경로는 `subprocess(shell=True)`·`eval`·명령 문자열 결합으로 전달하지 않는다. 파일 선택은 OS 권한을 확대하지 않는다.

## 3. 제안 config·저장·삭제 계약

v2 제안 스키마는 `additionalProperties=false`이며 source 배열은 **v0.3 최소 구현에서 길이 정확히 1**이다. 미래 다중 source를 위한 필드는 지금 parser가 무시하게 두지 않는다. 단일 source라도 고정 ID와 안전 별칭을 둔다.

```json
{
  "schema_version": "2",
  "sources": [{
    "source_id": "SOURCE-000001",
    "source_role": "application",
    "source_path": "/absolute/path/to/application.log",
    "display_alias": "애플리케이션 로그 1",
    "enabled": true,
    "start_position": "FROM_END",
    "parser_timezone": "Asia/Seoul",
    "checkpoint_policy": "DISABLED",
    "rotation_policy": "FAIL_CLOSED"
  }]
}
```

`source_id`는 역할 순서의 비개인정보 ID이며 path/계정/hash에서 파생하지 않는다. 별칭은 고정 생성값만; 자유 입력은 개인정보·HTML 경계 검증 전 보류. `parser_timezone`은 기존 application parser의 naive-time 해석과 같아야 하며 임의 변경 no-go. v2에서 checkpoint·rotation enum은 **DISABLED / FAIL_CLOSED만** 유효. `enabled=false`는 저장은 가능하되 실행하지 않으며 암묵적 나중 자동 시작 금지. key 중복·unknown·bool-as-int·상한 초과·비정상 Unicode·상대 경로·symlink를 모두 거부. v1 reader는 기존처럼 남고 v1→v2는 백업/승인 후 명시 변환; 조용한 rewrite 금지.

| 정책 | 제안 |
|---|---|
| 기본 위치 | macOS 사용자 `~/Library/Application Support/ai-security-log-analyzer/monitoring.json`; Linux `$XDG_CONFIG_HOME/ai-security-log-analyzer/monitoring.json` 또는 `~/.config/...`. 환경변수는 absolute·owner-private·symlink-free 확인; 아니면 고정 오류. 외부 지정 경로는 후속 옵션으로만, 동일 검증 적용. Windows 미지원 |
| 권한·owner | private parent `0700`, config `0600`, 현재 사용자 owner. `umask(077)`에만 의존하지 않고 `fstat/fchmod` 재검증. macOS ACL·sandbox/볼륨의 소유권 무시 설정도 별도 점검하고 의도한 격리를 확인할 수 없으면 저장 금지. 원래 source의 chmod/chown 절대 하지 않음 |
| 생성·원자성 | 열린 parent dir FD에만 작업; symlink-free 경로/owner 확인; 같은 디렉터리에 `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`로 `0600` 임시 파일 생성, bounded write→`fsync(file)`. **`os.replace`는 기존 대상을 덮어쓰므로 신규 설정의 no-clobber 조건에 단독 사용 금지**. 가능한 macOS/Linux FS에서는 임시 파일을 대상 이름에 `os.link(..., dir_fd=...)`로 no-clobber publish, temp unlink→parent `fsync`; 미지원 FS는 저장 실패. 기존 파일 update는 별도 승인·version CAS와 재검증 gate 없이는 금지 |
| 장애·cleanup | temp 이름에 source/path 포함 금지; 실패 시 특정 temp만 제거; crash 후 남은 owner-private temp는 다음 실행에서 사용자 확인 후 보수적으로 정리. `fsync` 실패는 성공이라 표시하지 않음. 원자적 이름 게시와 crash 내구성은 FS별 테스트 필요 |
| 백업·secret | 기본 backup 없음; config에 credential/API key/password 금지. OS backup·Time Machine 복제 가능성을 안내하며 정책은 사용자가 관리 |
| 출력·삭제 | 웹 UI·stdout/stderr·일반 log에는 원래 path/파일명 불가. 현재 `monitor_setup --delete`는 private 기본 config 하나를 owner·mode·identity 확인 및 재승인 뒤 삭제; source 원본은 삭제하지 않음. 사용자 지정 config와 미래 checkpoint 삭제는 범위 밖이며, 백업·crash dump까지 지웠다고 주장하지 않음 |

명시적 `--monitor-config`는 절대 경로 인자여서 shell history/프로세스 목록 노출 가능성이 있다. 기본 설정에 한한 `--monitor`는 경로를 명령 인자로 받지 않아 **초보 사용자의 완결된 흐름**을 제공한다. 공개 CLI help에는 generic placeholder만 둔다. Python 3.12의 `dir_fd`, `O_NOFOLLOW`, `os.link`, `fsync`, `os.replace` 문서가 제공하는 것은 API 의미이며, 위 조합의 보안성과 각 FS 내구성은 프로젝트가 테스트할 정책이다.

## 4. 프로세스 경계와 재시작 복구

| 구조 | 장점 | 한계 | 결정 |
|---|---|---|---|
| 현재 local_web 내부 collector | 단일 lifecycle·현재 단일 caller 유지, 구현 작음 | 웹 프로세스가 log-read 권한도 보유 | **v0.3 최소 단위** 유지. loopback/read-only web·safe DTO; 다른 로컬 사용자를 인증하지 못하므로 공유 호스트 고권한 로그 no-go |
| 별도 local collector 프로세스 | 최소 권한 격리, 분석/UI와 분리 가능 | IPC peer 인증·backpressure·service·crash 복구 설계 필요 | Phase 23 gate. 이 전에는 최소 권한 분리가 완료됐다고 주장하지 않음 |

Collector에 원격 명령, 임의 파일 다운로드, shell 실행, 자동 대응, 패키지 설치, 웹 경로 변경, 이벤트별 LLM 호출은 넣지 않는다. OS 사용자 권한을 올려 source를 읽는 것이 아니라, 사용자에게 이미 읽기 권한이 있는 파일만 승인받는다.

### Durable checkpoint (Phase 21 제안, v0.3 최소 단위에는 없음)

`source_id`, config/parser version, file identity(`st_dev,st_ino` 등 OS별), generation, **마지막 완성 줄 끝 byte offset**, partial 여부, queue/analysis committed revision, 체크섬을 후보로 한다. wall-clock의 마지막 확인 시각은 진단용이고 identity/순서 판정에 사용하지 않는다. 원래 path·raw 줄은 checkpoint에 저장하지 않는다. private state dir `0700`, file `0600`, 제한 크기·닫힌 schema·checksum, 원자적 no-clobber/replace·`fsync`와 owner 검증이 필요하다. 체크섬은 우발적 손상 탐지용이지 악의적 동일 사용자 변조 방지용 인증이 아니다. 손상·버전 불일치·삭제·파일 교체·inode 재사용 의심 시 **DEGRADED/fail closed**, 사용자에게 gap 가능성 고지 후 새 epoch를 명시 승인하도록 한다. 삭제 후 무언의 `FROM_END` 복귀 금지.

가장 중요한 제약: **tail offset만 저장하면 batch-prefix parity가 깨진다.** 현재 detection/analysis는 전체 bounded prefix(256 PARSED/256KiB)를 다시 계산한다. 재시작 시 offset만 복구하고 빈 accumulator로 시작하면 같은 로그 prefix의 탐지·관계·risk·case가 달라진다. Phase 21은 (a) 256/256KiB 이내 trusted history와 versioned analysis state를 private·bounded하게 보존·검증하거나 (b) 동일 file identity의 필요한 prefix를 경계 내에서 재읽고 batch parity를 증명해야 한다. 어느 것도 안전하게 할 수 없으면 resume no-go, 명시적 gap/새 session만 허용한다. Trusted history 저장은 민감 데이터 저장 정책을 새로 요구한다.

| 저장 타이밍 | crash window | 의미 |
|---|---|---|
| queue ack **전** offset 저장 | offset이 앞서고 commit 전 crash → 기록 유실 가능 | 채택 금지 |
| queue ack·detection·analysis·publication **후** checkpoint | commit 후 checkpoint 전 crash → 재독해·중복 가능. Process-only publication은 crash 후 replay 불가 | 후보. **bounded duplicate 가능 + 명시적 gap 가능 + 불확실하면 fail closed**, at-least-once/at-most-once/exactly-once 약속하지 않음 |
| checkpoint와 queue/analysis atomic 거래 주장 | 서로 다른 메모리·파일 상태에 단일 transaction 없음 | no-go |

매 record fsync는 비용이 크고 event loop 지연을 부를 수 있으므로 checkpoint 빈도는 Phase 21 성능·crash-window 평가로 결정한다. 임의 batch 간격을 공식 표준이라고 하지 않는다. partial line은 checkpoint offset을 완성 줄 끝까지만 전진시키며 재시작 후 동일 identity에서 읽기를 다시 검증한다. stopped 기간에 rotation으로 원본 inode가 사라졌거나 여러 generation이 지나간 경우에는 누락 범위를 알 수 없으므로 gap을 추측해 채우지 않는다. 사용자에게 “마지막 처리 위치 확인 필요”, 중복·누락 가능성, 재시작 후 새 세션을 별도 표시한다.

### Rotation·truncation 전이 (Phase 21.1 제안)

| 상황 | 관찰 가능한 근거 | 기본 동작 | 중복 위험 | 유실 위험 | 사용자 안내 |
|---|---|---|---|---|---|
| rename rotation | path의 `(dev,ino)` 변경, 열린 옛 FD 유지 | 옛 FD 완성 줄까지만 bounded drain 후 새 파일 identity 재검증; transition 자체는 사용자/정책 gate 전 fail closed | checkpoint 경계 | 옛 파일 삭제/미완성 줄 | 로그 파일 교체 감지 |
| copytruncate | 동일 identity, 관찰된 size 감소 | fail closed; 명시적 새 generation 승인 전 이어붙이지 않음 | 복사본 재독해 시 | copy→truncate 틈·감소 전 재성장 | 파일 잘림 확인 필요 |
| 파일 삭제 | path 없음, 기존 FD 생존 가능 | bounded drain 후 DEGRADED; 새 경로 추측 금지 | 낮음 | 삭제 후 쓰기 | 파일 확인 필요 |
| 새 파일 생성 | path 재등장, 새 identity | 기존 generation과 자동 결합 금지; 새 epoch 승인 | 이전 복사와 겹침 | 이전 줄 접근 불가 | 새 로그부터 시작 승인 |
| 같은 경로 다른 identity | `fstat`/path 비교 불일치 | fail closed 후 위 rename 절차 | 이전 offset 적용 시 | 이전 generation 누락 | 파일 교체 감지 |
| 파일 크기 감소 | `size < committed_offset` | fail closed; offset 0 추측 금지 | 재독해 가능 | 재성장 시 감지 불가 | 파일 잘림 확인 필요 |
| 잠시 사라짐 | 경로 open 실패 | bounded 재확인 횟수/기한은 후속 측정; 그 전 DEGRADED, busy retry 금지 | 재등장 identity에 따라 | 그사이 기록 | 일시 접근 불가 |
| 권한 변경 | reopen/FD 검사 실패 | 즉시 DEGRADED, 권한 상승 시도 금지 | 낮음 | 중단 구간 | 읽기 권한 확인 |
| symlink 교체 | `lstat`·`O_NOFOLLOW` 실패 | terminal fail closed | 없음 | 중단 구간 | 일반 파일 재선택 |
| 빠른 연속 rotation | 둘 이상 generation 후보·watch overflow | 순서 증명 불가면 fail closed | 파일 중복 후보 | 원본 삭제 | 일부 기록 미확인 |
| 중지 중 rotation | checkpoint identity 부재 또는 다른 identity | 기존 generation 찾지 못하면 gap·새 epoch 승인 | 존재하는 rotated 파일 재독해 | 제거된 파일 | 중단 중 기록 복구 불가 가능 |
| partial line 중 rotation | 옛 FD의 미완성 끝, 새 identity | partial을 다른 파일과 결합 금지; 폐기/보류 count와 gap 고지 | 없음 | 미완성 줄 | 완성되지 않은 줄 미처리 |

Linux `inotify`는 queue overflow·watch invalidation이 있고 macOS FSEvents도 변경 알림이지 byte-level ack 증거가 아니다. 두 OS 모두 알림은 “재검사 신호”로만 쓰고 opened FD의 identity/offset/완성 줄과 checkpoint를 검증한다. `copytruncate` 자체에 쓰기 손실 창이 있다는 logrotate 문서의 설명을 collector 무유실 약속으로 덮지 않는다.

## 5. 다중 source·IPC (후속 설계)

Phase 22에는 application/SSH/access/Linux Audit 각각 독립 tail·queue·cursor·revision·상태를 둔다. Linux Audit는 여러 record의 bounded assembly가 먼저 입증되어야 하며 batch/web 의미와 섞지 않는다. Source당 현재 32항목/16KiB를 출발점으로 하되 **전체 global byte budget**을 별도로 측정·명시한다; 합계 초과 시 새 입력을 fail-closed/backpressure하고 다른 source의 기록을 삭제하지 않는다. 단일 caller round-robin에 source당 poll 4,096B/16줄 상한을 적용해 공정성을 시험한다. 느린/오류 source는 자기 상태 DEGRADED/FAILED로 격리하되 전체 상태는 일부 실패를 명확히 표시한다. shutdown은 새 poll 중지→source별 lease 정산→checkpoint/상태 정리→FD→publication/SSE 종료를 bounded하게 한다. config 변경은 재시작·명시적 승인 필요, live hot reload 없음. Cross-source correlation은 계속 보류한다.

| IPC 후보 | 인증·권한 | framing/backpressure·replay | 개인정보·운영 | 판단 |
|---|---|---|---|---|
| Unix domain socket | private `0700` directory + peer credential(OS별 검증) | 길이 접두부·byte cap·bounded ack/cursor 가능 | macOS/Linux, 로컬 디버깅 가능 | **Phase 23 권장**, 아직 선택 확정/구현 아님 |
| loopback HTTP | IP만으로 동일 사용자 인증 안 됨 | HTTP framing 쉬움, 별도 인증/CSRF 필요 | 기존 web 경계와 혼동 위험 | 기본 보류 |
| stdin/stdout subprocess | 부모-child 소유 명확 | bounded frame·restart 관리 필요 | stdout raw 노출 위험 | 대안, 디버깅·lifecycle 평가 필요 |
| named pipe | filesystem mode 가능 | peer 신원·양방향 ack 복잡 | 재연결 모호 | 보류 |
| 파일 spool | private 권한 가능 | 용량·atomic rotation·cleanup 필요 | raw 디스크 잔존·backup 위험 | v0.3 no-go |

IPC는 고정 message type·source ID·sequence·bounded UTF-8 payload만 허용하고 임의 명령, shell fragment, config 전체 경로, hostname, credential을 보내지 않는다. 별도 collector가 parser/분석과 분리되면 raw 줄의 trusted IPC 전송이 불가피할 수 있으므로 peer UID 검증·private socket·크기 제한·log 비노출을 통과하기 전 구현 no-go. Replay·인증은 SSE cursor와 별개이며 프로세스 경계의 중복/유실을 별도 설계한다.

## 6. 웹 UI·접근성·사용자 용어

Trusted setup CLI에서만 source 추가·삭제·권한 확인·config/checkpoint 수정을 허용한다. 웹은 승인된 **source 역할·안전 별칭**, 모니터링/queue pressure/“마지막 처리 위치 확인 필요”/“로그 파일 교체 감지”/DEGRADED와 재시작 안내만 읽기 전용으로 보여준다. 브라우저 임의 경로, start 권한, 파일 권한 변경, raw 로그, 자동 강제 복구는 no-go. 다른 로컬 프로세스에 대한 인증 없는 loopback control route도 no-go.

사용자 용어는 “로그 파일 연결”, “새 로그부터 모니터링”, “기존 로그는 읽지 않음”, “마지막 처리 위치”, “로그 파일 교체 감지”, “확인이 필요한 상태”, “모니터링 다시 시작”을 쓴다. `collector/checkpoint/rotation`은 도움말에서만 괄호 설명한다. 설정 UI가 추후 생겨도 `lang=ko`, native control·visible label/focus, keyboard-only, 오류 요약과 field 연결, 색상 외 상태 텍스트, 200%·좁은 폭 reflow, 승인 전 저장/시작 금지, countdown/자동 진행/불필요한 focus·scroll 이동 금지를 gate로 한다. WCAG 준수 완료는 별도 감사 전 주장하지 않는다.

## 7. 위협 모델

아래 실패 동작은 설계 정책이다. “검출”은 완전 탐지 보장이 아니다.

| 위협 | 자산 | 공격자·진입점 | 예방 | 탐지 | 실패 동작·잔여 위험 |
|---|---|---|---|---|---|
| 악의적 로그 내용 | parser·UI | 로그 작성자/줄 | strict UTF-8, typed parser, safe DTO | parse reject count | fail closed; 허용 형식 내 의미 오도 가능 |
| 매우 긴 줄 | 메모리 | 로그 작성자/줄 | 2,048B cap | length check | DEGRADED; 줄 손실 가능 |
| 빠른 append | queue·CPU | 로그 작성자/속도 | poll/queue caps | pressure count | fail closed; 미처리 구간 |
| 디스크 고갈 | config/checkpoint | 로컬 사용자/FS | bounded 파일·quota gate | write/fsync 실패 | 저장 실패·DEGRADED; 원본 FS 영향 |
| queue 고갈 | 기록 완전성 | 빠른 source | item/byte caps | overflow code | silent drop 금지; 수집 중단 |
| checkpoint 손상 | resume 위치 | crash/로컬 변조 | closed schema·checksum·private mode | checksum/버전 | DEGRADED·재승인; 동일 UID 변조 탐지 한계 |
| config 바꿔치기 | source 권한 | 다른 로컬 사용자/경로 | owner·dir FD·no-clobber | 재open identity | 시작 금지; 동일 UID 악성 프로세스 불가 격리 |
| symlink 교체 | 임의 파일 | 다른 로컬 사용자/path | `O_NOFOLLOW`, 경로 단계 검증 | `lstat/fstat` | fail closed; race 재검증 필요 |
| TOCTOU | file identity | 경로 조작자/검사와 open | descriptor 기준 비교 | identity mismatch | 중단; 동일 inode 내용 변조는 별도 위험 |
| 권한 변경 | 가용성·기밀성 | 관리자/FS mode | 최소 read 권한 | reopen 실패·mode check | DEGRADED; OS 접근 정책 변동 |
| rotation race | 순서·완전성 | rotator/rename | generation 확인 | identity·size mismatch | gap·중단; 삭제된 세대 복구 불가 |
| inode reuse | source identity | FS 재사용 | generation·추가 증거 요구 | inode/size/version 불일치 | 애매하면 중단; 완전 식별 보장 없음 |
| 다른 로컬 사용자 | 로그/상태 | 공유 호스트/loopback | private config/socket, 공개 safe DTO | owner/peer 검증 | v0.3 web은 인증 안 됨; 고권한 로그 공유 호스트 no-go |
| 웹 origin 위조 | 상태·제어 | 악성 웹/headers | 기존 peer/Host/Origin/forwarding 거부, control API 없음 | 요청 거부 count | 동일 사용자 악성 로컬 프로세스는 남음 |
| 다른 로컬 프로세스 API | 상태 | 같은 호스트/loopback | 읽기 전용·safe DTO | connection cap | loopback 자체 인증 아님 |
| collector impersonation | IPC 원문 | 다른 사용자/socket | private socket·peer UID | handshake mismatch | IPC 차단; 동일 UID 공격자 잔여 |
| IPC replay | 분석 중복 | 악성 peer/frame | source generation·sequence·ack cap | 중복 frame | 거부·DEGRADED; crash 창 중복 가능 |
| crash 중 상태 불일치 | ack/offset/분석 | crash/commit 경계 | checkpoint after commit·version | revision mismatch | gap·중복 고지; exactly-once 없음 |
| stdout/stderr 노출 | 경로·원문 | 터미널/로그 수집 | 고정 오류·safe repr | canary test | 잔여 traceback/외부 런타임 로그 감사 필요 |
| shell history 경로 | source path | 셸 기록 접근자 | CLI 프롬프트·profile 실행 | 명령 검사 | 기존 v0.2 CLI는 노출 위험 유지 |
| backup/Time Machine | config/history | 백업 접근자 | private mode·최소 저장·안내 | backup 정책 점검 | OS 백업 보존은 앱 삭제와 별개 |
| uninstall 잔존 | config/checkpoint | 잔존 디스크 | 명시적 remove·목록 | 잔존 검사 | backup/crash dump/원본까지 자동 삭제 못함 |

## 8. 데이터 보존·삭제 정책

기간 미정인 것은 **미정**으로 둔다. 삭제는 secure erase 보장이 아니다.

| 데이터 | 위치·권한 | 보존/종료·crash | 삭제 주체·웹/전송 |
|---|---|---|---|
| raw 로그 원본 | 사용자 지정 source, 기존 OS 권한 | app이 변경·삭제 안 함; 원래 정책 미정 | source 소유자; 웹 미노출·외부 전송 없음 |
| in-memory queue | collector RAM, process 권한 | 현재 32/16KiB, 정상 close 해제; crash 시 소멸, secure erase 아님 | process; 웹 count만, 외부 없음 |
| parser/analysis event history | trusted RAM, process 권한 | 256/256KiB fail closed, close/crash 후 소멸 | process; raw 웹·외부 없음; Phase 21 저장은 별도 승인 필요 |
| checkpoint | **현재 없음**; 제안 private state dir 0700/file 0600 | Phase 21 보존 기간 미정; 정상·crash 뒤 남음 | 명시적 remove; 웹은 safe 상태만 |
| config | 현재 사용자가 만든 0600 파일; 제안 private dir 0700/file 0600 | 삭제 전 지속, backup 가능 | 사용자/명시적 remove; 원래 path 웹·외부 없음 |
| safe publication | 현재 process RAM, 32/16KiB | eviction gap, close/crash 소멸 | process; bounded SSE로 loopback 제공 |
| HTML report | 사용자가 요청한 저장 위치·권한(writer 0600) | 사용자가 지울 때까지; backup 가능 | 사용자; 다운로드에 안전 projection이나 민감 조사 내용 가능, 외부 전송 없음 |
| operational log | stdout/stderr 및 호스트 수집 환경, 권한·retention **미정** | 고정 code만 앱이 출력; 호스트 보존은 별도 | 운영자; 웹 미노출, 외부 수집 설정은 앱 범위 밖 |
| crash dump | OS/호스트 설정, 권한·retention **미정** | trusted RAM 잔존 가능 | OS/운영자; 웹 미노출, OS 수집 가능 |
| backup | OS/사용자 설정, 권한·retention **미정** | 삭제 후에도 잔존 가능 | 사용자/백업 운영자; 앱이 일괄 삭제 주장 안 함 |

## 9. v0.3 최소 범위·로드맵·중단 조건

**v0.3 최소 구현 확정:** trusted 대화형 CLI wizard, 닫힌 v2 config(application 1개), private·atomic no-clobber 저장/기본 설정 하나의 승인 삭제, bounded dry-run, 안전 미리보기·명시 승인, 기본 `FROM_END`, 기존 v0.2 `--monitor-config` 호환. Phase 20.1에서 기본 위치의 경로 없는 `--monitor`를 구현했다. 명시적 사용자 지정 config 경로는 여전히 shell history·프로세스 목록·터미널 기록에 남을 수 있다. Durable checkpoint·rotation 자동 복구·다중 source·별도 collector·service 설치·원격/hosted는 **v0.3 최소 출하에 포함하지 않는다**. 실무 수준의 재시작 연속성은 Phase 21 통과 전 별도 제한으로 고지한다.

| 단계 | 사용자 가치·public contract | privacy boundary·시험/benchmark | 중단 조건·의존성 |
|---|---|---|---|
| Phase 20 wizard core | `app.monitor_setup` 역할/파일 검증·dry-run·안전 미리보기 | raw 경로/샘플 미출력 canary; sample 4KiB/16줄 latency | parser parity·identity 실패 시 중단; v1 loader 검토 |
| Phase 20.1 저장·삭제 | 기본 v2 config 조회·승인 삭제, 경로 없는 `--monitor`; 구현 완료 | 0700/0600·TOCTOU·종료 검증; 최종 검사 직후 same-user 교체 race 잔존 | symlink·existing overwrite 거부; 20 의존 |
| Phase 20.2 사용자 흐름 | 실제 초보 CLI·접근성/오류 복구 | Safari는 read-only 유지; keyboard·문구·privacy test | 승인 없는 시작·오해면 중단; 20.1 의존 |
| Phase 21 checkpoint core | 마지막 처리 위치·재시작 동등성 | private trusted prefix/state; crash-window·256-prefix parity·fsync p95 | offset-only parity 위반·손상 무시면 중단; 20.2 의존 |
| Phase 21.1 rotation | generation 검증·교체 경고 | 파일 identity 원문 비공개; rename/copytruncate/race tests·poll p95 | 추측 병합·silent loss면 중단; 21 의존 |
| Phase 21.2 crash 평가 | 중복/gap 명시 정책 | crash matrix·backup/private cleanup; restart latency | exactly-once 허위 주장·불명확 gap이면 중단; 21.1 의존 |
| Phase 22 multi-source | application/SSH/access/Linux Audit 독립 상태 | source별 queue + global budget; fairness·Linux multiline·stress | 다른 source silent eviction/cross-source 추측이면 중단; 21.2 의존 |
| Phase 23 separate collector/IPC | 읽기 권한 분리 | UDS peer auth·bounded frames; impersonation/replay·throughput | peer 인증/rollback 불명확하면 중단; 22 의존 |
| Phase 24 OS service | 명시적 사용자 서비스 실행·복구 | LaunchAgent/systemd 최소 권한; 설치/제거·FD/crash test·startup p95 | 자동 권한 상승·잔존 서비스면 중단; 23 의존 |
| Phase 25+ remote | 중앙 연계 선택지 | mTLS·tenant 격리·별도 threat model/SLA 평가 | 그 전 hosted/remote no-go; 24 및 별도 승인 |

최소 no-go: 브라우저 arbitrary path/start, secret 저장, symlink/device 허용, 기존 config 무단 overwrite, world-readable config/checkpoint, 승인·dry-run 생략, 오류에 경로/로그 노출, queue/history silent eviction, checkpoint 손상 무시, rotation 추측 병합, 다른 로컬 사용자 무인증 제어, shell/원격 명령, 자동 LLM 전송, v0.2 개인정보·batch 의미 회귀, macOS만 시험하고 Linux 지원 확정 주장.

## 10. 외부 근거와 프로젝트 정책의 분리

| 공식 자료 | 적용 가능한 일반 원칙 / 특정 구현 | 이 설계에서 **새로 정한 정책** |
|---|---|---|
| [Python 3.12 `os`](https://docs.python.org/3.12/library/os.html) | `dir_fd`·`O_NOFOLLOW`·`os.link`·`os.replace`·`fsync`의 API 의미와 플랫폼별 지원 검사 | no-clobber temp+link·0700/0600·실패 시 fail closed; 원자성/내구성 FS 테스트 필요 |
| [Apple 파일 시스템·권한](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html), [Application Support 위치](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/ManagingFIlesandDirectories/ManagingFIlesandDirectories.html), [launchd Agent](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html), [FSEvents](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/Introduction/Introduction.html) | BSD mode 외 ACL·sandbox·볼륨 정책, 사용자별 Agent lifecycle, FS 변경 알림 | private mode만으로 모든 macOS 권한 모델을 충족한다고 주장하지 않음; Phase 24 전 자동 설치 없음; 알림만으로 offset ack하지 않음 |
| [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html), [Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html) | 서비스 권한 sandbox와 watch overflow·rename 관찰 | Phase 24 전 service 없음; event는 재검사 신호 |
| [logrotate.conf(5)](https://man7.org/linux/man-pages/man5/logrotate.conf.5.html) | `copytruncate`에 기록 손실 창 존재 | 자동 generation 병합 금지 |
| [OWASP File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [Path Traversal review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html) | 최소 파일 권한·경로/원문을 로그에 쓰지 않기·경로 검증 | browser path no-go·safe fixed error·setup만 write |
| [NIST SP 800-92 final](https://www.nist.gov/publications/guide-computer-security-log-management) | 수집·저장·접근·폐기의 전체 lifecycle 계획. Rev.1은 [initial public draft](https://csrc.nist.gov/pubs/sp/800/92/r1/ipd)라 최종 표준으로 취급하지 않음 | retention은 미정, 프로젝트 운영 환경별 별도 결정 |
| [OpenTelemetry filelog receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/filelogreceiver/README.md), [Fluent Bit Tail](https://docs.fluentbit.io/manual/data-pipeline/inputs/tail) | 각 제품의 `storage`/offset DB·rotation·버퍼 동작은 **제품별 구현 사례** | 둘을 도입하거나 그 보장을 상속하지 않음; 256/256KiB·0.5초·보존 기간을 외부 자료가 정했다고 주장하지 않음 |

연구의 결론은 특정 collector 복제가 아니다. 기존 파일 identity·bounded prefix·queue ack·safe publication 불변식에 맞는 **검증 가능한 최소 구현**을 단계별로 추가해야 한다. 파일 내용에서 탐지·관계·위험도 의미를 새로 만들지 않는다.
