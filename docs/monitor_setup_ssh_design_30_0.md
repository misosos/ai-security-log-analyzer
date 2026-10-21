# application·SSH 모니터링 설정 마법사 통합 설계

**상태: 설계 gate.** 이 문서는 구현·지원 완료 선언이 아니다. 기준은 v0.4.0 릴리스 커밋 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`이며, [CI run 39549559951](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39549559951)은 completed/success였다. 시작 `main`·`origin/main`은 같고 clean, behind/ahead 0/0이었다. 변경 전 전체 회귀는 2,384 passed·기존 경고 2개다. 공개 v0.1.0~v0.4.0 tag·Release는 그대로 둔다.

## 결정과 현재의 실무 공백

사용자는 현재 `uv run python -m app.monitor_setup`으로 application 로그만 등록할 수 있다. SSH의 batch/live 분석과 기본 private v2 checkpoint 복구는 이미 있지만 SSH 설정을 사용하려면 닫힌 JSON을 직접 작성해야 한다. 잘못된 역할·별칭·정책 또는 파일 권한 때문에 시작이 거부되기 쉽다. 마법사는 탐지나 운영 적합성을 판정하는 도구가 아니라 **단일 로컬 파일을 안전하게 등록하는 단계**로 유지한다.

| 현재 경로 | 확인한 계약과 수정 지점 |
| --- | --- |
| `app/monitor_setup.py` 생성 | 개인정보 안내 → `application` 입력 → 절대 경로 → `_open_regular` → 최대 4,096 byte·완성 16줄·줄 2,048 byte의 `_inspect` → 승인 → private v2 저장. `DryRunSummary`는 parsed/ignored/rejected 수만 가진다. `_inspect`의 `LiveTailRecord("application", …)`, `parse_live_records("application", …)`, `LiveMonitorConfigV2` 기본 역할, 저장 후 `runtime.role != "application"`, CLI 출력·도움말이 역할 고정 지점이다. |
| `--show`·`--delete`·`--reset-checkpoint` | `app/live_monitoring/default_config.py`의 private v2 guard와 `LiveCheckpointManager`를 사용한다. `--show`는 경로 없는 역할·복구 요약, delete는 승인 뒤 config와 연결 checkpoint를 순서대로 삭제, reset은 승인 뒤 checkpoint 하나만 삭제한다. 원본 로그는 보존하고 활성 lock·불확실한 상태는 거부한다. 두 파일 삭제는 원자적이지 않다. |
| 기본 `--monitor` | `app/local_web.py`가 같은 기본 resolver의 v2를 읽는다. `application`·`ssh`는 분석과 bounded checkpoint를 지원한다. 새 설정은 `FROM_END`, `BOUNDED_REPLAY_V1`, `FAIL_CLOSED`; 동일 파일의 한정된 prefix만 복구한다. |
| 명시적 `--monitor-config` | v1 application·SSH·access와 v2 application·SSH의 기존 실행 경로다. 기본 설정용 checkpoint를 연결하지 않고 시작마다 `FROM_END`다. v2를 직접 지정해도 자동 복구 대상은 아니다. |
| SSH parser·분석 | `app/live_monitoring/parser_adapter.py`는 `app/parser/registry.py`의 SSH parser와 `Asia/Seoul`을 사용한다. `app/parser/ssh_auth.py`는 지원하는 Failed/Accepted password/publickey 문구를 인증 event로 만든다. 시각은 맞지만 다른 sshd 문구는 `event_type=None`인 PARSED event가 될 수 있다. 기존 SSH 실패→성공 관계·risk·case 의미는 바꾸지 않는다. |
| checkpoint 결합 | v2는 source 1개, 고정 source ID, 역할별 별칭을 검증한다. `app/live_monitoring/checkpoint.py`는 checkpoint 역할·timezone·파일 identity·안전 digest를 대조한다. 역할이 다르면 `FROM_END`로 조용히 대체하지 않는다. |

영향 후보는 `app/monitor_setup.py`, 관련 CLI·설정·runtime·checkpoint 테스트와 사용 문서다. v2 schema, `app/local_web.py`, SSH parser, detector, correlation, risk, case, API/SSE의 변경은 계획하지 않는다. 실제 구현에서 공통 함수 추출이 필요해도 application 기존 입력·출력·명시적 `--output` 의미를 먼저 회귀로 고정한다.

## 사용자 흐름과 안전한 문구

1. 개인정보·파일 권한과 로컬 처리, 기존 줄 미처리, 설정에 경로가 저장됨을 짧게 알리고 `y/yes`로 진행한다.
2. **애플리케이션 로그인 로그** 또는 **SSH 인증 로그** 중 정확히 하나를 선택한다. 선택하지 않거나 둘 다 선택한 입력은 저장하지 않는다. 첫 화면에는 parser·role ID·checkpoint 같은 내부 이름을 쓰지 않는다. 기존 `application` 입력은 호환 별칭으로 허용하고 기존 대화형 자동화가 깨지지 않도록 별도 테스트한다.
3. 로그 파일의 절대 경로를 대화형 입력으로 받는다. shell 확장·URL·상대 경로를 해석하지 않고, 경로를 오류·일반 출력에 다시 표시하지 않는다.
4. symlink·일반 파일·읽기 가능성·소유권·쓰기 권한과 경로 구성요소를 확인한다. 불확실하면 고정 코드와 다음 행동만 보여 준다.
5. 기존 완성 줄의 bounded dry-run을 한 번 수행한다. 분석 결과·사용자 식별자를 출력하지 않는다.
6. “검사한 줄 / 읽을 수 있었던 줄 / 건너뛴 줄 / 형식을 확인하지 못한 줄”, SSH에서 확인한 “로그인 실패 / 성공 기록 / 그 밖의 SSH 문구”의 안전한 **건수**만 표시한다. 성공 기록은 침해 성공이 아니다.
7. 선택한 로그 종류, **기존 줄은 건너뛰고 이후 새 줄부터 시작**한다는 뜻, 같은 파일에서만 제한적으로 이어받는다는 뜻을 재확인한다. 기술 정책 이름은 펼친 도움말 또는 개발 문서에 둔다.
8. 별도의 `y/yes` 저장 승인을 받는다. 기존 설정이 있으면 생성 실패로 멈추고 경로 없는 `--show`·`--delete`·`--reset-checkpoint` 안내를 보여 준다. 기존 파일을 자동 덮어쓰거나 백업·교체하지 않는다.
9. 저장 후 `uv run python -m app.local_web --monitor`를 **안내만** 한다. 자동 실행하지 않는다. 사용자 지정 `--output`은 기존 명시적 `--monitor-config` 경계를 유지하고, 그 명령에는 config 경로가 shell history·화면에 남을 수 있음을 별도로 경고한다.

“기존 줄 미처리”는 시작 시점의 정책이다. Dry-run은 작은 기존 구간의 형식 확인일 뿐 그 줄을 분석·발행하지 않는다. 빈 파일·완성 줄 없음·상한 때문에 잘린 샘플은 “형식 확인 불충분”을 보여 주고 명시 승인만 허용한다. 유효한 시각만 있는 비인증 SSH 줄은 로그인 성공/실패로 세지 않는다.

## SSH dry-run의 정확한 경계

| 항목 | 현재 application | Phase 30.1 SSH 설계 |
| --- | --- | --- |
| byte·완성 줄·줄 길이 | 4,096 byte·16줄·2,048 byte | **같은 상한**을 재사용하고 더 큰 읽기·메모리 보유를 도입하지 않는다 |
| 읽기 | 처음 최대 4,096 byte, 완성 LF 줄만 parser에 전달 | 같은 방식. 마지막 partial LF는 입력하지 않고 표시한다. UTF-8 경계와 긴 줄·NUL/제어 문자는 기존 고정 오류 |
| parser 호출 | `parse_live_records("application", records)` 한 번 | `parse_live_records("ssh", records)` **한 번**. 결과 event의 기존 `authentication.outcome`/`event_type`으로 실패·성공·그 밖의 줄을 분류한다. SSH parser를 다시 호출하지 않는다 |
| PARSED | 정규화된 event | “형식을 읽은 줄”. SSH에서는 인증 event와 `event_type=None`을 반드시 따로 센다. PARSED만으로 SSH 인증 호환을 주장하지 않는다 |
| IGNORED / REJECTED | 빈 줄 등 / 예상한 parse 실패 | “빈 줄 등 건너뛴 줄” / “형식을 확인하지 못한 줄”. 정확한 고정 코드만 사용하며 원문·실패 이유의 사용자 값은 숨긴다 |
| 그 밖의 SSH 줄 | 해당 없음 | timestamp가 유효한 비인증 sshd 줄은 PARSED이지만 **로그인 관찰 0건**이다. 모두 비인증이면 경고하고 저장 승인 전에 다시 알려 준다 |
| 탐지 의미 | dry-run은 형식 검사 | detector·correlation·risk·case·LLM을 실행하지 않는다. 공격 탐지·계정 침해·운영환경 호환성 보증으로 표현하지 않는다 |

샘플이 파일 앞부분이라 최신 형식과 다를 수 있고, cap 뒤의 malformed UTF-8·긴 줄·rotation은 확인하지 못한다. SSH의 로그 형식은 OS의 syslog/journal 배치와 OpenSSH 설정에 따라 달라질 수 있다. 현재 parser가 기대하는 **날짜·시간을 앞에 둔 합성/변환된 텍스트 파일**만 검사한다. 기본 OS journal, macOS unified log, 외부 syslog를 마법사가 직접 읽거나 변환하지 않는다. OpenSSH의 `LogLevel`·`SyslogFacility` 설정이 이 프로젝트 parser의 입력 형식을 보증하지 않는다.

## 설정·기존 파일 정책

- 새 기본 설정은 기존 닫힌 `LiveMonitorConfigV2`의 source **정확히 하나**다. `application`은 `애플리케이션 로그 1`, `ssh`는 `SSH 로그 1`; 둘 다 `SOURCE-000001`, `enabled=true`, `FROM_END`, `Asia/Seoul`, `BOUNDED_REPLAY_V1`, `FAIL_CLOSED`다. Unknown key·다중 source·역할/별칭 불일치는 거부한다.
- **기존 설정을 안전하게 거부**한다. 대안인 별도 replace 명령은 별도 설계와 명시적 마이그레이션·rollback gate가 필요하고, 백업 후 교체는 경로·개인정보 복제와 삭제 책임이 늘어난다. 두 대안 모두 이번 범위에서 채택하지 않는다. `--reset-checkpoint`는 기존 설정의 **분석 연속성**만 포기할 때 쓰며 역할 변경 승인이나 설정 교체 도구가 아니다. 역할을 바꾸려면 모니터를 정상 종료하고 기존 설정·연결 checkpoint 상태를 `--show`로 확인한 뒤, 사용자가 의도한 `--delete` 절차를 명시적으로 완료하고 새 설정을 생성한다. orphan·불일치 checkpoint는 수동 확인이 선행된다.
- 저장은 현재의 private parent `0700`, 파일 `0600`, `O_EXCL|O_NOFOLLOW` 임시 파일, `fsync`, no-clobber `os.link`, loader round-trip을 재사용한다. 저장 후 역할 검증은 고정 `application` 비교 대신 **선택한 역할과 정확히 일치**해야 한다. 게시 실패·검증 실패는 성공으로 보이지 않는다.
- 기본 `--show`·`--monitor`·restart·reset·delete는 source role과 checkpoint role을 재검증한다. 역할이 다른 checkpoint는 사용·자동 reset·자동 삭제하지 않는다. 기존 application v2 및 명시적 v1/v2 흐름은 migration 없이 유지한다. Access와 Linux Audit은 설정 마법사 확장 대상이 아니다.

### 호환성 표

표의 `기본`은 private 기본 경로, `명시`는 `--monitor-config` 경로를 뜻한다. `reset/delete`는 기본 설정 관리 명령만 가리킨다. `—`는 이 흐름에 적용되지 않는다는 뜻이다.

| 조합 | setup | show | monitor | restart recovery | reset | delete |
| --- | --- | --- | --- | --- | --- | --- |
| 기존 application v2 기본 | 기존 파일 no-clobber | 안전 요약 | 기본 실행 | BOUNDED면 같은 파일 복구, DISABLED면 FROM_END | BOUNDED+checkpoint만 승인 | 승인 후 config·연결 checkpoint |
| 새 application v2 기본 | 생성·승인 | 안전 요약 | 기본 실행 | 같은 파일 bounded 복구 | 승인 후 checkpoint 하나 | 승인 후 config·연결 checkpoint |
| 새 SSH v2 기본 | **Phase 30.1 후보** 생성·승인 | 역할·안전 요약 | 기본 실행 | 같은 파일 bounded 복구 | 승인 후 checkpoint 하나 | 승인 후 config·연결 checkpoint |
| 명시적 application v1/v2 | v2 `--output`만 기존 방식 생성; v1 생성 없음 | 기본 명령 대상 아님 | `--monitor-config` | 매번 FROM_END, checkpoint 없음 | 대상 아님 | 대상 아님 |
| 명시적 SSH v1/v2 | v2 `--output`은 후보; v1 생성 없음 | 기본 명령 대상 아님 | `--monitor-config` | 매번 FROM_END, checkpoint 없음 | 대상 아님 | 대상 아님 |
| access 설정 | 생성 제외 | 기본 v2로 거부 | 명시적 v1 detection-only | FROM_END, checkpoint 없음 | 대상 아님 | 대상 아님 |
| 손상·권한 오류·symlink 기본 설정 | no-clobber 또는 안전 오류 | 고정 오류·경로 숨김 | fail closed | 없음 | 자동 수리·삭제 거부 | 자동 수리·삭제 거부 |
| 역할이 다른 checkpoint | orphan이면 생성 거부 | `NEEDS_REVIEW`, 실행 불가 | fail closed | 과거 상태 재사용 거부 | 불일치 자동 reset 거부 | 연결 불명확하므로 거부 |

`--delete`는 config와 checkpoint를 하나의 원자적 연산으로 지우지 않는다. 중간 실패는 수동 확인이 필요하다. `--show`의 사용 가능 여부는 조회 시점의 관찰이지 이후 실행 성공 보장이 아니다.

## 보안·개인정보 위협 모델

| 위협 | 예방 | 탐지·실패 동작 | 잔여 위험 |
| --- | --- | --- | --- |
| symlink·TOCTOU·승인 대기 중 교체 | 절대 경로, `O_NOFOLLOW`/directory FD, `lstat`·`fstat`·path identity 재검사; 승인 뒤 다시 확인 | 파일·parent가 바뀌면 고정 `SETUP_SOURCE_CHANGED` 등으로 저장 중단 | 같은 UID 비협력 프로세스의 마지막 검사 직후 교체와 filesystem 특수 동작을 원자적으로 차단한다고 주장하지 않음 |
| 다른 사용자 소유 파일 | 새 SSH 마법사에서는 **현재 UID 또는 root 소유**이고 현재 프로세스로 읽을 수 있는 일반 파일만 허용하는 안을 Phase 30.1 실패 테스트로 고정. root 로그 접근을 위해 권한 상승·chmod를 자동 수행하지 않음 | 다른 비root 소유나 읽기 실패는 경로 없는 권한 오류; application의 기존 허용 범위는 이번 설계만으로 변경하지 않음 | root 소유라고 내용의 신뢰성까지 보증하지 않으며 ACL·그룹 권한과 OS별 파일 권한 차이가 남음 |
| group/world writable source 또는 parent | 기존 source의 `mode & 0o022` 거부 유지. 새 SSH에서는 쓰기 가능한 parent를 거부하되 root 소유 sticky 임시 상위 디렉터리 아래의 private 테스트 subtree만 좁게 예외 검토 | 불안전 parent·source는 고정 안전 오류; macOS/Ubuntu 합성 테스트로 실제 행태 확정 | 기존 application parent 정책과의 차이, sticky 디렉터리·ACL·mount 옵션은 별도 검증 필요. 부모 검사만으로 동시 교체가 완전히 사라지지 않음 |
| 역할이 다른 checkpoint·실행 중 monitor 경쟁 | 고정 역할·alias와 checkpoint role binding, 기존 advisory lock, no-clobber config | mismatch·lock 보유·orphan은 fail closed; `FROM_END`로 조용히 재시작·자동 reset하지 않음 | advisory lock은 같은 UID 비협력 프로세스를 막지 못하고 config·checkpoint 두 파일 삭제는 비원자적 |
| SSH 계정·IP·hostname·원문·경로 노출 | 결과는 안전한 건수와 고정 문구만. preview·오류·repr·일반 stdout/stderr·테스트 artifact에 사용자 필드·path를 넣지 않음 | 합성 canary로 CLI/예외/공개 API·SSE 검증; 실패 시 고정 코드 | trusted 내부 event와 private config에는 원문·path가 남을 수 있음 |
| CLI 인자·shell history 경로 | 기본 interactive 경로 입력과 경로 없는 `--monitor` 권장; 명시적 `--output`은 별도 경고 | 도움말과 승인 문구에서 history 노출 가능성 안내 | 터미널 입력·scrollback·OS process list·shell history는 이 도구가 삭제하지 못함 |
| 악의적인 긴 줄·잘못된 UTF-8·partial LF | 4,096 byte/16줄/2,048 byte, strict UTF-8, 완성 줄만 parser 호출 | 고정 `SETUP_LINE_TOO_LONG`·`SETUP_INVALID_UTF8`·`SETUP_BINARY_INPUT`; partial은 검사 미완료로 표시 | 샘플 밖 오류와 향후 append 형식은 검증되지 않음 |
| backup·snapshot·crash dump | private 0700/0600 및 원본 비복제·비출력 | 사용자에게 민감 파일 경고, reset은 checkpoint 하나만 승인 삭제 | snapshot·백업·메모리 dump 잔존. `--delete`·reset은 **secure erase가 아님** |

새 소유권·parent 정책은 **제안**이며 현재 코드가 모두 시행한다고 주장하지 않는다. 특히 현재 `_open_regular`은 source 소유자나 parent 쓰기 권한을 전부 검증하지 않고, source의 group/world writable bit만 거부한다. Phase 30.1은 별도 실패 테스트를 먼저 작성하고 macOS·Ubuntu에서 실제 읽기 가능한 root-owned SSH 파일과 합성 디렉터리의 동작을 확인한 뒤 정책을 확정한다. 지원 가능한 파일이 없으면 범위를 조용히 완화하지 않고 gate를 멈춘다.

## Phase 30.1 전 실패 테스트와 검증 계획

현재 구현에는 아래 SSH 마법사 경로가 없으므로 **후속 구현 전에 실패 테스트를 먼저 남긴다**. 이번 Phase에는 실패 테스트를 실행 상태로 추가하지 않는다.

| 테스트 후보 | 기대 계약 |
| --- | --- |
| 역할 미선택·application+SSH 동시 선택 | 저장 0건, 고정 입력 오류; 기존 `application` 한 선택은 계속 성공 |
| 합성 SSH 실패·성공·기타 sshd 줄 | parser adapter 한 번, 인증 종류별 안전 건수; event_type 없는 PARSED를 성공으로 세지 않음; detector/LLM 호출 0회 |
| malformed·공백·partial UTF-8·긴 줄 | REJECTED/IGNORED/partial 또는 고정 오류를 정확히 구분; byte·줄 상한 유지 |
| path·계정·IP·hostname canary | preview·stdout/stderr·예외·repr·CLI help·테스트 실패 출력에 값 없음; private config 내부 path와 공개 출력 구분 |
| 기존 config no-clobber·orphan checkpoint | 원래 config/checkpoint byte 불변; 자동 replace·backup 없음; `--show`·명시적 관리 절차 안내 |
| SSH v2 생성·loader round-trip | 단일 source·역할별 alias·FROM_END·BOUNDED_REPLAY_V1·private 0700/0600; application 기존 v2도 byte 계약 유지 |
| `--monitor` 새 줄·정상 종료·재시작 | 기존 줄 미처리, 새 줄 분석, 동일 파일 bounded 복구·과거 SSE 재알림 없음, source role 불일치 fail closed |
| reset 취소·승인·delete | 취소 byte 보존; 승인 시 checkpoint 하나만 삭제, 원본 로그·config 보존; delete는 원본 로그 보존 |
| application·명시적 v1/v2·access 회귀 | 기존 application CLI prompt·`--output`·show/delete/reset·runtime 유지; explicit은 FROM_END, access는 detection-only |
| macOS·Ubuntu 별도 process smoke | 합성 파일·임시 HOME만, source/권한·lock·listener·FD·임시 자료 정리, UTC와 Asia/Seoul 동일 결과 |

검증은 focused setup·loader·SSH checkpoint → UI/API/SSE/privacy → 전체 pytest → 합성 인증·웹 79/79, Linux Audit 21/21, risk/case 70/70 순서로 한다. 실제 사용자 로그·기본 설정·checkpoint는 입력으로 쓰지 않는다. `uv lock --check`, Python 문법, `git diff --check`와 합성 canary 검사를 포함한다. Test stdout·stderr·artifact에는 raw 로그와 경로를 저장하지 않는다.

## 다음 단계와 계속되는 NO-GO

- **Phase 30.1:** 역할 선택, SSH bounded dry-run, private v2 설정 생성만. 기존 public API·SSE, 분석 pipeline, v2 schema는 그대로 둔다.
- **Phase 30.2:** application·SSH의 show·monitor·restart·reset·delete 통합 회귀와 fail-closed 문구 점검.
- **Phase 30.3:** macOS·Ubuntu 별도 프로세스와 사용자 수용 검수. 실제 Safari·보안 정책과 자동 테스트 증거를 분리한다.

다중 source, cross-source correlation, automatic rotation/copytruncate handoff, 두 세대 replay, exactly-once·무유실은 계속 **NO-GO**다. 설치는 source checkout이며 wheel/PyPI 배포는 이 설계의 대상이 아니다.

## 근거, 관찰 가능한 자료와 한계

| 공식 자료 | 이 설계에 연결한 관찰·기술 사실 | 자료가 정하지 않는 것 |
| --- | --- | --- |
| [OpenSSH `sshd_config(5)`](https://man.openbsd.org/sshd_config) | `LogLevel`·`SyslogFacility`가 로그 내용과 전달 경로에 영향을 준다. DEBUG 수준은 개인정보 위험이 있다. | 이 프로젝트의 `YYYY-MM-DD HH:MM:SS` parser 형식이나 탐지 임계값을 보증하지 않는다. |
| [Python 3.12 `os` 문서](https://docs.python.org/3.12/library/os.html)와 [Linux `open(2)`](https://man7.org/linux/man-pages/man2/open.2.html)·[`stat(2)`](https://man7.org/linux/man-pages/man2/stat.2.html)·[`flock(2)`](https://man7.org/linux/man-pages/man2/flock.2.html) | dir FD·`O_NOFOLLOW`·`fstat`는 파일 타입과 identity 검사에 쓰고, `flock`은 advisory lock이다. | 검사와 게시 사이의 모든 race, 비협력 같은 UID 프로세스, 모든 filesystem의 원자성을 보장하지 않는다. |
| [Apple 파일 시스템 보안](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html) | macOS의 접근 제어는 BSD mode 외 ACL·volume 정책의 영향을 받을 수 있다. | macOS의 모든 볼륨이나 Linux와 같은 permission 결과를 보증하지 않는다. |
| [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet/)와 [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) | 로그의 개인정보·보존·접근 통제와 안전한 표시를 설계할 근거다. | 본 프로젝트의 4,096 byte·16줄·2,048 byte 한계, 탐지 의미, 운영 탐지율을 정하지 않는다. |

**Observable Evidence Mapping:** 선택한 source role은 v2의 고정 role·alias로, 안전한 파일 identity는 열린 FD와 경로의 재검사로, 완성된 SSH 인증 줄은 기존 `NormalizedEvent.authentication.outcome`으로, 기타 시각 유효 줄은 `event_type=None`으로 연결한다. 사용자에게는 원본 대신 bounded 건수·고정 오류·복구 행동만 투영한다. 이 관찰로 알 수 없는 것은 실제 공격 의도·침해 성공, 모든 파일 구간의 parser 적합성, 다른 source와의 인과관계다.
