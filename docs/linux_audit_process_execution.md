# Linux Audit Process Execution Telemetry

## 1. 목적

이 기능은 하나의 Linux Audit compound event에 함께 기록된 실행 관련
record를 내부 `process_execution_attempt` 관찰로 정규화한다. 목적은 원본
evidence를 보존하면서 구조적으로 확인 가능한 실행 시도와 evidence
완전성을 표현하는 것이다.

정규화된 관찰은 탐지나 보안 결론이 아니다. 실행이 관찰됐다는 사실만으로
정상·악성 여부, 사용자의 의도, 공격 성공 또는 침해를 판단하지 않는다.

## 2. 처리 흐름

현재 처리 경로는 다음과 같다.

```text
raw Audit records
→ app/loader/linux_audit_loader.py:load_linux_audit_events()
→ GroupedAuditEvent
→ app/parser/linux_audit.py:_assemble_execve_arguments()
→ app/parser/linux_audit.py:_build_process_execution_context()
→ app/parser/linux_audit.py:parse_linux_audit_events()
→ NormalizedEvent(event_type="process_execution_attempt")
├→ app/analyzer/process_execution.py:aggregate_process_execution_observations()
└→ app/analyzer/process_execution_classification.py:classify_process_execution_observations()
→ app/main.py:main()
→ app/analyzer/report.py:print_analysis_result()
```

Loader는 `source_instance`, `node`, `event_id`를 grouping scope로 사용한다.
같은 group의 record는 deterministic order로 보존하지만 이를 원래 도착
순서라고 주장하지 않는다. CLI의 `main()`은 normalized logs를 한 번만
로드하고 동일 list로 기존 분석과 process aggregate를 계산한다.

## 3. 입력 record 역할

- `SYSCALL`: architecture와 syscall의 raw 표현, syscall 관찰 결과,
  PID/PPID, UID/GID 계열 및 실행 관련 metadata를 제공한다.
  `success=yes`는 syscall 관찰 결과일 뿐 프로그램 목적 달성, 정상 실행,
  공격 성공을 뜻하지 않는다.
- `EXECVE`: `argc`, `aN`, `aN_len`, `aN[k]` 형태의 serialized argument
  evidence를 제공한다. `SYSCALL`의 `a0`부터 `a3`까지는 syscall 인자
  word 또는 pointer 값이므로 `argv` 문자열로 사용하지 않는다.
- `CWD`: 관찰된 working directory를 제공한다. 파일 접근이나 실행 성공을
  증명하지 않으며 현재 filesystem을 조회하거나 경로를 해석하지 않는다.
- `PATH`: 한 compound event에 관련된 pathname 및 `item`, `nametype`,
  inode, device, mode, owner ID metadata를 제공한다. `PATH` record 자체는
  파일 생성·변경·삭제를 증명하지 않는다.
- `PROCTITLE`: bounded supporting evidence다. NUL-separated byte sequence를
  해석할 수 있지만 authoritative `argv`의 대체물이나 shell command로
  취급하지 않는다.

## 4. 내부 스키마

`LinuxAuditPathContext`는 하나의 `PATH` record에서 정규화한 path 관련
관찰을 나타낸다. 값이 없거나 안전하게 해석되지 않으면 `None`을 보존한다.

`ProcessExecutionContext`는 syscall outcome, raw architecture/syscall,
PID/PPID, numeric identity context, `argv`와 completeness, working directory,
여러 path context, PROCTITLE supporting evidence 및 모든 `raw_records`를
보존한다. 이 context는 `frozen=True`이며 detection, risk 또는 공격 여부를
판정하지 않는다.

`NormalizedEvent.process_execution`은 내부 optional context다. process
candidate가 아닌 기존 event에서는 `None`이며 API response model로 자동
직렬화되지 않는다.

`argv`, PROCTITLE, path name, working directory, executable, identity 및
raw record에는 credential, token, 개인정보나 내부 환경 정보가 포함될 수
있으므로 상세 context는 내부 evidence 전용이다.

## 5. EXECVE argument assembly

- Quoted value는 outer quote를 제거하되 shell quoting을 복원하지 않는다.
- `aN=""`은 존재하는 empty argument이며 누락된 argument와 구분한다.
- Unquoted value는 짝수 길이의 유효한 hexadecimal byte sequence일 때만
  strict UTF-8로 decode한다.
- Invalid hex, invalid UTF-8 또는 NUL이 포함된 단일 argument는 완전한
  문자열로 가장하지 않고 `None`으로 제한한다.
- Argument와 fragment index는 문자열이 아닌 numeric order로 정렬한다.
- Split argument는 `aN[k]` fragment index가 연속일 때 numeric order로
  결합하고 `aN_len`의 serialized length와 대조한다.
- `argc`는 non-negative decimal event metadata이며 observed argument로
  추정하지 않는다. Missing, invalid 또는 conflicting `argc`는 candidate를
  안전하게 만들 수 없으므로 context 생성을 중단한다.
- 동일 field의 duplicate나 conflicting evidence, whole value와 fragment의
  동시 존재, 누락된 fragment와 범위 밖 argument는 completeness를 낮춘다.
- 복원되지 않은 index는 `argv`에서 `None`이고
  `incomplete_argument_indexes`에 numeric order로 기록된다.

## 6. Candidate와 completeness

V1 process candidate에는 같은 `GroupedAuditEvent` 안의 정확히 하나인
`SYSCALL`, 하나 이상인 `EXECVE`, 유효한 `arch`, `syscall`, `pid`, `ppid`,
그리고 확정 가능한 `argc`가 필요하다. Core record cardinality 또는 필수
구조가 모호하면 process event를 만들지 않는다. 이는 실행 시도가 없었다는
판정이 아니라 현재 contract로 안전하게 정규화하지 않았다는 뜻이다.

일부 argument를 복원하지 못하더라도 `argc`가 확정되면 candidate는 생성될
수 있고 `argv_complete=False`로 표현된다.

`paths_complete=True`는 `SYSCALL.items`가 유효하고 실제 `PATH` 수와
일치하며 numeric `item`이 중복 없이 `0..items-1`을 이루고 각 record를
구조적으로 해석할 수 있음을 뜻한다. Completeness는 correctness, trust,
confidence 또는 safety가 아니다.

## 7. CLI 출력

CLI는 기존 개별 process event 대신 고정 크기 aggregate를 표시한다. Phase 9에서는 그 다음에 고정 category별 조사 후보 건수·한계·다음 단계를 표시하지만 원문 실행 identity는 표시하지 않는다.

```text
===== Process Execution Telemetry =====
Linux Audit 프로세스 실행 관찰 집계
  관찰 수: 3
  SYSCALL outcome 관찰:
    success: 2
    failure: 1
    unknown: 0
  argv evidence completeness:
    complete: 2
    incomplete: 1
  PATH evidence completeness:
    complete: 1
    incomplete: 2
```

Section에는 `success`가 프로그램 목적 달성 또는 공격 성공을 의미하지
않고, completeness가 evidence 완전성일 뿐 정확성·신뢰도·안전성을
의미하지 않는다는 고정 안내가 함께 표시된다. Aggregate가 없거나
`observation_count == 0`이면 section을 생략한다.

CLI는 개별 event, executable, `argv`, PID/UID, PATH/CWD, PROCTITLE,
raw evidence, audit key, node 또는 source identity를 출력하지 않는다.

Shared-memory privileged execution review의 bounded detector 조건, CLI 입력과
count 의미는 [Shared-memory Privileged Execution Review](shared_memory_execution_review.md)에
별도로 설명한다.

Session lifecycle과 process observation의 bounded 공동 관찰 및 CLI count
의미는 [Linux Audit Session–Process Co-Observation Review](linux_audit_session_process_review.md)에
별도로 설명한다.

## 8. 외부 노출 정책

| 경계 | Aggregate | Detailed evidence | 정책 |
|---|---|---|---|
| CLI | 기존 고정 count aggregate와 Phase 9 조사 후보 category count | 없음 | 명시적 allowlist field만 표시 |
| 기본 API·웹 | 없음 | 없음 | 기존 계약 유지 |
| 선택적 보안 Linux Audit API | 기존 count-only 응답 | 없음 | 별도 인증·인가·audit sink가 필요한 현재 route는 유지하고 Phase 9 category를 추가하지 않음 |
| LLM | 없음 | 없음 | per-IP 및 overall input에서 제외 |
| Frontend | 없음 | 없음 | API에 없는 정보를 재구성하지 않음 |
| Detection | CLI fixed review count만 | 내부 observation | IP results에는 포함하지 않음 |
| Correlation | 사용하지 않음 | 내부 event만 존재 | process correlation 없음 |
| Risk | 사용하지 않음 | 내부 event만 존재 | risk factor에 반영하지 않음 |

## 9. Privacy와 보안 경계

외부 projection은 explicit allowlist를 사용한다. Context 전체에 대한
`asdict()`, `vars()`, generic JSON serialization 또는 임의 key 순회는
허용하지 않는다. 내부 raw evidence는 forensic analysis 가능성을 위해
삭제하거나 presentation 제한에 맞춰 변형하지 않는다.

Heuristic redaction이 성공해도 secret이 없다는 보장은 되지 않는다.
현재 애플리케이션에는 protected forensic detail을 위한 authorization/RBAC,
access audit 및 export control이 없으므로 상세 외부 노출은 승인되지 않았다.

## 10. 의미 제한

- `observation_count != unique process count`
- `observation_count != 시스템 전체 실행 횟수`
- `success != program goal achieved`
- `success != benign execution`
- `success != attack success`
- `completeness != correctness`
- `completeness != trust`
- `section absence != absence of execution`
- `normalized event != malicious activity`
- `process telemetry != compromise evidence`

## 11. 검증 방법

- Fixture 구조와 grouping: `tests/test_linux_audit_process_execution_fixtures.py`
- EXECVE assembly: `tests/test_linux_audit_execve_arguments.py`
- Context builder: `tests/test_linux_audit_process_execution_builder.py`
- Parser integration: `tests/test_linux_audit_process_execution_parser.py`
- Pipeline 및 외부 비노출: `tests/test_linux_audit_process_execution_isolation.py`
- Aggregate allowlist와 불변조건: `tests/test_process_execution_aggregate.py`
- CLI 연결과 privacy 경계: `tests/test_process_execution_cli.py`
- Report format과 empty behavior: `tests/test_report.py`
- 전체 회귀: `uv run pytest -q`

테스트는 fixture 원문을 외부 출력으로 복사하지 않고 event 생성 여부,
aggregate 불변조건, consumer 격리 및 민감 evidence 비노출을 검증한다.

## 12. 알려진 한계

- Architecture-aware syscall name 해석이 없다.
- Process tree 또는 parent-child causation을 구성하지 않는다.
- PID reuse를 해결하거나 장기 process identity를 제공하지 않는다.
- 개별 process 상세 presentation이 없다.
- Shared-memory detector는 CLI fixed review count에만 사용되며 기존 IP
  detection results, correlation 또는 risk에는 반영되지 않는다.
- ATT&CK mapping을 생성하지 않는다.
- Authorization/RBAC와 상세 접근 audit 기능이 없다.
- Internal evidence의 retention 정책을 구현하지 않았다.

## 13. 향후 확장 전제

향후 별도 연구와 승인을 거쳐 protected forensic detail access,
authorization 및 access auditing, explicit data classification/redaction,
추가 process detection, process/session correlation을 검토할 수 있다.
이 항목들은 현재 구현되거나 승인된 기능이 아니다.

## 14. Phase 9 — Linux 프로세스 실행 조사 후보 (2026-10-10)

`classify_process_execution_observations()`는 parser를 재실행하지 않고 정확한 `tuple[NormalizedEvent]`의 `process_execution_attempt`만 받는다. frozen dataclass와 tuple로 category 관찰·건수·고정 한계·read-only 다음 단계를 반환한다. 내부 raw event/context 참조는 반환하지 않는다. CLI는 기존 count-only aggregate 다음에 별도 **Linux 프로세스 실행 조사 후보** 섹션을 표시한다. 이는 탐지·risk·인증/웹 조사 사례·Timeline과 결합하지 않으며 기본 API, 보안 Linux Audit API, 웹, HTML, LLM에 연결하지 않는다.

| Category ID | 정확 일치 allowlist·조건 | 고정 검토 우선순위 |
| --- | --- | --- |
| `LINUX_SHELL_INTERPRETER_EXECUTION` | `sh`, `bash`, `dash`, `zsh`, `ksh` | LOW |
| `LINUX_NETWORK_TRANSFER_UTILITY_EXECUTION` | `curl`, `wget` | LOW |
| `LINUX_PERMISSION_CHANGE_UTILITY_EXECUTION` | `chmod`, `chown` | LOW |
| `LINUX_TEMP_DIRECTORY_EXECUTION` | 신뢰 가능한 `exe` 절대 경로가 `/tmp`, `/var/tmp`, `/dev/shm` 자체 또는 하위 경로 | MEDIUM |

검증된 `SYSCALL exe` 절대 경로의 basename을 우선 사용하고, 없으면 `comm`, 그마저 없으면 `EXECVE argv[0]`로만 fallback한다. 제공된 source의 basename이 충돌하거나 경로가 비정상이면 추측하지 않고 unclassified로 센다. `PATH` record에는 실행 파일 외의 다른 항목도 들어가므로 현재 parser만으로 특정 item을 실행 identity라고 확정하지 않는다. CWD가 임시 디렉터리인 것만으로 temp category를 만들지 않는다. 경로는 filesystem resolve·symlink follow 없이 POSIX segment 단위로 확인한다. substring·대소문자 변환을 하지 않는다. Python·Perl·Ruby, `scp`·`sftp`, package manager, `setfacl`·`chgrp`는 초기 allowlist 밖이다.

신뢰도는 식별 근거의 완전성을 뜻한다. `exe`와 argv/PATH completeness가 모두 완전하면 HIGH, `exe`가 있으나 불완전하거나 `comm` fallback이면 MEDIUM, `argv[0]`만 있으면 LOW다. `comm`은 잘릴 수 있고 `argv[0]`은 호출자가 지정할 수 있다는 한계를 함께 표시한다. `SUCCESS`/`FAILURE`/`UNKNOWN`은 기존 syscall outcome의 표현이며 전송·권한 변경·프로그램 목적 달성 여부가 아니다. 우선순위는 고정 조사 순서이며 위험 점수나 침해 확률이 아니다.

같은 `(source_instance, node, event_id)`의 정확한 normalized execution 중복만 하나로 세며, 동일 identity에 상충하는 context는 고정 오류로 실패한다. 하나의 `/tmp/curl`은 network-transfer와 temp 두 category에 모두 남지만 실행 건수는 하나다. 공개 `observation_id`는 정렬된 결과의 순번일 뿐 audit serial·node·PID를 담지 않는다. 출력에는 실행 파일명·경로, argv, URL, CWD, PATH, PROCTITLE, 계정과 raw record가 없다. 내부 trusted parser event에는 원문이 남아 직접 출력·범용 직렬화하면 노출될 수 있다. 메모리 안전 삭제를 보장하지 않는다.

분류되지 않은 실행은 안전·정상 판정이 아니다. 실행 도구만으로 악성 여부, 공격자 의도, 네트워크 전송·권한 변경 성공을 판정하지 않는다. 합성 평가에는 별도 Linux category section을 두고 기존 79개 IP 기반 confusion matrix와 합치지 않는다. 기본 CLI에서 Linux Audit 파일이 없을 때 출력은 이전과 같다. 웹 연결은 별도 업로드·privacy·권한 설계 전까지 no-go다.

공식 근거 확인일: 2026-10-10. [Red Hat Audit log 설명](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files)은 `SYSCALL success/exit`, `comm/exe`, `PATH`가 서로 다른 관찰 필드임을 보여준다. [Linux Audit field dictionary](https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv)는 필드 계약 확인에 사용했다. [MITRE ATT&CK Process Creation](https://attack.mitre.org/datacomponents/DC0032/)은 실행 telemetry의 조사 가치를 설명하지만 이 프로젝트의 allowlist·우선순위의 근거는 아니다. [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final)는 로그 보호·분석 운영의 일반 원칙을 제공하며 악성 판정이나 category 조건을 지정하지 않는다. 네 allowlist와 LOW/MEDIUM은 저장소 평가를 위한 프로젝트 정책이다.

## 문서 근거

접근일: 2026-09-26

- Red Hat, *RHEL 8 Security hardening — Auditing the system*.
  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening
  Compound Audit event와 record field 설명을 event grouping 및 record 역할의
  근거로 사용했다.
- Linux Audit Project, *Linux Audit field dictionary*.
  https://raw.githubusercontent.com/linux-audit/audit-documentation/main/specs/fields/field-dictionary.csv
  `argc`, argument, process identity 및 Audit field 의미를 확인하는 근거로
  사용했다.
- Linux kernel, `kernel/auditsc.c`.
  https://github.com/torvalds/linux/blob/master/kernel/auditsc.c
  EXECVE argument encoding과 split fragment 경계를 확인하는 근거로
  사용했다.
- MITRE ATT&CK, *Process Creation (DC0032)*.
  https://attack.mitre.org/datacomponents/DC0032/
  Process creation telemetry의 분석 가치를 설명하는 참고자료로만 사용했으며
  parser truth나 detection 조건으로 사용하지 않았다.
- OWASP, *Logging Cheat Sheet*.
  https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
  로그의 credential·token·개인정보 노출 제한과 접근 통제 원칙에 반영했다.
- NIST, *SP 800-92: Guide to Computer Security Log Management*.
  https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf
  로그 관리, 보호 및 보존을 별도 운영 책임으로 구분하는 근거로 사용했다.
- NIST, *AI 600-1: Artificial Intelligence Risk Management Framework —
  Generative Artificial Intelligence Profile*.
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
  외부 AI consumer에 필요한 최소 데이터만 전달하는 정책의 참고 근거로
  사용했다.
- OWASP, *LLM02:2025 Sensitive Information Disclosure*.
  https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
  민감한 process evidence를 LLM input에서 제외하는 정책에 반영했다.
