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
→ app/analyzer/process_execution.py:aggregate_process_execution_observations()
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

CLI는 개별 process event가 아닌 고정 크기 aggregate만 표시한다.

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

## 8. 외부 노출 정책

| 경계 | Aggregate | Detailed evidence | 정책 |
|---|---|---|---|
| CLI | 고정 count aggregate만 | 없음 | 명시적 allowlist field만 표시 |
| API | 없음 | 없음 | 기존 `AnalysisResponse` 유지 |
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
