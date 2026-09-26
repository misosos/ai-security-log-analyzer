# Linux Audit Session–Process Co-Observation Review

## 1. 목적

이 기능은 Linux Audit의 session lifecycle과 process execution이 제한된 동일 scope와 lifecycle 시간 구간에서 함께 관찰됐다는 조사 맥락을 제공한다. 결과는 bounded co-observation이며 session event가 process를 발생시켰다는 인과관계, 동일 인간의 행위 또는 공격·침해 판정이 아니다.

## 2. 전체 데이터 흐름

CLI에서 `--linux-audit`를 반복해 파일을 지정할 수 있다.

```text
app/main.py:main()
→ --linux-audit 검증과 invocation-local source config 생성
→ app/analyzer/pipeline.py:load_normalized_logs() (1회)
→ app/loader/linux_audit_loader.py:load_linux_audit_events()
→ (source_instance, node, event_id)별 GroupedAuditEvent
→ app/parser/linux_audit.py:parse_linux_audit_events()
→ session_start / session_end / process_execution_attempt
→ aggregate_process_execution_observations()
→ collect_shared_memory_execution_observations()
→ collect_session_process_co_observations()
→ summarize_session_process_co_observations()
→ app/analyzer/report.py:print_analysis_result()
```

`main()`은 normalized logs를 한 번 생성하고 동일 list를 기존 분석, telemetry aggregate 및 두 collector에 전달한다. Shared-memory observation tuple도 전체 review summary와 session-linked summary가 함께 사용한다. Relation과 observation은 `main()` local scope에만 머물며 analysis dict에는 삽입되지 않는다.

## 3. Strict session scope

Session lifecycle과 process의 join key는 정확히 다음 tuple이다.

```text
(source_instance, node, audit_session_id, audit_user_id)
```

- `source_instance`는 한 CLI invocation의 입력 source를 격리한다. Host identity나 cross-run identity가 아니다.
- `node`는 Audit record에 관찰된 scope다. 신뢰된 hostname 증명이 아니다.
- `audit_session_id`는 Linux Audit의 login session ID 관찰값이다.
- `audit_user_id`(`auid`)는 login user ID 관찰값이며 process의 `uid` 또는 `euid`와 의미가 다르다.

모든 값은 유효해야 하며 `source_instance`와 `node`는 non-empty string, 두 numeric ID는 `bool`이 아닌 non-negative integer여야 한다. Session ID만, username, IP, PID/PPID, executable 또는 event ID만으로 join하지 않는다. 동일 scope도 동일 인간, SSH connection 또는 PAM transaction을 보장하지 않는다.

## 4. Lifecycle eligibility

하나의 strict scope에서 성공한 `session_start`가 정확히 하나, 성공한 `session_end`가 정확히 하나 있어야 한다. 두 timestamp는 timezone-aware이고 `start < end`여야 한다. Start/end 누락, duplicate, 같거나 역전된 timestamp, invalid identity 또는 malformed runtime context는 relation을 만들지 않는다. 이는 실제 session이나 process 또는 공격이 없다는 뜻이 아니다.

## 5. Process eligibility

`source == "linux_audit"`인 `process_execution_attempt`와 정확한 `ProcessExecutionContext`가 필요하다. Strict scope가 lifecycle과 같고 다음 inclusive interval 안에 있는 event만 relation에 포함한다.

```text
session_start_timestamp <= process_timestamp <= session_end_timestamp
```

SYSCALL outcome `success`, `failure`, `unknown`을 모두 관찰 대상으로 삼는다. Incomplete `argv`, PATH/CWD/PROCTITLE의 누락·ambiguity 또는 `executable=None`은 core relation을 반드시 막지 않는다. Outcome은 syscall 관찰 결과이며 프로그램 목적이나 공격 성공을 판정하지 않는다.

## 6. Shared-memory matching

Session relation의 process와 `SharedMemoryExecutionObservation`은 다음 bounded key로만 연결한다.

```text
(source_instance, node, process_event_id)
```

여기서 `process_event_id`는 relation의 `process_event_ids` occurrence와 observation의 `event_id`를 뜻한다. Event ID 단독은 global process identity가 아니다. Timestamp 근접성, executable, UID/EUID, PID/PPID, input ordering, `detection_type`만으로 session을 역추정하지 않는다.

Duplicate는 제거하지 않고 양쪽 occurrence의 multiset cardinality 중 작은 값까지만 연결한다. 하나의 observation occurrence를 여러 relation에 배정하지 않는다. 같은 bounded key가 여러 relation에 나타나는 cross-session ambiguity는 임의 귀속하지 않고 internal contract error로 거부한다. Relation 출력은 lifecycle timestamp와 bounded scalar key로 deterministic하게 정렬되지만 ordering은 causation이 아니다.

## 7. CLI count 의미

`SessionProcessReviewSummary`는 다음 non-negative integer count만 보존하고 CLI section도 이 allowlist만 읽는다.

- `session_co_observation_count`: eligible relation 수
- `process_observation_count`: relation에 포함된 process occurrence 수
- `process_outcome_success_count`
- `process_outcome_failure_count`
- `process_outcome_unknown_count`
- `shared_memory_privileged_execution_observation_count`: relation process와 bounded key로 연결된 shared-memory observation occurrence 수
- `sessions_with_shared_memory_privileged_execution_count`: 그런 occurrence가 하나 이상 연결된 relation 수

Outcome 세 count의 합은 `process_observation_count`와 같아야 한다. Duplicate process는 보존되므로 process count를 unique process 수라고 부르지 않는다. `session_co_observation_count == 0`이면 section을 생략하며 안전 또는 활동·공격 부재를 출력하지 않는다.

## 8. 전체 count와 session-linked count

전체 shared-memory review count는 모든 positive observation occurrence를 센다. Session-linked count는 그중 eligible relation의 process occurrence와 strict bounded key로 연결된 것만 센다. 따라서 다음 관계만 보장한다.

```text
session-linked shared-memory count <= overall shared-memory review count
```

Synthetic acceptance fixture에서는 전체 observation이 `2`, session-linked가 `1`이다. Lifecycle 구간 밖이거나 eligible session relation이 없는 observation도 전체 count에는 포함될 수 있지만 session-linked count에는 포함되지 않는다. 이 차이는 오류가 아니며 두 count가 항상 같다고 가정하지 않는다.

## 9. Privacy allowlist

신규 session-process CLI section은 위의 고정 count만 표시한다. `argv`, PROCTITLE, raw records, executable, PATH/CWD, PID/PPID, UID/GID/AUID, `source_instance`, `node`, session/event ID 및 timestamp는 표시하지 않는다. Summary는 상세 object를 보관하거나 generic serialization하지 않는다.

이 count-only 정책은 신규 section에 대한 것이다. 기존 `Telemetry Relations` section은 별도의 기존 lifecycle correlation contract에 따라 계정, Audit session ID와 관찰 시각을 표시할 수 있으므로 두 presentation 경계를 혼동하면 안 된다. Protected detail view와 authorization/RBAC는 현재 제공하지 않는다.

## 10. 외부 consumer 정책

| Boundary | Session-process review | 정책 |
|---|---|---|
| CLI | fixed summary count만 | 명시적 scalar allowlist |
| API | 없음 | 기존 `AnalysisResponse` 유지 |
| LLM | 없음 | deterministic serialization input에서 제외 |
| Frontend | 없음 | API contract 변화 없음 |
| Risk | 사용하지 않음 | 기존 IP risk factor 불변 |
| 기존 IP analysis | 없음 | `results`와 `global_correlation` contract 불변 |

Public `analyze(log_sources=None)`는 계속 `results`와 `global_correlation`만 반환한다. API는 `analyze()` 경로를 사용하며 CLI-only collector와 summary를 호출하지 않는다.

## 11. Failure contract

- Linux Audit path validation, open 또는 decode 입력 오류: exit code `2`
- Shared-memory/session collector·summary 또는 report validation의 internal contract 오류: exit code `1`

두 경계 모두 bounded stderr를 사용한다. 전체 path, raw evidence, underlying exception text 또는 traceback을 출력하지 않는다. Internal error를 zero count로 바꾸지 않으며 report 전에 모든 summary를 계산·검증하므로 partial report를 출력하지 않는다.

## 12. 의미 제한

- `co-observation != causation`
- `session scope != 동일 인간`
- `session scope != 동일 SSH connection 또는 PAM transaction`
- `process count != unique process count`
- `success != program goal achieved`
- `success != attack success`
- `shared-memory observation != malware`
- `count != attack, incident 또는 compromise count`
- `event ID != global process identity`
- `ordering != causation`
- `section absence != activity or attack absence`

## 13. 운영자 해석 예시

허용되는 표현:

> 동일한 bounded Linux Audit session scope의 lifecycle 구간 안에서 프로세스 실행 관찰 3개가 함께 기록되었고, 그중 1개가 shared-memory review 조건과 일치했다.

금지되는 표현:

- “해당 사용자가 악성 파일을 직접 실행했다.”
- “공격이 성공했다.”
- “시스템이 침해되었다.”
- “고유 프로세스 3개가 실행되었다.”

## 14. 검증과 알려진 한계

주요 contract는 다음 테스트로 검증한다.

- Fixture와 parser: `tests/test_linux_audit_session_process_co_observation_fixtures.py`
- Pure collector: `tests/test_session_process_co_observation.py`
- Immutable summary: `tests/test_session_process_review_summary.py`
- Session-linked fixture: `tests/test_session_shared_memory_review_fixture.py`
- CLI/report/failure/privacy: `tests/test_session_process_cli.py`, `tests/test_report.py`, `tests/test_linux_audit_cli_input.py`
- API/LLM isolation 및 전체 regression: 기존 API·LLM test와 `uv run pytest -q`

현재 stable process identity가 없고 PID 및 session ID는 재사용될 수 있다. Raw evidence는 누락될 수 있으며 cross-run deduplication, 운영 false-positive rate 측정, protected detail view, real-time ingestion, API Linux Audit upload가 없다. Loader/grouping과 normalized logs list 때문에 큰 파일은 memory 사용량을 늘릴 수 있다.

## 15. 공식 근거

접근일: 2026-09-26

- Red Hat, *RHEL 8 Security hardening — Auditing the system*, 특히 “Linux Audit”, “Understanding Audit log files”.
  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening
  Compound event의 timestamp/serial 공유, SYSCALL 결과와 Audit telemetry 역할의 근거다. 동일 인간, session-to-process causation 또는 공격 판정을 보장하지 않는다.
- Linux Audit Project, *Linux Audit field dictionary* (`auid`, `ses`, `uid`, `euid`, `pid`, `ppid`, `success`).
  https://raw.githubusercontent.com/linux-audit/audit-documentation/main/specs/fields/field-dictionary.csv
  Field 분류의 근거이며 장기 identity 또는 ID 전역 유일성을 보장하지 않는다.
- Linux-PAM / Linux man-pages, `pam_loginuid(8)`.
  https://man7.org/linux/man-pages/man8/pam_loginuid.8.html
  Login UID 초기화 의미의 참고 근거이며 동일 인간 또는 PAM transaction의 연속성을 증명하지 않는다.
- Linux kernel, `kernel/auditsc.c`.
  https://github.com/torvalds/linux/blob/master/kernel/auditsc.c
  Kernel Audit syscall/EXECVE emission 구현을 확인하는 primary source이며 이 repository의 correlation semantics를 정의하지 않는다.
- MITRE ATT&CK, *Process Creation (DC0032)*.
  https://attack.mitre.org/datacomponents/DC0032/
  Process telemetry의 조사 가치를 설명하는 참고자료로만 사용한다. 현재 co-observation의 공격 판정이나 ATT&CK mapping 근거로 사용하지 않는다.
- OWASP, *Logging Cheat Sheet*.
  https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
  민감한 log data의 보호와 외부 projection 최소화에 반영했다. 특정 Audit relation의 진실성이나 인과관계를 보장하는 자료는 아니다.
