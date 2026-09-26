# Shared-memory Privileged Execution Review

## 1. 목적

이 기능은 Linux Audit process execution 관찰 중 shared-memory 경로 아래의
privileged execution을 운영자가 추가로 검토할 수 있도록 고정 count로
표시한다. 이는 관찰 가능한 조건에 한정된 review signal이며 확정 공격
탐지, 침해 판정 또는 risk 평가가 아니다.

## 2. 사용 방법

기본 실행:

```bash
uv run python -m app.main
```

단일 Linux Audit 파일:

```bash
uv run python -m app.main --linux-audit /path/to/audit.log
```

복수 파일:

```bash
uv run python -m app.main \
  --linux-audit /path/to/audit-a.log \
  --linux-audit /path/to/audit-b.log
```

`--linux-audit`는 반복할 수 있다. 각 입력에는 입력 순서에 따른
invocation-local `source_instance`가 부여되지만, 이는 host identity,
`node` 또는 신뢰된 hostname이 아니다. 동일 underlying file의 중복 입력은
거부한다. 이 option은 CLI 파일 입력이며 API upload 기능이 아니다.

## 3. 입력 경계

기존 regular file과 regular file을 가리키는 symlink를 허용한다.
Nonexistent path, directory, empty file, broken symlink, FIFO·socket·device
같은 special file 및 동일 underlying file의 중복 입력은 거부한다.
Symlink 입력 문자열은 source config에 그대로 유지하며 canonical path로
교체하지 않는다.

Malformed individual line은 기존 loader/parser 정책에 따라 건너뛰고
해석 가능한 group은 계속 처리한다. Non-empty 파일의 모든 line이
malformed라면 normalized result가 비어 있을 수 있으며, 이는 안전 또는
공격 부재를 뜻하지 않는다. 임의 size limit은 없고 loader가 파일의 line을
수집한 뒤 grouping하므로 큰 파일은 memory 사용량을 늘릴 수 있다.
Metadata validation과 실제 open 사이의 TOCTOU를 완전히 해결하지 않는다.

## 4. 탐지 조건

`app/detector/shared_memory_execution.py`의
`detect_shared_memory_privileged_execution()`은 다음 조건을 모두 만족할
때만 positive observation을 만든다.

- `event_type == "process_execution_attempt"`
- `source == "linux_audit"`
- `process_execution` context 존재
- `outcome == "success"`
- `effective_user_id`가 `bool`이 아닌 exact integer `0`
- `executable`이 non-empty string이며 `/dev/shm/` 또는 `/run/shm/` 뒤에
  실제 문자가 있는 lexical child path

따라서 `/dev/shm/item`과 `/run/shm/item`은 path 조건을 만족하지만
`/dev/shm`, `/dev/shm/`, `/dev/shm-backup/item`, `/run/shm_backup/item`은
만족하지 않는다. Filesystem lookup, mount·permission 확인, binary inspection,
path canonicalization 또는 dot-segment normalization을 수행하지 않는다.

## 5. 처리 흐름

```text
app/main.py:main()
→ --linux-audit validation과 source config 생성
→ app/loader/linux_audit_loader.py:load_linux_audit_events()
→ app/parser/linux_audit.py:parse_linux_audit_events()
→ NormalizedEvent(event_type="process_execution_attempt")
→ app/analyzer/process_execution.py:aggregate_process_execution_observations()
→ app/detector/shared_memory_execution.py:detect_shared_memory_privileged_execution()
→ collect_shared_memory_execution_observations()
→ summarize_shared_memory_execution_observations()
→ app/analyzer/report.py:print_analysis_result()
```

`main()`은 source를 한 번 load하고 동일 normalized logs로 기존 IP 분석,
telemetry aggregate와 collector를 실행한다. Public `analyze(log_sources=None)`는
기존 분석만 반환하며 CLI argument parser, collector 또는 review summary를
사용하지 않는다. 따라서 API 경로와 review 경로는 분리된다.

## 6. 내부 Observation

Pure detector는 bounded `DetectionResult`를 만들고 collector는 exact evidence
contract를 확인한 뒤 detector-local frozen
`SharedMemoryExecutionObservation`으로 scalar만 projection한다. Mutable
`DetectionResult`, `Evidence`, process context 또는 raw evidence는 observation에
보관하지 않는다.

Collector는 입력 순서와 duplicate를 그대로 보존한다. 이 순서는 physical
arrival 또는 causation이 아니며 event scope도 process identity나 host identity가
아니다. Observation tuple은 `main()`의 local scope에만 머물고 frozen
`SharedMemoryExecutionReviewSummary`에는 count 하나만 존재한다.

## 7. CLI 출력

CLI는 기존 process telemetry count와 다음 review count 및 의미 제한 안내만
표시할 수 있다.

```text
shared-memory privileged execution 검토 관찰 수: 2
```

Executable, effective UID, timestamp, `node`, `source_instance`, `event_id`,
`argv`, PATH/CWD, PROCTITLE, raw records 및 개별 observation은 출력하지 않는다.
Count가 0이면 review line과 전용 안내를 생략하며, 이는 공격 부재 또는
안전을 뜻하지 않는다.

## 8. 의미 제한

- `Observation count != unique process count`
- `Review count != confirmed attack count`
- `Review count != incident count`
- `Shared-memory path != malware`
- `Effective UID 0 != compromise`
- `Syscall success != attack success`
- `Syscall success != program goal achieved`
- `Event scope != process identity`
- `Event scope != host identity`
- `Ordering != causation`
- `Count zero != absence of attack`
- `Absence of review observation != absence of malicious activity`

## 9. 오탐 가능성

Container runtime, IPC framework, legitimate administration, test/build tooling
및 environment-specific software도 shared-memory 경로에서 실행될 수 있다.
현재 environment allowlist는 없으며 운영 false-positive rate를 측정하지
않았다. Elastic 공식 규칙도 container·orchestration·service의 정상 동작과
환경별 tuning 필요성을 false-positive 분석에서 다룬다. 이러한 공식 규칙은
조사 동기와 오탐 검토 자료이지 현재 관찰을 악성으로 확정하는 근거가 아니다.

## 10. Privacy와 외부 경계

| Boundary | Review count | Detailed observation | Policy |
|---|---|---|---|
| CLI | fixed count only | none | explicit scalar allowlist만 표시 |
| API | none | none | 기존 response contract 유지 |
| LLM | none | none | per-IP 및 overall input에서 제외 |
| Frontend | none | none | API에 없는 정보를 소비하지 않음 |
| Risk | 사용하지 않음 | none | IP risk factor에 반영하지 않음 |
| Correlation | 사용하지 않음 | none | process/session 관계를 만들지 않음 |

Detailed observation과 sensitive process evidence는 internal only다. Generic
serialization이나 heuristic redaction에 의존해 외부로 내보내지 않는다.

전체 shared-memory review count와 eligible session relation에 연결된 count의
차이는 [Linux Audit Session–Process Co-Observation Review](linux_audit_session_process_review.md)에
별도로 설명한다.

## 11. Failure behavior

CLI input validation 오류는 exit code `2`로 종료한다. Detector/collector 또는
summary의 internal contract 오류는 exit code `1`로 종료하며 zero count로
숨기지 않는다. 오류 문구는 bounded fixed text만 사용하고 path, raw evidence,
underlying exception text 또는 traceback을 출력하지 않는다.

## 12. 검증

- CLI input 및 file boundary: `tests/test_linux_audit_cli_input.py`
- CLI orchestration과 single-load: `tests/test_process_execution_cli.py`
- Fixture contract: `tests/test_linux_audit_shared_memory_execution_fixtures.py`
- Pure detector: `tests/test_shared_memory_execution_detector.py`
- Immutable collector와 summary: `tests/test_shared_memory_execution_observation_collector.py`
- Report allowlist와 의미 제한: `tests/test_report.py`
- EXECVE/parser/builder: `tests/test_linux_audit_execve_arguments.py`,
  `tests/test_linux_audit_process_execution_parser.py`,
  `tests/test_linux_audit_process_execution_builder.py`
- API/LLM isolation: 기존 API 및 deterministic LLM test
- Full regression: `uv run pytest -q`

## 13. 알려진 한계

- Lexical path observation만 수행하며 dot-segment canonicalization이 없다.
- Mount type, permission, binary content 또는 실제 filesystem 상태를 검증하지 않는다.
- 운영 false-positive rate와 environment allowlist가 없다.
- Protected detailed evidence view와 API upload가 없다.
- Session/process correlation과 process risk 반영이 없다.
- ATT&CK mapping과 stable process identity가 없다.
- `source_instance`는 cross-run source identity가 아니다.
- 큰 파일은 memory 사용량을 늘릴 수 있다.

## 14. 공식 참고자료

접근일: 2026-09-26

- Red Hat, *RHEL 8 Security hardening — Auditing the system*.
  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening
- Linux Audit Project, *Linux Audit field dictionary*.
  https://raw.githubusercontent.com/linux-audit/audit-documentation/main/specs/fields/field-dictionary.csv
- Linux kernel, `kernel/auditsc.c`.
  https://github.com/torvalds/linux/blob/master/kernel/auditsc.c
- SigmaHQ, *Process Execution From Shared Memory Directory*.
  https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_susp_exec_from_dev_shm.yml
- Elastic Security, *Binary Executed from Shared Memory Directory*.
  https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_process_started_in_shared_memory_directory.toml
- Splunk Security Content, *Linux Binary Executed from Shared Memory Directory*.
  https://github.com/splunk/security_content/blob/develop/detections/endpoint/linux_binary_executed_from_shared_memory_directory.yml
- OWASP, *Logging Cheat Sheet*.
  https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

SigmaHQ, Elastic 및 Splunk 규칙은 shared-memory execution을 조사할 동기와
운영 오탐 검토에 사용한 공식 rule source다. 이들은 이 repository의
observation을 confirmed attack, malware 또는 compromise로 확정하는 근거가
아니다. Red Hat, Linux Audit field dictionary 및 kernel source는 Audit
record와 field 의미를 확인하는 근거이며 repository 고유 contract를 대신하지
않는다. OWASP 자료는 sensitive logging data를 최소화하는 privacy 경계에
반영했다.
