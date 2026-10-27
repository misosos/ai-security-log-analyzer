# Phase 35.4A1 — pair truncation regression stability

검증 범위는 합성 application·SSH 파일과 Phase 32 pair runtime뿐이다. Vector artifact를 다운로드·해제·설치하지 않았고 **Vector binary를 실행하지 않았다**. 실제 로그나 OS 격리 환경도 사용하지 않았다.

## Initial failure evidence

기준 HEAD는 `cfdc105afcb248ce414f25bde685e57b6c7630f1`이며 `origin/main`은 `c71be0e54107db8bfd37a464f9c97250bb329db2`였다. 기존 커밋은 수정하지 않았다. 직전 전체 pytest 요약은 `2948 passed, 1 failed, 2 warnings`였고 node는 `tests/test_multi_source_phase32_4.py::test_each_role_file_identity_fault_stops_pair_without_quiet_success[truncate-application]`였다. 저장된 요약에 나타난 실패 category는 `DID NOT RAISE MultiSourceRuntimeError`다. 그 실행의 상세 traceback은 저장되지 않았고 `.pytest_cache`에도 재사용 가능한 최초 실패 기록이 없었다. 따라서 최초 실패의 assertion line을 소급해 확정하지 않는다. 단독 재실행은 통과했지만 이를 원인 해소의 증거로 사용하지 않았다.

## Call path and diagnosis

테스트는 `open_internal_pair_runtime()`으로 v3 pair를 열고, 첫 `cycle()` 뒤 application 파일을 truncate하고 SSH 파일에 합성 record를 append한 다음 한 번의 `cycle()`에서 pair 오류를 기대했다. `InternalPairRuntime.cycle()`은 역할 순서를 교대로 바꾸며 `SOFT_CYCLE_BUDGET_SECONDS` (0.1초)를 admission budget으로 쓴다. 이미 한 worker를 처리한 뒤 budget을 넘으면 해당 cycle은 남은 역할을 건너뛰고 정상적으로 반환할 수 있다. 이 경우 SSH step은 처리됐지만 application의 `_probe_identity()`가 아직 호출되지 않아 truncate 오류는 다음 cycle에서 관찰된다.

이 경로는 production의 quiet-success 결함이 아니다. cycle 반환은 pair 전체 검사가 완료됐다는 보증이 아니며, 다음 cycle에서 해당 역할을 검사한다. 테스트가 단일 cycle이 반드시 두 worker를 모두 검사한다고 가정한 동기화 결함이다. 기존 단독 실행의 성공만으로는 이 설명이 입증되지 않으므로, 고정된 clock으로 SSH step 뒤 budget 경계를 재현하는 회귀 테스트를 추가했다. 수정 전 이 결정적 테스트는 `DID NOT RAISE`로 실패했다. 보정 후 bounded cycle helper는 두 번째/최대 세 번째 cycle 안에서 pair 오류를 관찰한다. 실패 시에는 경로·원문 없이 `PAIR_FAULT_NOT_OBSERVED`만 낸다.

## Resource and privacy boundaries

변경은 `tests/test_multi_source_phase32_4.py`의 테스트 synchronization에 한정됐다. Production monitor, checkpoint, analysis, API/SSE/UI, publication, restricted report, guidance, Vector manifest와 fixture는 변경하지 않았다. 테스트는 runtime close를 `finally`에서 실행하고 기존 FD/checkpoint-lock 해제 assertion을 유지한다. 오류와 repr은 고정 pair category만 검사하며 임시 경로, account, IP 또는 raw line은 기록하지 않는다. 기존 fault 테스트는 다른 역할이 이미 확정한 결과를 rollback하지 않고, pair가 degraded된 뒤 이후 수집을 막는 계약을 계속 확인한다.

## Filesystem behavior boundary

검사 코드는 path stat timestamp가 아니라 open source descriptor의 `fstat`으로 device/inode identity와 size를 확인하고, shrink가 acknowledged offset 또는 직전 관찰 size 아래로 내려가면 오류 처리한다. Python `Path.write_text`는 기존 파일을 열어 덮어쓴 뒤 닫는다. Linux `ftruncate(2)` 문서는 파일 크기를 지정 길이로 바꾸고 file offset은 바뀌지 않는다고 명시하며, Apple의 `ftruncate(2)` manual도 같은 호출이 참조한 파일을 지정 길이로 truncate한다고 설명한다. 이 문서만으로 macOS/Linux의 모든 filesystem·timestamp granularity가 동일하다고 일반화하지 않는다. 여기서 검증한 regression은 size-based synchronous probe와 runtime scheduler budget 경계이며, Ubuntu에서의 filesystem/timestamp 검증은 하지 않았다. [Linux truncate(2)](https://man7.org/linux/man-pages/man2/ftruncate.2.html), [Apple ftruncate(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ftruncate.2.html), [Python pathlib.write_text](https://docs.python.org/3/library/pathlib.html#pathlib.Path.write_text).

## Reproduction matrix

macOS 15.7.7 arm64에서 bounded subprocess pytest 실행, 각 subprocess 최대 120초 제한. 무작위 순서 plugin은 설치·사용하지 않았다.

| Matrix | Runs | Failures | Timeouts |
|---|---:|---:|---:|
| 정확한 truncate-application node, 수정 후 | 100 | 0 | 0 |
| 같은 Phase 32.4 테스트 파일 전체 | 30 | 0 | 0 |
| 현재 collection 순서의 immediate previous/target/next 3개 node | 30 | 0 | 0 |
| Phase 32 pair runtime/checkpoint/cleanup 조합 | 20 | 0 | 0 |
| `TZ=UTC`, Phase 32.4 파일 | 1 | 0 | 0 |
| `TZ=Asia/Seoul`, Phase 32.4 파일 | 1 | 0 | 0 |

정확한 node 반복은 `test_each_role_file_identity_fault_stops_pair_without_quiet_success[truncate-application]`을 100회 실행했다. 인접 반복은 deterministic budget-boundary regression node, 실패 target, 다음 truncate-ssh parameter node를 현재 pytest collection 순서대로 묶었다.

UTC·Asia/Seoul 각 focused run은 9 tests passed였다. 전체 suite는 연속 3회 각각 `2953 passed, 2 warnings`로 성공했다. 이번 수정 전에도 요청된 단독 100회, 파일 30회, 인접 30회, pair/checkpoint 조합 20회를 실행해 실패 0건을 관찰했다. 수정 후 동일 matrix 역시 실패와 timeout 없이 통과했다.

## Decision and limitations

결정적 reproduction은 단일 cycle에 pair 전체 검사가 보장되지 않는 경계를 재현했고, 테스트 synchronization 보정 후 회귀 matrix와 전체 suite 3회가 통과했다. 최초 전체 suite의 상세 traceback은 보존되지 않아 과거 실행의 정확한 assertion line은 알 수 없다. 확인된 failure mechanism은 테스트 동기화이며 production 수정은 없다. 판정은 `READY_TO_PUSH`다. Vector artifact preflight 결과는 유지되며 Vector 실행은 계속 `ISOLATION_BLOCKED`; 실제 사용자 자료·조직 운영·원격 수집은 `NO_GO`다.
