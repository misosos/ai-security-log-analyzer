# Phase 32.1B — bounded internal multi-source runtime

**Phase 32.1B 당시 상태:** application 1개와 SSH 1개를 내부 Python 호출에서 함께 처리했다. [Phase 32.1A](multi_source_private_config_32_1.md)의 private v3 설정을 읽었고 `app.local_web --monitor`는 거부했다. [Phase 32.2](multi_source_publication_32_2.md)에서 별도 internal/test-only launcher를 통해 publication·API·SSE를 검증했다. Production UI와 setup/show/reset/delete 관리 흐름은 32.1B에 포함되지 않았다.

**후속 상태:** [Phase 32.3](multi_source_user_monitoring_32_3.md)에서 v3 setup·관리 UX, 일반 `--monitor`, schema 3 production UI를 구현했다. macOS Safari와 실제 보조기술 사용자 수용은 아직 `NOT_TESTED`다. 아래 32.1B 경계와 기록은 그 단계의 역사적 구현·검증 내용을 보존한다.

Phase 32.1B 단독 범위에는 API·SSE·UI 연결이 없었다. 이후 32.2에서 내부 launcher의 API·SSE만 추가했다.

## 닫힌 실행 계약

`open_internal_pair_runtime(config_path)`는 v3의 application→SSH 순서로 기존 `LiveCheckpointManager` lock을 획득한 뒤 각 source의 tail, bounded queue, detector, analysis accumulator, publication buffer 및 checkpoint를 독립적으로 만든다. 같은 file identity는 두 역할에 등록할 수 없다. v3 checkpoint는 역할별 고정 이름·source ID 및 `config_schema_version=3`으로 결속한다. 기존 v2 checkpoint 이름·`config_schema_version=2`와 복구 의미는 유지한다. Source별 256 event·256 KiB prefix와 checkpoint 8,192 byte 상한을 유지하며 다른 역할의 prefix를 재사용하지 않는다. 재시작 때 detection·analysis 상태를 각 source의 같은 파일 prefix에서 복구하고 과거 publication event를 다시 보내지 않는다.

`cycle()`은 한 caller가 각 역할의 기존 `worker.step()`을 최대 한 번 호출한다. 시작 역할은 cycle마다 교대한다. 각 step은 최대 16 records·4,096 byte이고 두 역할 합계의 admission 상한은 32 records·8,192 byte다. **100 ms soft admission**을 넘으면 다음 step은 다음 cycle로 미룬다. 이미 시작한 동기 step은 중단할 수 없으므로 이는 hard wall-clock 상한이나 0.5초 운영 SLA가 아니다. `run()`은 단일 asyncio loop에서 cycle 뒤 0.5초를 기다려 idle busy loop를 만들지 않는다. Thread, subprocess, IPC, event-time 재정렬은 추가하지 않았다.

한 역할의 ack 전 prepare 실패는 기존 worker가 proposal을 abort하고 lease를 release한 뒤 DEGRADED로 전환한다. Ack 후 commit·publication·checkpoint 실패는 FAILED로 중단한다. 상위 scheduler는 어느 한 역할이 DEGRADED/FAILED가 되면 두 역할의 새 step을 모두 막는다. 앞서 다른 역할에서 확정된 결과를 rollback하거나 자동 재처리하지 않는다. 이 경계는 두 역할 간 원자적 transaction, exactly-once 또는 무유실을 제공하지 않는다. 시작 중 두 번째 역할이 실패하면 이번 시작에서 만든 첫 번째 역할의 revision 0 checkpoint를 lock 아래 재검증하고 제거한다. 재검증 실패 시 추측 삭제하지 않고 수동 검토가 필요한 잔여물로 남긴다. Close는 SSH→application 역순으로 두 worker 모두 시도하고, 한쪽 실패 시에도 각 FD·checkpoint lock·tail·proposal 소유 객체를 독립적으로 닫으려 한다. 오류는 고정 코드만 사용하며 내부 예외·경로·계정·IP·hostname·원문을 노출하지 않는다. Lock 파일 자체는 기존 checkpoint 정책대로 private 디렉터리에 남을 수 있으나 FD lock은 해제한다.

### 독립 감사에서 발견한 시작 실패 정리 결함과 수정

미게시 로컬 32.1B 커밋 `24660a9`의 독립 감사에서, 두 checkpoint lock 획득 뒤 tail 생성이 실패하고 SSH manager `close()`도 실패하면 application manager 정리를 시도하지 않는 결함을 발견했다. 내부 `RuntimeError` 원문도 외부로 전파됐다. 수정 전 production `open_internal_pair_runtime()`을 직접 호출하는 합성 회귀 두 개가 각각 application close 미호출과 원문 canary 노출로 실패함을 확인했다.

시작 실패 정리는 새 checkpoint의 안전한 revision-0 제거를 먼저 시도한 다음, 생성된 worker→tail→checkpoint manager를 역순으로 방문한다. 각 대상의 close를 독립적으로 시도한다. Worker close가 중간에 실패하면 소유한 analysis·checkpoint·tail·publication·detection의 close도 각각 시도한다. Manager close가 중단되면 남은 lock·parent FD를 각각 닫고, tail close가 중단되면 FD와 queue·lease 임시 상태의 정리를 시도한다. 어느 한 실패도 뒤따르는 source 정리를 생략하지 않는다. 이미 ack·commit된 다른 source의 결과는 되돌리거나 재처리하지 않는다. 최초 시작 실패와 cleanup 실패를 성공으로 보고하지 않으며, 외부에는 `PAIR_START_FAILED` 같은 고정 code와 일반화된 문구만 반환한다. 내부 예외 메시지는 오류 문자열·repr·일반 로그에 전달하지 않는다. OS가 FD close 자체를 계속 거부하는 경우 해제 성공을 주장하지 않는다.

합성 fault matrix는 SSH manager만, application manager만, 양쪽 manager, tail과 manager 동시, lock FD close 일회 실패, SSH worker 초기화 실패, 일반 close 실패 뒤 재호출을 확인했다. 생성된 대상의 close 시도와 직접 소유한 FD·lock 종료, 빈 queue와 active lease/proposal 부재, lock 재획득, 경로·계정·IP·hostname·raw line·내부 예외 canary 비노출을 확인했다. 아직 생성되지 않은 worker나 tail의 close는 호출하지 않는다. 같은 객체를 다시 닫아도 다른 역할의 자원은 손상되지 않았다. 공개 status·API·SSE·OpenAPI 계약은 변경하지 않았다.

## 합성 검증

수정 전 내부 runtime import 테스트는 모듈 부재로 실패했다. 이후 합성 application·SSH 파일을 사용하는 in-process 테스트에서 idle, 각 역할 입력, 양쪽 입력, 양방향 burst, 순서 교대, 같은 file identity 거부, 두 번째 lock 경쟁, 손상 checkpoint, restart 복구, 과거 publication 미재전송, ack 전/후 fault, 전체 중단, close fault를 검사했다. 기존 단일-source worker와 detection·analysis 및 session 고유 ID를 제외한 publication 의미를 비교했다. 실제 raw state는 역할별 객체에만 남으며 하나의 공개 replay buffer로 합치지 않는다. UTC와 Asia/Seoul 결과 결정성은 동일 합성 테스트를 각 시간대에서 별도로 확인한다. v3의 기존 `--monitor` 거부와 v1/v2 회귀도 유지한다.

개발용 macOS 합성 측정은 case별 5회, checkpoint commit 170회다. `p95`는 관측 표본의 95번째 백분위에 해당하는 nearest-rank 값이다.

| 측정 | n | median ms | p95 ms | max ms |
|---|---:|---:|---:|---:|
| 두 source idle cycle | 5 | 1.247 | 3.981 | 3.981 |
| application 256-event prefix 전체 처리 | 5 | 116.923 | 125.133 | 125.133 |
| SSH 256-event prefix 전체 처리 | 5 | 117.363 | 121.863 | 121.863 |
| 양쪽 16-record backlog cycle | 5 | 10.993 | 11.637 | 11.637 |
| 역할별 checkpoint commit | 170 | 1.963 | 2.651 | 4.767 |
| 두 worker close | 20 | 0.383 | 0.442 | 0.460 |

측정 전후 열린 FD 수 차이는 0이었다. 테스트는 active lease/proposal과 queue의 bounded 상태, lock 경쟁 후 재획득, 폐기된 임시 source 디렉터리를 확인한다. 이 값은 합성 파일·개발 머신의 관측치이며 실제 운영 부하, OS scheduling, status/SSE latency 또는 서비스 SLA를 뜻하지 않는다. Ubuntu 별도 프로세스와 실제 사용자 검증은 수행하지 않았다.

### 재실행 가능한 합성 benchmark

위 표는 원래 구현 시점의 기록이다. 독립 감사에서 재현 스크립트가 없다는 근거 부족을 발견해 `tests/benchmark_multi_source_cleanup_32_1b.py`를 추가했다. 저장소 루트에서 `env PYTHONPATH=. uv run python tests/benchmark_multi_source_cleanup_32_1b.py`로 실행한다. 기본값은 case별 warm-up 2회와 측정 20회이며 `--warmup`, `--samples`로 바꿀 수 있다. p95는 정렬 표본의 nearest-rank 값이다. 각 표본은 private 임시 합성 application·SSH 파일을 새로 만들고, 종료 뒤 runtime 소유 FD·lock·queue·lease·proposal 정리를 확인한다. 출력은 고정 case 이름과 수치만 포함한다. CI 필수 성능 gate로 사용하지 않는다.

| 재측정 항목 | n | median ms | p95 ms | max ms |
|---|---:|---:|---:|---:|
| 두 source idle cycle | 20 | 1.188 | 1.338 | 1.734 |
| application 256-event prefix | 20 | 99.428 | 104.800 | 107.333 |
| SSH 256-event prefix | 20 | 105.283 | 117.240 | 126.303 |
| 양쪽 16-record backlog cycle | 20 | 11.676 | 13.201 | 13.460 |
| application checkpoint commit | 20 | 1.749 | 2.104 | 2.123 |
| SSH checkpoint commit | 20 | 1.855 | 2.257 | 2.281 |
| 정상 close | 20 | 0.273 | 0.292 | 0.298 |
| 합성 close fault cleanup | 20 | 0.305 | 0.457 | 0.474 |

서로 다른 실행·표본·계측 방법의 수치는 직접 비교할 수 없다. 합성 파일·개발 머신의 관측치이며 운영 SLA, 최악 지연, 모든 OS의 FD 동작이나 실제 사용자 검증을 뜻하지 않는다.

## 후속 Phase 32.2와 남은 NO-GO

Phase 32.2에서 안전한 공개 publication·API·SSE를 별도 내부/test-only launcher에 구현했다. Production UI, v3 `--monitor` 사용자 실행, v3 setup/show/reset/delete, cross-source correlation·risk·case, 자동 rotation/copytruncate, 두 파일 세대 replay, source 무제한 추가, silent eviction, crash 뒤 exactly-once·무유실은 구현하지 않았다. 한 역할의 실패를 다른 역할의 정상 상태로 숨기지 않는다. PentAGI 등 외부 실행 도구도 연결하지 않았다.
