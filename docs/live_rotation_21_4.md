# Phase 21.4 — poll 이후 ack 이전 source 재검증

상태: 기존 단일-source live worker의 **관찰 가능한 파일 교체·축소** 경계를 좁혔다. Rotation/truncation 자동 복구나 새 파일 handoff는 구현하지 않았다. 분석 규칙, checkpoint 형식, API·SSE·UI schema도 바꾸지 않았다.

## 수정 전 실패와 사용자 영향

Tail의 `poll_once()`는 읽기 전후에 경로 identity와 관찰된 크기를 확인했다. 그러나 poll이 끝난 직후부터 queue ack 전까지 parser·detection·analysis·publication proposal 계산이 이어진다. 이 사이 파일이 교체 또는 축소되면 checkpoint 사용 시 **detection·analysis·publication 확정 뒤** checkpoint write에서 `CHECKPOINT_FAILED_AFTER_PUBLICATION`으로 중단할 수 있었다. Checkpoint가 없는 기존 live worker는 해당 step을 정상 ack·게시한 뒤 다음 poll에서만 교체를 알 수 있었다. 즉 관찰 가능했던 불연속을 ack 전에 막지 못했다.

수정 전 실제 합성 regular file 테스트 3건은 위 동작으로 실패했다. 현재 worker는 모든 proposal과 안전한 step result를 준비한 다음, **queue ack 바로 앞**에서 기존 tail의 경로·FD identity/size probe를 다시 수행한다. 새 검사에 실패하면 고정 `SOURCE_CHANGED_BEFORE_ACK`로 proposal을 abort하고 lease를 FIFO release하며 worker는 `DEGRADED`가 된다. 이 단계의 ack 수, detection·analysis revision, publication event 수, durable checkpoint는 전진하지 않는다. 기존 runner는 자동 resume하지 않는다. 명시적 resume을 시도하더라도 source가 여전히 바뀌어 있으면 다음 poll에서 terminal 실패한다. 오류·safe snapshot에는 원래 경로, inode, offset, 로그 줄, 계정, IP 또는 내부 예외가 없다.

| 주입 위치·source | ack | proposal·lease | worker | 기존 확정 상태 |
|---|---|---|---|---|
| poll 직후 rename 교체, private checkpoint 사용 | 없음 | 전부 abort, FIFO release | `DEGRADED` | 변경 없음 |
| poll 직후 관찰 가능 축소, private checkpoint 사용 | 없음 | 전부 abort, FIFO release | `DEGRADED` | 변경 없음 |
| publication batch prepare 직후 rename 교체 | 없음 | 두 event batch 모두 abort, FIFO release | `DEGRADED` | 변경 없음 |
| poll 직후 rename 교체, checkpoint 미사용 | 없음 | 전부 abort, FIFO release | `DEGRADED` | 변경 없음 |

이는 **마지막 검사 시점**의 보장이다. 검사 직후부터 실제 ack 사이의 TOCTOU race에서 다시 교체될 수 있으며, ack 이후 checkpoint 검사에서 발견되면 이미 확정된 queue·분석·게시를 rollback하지 않는다. 동일 inode의 truncate·빠른 재성장 또는 제자리 같은 크기 변경은 stat만으로 반드시 검출할 수 없다. 따라서 무유실, exactly-once, 모든 rotation 감지, 안전한 자동 복구를 주장하지 않는다. 오랜 이전 세대의 미완료 줄을 새 세대에 이어 붙이거나 여러 세대를 추측해 병합하지 않는다.

macOS 합성 파일에서 source 교체·축소와 checkpoint 사용/미사용 경계를 검증했다. Linux 실제 logrotate, 빠른 copytruncate 재성장, 프로세스 강제 종료와 전원 손실, Safari 수동 화면은 이 단계에서 검증하지 않았다. 다음 Phase는 자동 handoff 전에 파일 세대 identity, old-writer drain, partial-line 처리, bounded replay와 crash window를 독립적으로 설계·검증해야 한다.

개발용 기존 checkpoint benchmark를 `PYTHONPATH=. uv run python tests/benchmark_live_checkpoint_21.py`로 실행했다(Darwin/Python 3.12.7, 합성 application 로그, warm-up 1회·표본 3개). 16-event 입력의 worker step median/p95/max는 4.371/4.833/4.833ms, 256-event prefix에서 **최대 16개 record씩 처리한 각 step**의 median/p95/max는 5.318/5.553/5.553ms였다. 256-event replay 전체는 `tracemalloc`을 켠 조건에서 180.433/182.771/182.771ms였다. 이전 Phase 21.2의 다른 계측 조건과 직접 비교하지 않고, 256개를 한 step으로 처리한 수치나 운영 SLA로 해석하지 않는다.
