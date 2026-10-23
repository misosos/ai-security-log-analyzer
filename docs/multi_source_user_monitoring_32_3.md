# Phase 32.3 — multi-source 사용자 실행·관리·production UI

## 범위와 단계 경계

- **32.1A:** private v3 설정 생성·로드 계약.
- **32.1B:** 역할별 내부 worker/runtime, bounded round-robin, checkpoint와 lock.
- **32.2:** 역할별 공개 snapshot, global publication cursor, API/SSE 계약.
- **32.3:** 두 로그 설정 wizard·관리, production `--monitor` 연결, 역할별 schema 3 UI.
- **32.4 후속 검증:** [독립 수용 기록](multi_source_acceptance_32_4.md)은 합성 CLI·loopback·장애 및 자동 UI 증거를 기록한다. Safari 사용자 수용은 `NOT_TESTED`다.

32.3은 역할별 분석을 기존 source 내부 detection/correlation/risk/case pipeline에 연결한다. cross-source 분석은 없다. v1/v2 설정과 schema 2 UI는 기존 경로를 유지한다. v3는 기본 `--monitor` 및 명시적 `--monitor-config PATH`에서 실행한다. 명시 경로도 닫힌 v3 loader로만 읽으며 v1/v2의 명시적 `FROM_END` 의미는 유지한다. malformed v3는 다른 설정으로 fallback하지 않는다.

## 사용자 흐름

```sh
uv run python -m app.monitor_setup --multi-source
uv run python -m app.local_web --monitor
```

마법사는 로컬 처리·개인정보 안내, 각 역할 경로 입력과 bounded parser dry-run, 두 역할 및 새 줄부터 시작하는 의미 확인, 복구 정책 안내, 저장 승인을 순서대로 진행한다. detector·risk·case·LLM을 실행하지 않는다. 두 파일 identity가 같거나 경로가 symlink/비정상 파일/안전하지 않은 권한이면 거부한다. 설정 저장은 private no-clobber다. 성공 출력은 경로를 다시 표시하지 않는다.

`--show`는 역할별 로그 사용 가능성과 복구 상태, 전체 실행 가능 여부를 쉬운 문구로 표시한다. `--reset-checkpoint --role application|ssh|all`은 선택 범위만 승인 후 초기화하고, role이 없으면 취소 대신 입력 오류로 거부한다. `--delete`는 설정과 연결된 복구 자료만 대상으로 삼으며 승인 전 원본 로그 보존을 설명한다. 설정·checkpoint 경쟁은 lock으로 거부한다. 부분 실패는 전체 성공으로 표현하지 않는다. 어느 삭제도 secure erase를 뜻하지 않는다.

## Runtime·HTTP·UI

Production `--monitor`는 v1/v2를 기존 single-source schema 2 경로로, v3를 pair runtime 및 schema 3 service로 분기한다. 두 역할 lock/runtime 준비를 마친 뒤 listener를 열며 시작 실패는 서버 시작을 막는다. terminal source 상태는 전체 새 수집을 중단한다. shutdown은 pair runner/service와 두 역할 tail/checkpoint, SSE connection, listener를 닫는다. 자동 resume, 자동 checkpoint reset, rotation 복구, 과거 SSE 재게시가 없다.

Schema 3은 기존 `/api/v1/live/status`·`events` 경로의 닫힌 pair DTO다. 전체 상태와 역할별 처리·복구 요약을 함께 표시한다. UI는 기존 작업 폭과 왼쪽 탐색을 유지하고 역할 선택에 따라 해당 역할 결과만 보인다. 수신한 event는 자동 적용하지 않고 역할별 “새 결과 보기”로 staged 반영한다. event ID는 메모리에서 중복 적용을 막고 URL·브라우저 storage에 기록하지 않는다. pause는 화면 반영만 멈춘다. overflow/gap은 stale 안내와 재조회 경계를 제시하며 terminal 상태에서 자동 재연결하지 않는다.

Frontend validator는 status/event DTO를 닫힌 필드 집합과 역할·revision·enum으로 검사한다. 추가 필드/private canary를 거부한다. 두 역할은 같은 public replay cursor를 공유하되 analysis 결과를 합치지 않는다. schema 2 controller 경로도 별도 회귀로 유지한다.

## 검증과 재현

- Targeted regression: `uv run pytest -q tests/test_multi_source_user_flow_32_3.py tests/test_multi_source_runtime_32_1b.py tests/test_multi_source_publication_32_2.py tests/test_live_http.py tests/test_live_checkpoint.py tests/test_checkpoint_epoch_reset.py`
- Production wiring synthetic loopback HTTP/SSE: `PYTHONPATH=. uv run python tests/smoke_multi_source_publication_32_2.py`
- UI staged-role validator: `node tests/multi_source_ui_behavior.cjs`
- Development benchmark: `PYTHONPATH=. uv run python tests/benchmark_multi_source_user_flow_32_3.py --samples 5`
- Bounded append soak: `PYTHONPATH=. uv run python tests/soak_multi_source_32_3.py --cycles 150`

2026-10-23 local macOS developer run, Python 3.12, synthetic files only; benchmark warm-up 3, sample count 5 (restart and close are single lifecycle samples):

| Operation | Median ms | p95 ms | Max ms | Payload bytes |
|---|---:|---:|---:|---:|
| v3 server start | 7.871 | 9.640 | 9.640 | 1,039 |
| two-role status | 0.178 | 0.532 | 0.532 | 1,040 |
| initial SSE snapshot | 0.682 | 0.804 | 0.804 | 1,173 |
| application append to publication | 7.371 | 7.680 | 7.680 | 6,076 |
| SSH append to publication | 5.788 | 7.327 | 7.327 | 12,056 |
| both-role publication | 12.899 | 13.902 | 13.902 | 16,358 |
| mixed replay | 0.003 | 0.004 | 0.004 | 32 events |
| status HTTP | 2.054 | 2.282 | 2.282 | 1,216 |
| checkpoint restart | 6.466 | 6.531 | 6.531 | 1,040 |
| normal close | 0.829 | 0.934 | 0.934 | 0 |
| Chromium schema 3 role switch | 0.200 | 0.300 | 0.300 | 0 |
| Chromium staged DOM apply | 0.300 | 0.300 | 0.300 | 517 |

The Python lifecycle benchmark uses three warm-ups plus five measured synthetic samples per operation. The two UI measurements use five in-browser Chromium samples in the axe pilot; they measure synchronous synthetic role switching and staged DOM application, not Safari or human perception. The benchmark uses generated records and short local samples; it is not an operating SLA or a worst-case latency guarantee. The 150-cycle soak reached 31 replay items / 15,992 bytes, stayed within role queue bounds, showed 1,138,489 bytes traced memory growth (1,159,959 byte peak), and left zero SSE connections/listeners plus closed owned tail FDs and checkpoint locks. This is a bounded development soak, not a long-duration production stability result. The automated 14-state axe pilot reported zero rule violations and zero external requests; this does not establish WCAG 2.2 AA conformance.

## Safari user acceptance

**NOT_TESTED — requires human review.** No user response was available during implementation. The following are not marked PASS: understanding setup and role switching, staged result discovery, whole-state failure, gap recovery, reset meaning, keyboard-only/Option+Tab, real 200% zoom, minimum window width, VoiceOver, and Web Inspector checks for JS/CSP/MIME/external requests/duplicate EventSource/privacy. `npm run test:a11y` axe automation is only an automated check; it does not establish WCAG 2.2 AA conformance.

For acceptance, start a synthetic-only pair and inspect it in macOS Safari. Follow the checklist in `docs/safari_multi_source_acceptance_32_3.md`; do not use operational logs. Record every item as PASS/FAIL/NOT_TESTED and report browser/OS version without copying log content or local paths.

## Not supported

Rotation and copytruncate recovery, replay across a second file generation, remote collection, cross-source correlation/risk/cases, exactly-once or no-loss guarantees, and general user setup-management UI are not provided. Safari acceptance remains pending. Phase 32.3 did not add a new analysis semantic or claim that login success proves compromise.
