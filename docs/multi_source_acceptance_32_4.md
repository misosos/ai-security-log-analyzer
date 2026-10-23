# Phase 32.4 — multi-source 독립 수용·장애·사용성 검증

**범위:** 32.3의 application+SSH 설정·관리·pair runtime·schema 3 UI를 합성 자료로 검증한다. 이 단계는 기능 확장이 아니라 수용·장애·운영 경계 확인이다. **macOS/Safari 사용자 조작과 보조기술 수용은 사용자 응답 전까지 NOT_TESTED**다.

단계 구분: 32.1A private v3 설정, 32.1B 내부 runtime·scheduler·checkpoint, 32.2 안전한 publication·API·SSE, 32.3 사용자 설정·관리와 production UI, 32.4 독립 수용·장애·사용성 검증. 32.4는 33.0의 로컬 오픈소스 AI/RAG 아키텍처·위협 모델 설계와 별도다.

## 증거 상태

| 범위 | 상태 | 증거와 한계 |
|---|---|---|
| 시작 gate·원격 Ubuntu CI | PASS | `8ad1d133ea41df73821c490a98ad19cd5ebc18b5`, Actions run `39902991518` completed/success; 전체 pytest 2,519, locked install, Node·axe, artifact 0. 원격 개별 단계는 아래 Linux 항목별 구분을 따른다. |
| CI Linux: 설정 관리·pair runtime·checkpoint·schema 3·SSE·replay·terminal·v1/v2 | PASS | CI named steps와 전체 pytest가 통과. 개별 계약은 해당 32.1A/B·32.2·32.3 테스트의 직접 근거가 있는 범위만 PASS다. |
| CI Linux: 별도 프로세스 v3 HTTP/SSE·정상 SIGINT 후 listener/FD/lock | NOT_TESTED | CI 로그에서 전용 32.2 HTTP/SSE smoke 스크립트 및 32.4 CLI process smoke 실행을 확인하지 못했다. |
| CI Linux: Node·axe 및 artifact | PASS | 14 UI states, external requests 0, 저장 artifact 0. axe는 자동 검사이며 WCAG 2.2 AA 적합성 증거가 아니다. |
| macOS 실제 CLI, 합성 로그·임시 HOME | PASS | 자동 in-process/프로세스 harness에서 wizard/show/monitor/role reset/all reset/delete, 기존 줄 건너뜀, append 수집, 실행 중 reset/delete 거부, 로그 보존 확인. 이는 사용자 이해도나 직접 조작 검수가 아니다. |
| CLI 안내 문구 사용자 출력 이해도 | NOT_TESTED | 합성 CLI 출력은 자동 assertion으로만 점검했다. 사용자가 문구를 읽고 이해했는지 답하지 않았다. |
| macOS loopback HTTP/SSE smoke | PASS | 별도 synthetic application·SSH 자료로 health/status/SSE 경로 확인. |
| Safari 18.6 loopback 준비 | PASS | 서버가 `http://127.0.0.1:55863/`에서 합성 초기 상태로 준비됨. |
| Safari 사용자 흐름·문구 이해도 | NOT_TESTED | 사용자가 직접 확인/응답하지 않았다. 서버 준비는 사용자 수용 PASS가 아니다. |
| 사용자 직접 CLI 조작 | NOT_TESTED | 명령 흐름은 harness가 실행했다. 사용자의 실제 조작으로 확대 해석하지 않는다. |
| Safari 키보드·Option+Tab·200%·320 CSS px·VoiceOver | NOT_TESTED | WebDriver/axe 결과는 실제 Safari 수동 보조기술 검수를 대체하지 않는다. 정확한 320 CSS px 측정도 하지 않았다. |
| Web Inspector 사용자 검사 | NOT_TESTED | 아래 자동 canary·axe 검사와 분리한다. |
| Chromium/Playwright schema 3 DOM 동작·axe | PASS | schema 3 역할 전환 및 DOM 적용 측정 표본 5; 14 상태 axe, 외부 요청 0. WebDriver는 Safari 증거가 아니다. |

## 장애·복구 경계

실제 CLI harness와 focused fault tests는 application/SSH별 truncation·file replacement·손상 checkpoint를 독립적으로 유도했다. 해당 역할의 복구 경로는 자동 초기화하지 않고 pair 처리를 중단하며, 다른 역할의 추가 수집이 계속되지 않는지 검사했다. lock release와 owned tail FD 정리를 확인했다. pending 32건 및 16 KiB 상한, runner/UI terminal handling도 테스트했다. 이들은 정상적인 고정 오류 경계의 합성 자동 검사이며 OS crash 복구 증거는 아니다.

Phase 32.3 UI 회귀에서 `service_status` terminal event 뒤 전체 상태가 계속 정상처럼 보이는 production 결함을 재현했다. 수정 전 `tests/multi_source_ui_behavior.cjs`에서 전체 상태가 주의 필요로 바뀌고 연결이 닫히는지 검사해 실패를 확인했다. 최소 수정은 역할별 상태를 보존하면서 전체 중단 안내를 표시하고 EventSource를 닫도록 했다. 알 수 없는 예외 원문은 표시에 포함하지 않는다. 같은 테스트는 수정 후 통과했다.

Truncation, replacement, corrupt checkpoint, replay gap, pending overflow, notify fault, normal SIGINT는 automated regression/smoke에서 다룬다. macOS에서 synthetic v3 subprocess에 SIGTERM을 보내는 시도는 정상 종료 code를 얻지 못해 graceful SIGTERM 경로는 **NOT_TESTED**로 둔다. Linux SIGTERM 및 CI 별도 프로세스 정리 근거도 **NOT_TESTED**다. SIGKILL·전원 차단 후 복구를 주장하지 않는다. 사용자-facing 오류는 고정 code/일반 문구이며 trusted internal state에는 입력 원문이 있을 수 있다.

## 제한 soak와 성능 표본

재현 명령:

```sh
PYTHONPATH=. uv run python tests/soak_multi_source_32_4.py
```

현재 개발 환경(macOS 15.7.7, Python 3.12, local filesystem), 합성 입력, warm-up 3회/role, 양방향 고속·저속 60 cycle, role별 SSE 알림 5개, status 표본 290, close 표본 5개로 실행했다. 일부 관측치:

| 항목 | 표본 | median / p95 / max |
|---|---:|---:|
| Status 조회 | 290 | 1.149 / 1.247 / 1.926 ms |
| Application append→SSE 알림 | 5 | 506.993 / 507.430 / 507.430 ms |
| SSH append→SSE 알림 | 5 | 506.976 / 507.097 / 507.097 ms |
| Normal close | 5 | 0.226 / 0.274 / 0.274 ms |

처리 증거: application 210, SSH 90 records; detection/checkpoint revision application 195, SSH 75; replay 31 items/16,120 bytes, eviction 505; queue resident 최대 역할별 0, global pending/replay 최대 32, traced memory growth 1,038,823 bytes, peak 1,058,002 bytes, owned tail FD 2개가 close 뒤 모두 닫힘, listener/connection 0. 양방향 저속 역할 진행이 관찰되어 starvation은 없었다. 알림 시간은 polling 주기 영향을 포함한다. 유한 합성 표본의 개발 관측치로 운영 SLA, worst-case 상한, 장시간 안정성 보증이 아니다.

## 자동 검증

- Phase 32.4 pair fault focused tests: 8 passed; worker/checkpoint/analysis/publication/service/API/SSE/privacy/Hypothesis/Schemathesis·문서 focused batch: 194 passed.
- checkpoint·worker·analysis·publication·service/API/SSE/privacy/Hypothesis/Schemathesis·문서 focused suite: 194 passed.
- 전체 pytest: 2,528 passed, 2 dependency deprecation warnings.
- 합성 평가: boundary 79/79, Linux process 21/21, risk/case 70/70.
- npm ci, Node UI/pending behavior, axe 14 states, Python/Node syntax, locked uv sync와 lock check, UTC/Asia/Seoul 반복 checkpoint deterministic regression: PASS.
- macOS loopback HTTP/SSE, 실제 CLI subprocess harness, bounded soak: PASS.
- Linux 별도 프로세스 v3 smoke·SIGTERM: NOT_TESTED.

v1/v2 schema 2·기존 설정 및 checkpoint 경로, v3 schema 3, API/OpenAPI privacy, Hypothesis·Schemathesis 회귀를 기존 계약으로 유지한다. Cross-source correlation/risk/case, rotation/copytruncate 자동 복구, 두 번째 파일 세대 replay, exactly-once·무유실은 지원하지 않는다. Public v0.4.0 tag/release 불변이다.

## Safari 수동 점검

자동 검증과 분리해 실제 Safari 18.6에서 합성 loopback만 사용한다. 사용자 조작 결과가 아직 없어 모든 항목은 **NOT_TESTED**다. 화면 역할 전환/staged 적용, 한 역할 terminal/gap/reset, keyboard-only와 Option+Tab, focus/scroll, 실제 200%와 창 너비, VoiceOver disclosure, Web Inspector(JS/CSP/MIME/external request/EventSource/reconnect/privacy/zombie request)를 확인한 뒤 PASS/FAIL/NOT_TESTED만 기록한다. 실제 픽셀 폭 측정이 없으면 320 CSS px PASS를 부여하지 않는다. 전체 VoiceOver 검수를 하지 않았다면 전체 PASS로 올리지 않는다.

Inspector URL/Network/console의 사용자 확인은 automated HTTP/SSE/DOM canary와 별도다. trusted internal raw state에 원문이 존재할 수 있다는 사실은 유지한다. `--stop`으로 준비 서버를 종료하고 listener, SSE slot, FD, lock, 임시 자료가 남지 않았는지 자동 확인한다.
