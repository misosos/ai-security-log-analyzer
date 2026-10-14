# Phase 17 — v0.2.0 로컬 실시간 모니터링 최종 사용자 수용성 검수

> 아래 Phase 17 표는 2026-10-13 당시의 기록이다. **최신 사용자 직접 검수와 판정은 문서 끝의 Phase 17.1 후속 기록을 우선한다.** 이전의 `BLOCKED`/`NOT_TESTED`를 소급해서 PASS로 바꾸지 않는다.

2026-10-13 기준 `main`의 `be0e2dcc3e209c1ee089116791a48867d08ee762`에서 시작했다. 작업 트리는 clean, `origin/main...HEAD`는 0/0, 원격 `main`은 같은 SHA였고 GitHub Actions run `38353578626`은 completed/success였다. 변경 전 전체 회귀는 **1,989 passed, 기존 의존성 deprecation 경고 2개**였다. 검수 환경은 macOS, uv Python 3.12.7, Safari 18.6, loopback `127.0.0.1:8000`, 단일 application source, 비밀정보가 아닌 OS 임시 합성 로그다. 임시 절대 경로는 이 기록에 남기지 않는다.

아래 판정은 환경별로 독립적이다. WebDriver의 DOM click·script와 Node/pytest는 **사람이 실제 키보드·페이지 확대·개발자 도구를 조작한 증거가 아니다.** 사용자의 수동 확인을 한 번에 한 단계씩 요청했으나 이 기록을 작성할 때까지 응답이 없었다. 따라서 수동 항목은 PASS로 승격하지 않는다. 실제 사용자 연구나 WCAG 2.2 AA 준수 주장은 없다.

| 검수 항목 | 환경 | 판정 | 증거 | 남은 한계 |
|---|---|---|---|---|
| 1. `--monitor-config --no-browser` 서버 시작 | 실제 loopback CLI | PASS | 합성 config/source로 8000 listener·status 200 | hosted 실행 아님 |
| 2. Safari 페이지 접속 | Safari 18.6 WebDriver | PASS | 실제 Safari session에서 `/` 로드 | 사람의 탐색 아님 |
| 3. live 영역 발견 | Safari WebDriver | PASS | 영역 visible·`모니터링 중` 확인 | 10초 이내 인간 발견성은 NOT_TESTED |
| 4. 로그 역할 확인 | status API·Node | PARTIAL | application exact role과 한국어 매핑 계약 | Safari 사람 읽기 NOT_TESTED |
| 5. 기존 줄 미처리 안내 | CLI/status·Node | PARTIAL | 초기 줄 존재 상태에서 revision 0, 안내 문구 계약 | Safari 사람 읽기 NOT_TESTED |
| 6. 새 실패 줄 append | 실제 loopback | PASS | 합성 줄 append 후 revision 1 | 수동 조작 아님 |
| 7. 새 결과 알림 | Safari WebDriver | PASS | `새 결과 N건 보기` visible | 사람이 알림을 발견했는지는 NOT_TESTED |
| 8. 버튼 전 목록 불변 | Safari WebDriver | PASS | 네 영역 children 0 | 별도 event 순서의 수동 검수 아님 |
| 9. 결과 보기 버튼 선택 | Safari WebDriver DOM click | PASS | 버튼 뒤 네 영역 children 증가 | keyboard-only 증거 아님 |
| 10. 탐지 관찰 표시 | Safari WebDriver | PASS | 관찰 영역 1개 이상 | 의미를 사람이 이해했는지는 NOT_TESTED |
| 11. Brute Force 임계값 | 실제 loopback·WebDriver | PASS | 합성 실패 5건, observation SSE | 운영 탐지율 아님 |
| 12. 성공 인증 append | 실제 loopback·WebDriver | PASS | 합성 성공 줄 뒤 analysis SSE | 침해 증거 아님 |
| 13. 네 결과 영역 구분 | Safari WebDriver | PARTIAL | 탐지·관계·위험도·사례 각 영역 비어 있다가 채워짐 | 시각·인지 수용성 NOT_TESTED |
| 14. 관계 인과·공격 성공 미확정 | Node·정적 문구 | PARTIAL | 고정 안내 계약 검사 | 실제 사람 오해 여부 NOT_TESTED |
| 15. 위험도는 침해 확률이 아님 | Node·정적 문구 | PARTIAL | 고정 안내 계약 검사 | 실제 사람 오해 여부 NOT_TESTED |
| 16. 사례는 확정 사고가 아님 | Node·정적 문구 | PARTIAL | 고정 안내 계약 검사 | 실제 사람 오해 여부 NOT_TESTED |
| 17. 화면 일시 정지 | Safari WebDriver DOM click | PASS | 버튼이 다시 시작 문구로 변경 | keyboard-only 증거 아님 |
| 18. 정지 중 새 append | Node 동작 테스트 | PARTIAL | bounded pending·수집 지속 안내 계약 | 실제 Safari에서 append하지 않음 |
| 19. pending 증가·서버 수집 지속 | Node 동작 테스트 | PARTIAL | pause 중 pending 동작 검증 | 사람의 확인 NOT_TESTED |
| 20. 재개 후 사용자 적용 | Safari WebDriver·Node | PARTIAL | 재개 버튼과 staged apply 별도 검증 | 정지 중 append→재개 연속 Safari 미검증 |
| 21. focus·scroll 유지 | Node·정적 검사 | PARTIAL | 강제 이동 코드 없음 | 실제 Safari 사람 조작 NOT_TESTED |
| 22. Ctrl+C 종료 | 실제 loopback CLI | PASS | 정상 SIGINT와 오류 상태 뒤 SIGINT 각 1회 | 강제 kill/crash recovery 아님 |
| 23. 종료 안내·수동 복구 | Node·SSE 계약 | PARTIAL | `stream_end`·고정 복구 문구 검증 | Safari에서 사람 확인 NOT_TESTED |

## 별도 수용 범위

| 검수 항목 | 환경 | 판정 | 증거 | 남은 한계 |
|---|---|---|---|---|
| 실제 keyboard-only 전체 흐름·Tab/Option+Tab·visible focus | 사람의 Safari 조작 | BLOCKED | 한 단계 수동 확인 요청에 응답 없음 | WebDriver click을 대체 증거로 사용하지 않음 |
| 실제 Safari 200% 확대 | 사람의 Safari 페이지 확대 | NOT_TESTED | 자동 viewport 검사를 확대라고 부르지 않음 | 핵심 control 사용성 확인 필요 |
| Safari 최소 폭·정확한 320 CSS px | 사람의 Safari 창 조작 | NOT_TESTED | 별도 정적/Node reflow 계약만 존재 | 실제 CSS viewport 수치 기록 필요 |
| Safari 개발자 콘솔·Network·CSP | 사람의 Web Inspector | BLOCKED | 개발자 도구 화면 확인 없음 | HTTP/Node 검사는 별도 PASS 근거만 제공 |
| VoiceOver 전체 읽기 | 사람의 Safari VoiceOver | NOT_TESTED | 이번 로컬 gate의 필수 GO 조건은 아님 | WCAG 준수 주장 금지 |
| 최초 snapshot·혼합 replay·malformed gap | 실제 loopback HTTP/SSE | PASS | `tests/live_acceptance_17_http_audit.py` | Safari gap 복구 화면은 NOT_TESTED |
| pending 32 item·16KiB overflow, 연속 오류 3회·수동 재연결 | Node 동작 테스트 | PASS | `tests/live_monitoring_ui_behavior.cjs` | 실제 Safari fault-injection은 NOT_TESTED |
| `DEGRADED`·`FAILED`·terminal UI | Node·pytest | PASS | 기존 UI/runner 실패 테스트 | 실제 Safari terminal 화면은 NOT_TESTED |
| 정상 종료 listener·process FD·임시 자료 | 실제 CLI SIGINT | PASS | port 8000 listener 없음, child PID FD 없음, harness `CLEAN` | OS 전체 FD의 무관한 항목은 조사 대상 아님 |
| 파일 truncation 뒤 오류 종료 | 실제 CLI + 합성 source | PASS | service `FAILED`, D/A revision 0, SIGINT 뒤 port·임시 자료 정리 | EventSource zombie의 Safari 직접 확인은 NOT_TESTED |
| runner task·SSE slot·active lease/proposal close | pytest lifespan/cancellation/timeout | PASS | `tests/test_live_runner.py`, `tests/test_live_sse_stream.py`, worker cleanup 회귀 | 외부 강제 kill 뒤 보장 아님 |
| status·SSE·OpenAPI·CLI 개인정보 | 실제 loopback·자동 canary | PASS | safe schema2, 혼합 event·gap, 원문 불포함; stdout/stderr canary 검사 | Safari console/Network 직접 관찰은 BLOCKED |

실제 HTTP 감사에서 application revision 3/3, 활성 관계 2·위험도 1·사례 1, event 4개와 단일 순서 cursor를 확인했다. 기존 `observation_changes`와 `analysis_changes`가 함께 남아 있으며 `Last-Event-ID` 재연결과 malformed ID gap 모두 원문 없이 응답했다. `FROM_END`에서 초기 줄의 revision은 0이었다. 정상 종료와 truncation으로 유도한 `FAILED` 종료 모두 listener 해제와 임시 디렉터리 정리를 확인했다. 두 실행에서 강제 process kill이나 crash recovery는 시험하지 않았다. 실제 Safari WebDriver smoke의 append→analysis SSE 지연은 **83.167ms 단일 표본**으로 운영 SLA가 아니다.

자동 회귀는 live focused **368 passed**, runner/SSE/launcher focused **23 passed**, 관련 문서 계약 **36 passed**, Safari WebDriver smoke PASS, Node 문법·동작 PASS, 인증·웹 79/79·Linux 21/21·risk/case 70/70이었다. 변경 후 전체 회귀는 **1,991 passed, 기존 경고 2개**였다. UTC와 `Asia/Seoul`에서 동일 prefix·publication·detector focused **32개씩 PASS**였고 결과 계약이 같았다. 같은 Node 동작 테스트를 반복 실행해 PASS를 재확인했다. `uv lock --check`, 변경 Python `py_compile`, `node --check`, `git diff --check`도 통과했다. 기존 경고 2개는 Starlette/httpx와 anyio deprecation으로 변경 전후 동일하며 새 경고는 없다. 수치 일치는 운영환경 결정성 보장이 아니다.

## 판정 범위와 남은 gate

**CONDITIONAL GO — 자동·WebDriver·실제 socket의 단일 application 로컬 기능 무결성 범위에 한정.** 사용자 수동 keyboard-only, 실제 200% 확대, Safari Web Inspector 및 실제 Safari 복구 화면이 아직 미검증이므로 **v0.2.0 릴리스 실행 GO는 아니다.** 최소 NO-GO 조건을 자동 검증에서 발견하지 않았다는 것과 사용자가 실제 Safari에서 접근 가능한 핵심 흐름을 완료했다는 것은 다르다. 이 수동 gate에서 blocker가 발견되면 실패 테스트 후 최소 수정·전체 회귀를 다시 수행한다. 정확한 320 CSS px와 VoiceOver 전체 읽기만 미검증인 것은 자동 NO-GO로 간주하지 않는다.

검수 범위는 단일 application·loopback·process-local·bounded memory에 한정한다. Trusted 내부 history에는 계정·IP·원문이 있을 수 있지만 public DTO에는 없어야 한다. 탐지는 침해 확정이 아니고 관계는 인과관계가 아니며 risk 하향·`NO_LONGER_MATCHES`는 안전/해결이 아니다. SSH/access live analysis, cross-source, 영구 저장, crash recovery, exactly-once, hosted 운영은 보류한다. 이번 단계에서 production 기능·분석 규칙·API/SSE schema는 바꾸지 않았다.

## Phase 17.1 후속 사용자 직접 검수 — 2026-10-14

시작점은 `main`의 `904712d175a91f1bdb8d015bfa037b41ea1317c8`, clean tree, `origin/main...HEAD` 0/0이었다. 원격 `main`도 같은 SHA였고 CI run `38355709414`는 completed/success였다. 변경 전 `uv run pytest -q`는 **1,991 passed, 기존 deprecation 경고 2개**였다. 합성 application source의 기존 줄이 있는 임시 일반 파일과 절대 경로 config로 실제 loopback `127.0.0.1:8000` 서버를 시작했다. 초기 revision 0을 확인했고, 실패 인증 5건 뒤 D/A revision 2·retained event 3개, 성공 인증 뒤 D/A revision 3·event 4개를 확인했다. Privacy canary는 비밀정보가 아닌 서로 구분되는 합성값이며 원문·임시 절대 경로를 이 문서에 기록하지 않는다. 질문은 한 번에 하나씩 제시했고 사용자 응답을 받은 뒤에만 다음 상태를 준비했다.

| 검수 항목 | 환경 | 판정 | 증거 | 남은 한계 |
|---|---|---|---|---|
| keyboard-only live 일시 정지·재개, 새 결과 적용, visible focus·trap | 사용자 직접 Safari | PASS | 첫 질문에 사용자 `PASS` | 일반 Tab과 Option+Tab 중 실제 사용 조합, skip link·sample·파일 입력·다운로드의 이번 회차 상세는 별도 확인하지 않음 |
| 실제 Safari 페이지 확대 200%의 핵심 버튼·네 영역 사용성 | 사용자 직접 Safari | PASS | 두 번째 질문에 사용자 `PASS` | contrast·WCAG 계측 아님 |
| Safari가 허용한 최소 창 너비의 핵심 사용성 | 사용자 직접 Safari | PASS | 세 번째 질문에 사용자 `PASS` | 실제 CSS viewport 숫자와 정확한 320 CSS px는 NOT_TESTED |
| Web Inspector 사용 가능 | 사용자 직접 Safari | PASS | 개발자용 메뉴/Inspector 질문에 사용자 `PASS` | 설정 변경을 요구하지 않음 |
| 새로고침·새 결과 적용 중 JS/CSP/MIME·중복 EventSource·URL/SSE 개인정보 | 사용자 직접 Safari Web Inspector | PASS | 해당 흐름 질문에 사용자 `PASS: 문제 없음` | 이후 pause·terminal 시점의 Inspector 화면까지 다시 질문하지 않음 |
| 화면 일시 정지 선택 | 사용자 직접 Safari | PASS | 사용자가 선택 후 `PASS` 응답 | 서버 측 상태와 구분 |
| pause 중 append·pending 증가·수집 지속 안내·재개 후 수동 적용 | 사용자 직접 Safari + 실제 loopback | PASS | 사용자 `PASS`; append 뒤 D/A revision 4·event 6개 | 자동 focus/scroll 위치의 숫자 계측은 없음 |
| 실제 Safari replay gap 복구 화면 | 사용자 직접 Safari | NOT_TESTED | 기존 단일 연결에서 production 의미를 바꾸지 않고 안전하게 과거 cursor gap을 주입하지 못함 | Node/pytest 및 실제 HTTP gap PASS와 별개; UI 수동 gate로 남음 |
| 합성 파일 truncation 뒤 terminal 실패·복구 안내 | 사용자 직접 Safari + 실제 loopback | PASS | service/worker `FAILED`, D/A revision 4 유지, 사용자 `PASS` | 강제 kill·crash recovery 아님 |
| 종료 직전 safe 상태·SSE 연결 slot | 실제 loopback status | PASS | `FAILED`, 고정 `LIVE_RUNNER_FAILED`, active_connections 0 | 외부 브라우저 내부 요청 목록의 종료 직후 재검사는 없음 |
| 정상 SIGINT 뒤 listener·프로세스 FD·임시 검수 자료 | 실제 process/OS | PASS | harness `CLOSED`/`CLEAN`, port 8000 listener 없음, 검수 PID FD 없음, 알려진 임시 디렉터리 없음 | 관련 없는 OS 자원은 검사 범위 밖 |
| Safari WebDriver 재검수 | 이전 Phase 17 자동 실행 | PASS | 위 Phase 17 기록의 별도 자동 증거 | Phase 17.1의 사용자 직접 확인으로 대체하지 않음 |
| VoiceOver 상세 읽기 | 사용자 직접 Safari | NOT_TESTED | 요청 범위의 필수 GO 조건은 아님 | WCAG 2.2 AA 준수 주장 금지 |

Safari의 `window.innerWidth`를 Apple Events로 읽으려 했으나 Safari의 해당 설정이 비활성이라 값을 얻지 못했다. 설정 변경을 강요하거나 창의 픽셀 크기를 CSS viewport로 추정하지 않았다. Replay gap은 실제 HTTP/SSE 및 Node/pytest에서 안전한 gap·stale·수동 복구 계약을 검증했지만, 이번 사용자의 Safari 화면에는 주입하지 않았다. `NOT_TESTED`를 `PASS`로 바꾸지 않는다. Web Inspector 사용자 `PASS`는 질문 당시 새로고침·새 결과 적용 범위의 오류·네트워크·민감정보 확인이다. 이후 pause·terminal의 Inspector 재확인이나 실제 수동 재연결 관찰까지 포함한다고 주장하지 않는다.

종료 직전 status는 `FAILED`, detection/analysis revision 4/4, retained event 6개, 활성 관계 2·위험도 1·사례 1, SSE 연결 slot 0이었다. 고정 복구 문구는 프로세스 종료 뒤 설정·로그 확인과 재시작을 안내했다. SIGINT로 서버를 종료했고 listener·해당 PID FD·알려진 임시 자료 잔존은 확인되지 않았다. 새 production 동작이나 분석 의미는 변경하지 않았다.

최종 검증: Phase 17.1 문서 focused **5 passed**, live focused **371 passed**, 전체 문서 계약 **135 passed**, 전체 `uv run pytest -q` **1,992 passed, 기존 경고 2개**였다. 변경 전 1,991건보다 문서 계약 테스트가 1건 늘었고 새 경고는 없다. 합성 인증·웹 **79/79**, Linux **21/21**, risk/case **70/70**; UTC와 `Asia/Seoul` 동일 live prefix·publication·detection focused **32건씩 PASS**였다. Node 문법·동작, `uv lock --check`, 변경 Python `py_compile`, `git diff --check`도 통과했다. 이는 현재 합성 계약의 반복·timezone 일치이지 운영 SLA나 모든 Safari 상태의 검증이 아니다.

**최종 판정: CONDITIONAL GO.** 사용자가 확인한 keyboard-only, 200% 확대, 최소 너비, Inspector의 주요 흐름, pause 중 append, terminal 화면에서는 NO-GO blocker가 보고되지 않았다. 그러나 실제 Safari replay gap 화면과 이번 회차 수동 재연결·종료 뒤 zombie EventSource 관찰은 `NOT_TESTED`이므로 v0.2.0 릴리스 실행을 무조건 GO로 선언하지 않는다. 정확한 320 CSS px와 VoiceOver 상세 미검증만으로 NO-GO를 선언하지도 않는다. 자동·HTTP 계약 검증은 별도 증거이며 운영 무유실·exactly-once·hosted 준비 또는 WCAG 준수를 뜻하지 않는다.

## Phase 18 후속 gate

위 Phase 17.1 판정은 당시의 이력이다. 실제 Safari replay gap 화면과 정상 종료 뒤 bounded 재연결은 [Phase 18 복구 검증](live_monitoring_release_gate_18.md)에서 사용자 직접 확인과 서버 측 증거를 분리해 추가했다. Gap 화면은 `PASS`, 서버 종료 뒤 수동 복구 안내와 무조작 약 20초 동안 새 요청 비증가는 `PASS`다. Safari에서 `stream_end` frame 자체의 수신, 정확한 320 CSS px, VoiceOver 상세는 검증했다고 주장하지 않는다. 릴리스 후보 준비는 `CONDITIONAL GO`이며 최종 준비 SHA의 원격 CI와 tag/Release는 별도 gate다.
