# v0.2.0 Phase 15.1 로컬 실시간 UI 수용성 기록

이 기록은 **로컬 단일 source 실시간 UI의 개발자 walkthrough**다. 실제 초보 사용자를 모집한 연구가 아니다. 판정값은 `PASS`·`FAIL`·`NOT_TESTED`·`BLOCKED`이며 현재 미해결 `FAIL`은 없다. `PASS`는 적힌 방법과 범위에만 적용한다. `NOT_TESTED`와 `BLOCKED`를 자동 테스트의 `PASS`로 대체하지 않는다. WCAG 2.2 AA 준수, hosted 노출, 무유실·exactly-once, 공격 성공 판정의 근거가 아니다.

검증 환경: macOS, Python 3.12.7, Safari 18.6, WebDriver 사용, 기준 commit `5a9a142628dbdbbcfc0ee5f7e7516a78a404c786`, 합성 application 인증 로그 한 개. 실제 CSS viewport는 1600px에서 시작했고 Safari WebDriver가 320px 창 요청을 **640 CSS px**로 제한했다. 합성 설정·로그는 OS 임시 영역에 만들었고 개인 경로·credential을 문서에 남기지 않았다. 확대 수준은 Safari에서 검증하지 못했다.

| 영역 | 판정 | 관찰 및 범위 |
| --- | --- | --- |
| 변경 전 전체 회귀 | PASS | `1,878 passed, 기존 경고 2개` |
| Task A: live 영역·상태·역할·기존 줄 한계 발견 | PASS | 개발자 WebDriver walkthrough 0.16초. 상태 `모니터링 중`, application 역할, 기존 줄 미처리 안내 확인. 사람의 10초 탐색 성공률은 측정하지 않음 |
| Task B: append→새 결과 버튼→관찰 상태 | PASS | 합성 5줄 후 버튼까지 0.25초, 선택 전 목록 0건·선택 후 `CREATED` 1건. 화면에는 침해 확정 문구 없음. 사람의 오해 여부는 미측정 |
| Task C: 화면 일시 정지·pending·재개 | PASS | 개발자 walkthrough 0.47초. 정지 중 pending 1건, 서버 수집 지속 안내, 재개 후 버튼 선택으로 `UPDATED` 반영 |
| Task D: 연결 문제 구분·복구 | NOT_TESTED | 실제 Safari에서 replay gap·정상 stream 종료·수동 복구 전체를 검증하지 못함. Node 동작 테스트로 gap·3회 오류·수동 재연결·정상 stream 종료 안내를 별도 확인; 소요 시간·도움 요청·오해 미측정 |
| Safari 정상 흐름 | PASS | load, status, EventSource, 기존 줄 미표시, append, staged 적용, UPDATED, out-of-window 후 NO_LONGER_MATCHES, pause/resume까지 실제 backend와 Safari에서 확인 |
| Safari replay gap·DEGRADED/FAILED·stream_end | NOT_TESTED | 실제 browser/backend fault injection으로 만들지 않음. 서버 신호 시 UI의 정상 종료 event는 관찰되지 않아 PASS 처리하지 않음 |
| Safari 콘솔·Network 탭 | BLOCKED | WebDriver로 Safari 개발자 콘솔·Network를 읽지 못함. JS error, CSP violation, zombie request 부재를 실제 개발자 도구에서 확인하지 않음 |
| Keyboard-only | BLOCKED | WebDriver Tab action에서 focus가 BODY에 머물렀고 Safari keyboard navigation 설정을 확인하지 못함. element click을 keyboard 검증으로 취급하지 않음. skip link, live 버튼, sample, 입력, 다운로드의 사람 keyboard walkthrough 필요 |
| Event 수신·목록 적용의 focus/scroll | PASS | Safari에서 사전 focus `live-pause`와 scrollY 350이 event 수신 및 목록 적용 후 유지됨. 이는 keyboard-only 전체 검증이 아님 |
| 실제 Safari 200% 확대 | BLOCKED | WebDriver 확대 키를 보내도 innerWidth 1600·visualViewport.scale 1로 불변. GUI 확대 자동화 권한 확인이 끝나지 않아 200%를 검증했다고 주장하지 않음 |
| Safari 좁은 창 | PASS | 가능한 최소 640 CSS px에서 document scrollWidth 640, 페이지 전체 horizontal overflow 없음 |
| 정확한 320 CSS px | NOT_TESTED | Safari는 320px 요청을 640px로 제한. CSS의 wrap/reflow 정적 계약은 자동 테스트로 검사하지만 Safari 320px PASS는 아님 |
| Reduced motion·색상 외 상태 | PASS | 정적 CSS의 reduced-motion 규칙과 상태 text 확인. 실제 OS reduced-motion 동작은 NOT_TESTED |
| 대비 | NOT_TESTED | CSS 지정 색상의 계산값(흰색 대비 본문 15.42:1, 보조 text 8.71:1, focus 색 7.02:1)은 참고치. 실제 렌더링·모든 조합의 WCAG 대비 판정은 수행하지 않음 |
| Status 오류·malformed payload | PASS | Node 동작 테스트에서 404 비활성, 잘못된 status 거부와 별도 live 오류 확인. Safari 실제 fault injection은 NOT_TESTED |
| SSE 일시 오류·3회 오류·중복 방지 | PASS | Node 동작 테스트에서 기존 stream 자동 재연결 범위, 3회 뒤 종료·수동 버튼, 새 stream 한 개 확인. Safari 실제 네트워크 오류는 NOT_TESTED |
| Replay gap·pending overflow | PASS | Node 동작 테스트에서 pending 제거, stale 안내, 자동 재연결 없음, 최신 status 재조회. 실제 Safari fault injection은 NOT_TESTED |
| Service DEGRADED·FAILED | PASS | Node 동작 테스트에서 terminal 상태·자동 resume 없음. Safari 실제 fault injection은 NOT_TESTED |
| Privacy | PASS | 실제 Safari DOM에 합성 IP·source filename·config filename 없음. 기존 자동 canary 테스트가 status/SSE·오류·repr·저장소/console API 미사용을 검사. Safari 개발자 콘솔·Network 원문은 BLOCKED |
| 기존 sample·3파일·Linux 화면 | PASS | Safari DOM에서 세 영역의 기본 control 존재를 확인; 전체 상호작용은 기존 자동 회귀. 실제 Safari에서 각 업로드와 보고서까지 재실행하지 않음 |

발견한 사용성 결함: 정상 `stream_end` 뒤 연결 종료라는 짧은 상태만 남고 수동 복구 버튼·안내가 보이지 않았다. 수정 전에 Node 재현 테스트가 실패하는 것을 확인했다. 최소 보정으로 정상 종료 시 **서버 상태를 확인하고 필요하면 최신 상태로 다시 연결** 안내와 버튼을 표시한다. 자동 재연결은 시작하지 않으며 기존 관찰을 안전 상태로 바꾸지 않는다. 또한 live 영역에서 서버 종료 방법을 찾기 어려워, 실패한 문서/UI 계약 테스트를 먼저 확인한 뒤 **실행한 터미널에서 Ctrl+C** 안내를 추가했다. README의 오래된 “실시간 수집 미구현” 문구도 현재 단일 파일 로컬 범위에 맞게 바로잡았다.

현재 판정은 **CONDITIONAL GO — 개발자 자동·Safari WebDriver로 확인한 로컬 정상 흐름**이다. 핵심 keyboard-only와 실제 200% 확대, Safari 콘솔·CSP·Network, 실제 Safari replay gap/종료 복구는 수동 검증 전까지 수용 완료로 보지 않는다. Release blocker가 발생하면 판정을 NO-GO로 바꿔야 한다. VoiceOver 상세 읽기와 정확한 Safari 320px은 미검증이며 그것만으로 현재 범위를 자동 NO-GO로 만들지 않는다. 빈 결과는 안전의 증명이 아니며, 화면 일시 정지는 서버 수집 중지가 아니다.
