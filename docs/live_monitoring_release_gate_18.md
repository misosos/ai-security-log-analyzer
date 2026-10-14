# Phase 18 — 로컬 실시간 복구 gate

2026-10-14의 시작점은 `main` `d1dbcee5fad963c99754c62c01e5f4dad07bb1fc`였다. 시작 작업 트리와 원격 `main`은 같고 clean, GitHub Actions run `38519473010`은 completed/success였다. 변경 전 전체 회귀는 **1,992 passed, 기존 deprecation 경고 2개**이고 합성 평가 세 묶음은 **79/79, 21/21, 70/70**이었다.

검수는 Safari 18.6, loopback `127.0.0.1:8000`, 단일 application source와 OS 임시 합성 로그에서 했다. 원래 경로·계정·IP·raw line은 이 문서에 기록하지 않는다. `tests/live_release_gate_18_harness.py`는 검수 전용이며 production 의미를 바꾸지 않는다. 기존 `LivePublicationBuffer`의 item 상한만 이 검수 프로세스에서 2로 낮추고 SSE wake를 테스트용 event로 지연해 실제 retained event eviction과 기존 `replay_after()`의 gap을 만들었다. 첫 event를 Safari에서 확인한 뒤 변경 4줄을 추가했고, 서버의 revision 2·retained 2·evicted 1·gap 1을 확인했다. 사용자 직접 확인 전에는 다음 gate로 넘어가지 않았다.

| Gate | 환경 | 판정 | 증거 | 남은 한계 |
|---|---|---|---|---|
| Replay gap, stale·복구 버튼 | 실제 Safari 사용자 | PASS | 사용자가 이전 상세를 최신으로 표시하지 않고 안내·수동 복구가 보인다고 답함 | 사용자의 화면 조작·의미 확인이며 픽셀/초점 좌표 계측 아님 |
| Gap 발생 | 실제 loopback backend | PASS | 기존 replay cursor에서 eviction, `replay_gap_total=1`; partial publication 없음 | 검수 전용 작은 item 상한 사용 |
| 정상 재연결 | 실제 Safari 사용자 + 서버 | PASS | 새 Safari 탭에서 status `active_connections=1` 확인 | 앞선 gap 탭의 수동 연결은 서버 slot 0으로 관찰돼 직접 연결 증거로 쓰지 않음 |
| 연결 중 정상 서버 종료 | 실제 loopback | PASS | 종료 직전 SSE slot 1, 서버 정상 shutdown, listener 해제·임시 config/source 삭제 | 강제 kill/crash recovery 아님 |
| 종료 뒤 UI 수동 복구 | 실제 Safari 사용자 | PASS | 사용자에게 `실시간 연결을 유지하지 못했습니다. 최신 상태로 다시 연결해 주세요.` 표시 | `stream_end` frame 수신 자체는 NOT_TESTED; bounded 연결 오류 경로가 표시됨 |
| 종료 뒤 zombie 재연결 | 실제 Safari Web Inspector 사용자 | PASS | 새로고침·버튼 조작 없이 약 20초 관찰하도록 요청했고 사용자가 새 `events`/`status` 오류가 더 늘지 않는다고 답함 | 정확한 총 request 수·Network export는 미계측; 수동 `다시 연결` 클릭 때 오류 증가는 예상된 새 요청 |
| Safari 전체 320 CSS px·VoiceOver 상세 | 실제 Safari | NOT_TESTED | 이 gate의 대상 아님 | WCAG 2.2 AA 준수 주장 금지 |

첫 종료 시 사용자는 서버 종료 뒤 페이지를 다시 열어 Safari 자체의 `서버에 연결할 수 없다` 화면을 보았다. 이를 앱 복구 PASS로 오인하지 않고 서버를 재시작했다. 새 앱 탭에서 실제 SSE slot 1을 확인한 다음 정상 종료했다. 사용자에게는 앱의 bounded 연결 오류 및 수동 재연결 문구가 보였다. Inspector에는 종료 직후 실패한 요청과 사용자가 수동 재연결을 클릭하면서 발생한 실패 요청이 있었지만, 버튼을 누르지 않은 관찰 구간에는 새 요청이 계속 추가되지 않았다. 이 구분 때문에 무한 자동 재연결이라고 판정하지 않았다. `stream_end` frame 자체가 Safari에 도달했다고 주장하지 않는다.

초기 합성 파일의 기존 줄은 FROM_END로 제외했다. 검수 harness의 temp source/config는 종료 시 삭제됐고 8000 listener는 남지 않았다. 서비스의 정상 close·runner task·SSE slot·tail FD·active lease/proposal 정리는 기존 lifespan/worker 자동 테스트와 실제 프로세스 종료 증거를 구분한다. 다른 프로세스의 FD나 강제 종료 뒤 crash recovery는 검수 범위 밖이다. Private canary는 안전 DTO와 status/SSE에 없도록 기존 자동 회귀로 검증하며, 사용자가 앞선 Phase 17.1 Web Inspector 주요 흐름에서 노출 없음을 보고했다. 이번 종료 뒤 Inspector 전체 payload를 별도 export하지 않았으므로 해당 부분은 추가 수동 증거로 과장하지 않는다.

**판정: 로컬 source-checkout 릴리스 후보 준비는 CONDITIONAL GO.** 확인된 최소 NO-GO blocker는 없으며 replay gap과 종료 뒤 비증가 연결을 실제 Safari에서 확인했다. 최종 준비 커밋 자체의 원격 CI, local/remote SHA 일치, tag/Release 존재 여부와 실행 승인은 별도의 릴리스 gate다. 이 판정은 hosted·multi-worker·운영 무유실·exactly-once·WCAG 준수·wheel/PyPI 지원이나 보안 사건 확정을 뜻하지 않는다.
