# Phase 28.5 — 조사 작업 화면 Safari 수용 검수

## 시작 gate와 격리

- 시작 `main`: `6df8bc3419a655456fb423d16a36d1b503ea7732`. 시작 당시 작업 트리는 clean이고 local·remote `main`이 같으며 behind/ahead는 0/0이었다.
- [정확한 SHA의 CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39454069860)는 completed/success였다. 전체 pytest, locked Node 설치, pinned Chromium, 13개 상태 axe 단계가 성공했고 저장된 artifact는 0개였다.
- 기존 `v0.3.0` annotated tag의 peeled commit은 `a1b779ae857b885212352394ed72bc24ee5ce0b2`이고 공개 Release는 그대로 유지했다.
- macOS 15.7.7, Safari 18.6. private 임시 HOME과 합성 application 로그·private v2 설정으로 `127.0.0.1` 전용 `--monitor` 서버를 실행했다. 로그에는 예약된 합성 주소만 사용했고 실제 사용자 기본 설정·로그·checkpoint는 읽거나 수정하지 않았다. 시작 전 합성 한 줄은 FROM_END에 따라 분석하지 않았다.
- health와 live status는 HTTP 200 JSON, SSE는 HTTP 200 `text/event-stream`으로 확인했다. Safari WebDriver는 사용하지 않았고, 위 사용자 과업은 실제 Safari의 직접 조작 결과다. 자동 Chromium 조작을 keyboard-only PASS 증거로 사용하지 않는다.

## 사용자 직접 Safari 과업

PASS/FAIL/NOT_TESTED는 사용자가 직접 확인한 범위에 맞춰 쓴다. 자동 Chromium 검사와 이전 화면에 대한 PASS는 이 표의 Safari 결과가 아니다. 사용자는 Safari 키보드 이동에 **Option+Tab**을 사용했고 웹 사이트의 실제 페이지 확대 **200%**를 확인했다. 처음 viewport와 최소 창의 CSS 폭은 측정하지 않았으며 Safari 최소 창 검수만 사용자 응답으로 판정했다.

| 과업 | 판정 | 직접 확인 범위 |
| --- | --- | --- |
| 첫 화면: 메뉴 구분 | PASS | Safari 18.6에서 사용자가 ‘시작’·‘내 로그 분석’·‘Linux Audit’을 구분할 수 있다고 응답(P=PASS) |
| 첫 화면: 세 시작 카드·다음 행동 | PASS | 사용자가 세 선택지와 첫 행동을 빠르게 구분할 수 있다고 응답(P=PASS) |
| 결과: 네 요약 숫자 | PASS | 사용자가 결과 상단에서 네 지표를 먼저 찾았다고 응답(P=PASS) |
| 결과: 사례 2건 비교·LOW 해석 | PASS | 두 카드의 위험도·신뢰도·주요 활동을 큰 스크롤 없이 비교했고 LOW를 안전·해결로 읽지 않았다고 응답(P=PASS) |
| 상세: keyboard로 ‘상세 보기’ 도달 | PASS | 사용자 응답(P=PASS); 실제 이동 키는 Option+Tab |
| 상세: Enter·Space 열기/닫기와 focus 유지 | PASS | 사용자가 두 키로 열고 닫았으며 초점이 ‘상세 보기’에 남는다고 응답(P=PASS) |
| 상세: 관계·KST/UTC·근거·시간순 기록 | PASS | 기본 카드에서는 접히고, 사례·시간순 disclosure를 열면 기존 정보가 보존된다고 응답(P=PASS) |
| 기본 결과·상세·화면 왕복 scroll | PASS | 기본 사례를 큰 스크롤 없이 비교하고 상세를 펼칠 때만 길어지며 메뉴 왕복 시 결과 상단이 보인다고 응답(P=PASS) |
| SSE 수신 시 scroll·focus 유지 | PASS | 합성 application 새 줄 6개로 공개 관찰 1건·분석 revision 1을 생성했고, 사용자 응답에서 SSE 수신만으로 자동 이동이 없었다고 확인(P=PASS) |
| 실제 Safari 200% 페이지 확대 | PASS | 사용자가 Safari의 웹 사이트 페이지 확대 200%를 확인하고 메뉴·요약·사례·상세 조작에 겹침·잘림·가로 스크롤이 없다고 응답(P=PASS) |
| Safari 최소 창 너비 | PASS | 사용자가 가능한 최소 창에서 탐색 열기·닫기와 main·버튼 접근을 확인(P=PASS); CSS viewport 실측은 없음 |
| 정확한 320 CSS px Safari 수동 검수 | NOT_TESTED | Safari CSS viewport 값을 측정하지 않음; Chromium 320px 자동 결과와 구분 |
| VoiceOver navigation·main landmark | PASS | 사용자가 두 영역을 구분할 수 있다고 응답(P=PASS) |
| VoiceOver 현재 선택 메뉴 | PASS | 사용자가 선택 상태를 알 수 있다고 응답(P=PASS) |
| VoiceOver 요약 숫자·레이블 | PASS | 사용자가 네 지표의 숫자와 레이블을 연결해 이해한다고 응답(P=PASS) |
| VoiceOver 장식 아이콘 | PASS | 불필요한 아이콘 이름 반복이 없다고 사용자 응답(P=PASS) |
| VoiceOver disclosure 펼침·접힘 상태 | PASS | 사용자가 ‘상세 보기’의 접힘·펼침 상태를 구분할 수 있다고 응답(P=PASS) |
| Web Inspector JavaScript 오류 | PASS | 새로고침·예시 분석·결과 전환·상세 조작 중 오류가 없다고 응답(P=PASS) |
| Web Inspector CSP·MIME 오류 | PASS | 두 오류 유형 모두 없다고 응답(P=PASS) |
| Web Inspector 외부 요청 | PASS | 이 페이지에서 loopback 외 요청이 없다고 응답(P=PASS) |
| Web Inspector EventSource 단일 연결 | PASS | live·결과 화면 왕복 뒤 연결이 중복으로 늘어나지 않는다고 응답(P=PASS) |
| Web Inspector 개인정보 canary | PASS | 화면·DOM·Network·Console에서 합성 계정·IP·경로·원문 노출이 없다고 응답(P=PASS); 값은 수집하지 않음 |
| VoiceOver 전체 페이지 읽기 | NOT_TESTED | 위에 열거한 landmark·메뉴·요약·아이콘·disclosure 범위만 사용자 직접 확인 |

## 자동 검증과 수동 검수의 경계

시작 SHA의 로컬 변경 전 전체 pytest는 **2,378 passed·기존 경고 2개**였다. Locked `npm ci`와 `uv lock --check`가 통과했다. Chromium axe 13개 상태는 위반 0건·외부 요청 0건이었고, 별도 합성 UI 검사에서 320/640/767/768/1024/1200/1440/1600/2000 CSS px 가로 넘침 0건, 2열 사례, keyboard disclosure·focus·scroll·reduced-motion 계약을 확인했다. UTC와 Asia/Seoul에서 axe rule 결과는 모두 비어 있었고 workspace 수치도 일치했다. 합성 평가는 인증·웹 79/79, Linux Audit 21/21, risk/case 70/70이었다. 이 자동 결과는 위 표의 실제 Safari 200% 확대, VoiceOver, 사용자 이해도 또는 WCAG 2.2 AA 준수 증거를 대체하지 않는다.

수용 기록 작성 뒤 UI·API·SSE·privacy focused pytest는 **40 passed·기존 경고 2개**, 전체 pytest는 **2,380 passed·기존 경고 2개**였다. Python compileall, Node 문법, `git diff --check`도 통과했다. 별도 Node 동작 스크립트는 JSON stdin을 받는 pytest helper이므로 입력 없는 직접 호출의 파싱 오류는 테스트 실패로 계산하지 않았고, 이를 호출하는 pytest 계약은 전체 회귀에서 통과했다.

## 수정·개인정보·정리

열거한 Safari 과업에서 production 결함이 재현되지 않았으므로 production code는 수정하지 않았다. API/SSE schema, 분석 의미, production CSP, runtime dependency는 그대로다. 계정·IP·경로·query·원문을 UI나 검수 기록에 포함하지 않는다. 사용자에게는 Web Inspector의 문제 유무만 요청하고 로그 내용이나 파일명을 받지 않았다. 정확한 320 CSS px와 VoiceOver 전체 페이지 읽기는 수행하지 않았으며 WCAG 2.2 AA 준수는 주장하지 않는다.

검수 종료 시 서버에 SIGINT를 보내고 해당 loopback port의 listener 부재를 확인했다. 임시 HOME 아래 합성 log·private config·checkpoint를 함께 제거하고 디렉터리 부재를 확인했다. Screenshot·trace·report artifact는 생성하지 않았다. 실제 사용자 기본 설정은 사용하지 않았다. Secure erase는 주장하지 않는다.

이번에 요청한 실제 Safari 핵심 사용자 과업에는 재현된 blocker가 없었다. 판정은 **검수 범위 PASS**이며, 정확한 320 CSS px 측정과 VoiceOver 전체 페이지 읽기는 명시한 대로 NOT_TESTED다.
