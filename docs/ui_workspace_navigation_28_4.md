# Phase 28.4 — 조사 작업 화면 탐색

## 문제와 결정

기존 화면은 시작, 로컬 파일 입력, Linux Audit 입력, 실시간 모니터링, 분석 결과가 한 문서에 차례로 놓였다. 예시 분석을 시작한 뒤 결과를 보려면 아래쪽으로 이동해야 했고, 결과를 확인하는 동안 다른 입력 영역도 같은 페이지에 남았다. 시작점 `7be5779c7d02ca7582529b713c739d574e806f27`의 전체 회귀 기준선은 2,367 passed·기존 경고 2개이며, [정확한 SHA의 CI run](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39373619164)은 completed/success였다.

최종 탐색은 **시작 · 내 로그 분석 · Linux Audit · 실시간 모니터링 · 결과**다. 예시 데이터는 시작 화면의 주 행동이므로 별도 빈 메뉴를 만들지 않았다. 로컬 입력 두 항목은 loopback에서만, 실시간 모니터링은 `--monitor` 상태가 확인된 경우에만, 결과는 실제 표시할 결과가 생긴 뒤에만 탐색에 나타난다. 선택 상태는 `aria-current="page"`와 “현재” 텍스트, 배경·테두리로 함께 표시한다. 하나의 주요 패널만 보이며 URL hash·history·storage는 사용하지 않는다.

## 공식 패턴 참고

| 공식 자료 | 채택한 구조 | 채택하지 않은 요소 | 라이선스·출처 |
| --- | --- | --- | --- |
| [PatternFly Page](https://www.patternfly.org/components/page/design-guidelines/), [Empty state](https://www.patternfly.org/components/empty-state/design-guidelines/) | 탐색과 작업 패널 분리, 빈 화면의 다음 행동 | React 구성요소·브랜드·전면 디자인 토큰 | [PatternFly MIT](https://github.com/patternfly/patternfly/blob/main/LICENSE); 코드와 asset은 복사하지 않음 |
| [Primer NavList](https://primer.style/product/components/nav-list/), [접근성 지침](https://primer.style/product/components/nav-list/accessibility/) | 이름 붙은 탐색, 한 선택 항목의 프로그램적 상태, 키보드 순서 | URL 전환용 링크·React NavList·아이콘 | [Primer MIT](https://github.com/primer/design/blob/main/LICENSE); 패턴만 참고 |
| [Carbon left panel](https://www.carbondesignsystem.com/building-blocks/core/components/ui-shell-left-panel/guidelines) | 지속적인 작업 영역 탐색의 위치 | 고정 overlay·여러 단계 메뉴·Web Components | [Carbon Apache-2.0](https://github.com/carbon-design-system/carbon/blob/main/LICENSE); 구현 미복사 |
| [GOV.UK error summary](https://design-system.service.gov.uk/components/error-summary/), [details](https://design-system.service.gov.uk/components/details/) | 입력 오류의 해당 패널 내 요약과 keyboard disclosure | GOV.UK 브랜드·CSS·Nunjucks | [코드 MIT](https://design-system.service.gov.uk/components/), [문서 OGL 3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/); 코드·문구 미복사 |

현재 vanilla JS와 기존 CSS로만 구현했다. 외부 CDN·아이콘·폰트·새 런타임 의존성은 추가하지 않았다.

## 화면·focus·scroll 계약

최종 구조는 viewport 전체를 채우는 `.app-shell`이다. 왼쪽 navigation이 화면 왼쪽 끝에서 시작하며 1200px 이상에서 240px, 768–1199px에서 200px을 차지한다. 오른쪽 `.app-area`는 남은 폭 전체를 사용하고 header와 main을 포함한다. 별도 footer와 중앙 `max-width` wrapper, 전체를 감싸는 흰 panel은 없다. 필수 source checkout 안내는 sidebar 하단에 둔다. `position: fixed`나 본문 내부 스크롤은 쓰지 않는다. 시작 화면은 예시 데이터·내 로그·Linux Audit의 세 action card를 한 줄에 배치하고, 길이가 짧은 화면 나머지는 중립 배경으로 남긴다. 결과 제목·한계와 요약 4개는 전체 폭, 조사 사례 두 개는 왼쪽 2열 카드, 제공 범위·보고서는 오른쪽 보조 영역에 놓는다. DOM도 조사 사례 다음 보조 영역 순서다. 긴 문단은 최대 72ch, 시작 설명은 최대 65ch를 유지한다. 1199px 이하에서는 결과 본문과 사례가 1열로 접힌다. 767px 이하에서는 native `details` 탐색이 현재 영역을 표시하고 메뉴를 펼친다. 선택 뒤 닫히며 제목으로 focus를 옮기고, Escape로 닫으면 summary로 focus를 복귀시킨다.

1440px 합성 결과 2사례의 원래 긴 화면 작업 영역/패널/문서 높이는 **1152/912/1926 CSS px**였다. 가운데 wrapper를 사용한 중간안은 2000px viewport에서도 작업 영역이 1600px에 제한되어 사용자 피드백을 충족하지 못했다. 전체 폭 셸과 압축한 사례 요약의 1440px Chromium 측정은 **셀 1440px/sidebar 240px/결과 패널 1120px/문서 높이 945px**였다. 결과 문서 높이는 초기 화면보다 **981px(약 51%) 감소**했다. 2000px에서는 **셀 2000px/sidebar 240px/app area 1760px/문서 높이 900px**이고, 시작 화면의 큰 흰 panel 면적은 최종 구조에서 **0px²**이다. 첫 화면의 세 action card는 2000px에서 3열이며, 시작 설명은 약 65ch로 제한했다. 글자 크기 16px와 계산된 줄 높이 24.8px는 줄이지 않았다. 이 수치는 Chromium 합성 viewport 측정이며 실제 Safari 확대 결과가 아니다.

시작 패널은 목적, 침해 확정이 아니라는 한계, 예시·내 로그 행동을 표시한다. 예시/로컬/Linux Audit 분석을 사용자가 명시적으로 시작해 성공했을 때만 오른쪽 결과 패널을 선택하고 결과 제목에 focus를 둔다. 선택이 끝나면 결과 제목은 같은 작업 위치에 보이므로 사용자가 페이지 아래를 직접 찾을 필요가 없다. 탐색 버튼도 명시적 선택일 때만 해당 제목으로 focus를 옮긴다. SSE 수신만으로는 선택·focus·scroll을 바꾸지 않는다. Live pending은 탐색 배지와 원래의 “새 결과 N건 보기”에만 반영된다. 그 버튼을 누르면 결과 패널에 live 상세가 열린다. 위험도 하향·NO_LONGER_MATCHES와 replay gap의 주의 문구는 안전/해결로 바뀌지 않는다.

탐색은 기존 DOM 노드의 `hidden` 상태만 바꾼다. 분석 요청을 다시 보내거나 `EventSource`를 생성하지 않는다. 실제 연결은 기존 `live-monitoring.js`의 한 곳에서만 생성되고, 패널 왕복만으로 연결 수가 늘지 않는다. Live 상태가 비활성인 기본 실행에서 메뉴는 숨긴다. 오류 요약은 요청한 입력 패널에 표시하며 관련 입력 오류와 함께 읽힌다. 결과가 없는 경우의 기존 안내는 안전 상태로 표현하지 않는다.

## 개인정보·CSP와 자동 검증

API·SSE schema, 탐지·상관분석·risk·case 의미, 승인된 공개 projection, 기존 CSP, static asset route는 그대로다. 원본 로그·계정·IP·경로·query를 새 탐색 state나 DOM 속성에 넣지 않는다. `innerHTML`, `insertAdjacentHTML`, 외부 요청, 브라우저 storage, 새로운 router는 없다. 테스트는 합성 응답과 임시 HOME의 loopback 서버만 사용한다. 기본 서버의 비활성 live status 404는 예상된 응답으로 분리하고, 예상 밖 console/CSP/Network 오류와 혼동하지 않는다.

새 계약 테스트는 구현 전 세 항목에서 실패했다: 이름 붙은 탐색·단일 선택 패널 부재, 결과 패널 전환·pending 배지 부재, 반응형 탐색 부재. 넓은 결과의 기존 **1152px 작업 폭·1926px 문서 높이·1열 사례**, 2000px 화면의 **72% 폭**, mobile 접기 메뉴 부재도 실패 테스트로 고정했다. 전체 폭 수정 전에는 `.app-shell` 부재가 새 계약 테스트에서 실제 실패했다. 기존 UI/Node/API/SSE/privacy 계약은 유지한다. Chromium 자동 검사에서는 13개 axe 상태, 한 패널 불변식, keyboard 선택, 결과 제목의 viewport 위치, 320/640/767/768/1024/1200/1440/1600/2000 CSS px 가로 넘침, 1024px 결과 1열, 1600px·2000px 셀 전체 폭, mobile Enter/Escape focus, reduced motion, 단일 EventSource를 확인한다. 이 자동 결과는 실제 Safari 200% 확대나 VoiceOver 검수가 아니다.

최종 자동 재검증에서 전체 pytest **2,378 passed·기존 경고 2개**였다. 첫 sandbox 실행은 기존 Unix socket 테스트 12건이 권한 부족으로 실패했고, 권한을 갖춘 동일 전체 회귀에서는 모두 통과했다. 접근성 13개 상태는 UTC와 Asia/Seoul에서 각각 위반 0개·외부 요청 0건이었으며 제외 rule은 없다. 실제 loopback 합성 Chromium 검사는 320/640/767/768/1024/1200/1440/1600/2000 viewport에서 가로 넘침 0, mobile 메뉴의 Enter·Escape와 focus 복귀, 예시 요청 1회, 예상 밖 콘솔 오류 0, 외부 요청 0이었다. 기본 서버에서 모니터링 비활성 상태를 알리는 `/api/v1/live/status`의 예상된 404 한 건은 별도 기록했다. 합성 평가 **79/79**, Linux Audit **21/21**, risk/case **70/70**이 통과했고, `npm ci --ignore-scripts --no-audit --no-fund`, `uv lock --check`, Python·Node 문법 검사와 `git diff --check`도 통과했다. 합성 screenshot은 로컬 임시 자료로만 육안 검토한 뒤 디렉터리 존재 여부를 확인하고 삭제한다. Commit·CI artifact에는 포함하지 않는다.

## 실제 Safari 수동 검수

macOS·Safari 버전과 loopback/임시 HOME 조건을 기록하고, 사용자에게 탐색 항목 발견 → 결과 위치 → 선택 표시 → 좁은 창 → 실제 200% → keyboard-only → VoiceOver 범위 → Inspector → EventSource 중복 여부를 한 과업씩 확인받는다. 사용자가 본 것만 PASS로 기록하고 미확인 항목은 NOT_TESTED로 남긴다. 자동 axe 통과로 WCAG 2.2 AA 준수나 실제 Safari 검수를 주장하지 않는다.

검수 준비 환경은 **macOS 15.7.7, Safari 18.6**, private 임시 HOME과 `127.0.0.1` 전용 서버다. Safari 앞 창의 바깥 너비는 AppleScript 읽기에서 **1920pt**였으나 CSS viewport 폭과 동일하다고 주장하지 않는다. Safari의 Apple Events JavaScript 읽기는 사용자 설정에서 비활성이라 `window.innerWidth`를 자동 측정하지 못했고, 설정을 변경하지 않았다. WebDriver 조작은 사용자 직접 검수 증거로 계산하지 않는다. 실제 Safari CSS viewport·최소 창 너비·페이지 확대 배율·Tab/Option+Tab 방식은 사용자 응답 전이므로 기록하지 않는다.

| 사용자 과업 | 상태 | 기록 |
| --- | --- | --- |
| 전체 폭 sidebar·시작 행동 카드 | NOT_TESTED | 아이콘 도입 전 새 셸에서 사용자가 PASS. 최종 아이콘 화면은 재확인 전 |
| 왼쪽 탐색으로 작업 찾기 | NOT_TESTED | 가운데 wrapper를 사용한 중간안에서 사용자 PASS. 최종 전체 폭 셸의 작업 발견성은 재확인 전 |
| 결과 선택 후 추가 스크롤 없이 오른쪽 결과 보기 | NOT_TESTED | 아이콘 도입 전 새 셸에서 사용자 PASS. 최종 아이콘 화면은 재확인 전 |
| 현재 선택 항목 구분·작업 화면 전환 | NOT_TESTED | 아이콘 도입 전 새 셸에서 사용자 PASS. 최종 아이콘 화면은 재확인 전 |
| 좁은 창·실제 200% 페이지 확대 | NOT_TESTED | 사용자 직접 확인 전 |
| Safari keyboard-only·VoiceOver | NOT_TESTED | 사용자 직접 확인 전 |
| Web Inspector JS/CSP/Network·중복 EventSource | NOT_TESTED | 사용자 직접 확인 전 |
