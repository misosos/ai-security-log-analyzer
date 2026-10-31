# Phase UI4A — 사이드바 접기 버튼 간소화 및 브랜드 헤더 통합

## 변경 목적

UI4의 전체 사이드바 접기 버튼이 브랜드 아래 별도 행을 차지했다. 기존 폭, 색상, 브랜드, 접힌 아이콘 레일 및 카테고리 Accordion을 유지하고, 접기 조작을 브랜드 헤더의 아이콘 버튼으로 옮겼다.

## 시작 Gate

- 시작 SHA: `e5fcfaa6bad4ce28963d2b07ac338db220783936`
- Branch: `main`; local HEAD/main, origin/main, GitHub main 일치; Working Tree clean; ahead/behind `0/0`
- Exact-SHA GitHub Actions Run `41210793706`: `push`, `completed/success`; Locked Python 3.12, 전체 Regression, Linux checkpoint/SSH/TCP Syslog/JSONL, Restricted Report, Chromium/axe 및 tracked-file 검사 성공
- Artifact: 0개
- v0.4.0 target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

## Before / After

Before:

```text
🛡 Security Log
   LOCAL ANALYZER

   [사이드바 접기]

로컬 조사 작업공간
```

After:

```text
🛡 Security Log       [panel-left-close]
   LOCAL ANALYZER

로컬 조사 작업공간
```

전용 버튼 행을 제거해 `#workspace-sidebar-toggle`을 `.brand-lockup` 안으로 이동했다. 헤더 아이콘은 프로젝트 SVG sprite의 `icon-panel-left-close` / `icon-panel-left-open`을 사용한다. 외부 CDN이나 라이브러리는 추가하지 않았다. 버튼에는 낮은 장식의 투명 배경, Cyan hover/focus 표시와 44×44px hit area를 적용했다.

## 동작 및 접근성

- 넓은 화면에서는 브랜드 헤더 토글이 320px 사이드바를 기존 88px 아이콘 레일로 접고 펼친다. 열림/닫힘 전 카테고리 Accordion 상태를 복원한다.
- 768px 미만에서는 전체 레일 대신 기존 상단 탐색 disclosure를 토글한다. 버튼의 `aria-controls`, `aria-expanded`, 접근 가능한 이름은 실제 상태에 맞춰 갱신된다. `<button>` 기본 Enter/Space 동작을 사용한다.
- 메뉴 텍스트를 아이콘 레일에서 시각적으로 감춰도 접근성 트리에 유지한다. 기존 메뉴 버튼의 이름, title, 현재 페이지 표시를 보존한다.
- 그룹별 Accordion은 각 그룹의 Chevron과 네이티브 `details/summary`로 별도 유지한다.

## 검증

- Sidebar E2E에서 1920, 1440, 1280, 1024, 768, 390, 320px와 320px/200% equivalent를 순회하며 헤더 요소의 겹침, 토글 크기 및 화면 overflow를 검사한다.
- 1440px 접기/펼치기, close/open 아이콘, 상태에 맞는 접근 가능한 이름, Accordion 상태 복원, 390px 모바일 메뉴 열기/닫기를 검증했다.
- `npm run test:a11y --silent`: axe 25개 상태 통과, 외부 요청 0건. 새 접기 상태 자체도 axe 검사에 포함한다. 모든 지정 viewport와 200% equivalent에서 overflow, clipping, target size/gap 실패 0건.
- `node tests/ui_navigation_closure_36_10a_ui3.mjs`: 통과; Hash/Case Navigation, Case isolation, Checklist/Guidance opt-in, CSP 유지; 외부 요청 0건.
- `uv run pytest -q`: **3463 passed, 2 warnings**. 경고는 기존 Starlette/httpx 및 anyio deprecation이다.
- `uv lock --check`, `python3 -m compileall -q app tests`, `git diff --check`: 통과.
- 시각 확인 스크린샷은 `/tmp/phase-ui4a-screenshots/` 아래 `ui4a-1440-expanded.png`, `ui4a-1440-collapsed.png`, `ui4a-390.png`, `ui4a-320.png`, `ui4a-320-200pct.png`로 저장했으며 저장소에는 포함하지 않는다.

## Privacy / 범위 / Rollback

변경은 frontend navigation markup/style/상태 동기화, UI 테스트와 문서에 한정한다. Backend 분석 동작, API/schema, Public Projection, Checklist/Guidance 요청 계약은 바꾸지 않았다. Private Context나 원 로그를 표시하지 않으며 CSP와 외부 요청 0건 계약을 유지한다.

롤백은 이 Phase 커밋만 되돌려 토글을 이전 전용 행 위치로 복원하는 방식으로 제한한다. 기존 UI4 메뉴 구조와 분석 동작을 바꿔 되돌리지 않는다.

Safari 실사용 수용은 수행하지 않았다: `SAFARI_USER_ACCEPTANCE_PENDING`. VoiceOver 및 실제 모바일 기기 검수도 미실시다. `KEEP_LEGACY` Renderer와 실제 사용자 자료/조직 운영/자동 대응 `NO_GO` 상태를 유지한다.

## 최종 판정

`PHASE_UI4A_SIDEBAR_COLLAPSE_REFINEMENT_LOCAL_CONDITIONAL_GO`

이 판정은 UI 구조와 자동화 회귀 확인에 한정되며 Safari 사용자 수용을 의미하지 않는다.
