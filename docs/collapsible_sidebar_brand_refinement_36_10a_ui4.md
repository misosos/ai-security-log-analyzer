# Phase 36.10A-UI4 — 접이식 사이드바와 브랜드 정돈

## 목적

탐색 항목이 적더라도 화면 전체에 단순 나열되던 기존 사이드바를 제품 마크와 탐색 그룹 중심으로 정리했다. 기존 Cyberpunk navy/cyan 색상, 화면 전환 버튼의 ID, 분석 데이터 흐름과 사용자 opt-in 동작은 유지했다.

## 시작 Gate

- 기준 SHA: `1c43c6f767034c1dea16513e6e1b121cad9fddc8`
- Branch: `main`; local HEAD/main, origin/main, GitHub main 동일; 시작 Working Tree clean; ahead/behind `0/0`
- exact-SHA Actions Run `41205419543`: `push`, `completed/success`; 필수 Locked Python, pytest, Linux, SSH, TCP Syslog, JSONL, Restricted Report, Chromium/axe 및 tracked-file 검사 성공
- Artifact: 0개
- v0.4.0 tag/release target은 검사만 했으며 변경하지 않았다.

## 변경 내용

- 상단을 방패 심볼과 짧은 `Security Log` 제품명, `LOCAL ANALYZER` 보조 라벨로 바꿨다. 브랜딩은 링크로 취급하지 않아 기존 화면/hash route를 바꾸지 않는다. 프로젝트 전체 이름은 문서 제목과 HTML 문서 제목에 유지한다.
- 항목을 `조사 시작`, `분석 결과`, `보조 도구` disclosure 그룹으로 구성했다. 각 그룹은 네이티브 `<details>/<summary>`를 사용해 키보드 조작과 열린 상태를 제공한다.
- 아직 결과가 없는 동안 `분석 결과` 그룹은 숨기고, 실제 분석 결과가 만들어져 기존 결과 항목이 활성화될 때 표시한다.
- 활성 화면이 바뀌면 해당 메뉴 그룹을 자동으로 펼친다. 결과 화면 버튼은 기존 분석 동작이 결과를 만들기 전까지 계속 숨겨진다.
- 모바일의 기존 전체 메뉴 접기/펼치기와 Escape 동작을 유지하고, 내부 그룹을 세로형 접이식 메뉴로 보여준다.
- 사이드바는 데스크톱 280px에서 320px로 넓혔다. 중간 폭은 901–1199px에서 248px→276px, 768–900px에서 220px→248px로 조정했다. 768px 미만에서는 기존처럼 전체 폭 상단 탐색으로 전환한다.
- 메뉴 행 높이를 최소 52px(모바일 48px), 메뉴 글자를 17–18px대로 맞추고 그룹 사이 구분과 클릭 간격을 늘렸다. 시작 화면의 카드 padding과 흐름 간격도 소폭 늘렸다.

## 계약과 범위

Hash route, 현재 페이지의 `aria-current`, case isolation, Checklist/Guidance의 명시적 요청 조건, 분석 API·schema, detector/correlation/risk/case/report 로직은 바꾸지 않았다. `KEEP_LEGACY` renderer, 실제 사용자 자료/조직 운영/자동 대응 `NO_GO` 상태도 유지한다.

## 검증

- `uv sync --locked --dev`, `uv lock --check`: 통과
- `uv run pytest -q`: `3462 passed, 2 warnings` (Starlette/httpx 및 anyio deprecation warnings)
- `npm run test:a11y --silent`: axe 시나리오 통과; UI 상태 25개, 외부 요청 0건
- 시작 화면의 responsive geometry를 1920, 1440, 1280, 1024, 768, 390, 320 CSS px와 320px/200% equivalent에서 측정했다. 검사 결과 문서/본문 수평 overflow, 검사 대상 panel clipping, 작은 클릭 타깃, target 간격 실패는 없었다.
- `node tests/ui_navigation_closure_36_10a_ui3.mjs`: 통과; case route/isolation, checklist/guidance opt-in, CSP, 외부 요청 0건 유지
- `python3 -m compileall -q app tests`, `git diff --check`: 통과
- UI3 E2E에 disclosure 그룹의 키보드 Space 열기/닫기와 현재 그룹 표시를 확인하는 단계를 더했다.
- Safari 사용자 수용은 자동 Chromium 검증으로 대체하지 않는다. `SAFARI_USER_ACCEPTANCE_PENDING` 상태다.

## 한계

이 변경은 사이드바와 시작 화면의 시각·탐색 개선이다. Safari, VoiceOver, 실제 모바일 기기 사용자 수용은 수행하지 않았다. 넓어진 패널은 768–1199px에서 콘텐츠 폭을 줄이므로 실제 Safari 화면 수용은 별도 확인이 필요하다. UI 변경은 보안 탐지 정확도나 운영 적합성을 입증하지 않는다.
