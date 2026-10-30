# Phase 36.10A-UI1 — Cyberpunk Investigation Workspace Redesign

## 1. Executive Summary

기존 Sidebar, Dashboard, Hash Route 기반 사례 상세, Timeline, Evidence, 명시적 Checklist/Guidance를 유지하면서 어두운 네이비와 절제된 Cyan 강조를 적용했다. 이 작업은 화면 스타일과 브라우저 회귀에 한정하며 분석 규칙, API, 공개 Projection, 저장 방식은 바꾸지 않았다.

판정은 검증 완료 후 기록한다. 자동 검증은 합성 데이터와 로컬 Chromium 범위이며 실제 자료 사용, 조직 운영, Safari·VoiceOver·실제 모바일 수용을 승인하지 않는다.

## 2. 시작 Gate

- 저장소: `ai-security-log-analyzer` (`https://github.com/misosos/ai-security-log-analyzer`)
- Branch: `main`
- 기준 SHA: `464c9aaacfeb3012f66b91def016c52447c56624`
- HEAD/local `main`/`origin/main`: 기준 SHA와 일치, ahead/behind `0/0`
- 시작 작업 트리: clean
- GitHub Actions Run `41073085074`: exact SHA, `push`, `completed/success`, artifact 0
- 필수 Python 3.12, 전체 회귀, Linux recovery/SSH, TCP Syslog, JSONL, Restricted report, Chromium/axe, tracked-file 검사 성공
- `v0.4.0` tag/Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

## 3. 기존 UI 문제와 작업 범위

기존 화면은 Sidebar와 조사 워크스페이스를 이미 갖췄다. 이번에는 별도 내비게이션이나 새 페이지를 추가하지 않고 기존 App Shell을 재사용했다. 기본 화면의 라이트 색상, 약한 선택 강조, 제한적인 카드 구분을 개선하고 시작 카드가 그리드 행 높이를 따라 불필요하게 늘어나는 동작을 줄였다.

이번 작업은 참고 이미지의 보안 관제 시각 언어만 가져왔다. 코드 스캐너, Semgrep, 코드 취약점, 파일 코드 미리보기, 규칙 번들 및 Token UI는 추가하지 않았다.

## 4. Design System 및 색상

CSS 토큰은 `frontend/style.css`의 Phase 36.10A-UI1 섹션에 정의했다.

| 용도 | 값 |
|---|---|
| 기본 배경 | `#070b18` |
| Sidebar / 보조 표면 | `#0b1426` |
| 카드 표면 | `#101d33` |
| 선택/hover 표면 | `#152641` |
| 주요 Cyan | `#00d9f5` |
| Magenta | `#d946ef` |
| 보조 Purple | `#a78bfa` |
| 기본 텍스트 | `#e8f1ff` |
| 보조 텍스트 | `#b4c6dc` |
| 기본 테두리 | `#35516d` |

배경 Gradient는 고정 CSS 장식이며 외부 이미지, CDN, 폰트 또는 네트워크 리소스가 없다. Glow는 현재 선택된 Sidebar와 제한된 강조 면에만 적용했다. 지속 애니메이션은 추가하지 않았고 reduced-motion 설정에서 전환을 끈다.

## 5. Typography와 간격

기본 크기를 16px로 두고 본문 line-height 1.6을 유지한다. 페이지 제목은 반응형 1.9~2.55rem, 섹션 제목은 약 1.25rem로 구분한다. Sidebar는 0.98rem, 상단 화면 제목은 1.35rem이며 보조 설명도 14px 수준 아래로 축소하지 않는다.

Main padding과 카드 간격은 넓은 화면에서 늘고 작은 화면에서 줄어든다. 시작 작업 카드는 `align-items: start`와 콘텐츠 기반 Grid를 사용해 서로의 내용 높이를 강제로 맞추지 않는다. 사례 카드는 `align-self: start`로 불필요한 수직 확장을 피한다. 콘텐츠를 고정 높이로 잘라내지 않는다.

## 6. Sidebar와 Header

기존 `#workspace-nav`와 메뉴 버튼을 재사용했다. Desktop Sidebar는 252px이며 기능 제공 여부에 따라 기존 JS가 보여주는 시작, 내 로그, Linux Audit, Live, 결과 항목만 나타난다. 활성 메뉴에 Cyan 경계와 절제된 내부 강조를 적용했고 클릭 높이는 최소 48px이다. 768px 미만에서는 기존 `<details>` 모바일 메뉴를 유지한다.

Header는 화면 제목과 실제 화면 설명을 보여주는 기존 동적 DOM을 유지했다. 연결 상태를 가짜로 추가하거나 Backend 상태를 추측하지 않는다.

## 7. Dashboard, 사례 목록 및 상세

Dashboard의 기존 네 개 집계 카드, 검토 사례 목록, 독립 관찰, 결과 해석, 보고서 연결을 그대로 둔다. 집계는 검증된 API 값에서만 온다. `독립 관찰`, `분석 한계`, 위험도, Source-role, Review Priority 의미를 변경하지 않는다. 실제 사례/관계 수를 임의 생성하지 않는다.

기존 목록에서 상세 DOM을 중복 렌더하지 않는 구조를 유지했다. 선택한 사례는 기존 `#/investigations/{case_ref}` Hash Route의 넓은 상세 화면에서 Overview, Timeline/Relation, 확인 작업, Evidence/Limitations, Checklist를 확인한다. 상세 화면을 하나의 거대한 중첩 카드로 만들지 않고 기존 콘텐츠 구조를 그대로 스타일링했다.

목록 및 상세의 비인과적 표현을 유지한다. Detection은 침해 확정이 아니며 Relation은 인과 증거가 아니다. 관측 시간, Evidence, 분석 한계는 기존 검증된 projection으로만 표시한다.

## 8. Checklist / Guidance와 Navigation

Checklist와 Guidance 요청은 기존 명시적 버튼 동작을 유지한다. 화면 진입, Dashboard 표시, 사례 선택, 탭 이동, hover/focus에서 요청을 보내지 않는다. 기존 상태와 Case A/B 비동기 격리는 변경하지 않았다.

기존 독립 스크립트 `tests/ui_workspace_navigation_28_4.mjs`도 실행했다. 이 스크립트는 현재 36.6C 화면 계약과 다른 DOM 구조를 전제로 해 `GUIDANCE_MUST_BE_OPT_IN`에서 실패했다. Dashboard 목록에 상세 Guidance DOM을 미리 렌더하지 않는 현재 계약과 충돌하는 오래된 assertion이다. 이 파일은 변경하지 않았으며 활성 CI/npm UI 명령에도 연결되어 있지 않다. 현재 유지 중인 `npm run test:a11y`가 명시적 Guidance 요청과 Case별 응답 격리를 실제 Chromium에서 검증한다. 이 구형 스크립트의 나머지 시나리오는 실행되지 않았으므로 통과로 보고하지 않는다.

## 9. Responsive 및 Layout Stability

검증 매트릭스는 1920×1080, 1440×900, 1280×800, 1024×768, 768px, 390px, 320px이며 기존 별도 회귀의 200% equivalent text reflow도 유지한다. 768px 미만은 기존 모바일 Navigation을 사용하고, 카드와 상세는 한 열로 흐른다. 긴 문자열 줄바꿈과 overflow 검사를 유지한다.

Chromium 브라우저 검사에서 화면 폭 초과, 조사 패널 내부 overflow, 잘림, 터치 대상 크기/간격 위반을 확인했다. UI 회귀의 viewport에는 1920×1080, 1440×900, 1280×800, 1024×768, 768×1024, 390×844, 320×568과 200% equivalent reflow가 포함된다. 검사 중 200% 텍스트 확대에서 모바일 콘텐츠가 가로로 넘치는 문제와 사례 카드 간격 부족이 발견되어 작은 화면 패딩과 카드 간격을 보완했다. 수정 후 모든 레이아웃 assertion이 통과했다.

## 10. 접근성

기존 Skip link, landmark, Label, 키보드 경로, focus 복귀, ARIA 관계, reduced motion, 44px 클릭 대상과 axe 검사를 유지한다. 색상만으로 상태를 나타내지 않고 기존 텍스트 badge/label을 보존했다. 신규 강조 색의 명도 대비는 전체 Chromium/axe 상태 모음으로 검증한다.

Chromium/axe 결과는 Safari, VoiceOver 또는 실제 모바일 검증을 의미하지 않는다.

## 11. Privacy, CSP 및 Public Projection

`investigation-workspace-ui/v1`의 19개 필드, 기존 API Response Validation, Hash Route에 opaque case reference만 넣는 정책, Case isolation, Source-role `unknown`, Priority `undetermined`, Checklist v2, Guidance, Report 및 Rollback 경계를 변경하지 않았다. Raw log와 원계정/IP는 UI에 추가하지 않는다.

`app/web_ui.py`의 CSP 및 고정 Asset Serving은 수정하지 않았다. `style-src 'self'`, `style-src-attr 'none'`, `img-src 'none'`, `font-src 'none'`, same-origin `connect-src` 제약과 160 KiB 자산 상한을 유지한다. Inline style/script, 외부 연결, CDN, 외부 Font/Image를 추가하지 않았다.

## 12. Legacy Renderer 및 Rollback

`USE_WORKSPACE_DETAIL_SHELL_36_6B`와 구형 상세 렌더러는 그대로 유지한다. 시각 스타일만 되돌릴 때는 UI1 CSS 구간을 제거 또는 되돌리고, 별도 기능 롤백은 기존 switch를 사용한다. API, 데이터 마이그레이션, Backend 변경은 필요하지 않다. 기존 Phase 36.6G의 `KEEP_LEGACY` 결정을 유지한다.

Rollback trigger는 axe 대비 위반, overflow/clipping, route 또는 Case 혼입, 잘못된 Badge 의미, 자동 Checklist/Guidance 요청, Privacy canary, 외부 요청 또는 기존 렌더러 회귀다.

## 13. 테스트 및 화면 검증

기준 `uv run pytest -q`: `3367 passed, 2 warnings`. 최종 `uv sync --locked --dev`, `uv lock --check`, `uv run pytest -q`: `3367 passed, 2 warnings` (186.54초). `python3 -m compileall -q app tests`, `uv lock --check`, `git diff --check`, `node --check tests/ui_accessibility_axe_pilot_28_1.mjs`도 성공했다. Python 경고 2건은 기존 Starlette/httpx 및 AnyIO deprecation이다.

UI 회귀는 합성 입력과 로컬 Chromium을 대상으로 `npm run test:a11y --silent`로 실행했다. 결과: `states=25`, `external_requests=0`, 종료 코드 0. 25개 상태 전부 axe 위반 없음, viewport/overflow/target-size/layout 검증 통과, Cyberpunk 토큰과 Sidebar 폭 검증 통과. Privacy canary·Checklist/Guidance 명시적 요청·Case 격리 assertions도 통과했다. 화면 캡처는 `/tmp/ui1-before/`와 `/tmp/ui1-after/`에 저장했으며 저장소에는 추가하지 않았다. 비교 대상은 `start-1440.png`, `dashboard-1440.png`, `case-detail-1440.png`다. 같은 Chromium·합성 데이터에서 시작 화면, 실제 Dashboard 요약 및 Case 상세의 Before/After를 검토했다. After는 네이비 App Shell, 선택 상태 Cyan 표시, 읽기 쉬운 집계/사례 목록 및 넓은 상세 콘텐츠로 바뀌었고, 실제 API projection 내용은 그대로였다.

## 14. 변경 파일

최종 diff 확인 후 변경 파일과 자산 크기를 기록한다. 허용 범위는 Frontend CSS, Browser regression, 이 문서 및 `docs/index.md`다. Backend 분석 코드, API/schema, Evaluation, CSP, Dependency/lockfile은 변경하지 않는다.

## 15. 미검증 범위 및 사용자 수용

- 실제 사용자 로그·조직 운영·자동 대응: `NO_GO`
- 실환경 탐지 정확도 및 실제 조직에서의 사용성: `UNVERIFIED`
- Safari·VoiceOver·실제 모바일 기기: `NOT_TESTED`
- Vector/VM: `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`
- OS-level hard CPU/memory cap 및 강제 종료 후 secure erase: 미보장
- Renderer: `KEEP_LEGACY`

최종 사용자 수용은 Chromium 자동 검증과 별도다. 실제 사용자 자료 없이 시작 화면, Dashboard, 상세, 오류 상태의 가독성/탐색을 사용자가 확인해야 한다. 구형 `ui_workspace_navigation_28_4.mjs`는 현재 구조에 맞지 않는 선행 기대에서 중단됐으며 나머지는 미검증이다. 활성 Browser E2E는 통과했지만 이 비활성 스크립트의 전체 시나리오를 검증했다고 주장하지 않는다.

## 16. 최종 판정

`PHASE_36_10A_UI1_CYBERPUNK_REDESIGN_LOCAL_CONDITIONAL_GO`. 활성 Chromium/axe E2E와 전체 pytest가 통과했다. 비활성 과거 Navigation 스크립트의 stale DOM 가정 및 미실행 나머지 시나리오는 잔여 검증 공백으로 기록했다. 로컬 conditional 결과는 운영 승인이 아니다.
