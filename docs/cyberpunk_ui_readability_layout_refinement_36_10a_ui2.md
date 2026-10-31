# Phase 36.10A-UI2 — Cyberpunk UI 가독성 및 레이아웃 보완

## 1. Executive Summary

UI1의 짙은 네이비·시안 사이버펑크 테마와 기존 왼쪽 탐색을 유지하면서, Desktop 사이드바·글자·카드 여백을 키웠다. CSS cascade를 따라 기존 252px Desktop 폭이 UI1 후반 override에서 결정되는 점을 확인하고, 이를 280px로 조정했다. 시작 화면의 분석 흐름과 실제 입력 경로 카드가 넓은 화면을 쓰도록 했으며, 작은 화면에서는 기존 모바일 탐색과 단일 열 구성을 유지했다.

API, 분석 파이프라인, 공개 Projection, Checklist/Guidance 요청 계약은 변경하지 않았다. 합성 Browser 회귀는 전체 25개 상태를 통과했다. Chromium 결과는 자동화 검증 근거이며 Safari 사용자의 최종 수용 확인을 대신하지 않는다.

## 2. 시작 Gate 및 CI

- Repository: `ai-security-log-analyzer`
- Branch: `main`
- 기준 HEAD / local main / origin main: `641d504fff7cac3c09a76c1a39ed019ff4132634`
- 시작 Working Tree: clean, ahead/behind `0/0`
- GitHub Actions Run `41171148402`: exact SHA 일치, `push`, `completed / success`, 필수 Linux/Python/Chromium 검사 성공, artifact 0개
- 기존 v0.4.0 tag/Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`로 유지

CI 근거는 원격 Linux 경로이고, 이 문서의 추가 UI 실측은 로컬 Chromium/macOS 경로다. 두 결과를 동일한 환경으로 취급하지 않는다.

## 3. UI1 대비 변경 및 Safari 스크린샷 문제

사용자 Safari 캡처에서 사이드바와 본문이 좁고 작게 느껴진다는 지적을 받았다. 캡처의 물리 픽셀만으로 CSS viewport, browser zoom 또는 DPR을 추론할 수 없으므로 이를 CSS 크기 측정값으로 사용하지 않았다. Chromium 측정은 DPR 1, 명시한 CSS viewport에서 수행했다. Safari의 zoom 100% 및 실제 DPR은 이 작업 환경에서 측정하지 않았다.

UI1 cascade에서 Desktop sidebar는 기본 240px 위에 후반 UI1 override 252px가 적용됐다. 약 1200px 미만 구간에는 추가 축소 규칙이 있었고, 768px 미만은 모바일 탐색이었다. UI2에서는 최종 cascade 값이 1200px 이상 280px, 901–1199px 248px, 768–900px 220px, 768px 미만 단일 열이 되도록 명시했다.

## 4. Sidebar 및 Typography 실측

Computed Style과 실제 bounding rectangle 기준 비교다. CSS px이며 브라우저 확대를 보정한 물리 화면 크기가 아니다.

| 항목 | UI1 | UI2 측정 |
|---|---:|---:|
| Desktop sidebar (1440px) | 252px | 280px |
| 1024px sidebar | 220px | 248px |
| 768px sidebar | 220px | 220px |
| 390px / 320px navigation | 기존 모바일 단일 열 | 전체 폭 상단 Navigation |
| 브랜드 제목 | 17.28px | 약 20.06px |
| Desktop 메뉴 | 15.68px | 18.02px; 실제 높이 51.89px |
| 본문 기본 | 16px | 17px, root line-height 1.58 |
| lead 설명 | 17.28px | 18.36px |
| 카드 제목 | 20px | 22.1px |
| 카드 설명/helper | 16px | 17px |
| 버튼 | 16px | 17px, 높이 50.42px |
| 시작 카드 좌우 padding | 21.6px | 25.5px |
| 시작 카드 gap | 20px | 22.95px |

기본 페이지 제목은 화면 너비에 맞춘 `clamp()`로 실측상 1440px에서 40.32px, 1920px에서 44.2px이었다. 1280px에서 35.84px, 1024px에서 34px이다. UI1 대비 증가폭은 h1 selector에 따라 다르며 기존 `#page-title`도 큰 값이어서, 이 수정은 제목만 확대하기보다 본문·탐색·카드의 상대적 크기와 공간 활용을 맞춘다.

## 5. Main Layout 및 카드 안정성

- Main 좌우 padding: 1440px에서 30.24px, 1920px에서 40.32px; 작은 Desktop 구간은 콘텐츠 폭에 맞춰 축소
- 시작 화면 3개 실제 분석 경로 카드는 Desktop에서 3열, 중간 폭에서 2열 또는 1열, Mobile에서 단일 열
- 카드 높이는 콘텐츠에 의해 결정된다. 새 고정 높이를 두지 않았다.
- 긴 한국어 설명은 단어 단위 줄바꿈을 보존하고, Case detail·Evidence·Guidance의 긴 내용은 최소 폭과 wrap을 제한해 좁은 화면 넘침을 막는다.
- 접힌 안내 disclosure, loading/empty/error, Case 목록과 상세를 포함한 실제 DOM 상태에서 검사했다.

1440px Chromium 화면에서 카드 폭은 각각 약 351.22px, 1920px에서 약 504.5px이었다. Main 콘텐츠는 실제로 사이드바 오른쪽부터 내부 padding까지 확장됐다. 시작 화면과 Case 상세 전부 1920/1440/1280/1024/768/390/320px에서 document/body 가로 overflow가 없었고 Browser assertion의 clipped 요소도 0이었다.

## 6. Responsive 및 200% equivalent reflow

검사 viewport: `1920×1080`, `1440×900`, `1280×800`, `1024×768`, `768×1024`, `390×844`, `320×568`.

768px 미만에서는 기존 상단 모바일 탐색을 유지했다. 320px에서도 document와 body의 scroll width가 320px였다. 200% equivalent reflow는 테스트가 root font size를 32px로 바꿔 320px viewport에서 수행했다. document/body overflow, panel overflow, clipping, 주요 target-size 실패는 0이었다. 이는 실제 브라우저의 200% zoom과 같다고 주장하지 않는다.

## 7. Accessibility 및 기능 계약

활성 `tests/ui_accessibility_axe_pilot_28_1.mjs`에 Computed Style 및 bounding rectangle 기반 크기 assertion을 보완했다. 기존 navigation, keyboard focus, ARIA, target 크기·간격, reduced motion, axe 검사와 합성 Privacy Canary는 유지했다. 활성 테스트의 전체 실행은 `states=25`, `external_requests=0`으로 끝났다. Safari/VoiceOver 검증은 수행하지 않았다.

### 구형 Navigation 테스트

`tests/ui_workspace_navigation_28_4.mjs`는 구문 검사에는 통과하지만 실행 시 기존 `GUIDANCE_MUST_BE_OPT_IN` assertion에서 실패한다. 해당 assertion은 분석 후 Dashboard에 `.guidance-request` 버튼 2개가 있어야 한다고 기대한다. 현행 구조에서는 Guidance 컨트롤이 Case Detail에만 나타나며 Dashboard 진입/표시 자체가 Guidance POST를 요청하지 않는다. 활성 Browser 테스트는 Dashboard에서 요청이 없는 상태, Case Detail의 단일 명시적 버튼, 클릭 시 요청, Case A에서 B로 이동할 때 비동기 응답 격리를 실제로 검증한다. 따라서 이는 현행 기능 회귀가 아닌 오래된 DOM 위치/개수 가정이다. 구형 보안 assertion은 변경하거나 삭제하지 않았고, 별도 테스트 현대화 작업으로 남긴다.

분석·Navigation 불변 계약:

- `investigation-workspace-ui/v1` 19-field Projection, Hash route, Back/Forward, Case isolation 유지
- Source-role `unknown`, Review Priority `undetermined`, limitation/independent observation count의 기존 의미 유지
- Checklist v2와 Guidance는 명시적 사용자 요청만 실행
- API, Parser, Detector, Correlation, Risk, Case, provenance 및 Public schema 미수정
- CSP, 고정 asset serving 및 160 KiB per-asset bound 미완화; 외부 요청 0건
- `USE_WORKSPACE_DETAIL_SHELL_36_6B` 및 `KEEP_LEGACY` Renderer rollback 경계 보존

## 8. Design Taste 검사와 화면 비교

검토한 합성 화면:

- UI1 이전: `/tmp/ui2-before-1440.png`
- UI2 Browser 회귀 화면: `/tmp/ai-security-log-ui2-final-acceptance/desktop-1440-fold.jpg`, `desktop-1920-fold.jpg`

1440px에서는 메뉴·본문·카드 설명을 읽기 쉽게 키웠고, 1920px에서는 세 카드가 각 약 504px로 확장되어 넓은 작업 공간을 사용한다. 고정 높이로 하단 내용을 자르지 않는다. 캡처는 로컬 임시 파일이라 커밋하지 않았다.

Design Taste inspector는 첫 검사에서 `covered-text` 및 `unused-canvas` 두 finding을 냈다. `covered-text` 텍스트는 `#first-visit-details`의 닫힌 `<details>` 안에 있는 설명 제목이다. disclosure가 닫히면 일반 브라우저에서 감춰지며 실제 화면의 다른 요소가 위에 올라가 있지 않다. `unused-canvas` 1920px 추정은 텍스트/컨트롤 오른쪽 끝의 percentile을 사용해 198px 여백으로 보고했지만, 실제 Chromium에서 app-content는 x=280부터 폭 1640px이고 내부 workspace는 폭 1559.375px로 x=320.3125부터 1879.6875까지 이어졌다. 직접 캡처도 공간 활용을 확인했다. 두 finding은 검사기의 일반적인 heuristic이 이 화면의 접힌 disclosure 및 컨테이너 배경을 잘못 해석한 것으로 판별했으며, 이유를 확인한 뒤 별도로 적었다. 이를 무조건 PASS로 둔갑시키지 않는다.

## 9. 테스트

- `uv sync --locked --dev`: PASS
- `uv lock --check`: PASS
- `uv run pytest -q`: `3367 passed, 2 warnings` (209.68s)
- `python3 -m compileall -q app tests`: PASS
- `node --check tests/ui_accessibility_axe_pilot_28_1.mjs`: PASS
- `npm run test:a11y --silent`: PASS, `states=25`, `external_requests=0`, 최종 실행 127.397s
- `git diff --check`: PASS
- Static asset sizes: CSS 60,300 bytes, JS 149,889 bytes; each is below the existing 160 KiB serving bound. Other served assets are also below the bound.
- 구형 `node tests/ui_workspace_navigation_28_4.mjs`: 기존 `GUIDANCE_MUST_BE_OPT_IN` at line 111 재현. 상세 의미와 활성 Browser 테스트의 현행 계약 검증은 위 “구형 Navigation 테스트” 절 참조.

## 10. 변경 파일

- `frontend/style.css`: UI2 전용 CSS cascade와 좁은 Case detail wrap 보정
- `tests/ui_accessibility_axe_pilot_28_1.mjs`: 화면 크기/overflow 실측 assertion 및 실패 진단
- `docs/cyberpunk_ui_readability_layout_refinement_36_10a_ui2.md`: 본 기록
- `docs/index.md`: 문서 링크

분석 API 및 pipeline 변경 없음.

## 11. Rollback 및 미검증

Rollback은 이 Phase 커밋에 대한 `git revert`로 UI2 CSS, Browser assertion, 문서 링크를 함께 되돌린다. Production/분석 코드는 변경되지 않았으므로 데이터 마이그레이션은 없다. 기존 UI1 CSS와 Renderer rollback 경계는 그대로 있다.

Safari의 실제 CSS-pixel viewport, 100% browser zoom, DPR, 실제 표시 가독성 및 사용자 수용은 미검증이며 사용자의 Safari 확인이 남아 있다. VoiceOver와 실제 iOS 기기도 실행하지 않았다. Chromium과 axe 자동화는 이 제한을 대체하지 않는다.

## 12. 최종 판정

`PHASE_36_10A_UI2_READABILITY_LOCAL_CONDITIONAL_GO`

이는 로컬 합성 Browser 및 regression 범위의 결과다. Safari 사용자 수용, VoiceOver, 실제 모바일 수용은 별도로 수행해야 한다.
