# Phase 28.4 — 조사 작업 화면의 아이콘과 시각 계층

## 근거와 공급망

| 공식 자료 | 적용 | 도입하지 않은 요소 | 조건 |
| --- | --- | --- | --- |
| [Lucide icons](https://lucide.dev/icons), [공식 저장소](https://github.com/lucide-icons/lucide) | 탐색·시작 행동·결과 요약·위험 상태의 고정 SVG 도형 | 전체 icon runtime, CDN, 원격 폰트 | `lucide-static@1.59.0`, ISC와 일부 Feather 유래 도형의 MIT 고지. [추적된 원문](licenses/lucide-static-1.59.0-LICENSE) 보존 |
| [PatternFly dashboard](https://www.patternfly.org/patterns/dashboard/design-guidelines/), [empty state](https://www.patternfly.org/components/empty-state/design-guidelines/) | 카드당 한 지표, 짧은 빈 상태와 다음 행동 | React·CSS·브랜드·asset | PatternFly MIT, 구조 지침만 참고 |
| [Carbon status indicators](https://www.carbondesignsystem.com/building-blocks/core/patterns/status-indicators) | 도형·색·텍스트를 함께 사용하고 상태 표시 수를 제한 | Carbon 구성요소·색상 세트·브랜드 | Carbon Apache-2.0, 구조 지침만 참고 |

2026-10-21 npm registry metadata의 고정 tarball은 `https://registry.npmjs.org/lucide-static/-/lucide-static-1.59.0.tgz`, integrity는 `sha512-MuHZYaXbHgzN2QO6D3OM19bj09A+8GJiFSdXIMlbnLLEGQQ9+NRH2KaCxuivevD3Y23vM74kV17XBifgtqhfEg==`이다. 내려받은 tarball은 **6,972,252 bytes**였고 SHA-512가 registry 값과 일치했다. `package.json`의 직접 dependency는 0, `preinstall/install/postinstall`은 없고 native `.node/.dylib/.so/.dll/.exe` 파일도 없었다. Tarball 안에는 SVG 2,159개가 있지만 앱에는 전체 tarball이나 package를 설치하지 않았다. `package-lock.json`과 Python runtime dependency는 변경하지 않았다. 브라우저 바이너리·telemetry·version check·외부 runtime fetch는 추가되지 않는다.

추적된 `frontend/index.html`의 inline sprite에 아래 **13개**만 넣었다: `house`, `flask-conical`, `files`, `scan-line`, `clipboard-list`, `activity`, `search`, `link`, `shield-alert`, `folder-search`, `circle-help`, `triangle-alert`, `circle-x`. 공식 1.59.0 SVG의 도형을 고정하고, 계약 테스트가 정확한 이름·SVG 태그·속성 allowlist 및 각 도형의 SHA-256을 검사한다. `currentColor`, 20px 화면 크기, 2px stroke를 사용한다. 재배포되는 소스에 Lucide ISC 및 해당 Feather MIT 고지를 함께 보존한다.

## 적용 범위와 데이터 경계

왼쪽 메뉴는 각 항목 옆에 아이콘과 한국어 텍스트를 둔다. 시작 화면에는 네 단계의 **로그 선택 → 활동 확인 → 관계·위험도 검토 → 조사 사례 확인**을 짧은 strip으로 보여주고, 세 행동 카드에 기능별 아이콘을 둔다. 이 strip은 분석 흐름을 설명할 뿐 공격 성공이나 완료 상태를 뜻하지 않는다. 결과의 승인된 네 집계는 큰 숫자와 텍스트 레이블, 보조 아이콘으로 구분한다. 사례는 위험도와 신뢰도를 별개로 유지하고 주요 활동·관련된 활동을 label/value로 표시한다. LOW에는 완료나 안전을 뜻하는 check 아이콘을 쓰지 않는다.

공개 응답의 `analysis_summary`와 `case_summary`에는 네 요약 개수가 있고, `case_summary`에는 HIGH/MEDIUM/LOW **사례별 최고 위험도** 개수도 있다. 이 값은 전체 관찰이나 분석 대상의 위험 분포가 아니다. 예시의 사례 2건을 segmented bar로 그리면 분모가 작고 범위를 쉽게 오해하므로 이번 단계에는 표시하지 않았다. 사례별 `included_highest_risk`에서 새로운 전체 분포를 다시 추정하지 않는다. Apache ECharts·Chart.js도 넣지 않았다. 새 API 필드나 탐지·risk·case 의미는 바꾸지 않았다. 원본 계정·IP·경로·query·raw line을 아이콘 tooltip, DOM attribute, 집계에 추가하지 않는다.

## 사례 요약과 상세

사용자 피드백에서 기본 사례 카드의 긴 관계 목록과 반복 메타데이터를 확인했다. 카드 기본 영역은 사례 번호, 주요 활동 한 건, 위험도와 신뢰도, 관찰·관련 활동 수, 로그인 실패 후 성공 기록이 포함된 경우의 짧은 표시, KST 한 줄 시간 범위, “상세 보기”로 줄였다. 분석 대상, 설명, 전체 탐지·지원 관계 이름, KST·UTC 전체 시각, 근거, 한계와 다음 단계는 기존 사례 상세에 보존했다. 상세 안의 시간순 조사는 “시간순 기록 N건 보기”로 한 번 더 접는다. `NO_LONGER_MATCHES`나 위험도 하향을 안전·해결로 바꾸지 않았다. KST의 의미와 UTC의 위치는 오른쪽 “결과 해석 안내”에서 한 번 설명한다. 보조 rail의 “현재 제공 범위”와 보고서 형식은 별도 disclosure로 옮기고, 다운로드 경고·버튼은 남겼다.

같은 1440×900 합성 결과 2사례의 변경 전후 측정은 아래와 같다. 텍스트 줄 수는 사례 `summary`의 비어 있지 않은 텍스트 노드별 렌더링 줄 상자 수를 합한 개발용 지표다. 실제 Safari 글꼴·배율 수치와 동일하다고 주장하지 않는다.

| 측정 | 변경 전 | 변경 후 |
| --- | ---: | ---: |
| 기본 공개 사례 텍스트 줄 | 32 | 26 |
| 기본 공개 KST 시간 범위 | 0 | 2 |
| 기본 결과 문서 높이 | 1253px | 945px |
| 모든 사례·시간순 상세를 펼친 문서 높이 | 4687px | 4881px |
| 첫 900px viewport에서 카드 하단 | 927px | 897px |
| 기본 영역 | 결과 안내·요약·사례·보조 rail | 동일한 네 영역, 상세 문장은 접힘 |

상세를 모두 펼친 길이는 전체 관계 유형과 단계별 disclosure를 보존했기 때문에 늘었다. 기본 화면 높이는 308px 줄었고 글자 크기는 16px, 줄 높이는 24.8px를 유지했다. 두 사례의 기본 핵심은 합성 1440×900 viewport 안에 들어간다. 320px의 가로 넘침 검사는 자동 검증이며 실제 Safari 200% 확대 PASS는 별도로 받는다.

SVG는 같은 문서의 고정 fragment만 참조하고 모두 `aria-hidden="true"`, `focusable="false"`다. 아이콘만 있는 버튼은 없다. 상태에는 텍스트와 구분되는 테두리·도형을 함께 둔다. `DEGRADED`는 경고 삼각형, `FAILED`는 원형 X이며 복구 문구는 기존 계약을 따른다. 숨겨진 live/결과 영역은 기존 선택 규칙을 따른다. Inline event handler, unsafe DOM sink, CSP 완화, 외부 URL과 브라우저 storage는 추가하지 않았다. CSS 흐름은 1200px 이상 4단계 한 줄, 중간 폭 2×2, 좁은 폭 1열이고 `prefers-reduced-motion` 계약을 유지한다.

## 검증과 실제 Safari 경계

변경 전 계약 테스트는 추적된 SVG 고지와 분석 흐름 부재를 재현하며 **2 failed**였다. 자동 검증은 도형 digest·허용 속성, icon-only control 0건, 모든 장식 SVG의 접근성 트리 제외, Chromium axe 13개 상태, 외부 요청·CSP·콘솔 오류, 320/640/1024/1440/2000 CSS px 넘침, 키보드·focus·scroll·EventSource 연결 계약을 확인한다. 합성 screenshot은 로컬 임시 검토 뒤 삭제하며 CI artifact로 올리지 않는다. 자동 결과는 실제 Safari, VoiceOver, 사용자 이해도나 WCAG 2.2 AA 준수 선언이 아니다.

| Safari 사용자 과업 | 결과 | 범위 |
| --- | --- | --- |
| 아이콘과 텍스트로 메뉴 구분 | NOT_TESTED | 새 시각 언어 적용 후 사용자 직접 확인 전 |
| 세 시작 카드 차이와 네 단계 흐름 이해 | NOT_TESTED | 사용자 직접 확인 전 |
| 결과 숫자·위험 상태 우선순위 | NOT_TESTED | 사용자 직접 확인 전 |
| 아이콘 양과 장시간 피로 | NOT_TESTED | 사용자 직접 확인 전 |
| 실제 200% 확대·최소 폭 | NOT_TESTED | Chromium viewport 검사는 별개 |
| 실제 keyboard-only·VoiceOver | NOT_TESTED | 자동 axe와 별개 |
| Web Inspector 오류·외부 요청·CSP | NOT_TESTED | 자동 console/network 검사와 별개 |

Production UI는 이 변경 이후 새 Safari 직접 검수가 필요하다. 앞선 전체 폭 셸에 대한 부분 PASS는 아이콘을 더하기 전 화면에만 해당한다.
