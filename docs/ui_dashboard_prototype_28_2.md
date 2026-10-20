# Phase 28.2 — 보안 조사 대시보드 독립 prototype 비교

## 목적과 실행 경계

두 화면은 같은 고정 합성 집계(`관찰 3·관계 2·위험도 1·사례 1`)만 사용하는 **독립 HTML prototype**이다. [Calm Light Operations](prototypes/security_dashboard_calm.html)은 처음 보는 사람의 현재 상황·다음 행동 이해를 우선하며, [Dense Analyst Console](prototypes/security_dashboard_dense.html)은 같은 근거를 더 좁은 공간에서 비교한다. 개발자는 Calm을 기본 권장안으로 제시하지만 채택은 다음 단계의 실제 Safari 사용자 비교로 결정한다.

파일을 로컬 브라우저에서 열어 `RUNNING`, 새 결과 대기, 결과 적용, 화면 일시 정지, `DEGRADED`, `FAILED`, replay gap, 결과 없음 버튼을 비교한다. 상태 전환은 서버에 연결되지 않는다. 실제 로그·기본 config·checkpoint·사용자 홈을 읽지 않고 API·SSE·탐지·상관관계·risk·case 의미를 변경하지 않는다. 원래 계정·IP·path/query·파일명·raw line은 fixture와 DOM에 없다. 두 HTML은 production route/OpenAPI에 등록되지 않으며 production frontend·CSP hash·Python runtime dependency·`uv.lock`을 변경하지 않는다. 본 prototype의 CSP는 자체 HTML의 `default-src 'none'`, `script-src 'self'`, `style-src 'self'`, `connect-src 'none'`이며 외부 CDN·font·telemetry·runtime fetch가 없다. 실제 앱에 옮길 경우 production CSP와 정적 자산 경로를 별도로 재검증해야 한다.

## 공식 근거와 공급망 판정

| 출처 | 공식 자료·라이선스 | 참고한 원칙 | 실제 포함 |
| --- | --- | --- | --- |
| [Pico CSS 2.1.1](https://picocss.com/docs/maintenance) | [npm metadata](https://www.npmjs.com/package/@picocss/pico), MIT. 공식 유지관리 문서가 **archived**, 2.1.1 최종 릴리스라고 명시 | semantic HTML과 local CSS 사용 가능성만 검토 | 0 byte. Pico 설치·직접 복사 없음 |
| [PatternFly](https://www.patternfly.org/patterns/dashboard/design-guidelines/) | [공식 저장소 MIT](https://github.com/patternfly/patternfly/blob/main/LICENSE) | dashboard aggregate/details/events card, [data list](https://www.patternfly.org/components/data-list/design-guidelines/), [empty state](https://www.patternfly.org/components/empty-state/design-guidelines/)의 간결한 다음 행동 | 패턴만 참고. React/CSS/브랜드/asset 직접 복사 없음 |
| [Carbon Design System](https://www.carbondesignsystem.com/building-blocks/core/patterns/status-indicators/) | [공식 저장소 Apache-2.0](https://github.com/carbon-design-system/carbon/blob/main/LICENSE) | 상태를 색만으로 나타내지 않고 텍스트·형태·테두리를 결합; 중요한 notification을 문맥 가까이에 배치 | 패턴만 참고. 코드·asset 직접 복사 없음 |
| [GOV.UK Design System](https://design-system.service.gov.uk/components/error-summary/) | [Frontend MIT](https://github.com/alphagov/govuk-frontend/blob/main/LICENSE.txt); 문서 텍스트는 [Open Government Licence 3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/) 경계 | 오류와 복구 행동을 명확히 적고 focus 관리가 필요한 시점을 구분. 이 prototype은 사용자 선택에 따른 상태 전환이므로 자동 focus 이동하지 않음 | 패턴만 참고. GOV.UK 브랜드·문구·코드 직접 복사 없음 |
| [Lucide](https://lucide.dev/guide/packages/lucide-static) | [공식 저장소 ISC](https://github.com/lucide-icons/lucide/blob/main/LICENSE) | 다음 Phase에서 필요성 재평가 | 설치·asset 포함 없음 |

Pico npm registry의 `@picocss/pico@2.1.1` manifest는 `MIT`, tarball `sha512-kIDugA7Ps4U+2BHxiNHmvgPIQDWPDU4IeU6TNRdvXQM1uZX+FibqDQT2xUOnnO2yq/LUHcwnGlu1hvf4KfXnMg==`, 압축 2,694,953 byte, 압축 해제 19,558,862 byte, entry 305개를 기록한다. `npm pack --dry-run --ignore-scripts`로 파일 목록을 확인했다. `preinstall`·`install`·`postinstall` lifecycle script는 manifest에 없고, build/dev script만 있다. 직접·전이 runtime dependency 선언은 없고 목록에서 native addon은 발견되지 않았다. 제공된 CSS를 로컬에 self-host할 수 있지만 이번에는 설치하거나 포함하지 않았다. 따라서 package runtime network 동작을 실행 검증했다고 주장하지 않는다. 유지관리 종료와 prototype의 작은 범위 때문에 저장소 전용 CSS를 작성했다. 모든 CSS·JS·문구는 이 프로젝트가 새로 작성한 것으로 외부 구현의 직접 복사는 없다. 라이선스 링크는 참고 출처 attribution이며 제3자 코드 재배포 표시가 아니다.

## 설계 비교

| 공통 기준 | Calm Light Operations | Dense Analyst Console |
| --- | --- | --- |
| 초보자의 현재 상태 이해 | 회청색 배경과 큰 상태·설명, 다음 행동이 먼저 보임 | 상태는 상단에 있지만 설명 밀도 높음 |
| 다음 행동 발견성 | 새 결과·일시 정지·복구 버튼을 넓게 배치 | 같은 버튼을 촘촘히 배치 |
| 정보 밀도 | 넓은 카드와 여백, 점진적 disclosure | 3열 상세 카드와 짧은 간격 |
| 오류·복구 이해 | 별도 안내에 오류와 조치 설명 | 동일 문구를 더 압축된 시야에 표시 |
| 관찰·관계·위험도·사례 | 네 개의 요약 카드와 별도 목록 | 동일 카드·목록, 한 화면 비교 우선 |
| 좁은 화면 | 800px 이하 한 열, 500px 이하 헤더 접힘 | 같은 breakpoints, 밀도 이점 감소 |
| keyboard 접근 | 기본 버튼·details, 가시 focus | 동일 semantics와 focus |
| axe 결과 | 8상태 전체 impact 위반 0건, 제외 0개 | 8상태 전체 impact 위반 0건, 제외 0개 |
| CSP 적합성 | 로컬 CSS/JS, 외부 요청 없음 | 동일 |
| dependency·bundle 크기 | 추가 dependency 0, 공유 CSS/JS | 추가 dependency 0, 공유 CSS/JS |
| 장시간 사용 피로 | 밝은 대비와 넉넉한 간격을 의도 | 중립 dark와 짧은 간격; 사용자 평가 필요 |
| production 이식 범위 | 구조·스타일·문구 검토 필요 | 구조·스타일·문구 검토 필요. 두 안 모두 현재 앱을 교체하지 않음 |

두 안 모두 중요한 오류·stale 결과를 정상 0건처럼 표시하지 않고, 로그인 성공을 침해로 단정하지 않는다. 상태는 텍스트와 형태·테두리·색을 함께 사용한다. 고정 합성 데이터의 카드 위치는 상태 전환 중 재배치하지 않으며, 서버 수집과 화면 표시 일시 정지를 분리한다. `새 결과 2건 보기` 전 목록은 바뀌지 않는다. `details`는 checkpoint reset이 로그 삭제가 아니고 다음 실행이 새 epoch라는 설명을 제공한다. source checkout만 지원한다는 경계를 유지한다.

## 자동 검증과 남은 사용자 검수

`tests/ui_dashboard_prototype_28_2.mjs`는 기존 dev-only `@axe-core/playwright@4.14.0`와 `@playwright/test@1.64.1`의 고정 Chromium headless shell `156.0.8078.4`로 두 화면·8개 상태를 확인한다. axe 전체 rule 결과를 ID·impact·노드 수의 안전한 집계로만 다루고, 제외 rule은 0개다. 320·640·1024·1440 CSS px에서 가로 overflow를 검사한다. 640 CSS px 화면의 200% 확대에 해당하는 **레이아웃 proxy**로 320 CSS px를 별도 확인하되 실제 브라우저 확대와 동일하다고 주장하지 않는다. keyboard Enter로 상태·일시 정지·disclosure를 선택하고 focus·scroll 보존과 reduced-motion을 확인한다. UTC와 Asia/Seoul의 결과 서명을 비교한다. 임시 loopback 서버는 지정한 네 로컬 자산만 제공하고, 테스트 브라우저는 이 origin 외의 요청을 차단·실패한다. 종료 후 listener 부재를 확인한다. Test stdout에는 DOM text·HTML·axe raw JSON·canary가 없고 trace/HAR/video/screenshot을 저장하거나 업로드하지 않는다. `bypassCSP`는 axe 주입을 위한 **테스트 context에만** 사용한다. 별도의 정적 계약 테스트가 prototype CSP를 검사한다. Production CSP는 건드리지 않는다.

자동 axe/Chromium 통과는 WCAG 준수나 실제 Safari·VoiceOver·사용자 이해도 검증이 아니다. 다음 단계에서 사용자가 Safari로 두 화면을 열어 실제 keyboard-only, 200% 확대, 최소 창 너비, 문구 이해, 장시간 피로와 VoiceOver 필요성을 직접 비교한다. 합성 320 CSS px는 실제 Safari 최소 너비의 PASS 증거가 아니다. 두 안 중 하나의 채택 여부도 그 비교 전에는 미결정이다.

## 검증 기록과 비용 경계

시작 SHA `b5a18047bb269f096387373d6c71fafa76c1e8c6`의 [Ubuntu CI run 39284065990](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39284065990)은 `completed/success`였다. `npm ci`와 고정 Chromium 설치·실행 파일 hash 검사, 기존 axe 13상태(위반 0·외부 요청 0), 전체 pytest **2,357 passed·기존 경고 2개**가 통과했다. API로 조회한 저장 artifact는 **0개**다. Job은 16:15:49–16:17:40 UTC로 약 111초였다. Phase 28.1의 Node setup부터 axe 종료까지 해당 run의 실제 시간은 16:17:07–16:17:37 UTC로 약 30초다. 이것은 **단계 소요 시간**이며 같은 runner에서 pilot을 제거한 A/B 실험을 하지 않았으므로 정확한 CI 순증 시간으로 주장하지 않는다.

로컬 macOS baseline 전체 회귀는 **2,357 passed·경고 2개**였다. 처음 샌드박스 실행의 12개 Unix socket bind 실패는 권한 제한에서 발생했고, 정상 권한 재실행은 전부 통과했다. 기존 axe/Chromium 13상태도 새 고정 브라우저를 임시 위치에 설치한 후 위반 0·외부 요청 0으로 통과했다. 현재 prototype 검사 역시 두 화면×8상태×UTC/Asia-Seoul에서 전체 axe impact 위반 0·제외 0, 4개 viewport 가로 overflow 0, keyboard·focus·scroll·reduced-motion PASS, 외부 요청 0, JS console 오류 0이다. 초기 `file://` 접근은 axe 주입의 CORS 오류가 있어 검증 근거에서 제외하고 독립 loopback 서버로 교체했다. 이 수치들은 개발용 합성 검사이며 운영 SLA나 Safari 수용 결과가 아니다.

최종 prototype browser suite를 3회 반복했으며 상태별 rule ID·위반 수의 출력이 동일했다. 새 문서·prototype 계약을 포함한 전체 회귀는 **2,364 passed·기존 경고 2개**였고, 합성 평가 **79/79**, Linux Audit **21/21**, risk/case **70/70**도 유지됐다. `npm ci --ignore-scripts --no-audit --no-fund`, `uv lock --check`, Python·Node 문법 검사와 `git diff --check`를 실행했다. 이 기록은 로컬 검증이며 새 커밋의 Ubuntu CI를 의미하지 않는다.

새 CSS 7,441 byte, JS 13,396 byte, HTML 각 676 byte로 공유 자산 포함 총 **22,189 byte**다. 추가 Node·Python dependency, production bundle 증가, 추적 screenshot, CI artifact는 0이다. 두 디자인은 전용 CSS 변수와 spacing/layout만 달리하고 같은 JS fixture를 공유한다. 이는 prototype 파일 크기이며 production 이식 비용을 측정한 값은 아니다.
