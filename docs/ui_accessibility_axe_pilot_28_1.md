# Phase 28.1 — axe-core + Playwright 접근성 자동 회귀 pilot

2026-10-20. 시작 `main`과 `origin/main`은 `88169bccc440ab10e3061f04987e541bf65af133`에서 clean, behind/ahead 0/0이었다. 해당 SHA의 [GitHub Actions run 39255398064](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39255398064)는 completed/success다. 변경 전 macOS 전체 회귀는 **2,351 passed, 기존 경고 2개**, UI/Node 관련 pytest는 **17 passed, 같은 경고 2개**였다. 이 문서의 로컬 결과는 새 커밋을 push하기 전의 macOS 측정이다. 새 커밋의 Ubuntu CI 결과는 **NOT_TESTED**다.

## 범위와 실행 계약

Node가 없던 저장소에 `package.json`과 `package-lock.json`을 **UI 테스트 전용**으로 추가했다. 두 최상위 패키지는 `devDependencies`에 정확한 버전으로 고정한다. `npm ci --ignore-scripts --no-audit --no-fund`로 재현하고, 고정 Chromium headless shell만 `playwright install chromium --only-shell`로 설치한다. 브라우저는 `PLAYWRIGHT_BROWSERS_PATH`의 임시 위치에 둔다. `frontend/`, production Python dependency와 `uv.lock`, API/SSE schema, 탐지·관계·위험도·사례의 의미는 바꾸지 않았다. Production JS/CSS에 axe/Playwright import나 번들 과정은 없다. GOV.UK Frontend, Lucide, Chart.js, uPlot, Web Awesome은 설치하지 않았다.

테스트는 임시 `HOME`/`XDG_CONFIG_HOME`과 loopback `uvicorn`에서 **실제 배포 HTML/JS/CSS/CSP**를 연다. Live status 및 EventSource의 합성 상태만 테스트에서 주입한다. 실제 사용자 로그·기본 monitor config·checkpoint·사용자 홈 자료는 입력으로 쓰지 않는다. 테스트 브라우저는 loopback 외 page 요청을 거부하고, 외부 proxy를 무효 loopback으로 지정하며 DNS resolver를 제한한다. Chromium background networking도 끈다. 검사된 page 요청의 외부 origin 수는 0이었다. 이는 호스트 전체 네트워크 패킷의 완전한 증명이 아니다. 패키지/브라우저 설치 때의 npm·Playwright CDN 다운로드는 별도 공급망 단계다. Runtime telemetry나 version-check 호출은 테스트 page에서 관찰되지 않았고 production 실행 경로에는 Node 패키지가 없다.

테스트 중에만 `AxeBuilder`가 page에 주입된다. Production CSP(`default-src 'none'`, `script-src 'self'`, `style-src 'self'`, `connect-src 'self'`, `img-src/font-src/worker-src 'none'`)의 완화, `unsafe-inline`, `unsafe-eval`, CDN, 원격 font, runtime fetch는 없다. Production 정적 asset allowlist, `nosniff`, 128 KiB 상한도 그대로다.

## 공급망 고정 및 배포물 검증

2026-10-19~20 npm registry metadata와 실제 tarball 바이트의 SHA-512를 대조했다. Lockfile의 직접/전이 그래프는 정확히 아래 다섯 패키지다. 표의 integrity는 npm registry `dist.integrity`의 SHA-512 base64이며 tarball 재계산과 일치했다. [공식 axe wrapper manifest](https://github.com/dequelabs/axe-core-npm/blob/v4.14.0/packages/playwright/package.json), [Playwright 1.64.1 manifests](https://github.com/microsoft/playwright/tree/v1.64.1/packages), [npm lifecycle 문서](https://docs.npmjs.com/cli/v11/using-npm/scripts/)와 배포 metadata를 비교했다.

| 패키지 | 사용 관계 / 라이선스 | npm SHA-512 integrity |
| --- | --- | --- |
| `@axe-core/playwright@4.14.0` | 직접 dev, MPL-2.0; `axe-core ~4.14.0`, peer `playwright-core >=1` | `SGUhG5PIHd2eMdpgBF2PyQLOhX+qyDR2PT4cmoS4Qk2ak+jX/rrSvst9l0PGv5WTHolKpUMvVmoHpr4cZgf1RQ==` |
| `axe-core@4.14.0` | 전이, MPL-2.0 | `9WTZxEjsZ7b13TH8JPmbV2z8CHbl80/2hm3XPEG4JgNdQLK81IBRXmSxHfMAOkSqQeRxT/0dwNDz2GOm3zzpcQ==` |
| `@playwright/test@1.64.1` | 직접 dev, Apache-2.0; `playwright =1.64.1` | `IaYGml/nSOiZWROfPtuIL7neuu9qDOZ3TNvNljUIrhDMxiGTgPjzj/g9p9RxpS2tSepPDRY+UwAaEeiKtUvIAg==` |
| `playwright@1.64.1` | 전이, Apache-2.0; `playwright-core =1.64.1` | `HCrVhHr5QQuwYoswEUGTb7gGp522yflbv/ST8nF4sFWGuLjQCt17Q/EubpGGSNKYn1tsTCPZxqHhHCfVURu7UA==` |
| `playwright-core@1.64.1` | 전이/peer, Apache-2.0 | `BC4s8y6SEVA6Q1rSxZTto8hI1KUI3xXlHGZgvGqP4IqPdI/a6FX9H29IDNz7vKo9l21b6LfYosScPL6M3xxyDQ==` |

배포 tarball 다섯 개 모두 preinstall/install/postinstall script와 `.node`/`.dylib`/`.so`/`.dll` native addon이 없다. `@axe-core/playwright`의 `prepare`는 `pnpm exec playwright install && pnpm run build`이므로 **모든 npm lifecycle script를 `--ignore-scripts`로 막는다**. `playwright-core`에는 `webp_codec.wasm`이 있으며 이를 native addon 부재와 구분한다. 브라우저와 FFmpeg는 별도 native 실행물이다. npm lock integrity 검증과 별개로 브라우저 실행 파일 SHA-512를 CI에서 검사한다.

[Playwright 1.64.1 browser registry](https://github.com/microsoft/playwright/blob/v1.64.1/packages/playwright-core/browsers.json)와 [공식 설치 문서](https://playwright.dev/docs/browsers)에 따라 Chromium headless shell **156.0.8078.4, revision 1248**, FFmpeg revision **1013**만 설치한다. macOS arm64와 Ubuntu 24.04 x64의 Chromium archive는 `cdn.playwright.dev/builds/cft/156.0.8078.4/{mac-arm64,linux64}/chrome-headless-shell-*.zip`에서 Chrome for Testing GCS로 redirect된다. FFmpeg archive는 `cdn.playwright.dev/dbazure/download/playwright/builds/ffmpeg/1013/ffmpeg-*.zip`에서 Microsoft host로 redirect된다. Redirect와 최종 bytes를 확인했고 archive ZIP 검사 및 제공된 MD5와 계산값이 일치했다. FFmpeg archive는 LGPLv2.1 notice를 포함한다. 다른 브라우저 binary는 설치하지 않는다.

| 플랫폼 / 실행물 | 다운로드 archive 크기 | archive SHA-512 (hex) | 실행 파일 SHA-512 (hex) |
| --- | ---: | --- | --- |
| macOS arm64 Chromium shell | 103,778,487 B | `cb3b57c574152797ea41b806bf8579fd92982f71ae24adc88d85cf6e96fbb33c55d52935fea83dbd0cb77d7d2dd19e98bea1379ce5fd9c82303e0fcad49f4a58` | `140216da1077912c91e0764364ddd320d5b899fa2651da058fde5cec81bd53a45602ae8dd332f3fd369a84b51518be27ff427ab34ba241d4c367e2c32c288e5d` |
| Ubuntu x64 Chromium shell | 125,797,539 B | `f728498b50898cd538690e7bcc505d13d8bb7c51454e720752f235fcccf995a1aee867612890d0d9f558646e5cf074de81cb8f240d9d1750015ce9c6b5436830` | `2b1a87b7d808c989193887d24c2e7cfc74fc775629443eda629b72687585b95423f85ac180209d95ff3b562805c26a8b63afabb068dfa92b715da1246c0426b8` |
| macOS arm64 FFmpeg | 1,430,308 B | `bbd6b061f6a44380c6f4bef71d4bef235323ea43002cb439cfed36b3e5a9d634cbc4560da2002da5bc7f7a299957f2d0522701c8e74e2d0639add38f26b3049d` | `f580f0fa9ba978b71203966ccb4e7803688c4c68ac845000d5ac7442ef3daf61bb2a8efd57e33e5787663fd42947453e42695f5f6b35a4cd764a136f0786f003` |
| Ubuntu x64 FFmpeg | 2,302,701 B | `25b1b27e363e764bdb2aa9883bb6041d4a8e6ddd7125b26f74d401ba2043a56cb55e12e994de6e54e596b843c884eaf7929cd2d568f734edbc7193d0054d953f` | `7d5a4bd12741d3a62137f7702a5c754aad7ce24df2e3ca2e6af3cff67e2a59424d497353e6e8989d544b5a5f3d3213c0dcc0cab74bae89a0ef3f3cf2fb365217` |

CI는 `actions/setup-node` commit `949feb2413d6458794dcd2491c4babbbce0c15c1`(v7.1.0), Node **24.10.0**, npm lock과 Ubuntu 실행 파일 hash를 고정한다. 브라우저 설치는 네트워크를 필요로 하며 registry/CDN 가용성과 OS 라이브러리에 의존한다. 실제 새 커밋의 Ubuntu 실행 결과와 CI 증가 시간은 push 전이라 아직 측정하지 못했다.

## 검사 상태와 실패 처리

`tests/ui_accessibility_axe_pilot_28_1.mjs`는 다음 13개 독립 page를 검사한다: live 비활성 기본, 빈 live 초기 연결, 새 결과 대기, 관찰·관계·위험도·사례 적용, 일시 정지, `NO_LONGER_MATCHES`와 위험도 하향, private field 거부, `DEGRADED`, `FAILED`, replay gap, 합성 checkpoint reset 설명, 기존 3파일 form 오류, Linux Audit form 오류. **Checkpoint reset은 v0.3에서 CLI 절차다.** 해당 page section은 테스트에서만 붙인 동등한 합성 설명이며 제품 UI가 제공하는 기능으로 기록하지 않는다.

각 상태에서 DOM 안정 후 axe를 실행한다. 모든 rule을 활성화하고 serious/critical 위반·axe 실패·예상 상태 실패를 실패로 처리한다. 현재 예외 rule은 **0개**다. 출력 adapter는 상태 이름, impact, rule ID, 해당 rule의 node 수만 출력한다. Moderate/minor 위반이 생기면 출력·검토 대상이며 현재는 전 상태에서 위반 **0건**이다. `incomplete`는 자동 통과 증거가 아니며 별도 수동 판단이 필요하다. 수정 전 실제 production 접근성 결함은 발견되지 않았으므로 frontend 수정이나 사전 실패 회귀 테스트는 추가하지 않았다.

추가 계약은 문서 title/단일 h1, visible form label, 버튼 이름, `header`/`main`/`footer`, 중복 ID 부재, status/alert/aria-live, 숨겨진 live의 접근성 트리 배제, 오류 요약과 필드 연결, 대기 중 자동 적용 금지, SSE focus/scroll 유지, `NO_LONGER_MATCHES`/위험도 하향을 해결·안전으로 해석하지 않기, terminal/replay gap의 명시적 복구다. 색 대비와 상태 비색상 구분은 axe와 텍스트 계약의 자동 범위에서 검사된다. 실제 표시 조건 전체의 대비와 문구 적절성은 수동 검수다.

합성 canary가 포함된 **허용되지 않은 private SSE field**를 보내 rejection과 DOM 비노출을 확인한다. Production은 안전 projection만 노출한다. 이 검사는 trusted 내부 event/history의 보존·내용 검사와 다르다. 출력·오류에는 DOM text, HTML, selector, canary, 계정/IP/username/hostname, raw line, filename, config/log/checkpoint path, query, 내부 exception을 실지 않는다. Raw axe JSON, trace, HAR, video, screenshot과 CI artifact 업로드를 기본 생성하지 않는다. 실패 시에도 고정 오류 코드만 stdout/stderr로 내보낸다. Browser/context, 서버 SIGINT, listener, 임시 HOME은 종료 시 정리하고 실패도 별도 코드로 알린다. Secure erase는 주장하지 않는다.

## 비용, 결과, 남은 수동 gate

macOS arm64 개발 측정: `node_modules` 디스크 사용량 **22,680 KiB**, 브라우저 설치 디렉터리(Chromium shell+FFmpeg) **224,888 KiB**, lockfile **4 KiB**. `npm ci --ignore-scripts` 초기 설치는 약 **5초**, 기존 npm cache를 사용한 재설치는 **0.51초**였다. Browser download/설치 및 Ubuntu CI 전체 증가 시간은 아직 같은 조건으로 계측하지 못했다. 13상태 suite의 최초 실행은 **29.234초**, 후속 UTC **29.351초**, Asia/Seoul **17.748초**였다. 최종 코드 3회는 UTC **14.167초**, Asia/Seoul **14.445초**, UTC **14.523초**로 상태별 rule ID·위반 수가 동일하게 모두 0이었다. 워밍·시스템 부하·코드 수정에 따른 차이가 있어 운영 SLA나 CI 추정치가 아니다.

axe는 모든 접근성 문제를 찾지 못한다. Chromium 자동 검사는 실제 Safari와 동일하지 않다. Keyboard-only, 실제 Safari, 200% 확대/최소 폭, VoiceOver, 문구 이해도와 의미 적절성은 별도 수동 gate다. 자동 통과를 WCAG 2.2 A/AA 준수 선언으로 사용하지 않는다. 색 대비 자동 판정도 모든 상태와 실제 디스플레이 조건을 증명하지 않는다. 현재 pilot은 Mac에서 Chromium만 실행했으며 Ubuntu는 새 CI가 실행되기 전까지 **NOT_TESTED**다.

## 로컬 검증 기록

- 잠긴 Node 재설치 `npm ci --ignore-scripts --no-audit --no-fund` PASS. Python `uv lock --check` PASS; production runtime 의존성 집합과 `uv.lock`은 변경하지 않았다.
- Mac Chromium 13상태 접근성 suite 3회 반복 PASS, serious/critical **0건**, 다른 impact의 위반도 **0건**, 예외 rule **0개**, 외부 page 요청 **0건**. 합성 private field는 거부되고 DOM에서 발견되지 않았다. Canary 문자열은 stdout/stderr에 출력되지 않았고 pytest failure/CI summary용 raw axe report는 생성하지 않는다.
- 문서·CI 계약 focused **16 passed**, UI/Node·API/SSE·개인정보를 포함한 focused **60 passed, 기존 경고 2개**. 전체 `uv run pytest -q` **2,354 passed, 기존 경고 2개**. 중간 전체 실행에서 기존 CI action 목록, 단계별 env, Node manifest 부재를 전제로 한 계약 테스트 3건이 실패했고, 의도된 dev-only Node 도입에 맞춰 계약을 좁혀 고친 후 위 최종 결과로 재검증했다.
- `uv run python -m app.evaluation --format text`: 합성 인증·웹 **79/79**, Linux Audit **21/21**, risk **70/70**, case **70/70**. 이는 운영 탐지율이 아니다. Python `compileall`, 새 Node 파일 `node --check`, `git diff --check`, 새 파일의 민감 경로·secret 문자열 검사 PASS.
- 실제 loopback 서버 health, 제품 asset/CSP 응답, 격리 HOME, 종료 후 listener 부재와 임시 HOME 삭제는 browser suite에서 검사한다. Browser/context·server 종료 실패는 고정 `CLEANUP_FAILED`로 실패한다. Mac 실행 PASS. Ubuntu 새 커밋 CI, 실제 Safari/keyboard/zoom/VoiceOver는 **NOT_TESTED**다.
