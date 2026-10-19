# v0.1.0 로컬 공개 릴리스 체크리스트

이 문서는 v0.1.0 공개 전 준비·검증의 역사적 기록이다. **Phase 10.1 로컬 릴리스 후보 접근성 수용 판정은 GO**였으며, 공개 배포 여부의 현재 상태를 나타내지 않는다. `pyproject.toml`의 `0.1.0`은 프로젝트 버전이며 API/평가 schema version이 아니다. 이 기록을 작성할 당시 태그·GitHub Release·push·PyPI 배포는 수행하지 않았다.

표시 규칙: `[x]`는 기록 당시 실제 수행한 자동/저장소 검증만 뜻한다. `[ ]`는 당시 미수행, 확인 불가 또는 의사결정 대기였음을 뜻한다. 이 표시는 이후 tag·Release 게시 상태를 자동으로 갱신하지 않는다.

## 저장소와 공개 권한

- [x] 시작 시 working tree clean, `origin/main...HEAD` behind 0 / ahead 0, Phase 6.2 기준선 포함.
- [x] 프로젝트 version `0.1.0`은 `pyproject.toml` 한 곳에 있다.
- [x] CHANGELOG, 릴리스 노트 초안, SECURITY와 README 링크를 준비했다.
- [x] 루트 LICENSE는 [OSI MIT 원문](https://opensource.org/license/mit)과 승인된 `Copyright (c) 2026 misosos`를 사용한다. `pyproject.toml`의 SPDX license metadata는 `MIT`다.
- [x] GitHub Private vulnerability reporting은 사용자 확인에 따라 활성화됐다. 신고 안내는 Security → Report a vulnerability 경로를 가리킨다.
- [x] 합성 fixture만 추적하며 생성 보고서·raw 조직 로그·credential·secret은 추적하지 않는다.
- [x] `.gitignore`의 보고서·캐시·staging 패턴과 `git ls-files`/ignored inventory를 확인한다.
- [x] `uv lock --check`와 `uv sync --locked --dev`가 현재 및 clean checkout에서 성공했다.
- [ ] 최종 준비 커밋 후 working tree clean, origin behind 0, 원격 CI 통과를 재확인한다.

## 자동 테스트와 로컬 smoke

- [x] macOS Apple Silicon에서 uv가 CPython 3.12.7을 사용했다.
- [x] 기준선 전체 pytest `1,514 passed, 2 existing warnings`; 라이선스·릴리스 문서 추가 뒤 후보 작업 트리는 `1,518 passed, 2 existing warnings`다. 샌드박스 UNIX socket 제한은 허용 환경에서 재검증했다.
- [x] Phase 7 기준선 평가 `43/43`, parser `129/134` (ignored 2, rejected 3), risk·case `34/34`를 확인했다.
- [x] 반복 JSON SHA-256이 UTC/KST에서 `78584ce961096279ffe76974bfce57e2c0b0932270a7d53e75d8620c717ebe0c`로 같았다.
- [x] 변경 Python 테스트 compile, Node `--check`, documentation/first-user/privacy/API·CLI·HTML tests를 실행했다.
- [x] OpenAPI deprecation, privacy canary, standalone HTML CSP hash와 download byte count는 자동 테스트 범위다.
- [x] Phase 7 clean checkout의 loopback launcher `--no-browser`에서 health·root·CSS·JS·sample·로컬 3종 분석이 200, 사례 2·독립 관찰 3이었다. Phase 8 sample은 독립 관찰 4로 달라진다.
- [x] Ctrl+C 종료 뒤 8000번 port listener 없음, 알려진 staging directory 0건.
- [x] 최종 준비 커밋을 별도 clean checkout하여 `uv sync --locked --dev`, 전체 `1,518 passed, 2 existing warnings`, loopback health·웹 자산·sample·실제 로그 API·보고서 smoke를 다시 확인했다. 종료 후 port listener와 알려진 staging directory는 0건이었다.
- [x] 변경 Python 테스트 `py_compile`, `node --check frontend/app.js`, Node behavior test syntax, `git diff --check`, secret/private-path scan이 통과했다. Node behavior는 기존 pytest harness가 stdin fixture를 제공할 때 검증된다.

## 수동 접근성·사용성

Phase 8 추가 검증 gate:

- [x] 현재 작업 트리의 합성 평가 `79/79`, parser `195/200`, risk·case `70/70`을 확인했다. 이 표시는 기존 43개 ID의 의미를 바꾸지 않는다.
- [ ] Phase 8 기능 커밋 이후 새 clean checkout에서 locked 설치, 전체 pytest, launcher·sample/local API·HTML smoke, CSP·privacy canary를 다시 실행한다.
- [ ] Phase 9 기능 커밋 이후 clean checkout에서 Linux Audit CLI 분류·별도 합성 평가와 전체 회귀를 재검증한다. 기존 79개 IP 시나리오 metric은 그대로 유지한다.
- [ ] Phase 9.1 기능 커밋 이후 clean checkout에서 loopback 단일 Linux Audit 업로드, cleanup, frontend 시각·키보드 및 전체 회귀를 재검증한다. 기존 보안 Linux Audit API와 인증·웹 3파일 API를 분리해 확인한다.
- [ ] Phase 8의 새 네 독립 관찰을 Safari에서 시각·키보드·320px·200% 확대와 함께 검증한다.

아래는 실제 Safari 검증이 끝나기 전까지 모두 미체크다. 자동 DOM/source 검사로 WCAG 2.2 AA를 주장하지 않는다.

- [ ] Safari에서 첫 화면의 sample/실제 로그 경로를 구분하고 첫 사례·grouping 이유·다음 조사 단계를 찾는다.
- [ ] Keyboard-only: skip link, visible focus, 파일 선택·오류 복구, `<details>/<summary>`, report download.
- [ ] 320px, 200% zoom, page-level horizontal overflow·text spacing·reduced motion.
- [ ] Screen reader의 heading·상태·Timeline 읽기 순서 및 오류 focus.
- [ ] 실제 사용자의 누락 파일 복구와 sample/actual·침해 확정 오해 여부를 관찰한다.

## 패키지·배포 경계

- [x] `uv build`를 허용 환경에서 실행했고 setuptools flat-layout 다중 최상위 디렉터리 발견 오류로 실패했다. **v0.1.0 설치 방식은 source checkout**; wheel/sdist/PyPI 미지원.
- [x] CI workflow는 Python 3.12.7, locked sync, full pytest, `contents: read`, PR/main push, timeout/concurrency와 SHA-pinned actions를 사용한다. Secret 사용·report artifact upload·release publish는 없다.
- [ ] 원격 GitHub Actions 실행과 액션 갱신 상태 확인.
- [x] 최종 source archive 목록에서 LICENSE·SECURITY·README·CHANGELOG·릴리스 노트·frontend 자산·합성 fixture 포함을 확인했다. Tracked inventory와 scan에서 secret·생성 보고서는 없었다.

## 릴리스 실행 전 마지막 승인

- [ ] 최종 커밋 SHA·clean tree·behind 0·전체 검증 결과를 기록한다.
- [ ] 릴리스 노트·LICENSE·SECURITY·지원 환경 문구를 사용자/유지관리자가 검토한다.
- [ ] Annotated tag `v0.1.0` 생성 여부를 별도 승인한다. **이번 작업에서는 생성 금지**.
- [ ] GitHub Release 생성 여부를 별도 승인한다. **이번 작업에서는 생성 금지**.
- [ ] Tag/Release 뒤 다른 clean source checkout 설치·smoke와 rollback 기준(태그/배포 철회, 민감 artifact 회수)을 검토한다.

## Phase 10 후보 검증 — 2026-10-11

기준 기능 커밋 `2df45cf54f5dd062a2707b09417c9cd63cc2386a`는 검증 시작 시 clean이며 `origin/main`과 일치했다. 다음은 앞선 Phase 7–9 이력과 구분한 현재 증거다.

- [x] 별도 clean checkout에서 CPython 3.12.7, `uv sync --locked --dev`, `uv lock --check`, 전체 회귀 **1,617 passed, 기존 경고 2건**을 확인했다.
- [x] 합성 인증·웹 평가 79/79와 Linux 평가 21/21, 반복 및 UTC/Asia/Seoul JSON SHA-256 동일(`f15c3c6a0d937e3a49f19fcf7feb7b418fc99d4e3c776d160d01950eec0fe8c9`)을 확인했다. 이는 운영환경 탐지율이 아니다.
- [x] clean checkout의 `127.0.0.1` launcher에서 root, CSS, 두 JavaScript 자산, health, sample, 실제 3파일, 별도 Linux Audit API를 확인했다. Sample은 사례 2·독립 관찰 4·탐지 5이며 HTML byte count와 기존 CSP hash가 맞았다. Linux 합성 입력은 eligible 1·분류 1·범주 관찰 2로 인증·웹 사례와 결합되지 않았다.
- [x] 기준 기능 커밋의 GitHub Actions [CI 실행](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38064889966)은 해당 SHA에서 완료·성공했다. 이 문서 수정 커밋 자체의 원격 CI는 아직 검증되지 않았다.
- [x] `uv build`는 기존 flat-layout 다중 최상위 패키지 자동 발견 오류로 실패한다. 지원 설치 방식은 source checkout이며 wheel/PyPI는 제공하지 않는다.
- [ ] Safari WebDriver가 `Allow remote automation` 비활성화 오류로 세션을 만들지 못했다. 설정을 우회·변경하지 않았다. Safari 실제 시각·키보드·콘솔, 320px와 200% 확대, VoiceOver 핵심 흐름은 **미검증**이다.
- [ ] 실제 사용자 acceptance와 WCAG 2.2 AA 준수 증거는 없다. 원격 CI와 자동 DOM 테스트가 이를 대체하지 않는다.
- [ ] 이 문서 수정 커밋의 원격 CI는 push 전이므로 미검증이다. 공개 릴리스 판단 전 최종 commit SHA와 clean tree를 다시 확인한다.

Phase 10 당시 go/no-go: 기준 기능 커밋의 clean checkout과 원격 CI는 통과했다. 당시 Safari 실제 접근성 수용 테스트가 미완료였으므로 **공개 릴리스 NO-GO**였다. 아래 Phase 10.1 기록이 최신 수용 판정이다. Hosted/public 실제 로그 업로드는 별개의 더 강한 no-go다.

## Phase 10.1 Safari 자동화와 수동 수용 — 2026-10-11

시작 기준은 `536a73561b8df9fc3eff2e176708cb95d0ca06b9`, clean tree, `origin/main` 일치다. 해당 SHA의 [원격 CI 38066159704](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38066159704)는 성공했다. Safari 18.6 WebDriver 세션은 사용자가 Remote Automation을 활성화한 뒤 **CONNECTED**였다. 아래 자동화는 실제 Safari에서 수행했지만 사람이 직접 확인하는 접근성 수용을 대신하지 않는다.

- [x] Loopback launcher readiness 후 Safari에서 root의 한국어 title·`lang=ko`·header/main/footer·skip link·sample/3파일/Linux 영역을 확인했다. 이 페이지에는 별도 nav landmark가 없다.
- [x] WebDriver element Enter로 sample 요청을 한 번 실행해 사례 2·독립 관찰 4·탐지 5, HIGH 기본 펼침·LOW 접힘, details 토글, KST/UTC, 계정 별칭 안내, 보고서 버튼을 확인했다. 실제 다운로드 저장은 수행하지 않았다.
- [x] 합성 3파일 업로드와 Linux Audit 업로드를 실제 Safari에서 수행했다. 두 결과는 분리됐고 Linux 합성 입력은 eligible 1·분류 1·범주 관찰 2였다. 누락 파일, 빈 Linux 파일, 비지원 형식의 고정 오류·요약 focus·필드 연결·복구 문구도 확인했다.
- [x] Safari resource timing에는 고정 CSS/JS와 각 요청의 예상 API 경로만 나타났다. HTTP CSP·보안 헤더를 확인했다. WebDriver의 console log 명령은 지원되지 않았고, 콘솔 자체는 아래 사용자 수동 검수로 확인했다.
- [ ] WebDriver pointer click과 전역 Tab action은 이 세션에서 DOM 이벤트·focus 이동을 일으키지 않았다. Element-targeted Enter는 동작했으나 이것만으로 실제 Tab/Shift+Tab 순서·focus ring·keyboard trap 부재를 입증하지 않는다.
- [x] 사용자 수동 키보드 확인: `조사 사례 1`에서 `조사 사례 2`로 일반 Tab 이동이 가능했다. 그 다음 일반 Tab은 Safari 주소창으로 이동했지만, `조사 사례 2`에서 `Option+Tab`을 누르면 `HTML 보고서 다운로드` 버튼에 도달했고 Enter로 다운로드가 시작됐다. Safari 키보드 탐색 방식에 따른 차이로 기록한다. 사용자는 다운로드 버튼의 초점 표시가 보였다고 확인했다.
- [x] 사용자는 마우스 없이 skip link → 샘플 실행 → 사례 disclosure → 3파일 입력·제출 → Linux Audit 입력·제출의 주요 흐름에서 막히는 곳이 없다고 확인했다. 모든 focus ring의 대비를 계측하거나 WCAG 준수를 판정한 것은 아니다.
- [ ] WebDriver의 `window/rect` 요청 320에서 실제 CSS viewport는 426px였고 이 너비에서만 `scrollWidth == clientWidth`를 확인했다. **320 CSS px는 미검증**이다. 실제 Safari 200% page zoom도 제어하지 않았으므로 미검증이다.
- [ ] Safari의 실제 보고서 다운로드 파일명·MIME·저장 결과와 정확한 320 CSS px 검증은 미완료다. 사용자는 다운로드 동작과 해당 버튼의 visible focus, Safari 실제 200% 확대와 가능한 최소 창 너비에서 가로 넘침·잘림·겹침 없음은 확인했다. 최소 너비의 실제 CSS px 수치와 확대·최소 너비 조합은 별도 측정하지 않았다.
- [x] 사용자가 Safari JavaScript 콘솔을 직접 열어 샘플·3파일·Linux Audit 흐름에서 JavaScript 오류와 CSP 차단 메시지가 없음을 확인했다고 보고했다. WebDriver에는 console log 명령이 없어 이 항목은 사용자 수동 검수 증거다.
- [x] 사용자는 샘플·3파일·Linux Audit 결과의 시각적 구분과 파일 누락 오류 복구에 문제가 없다고 확인했다. Safari 자동화에서도 고정 오류·field 연결·재제출 성공을 별도로 확인했다.
- [x] 사용자 VoiceOver 확인: 페이지 제목·주요 heading 구분, header/main/footer landmark, 네 파일 입력의 label·필수 상태는 PASS였다.
- [ ] **VoiceOver 후속 접근성 검증:** 오류 안내 읽기: NOT_TESTED. Disclosure·Timeline·동적 상태 등 나머지 screen-reader 흐름도 NOT_TESTED다. 사용자 승인에 따라 v0.1.0의 필수 GO gate가 아니라 후속 검증으로 분리한다. VoiceOver 미검증만으로 NO-GO로 판정하지 않는다.

**Phase 10.1 로컬 릴리스 후보 접근성 수용 판정: GO.** Safari WebDriver 주요 흐름, 사용자 수동 keyboard-only 주요 흐름·visible focus, 실제 200% 확대·가능한 최소 창 너비, 콘솔 오류 부재, 시각적 구분·오류 복구 및 전체 회귀가 확인됐다. 사용자의 변경된 수용 기준에 따라 VoiceOver 나머지 읽기와 정확한 320 CSS px 측정은 후속 검증이며 이번 GO의 근거로 삼지 않는다. 다운로드 파일 속성의 Safari 직접 확인도 미완료이나 서버·브라우저 자동 계약 검증과 사용자 Enter 시작 확인을 구분한다. WCAG 2.2 AA 준수를 주장하지 않는다. 기준 기능 SHA의 원격 CI는 성공했지만 이 문서 변경 커밋 자체의 원격 CI는 push 전에는 확인할 수 없으므로 실제 tag·Release 전 최종 SHA의 CI를 다시 확인해야 한다. GO는 공개 배포 실행 승인이나 hosted upload 승인이 아니다.

## v0.2.0 로컬 live 릴리스 후보 gate — Phase 17, 2026-10-13

이 절은 위의 **v0.1.0 역사적 판정과 별개**다. [Phase 17 수용성 기록](live_monitoring_acceptance_17.md)의 environment별 PASS/BLOCKED/NOT_TESTED를 따른다. 현재 판정은 **로컬 기능 무결성 CONDITIONAL GO, 실제 릴리스 실행 GO 아님**이다. 이 checklist 자체는 버전 확정·tag·Release 승인이 아니다.

- [x] 시작 기능 SHA의 원격 main/CI, 변경 전 전체 회귀, 합성 단일 application loopback, FROM_END, status·혼합 SSE/replay/gap, 정상·오류 종료 뒤 listener/process FD·임시 자료 정리를 확인했다.
- [x] Safari 18.6 WebDriver에서 live 영역, staged 버튼 전후 네 결과 영역, pause 버튼을 확인했다. 이것은 사람의 키보드·확대·콘솔 검수를 대체하지 않는다.
- [ ] 실제 사용자 Safari keyboard-only: skip link, sample/파일 입력, live 버튼, 재연결, 다운로드, focus·trap·Tab/Option+Tab을 확인한다.
- [ ] 실제 Safari 200% 페이지 확대와 가능한 최소 CSS viewport에서 네 영역의 사용성·페이지 전체 overflow를 확인한다. 정확한 320 CSS px가 불가능하면 별도 NOT_TESTED로 남긴다.
- [ ] Safari Web Inspector의 JavaScript/CSP/MIME 오류, EventSource zombie, URL/Network 개인정보와 SSE 종료를 확인한다.
- [ ] 실제 Safari에서 pause 중 append, gap/overflow, DEGRADED/FAILED/stream_end, 수동 복구의 문구·focus·scroll을 확인한다. 재현하지 못한 상태는 Node PASS와 구분한다.
- [ ] Phase 17 검수 커밋의 원격 CI를 **push 이후 별도 승인된 릴리스 단계**에서 확인한다. 이번 작업에서는 push하지 않는다.
- [ ] 위 수동 gate의 blocker가 없고 새 전체 회귀·개인정보·자원 정리 결과가 유지된 뒤에만 v0.2.0 tag/Release 실행 여부를 별도 결정한다.

단일 source·loopback·process-local 범위만 후보에 포함한다. SSH/access live analysis, cross-source, 영구 저장, crash recovery, exactly-once, hosted 배포는 후보 밖이다. VoiceOver 전체 읽기와 Safari 정확한 320 CSS px 미검증만으로 자동 NO-GO를 선언하지 않지만 이를 PASS로 표시하지 않는다. 탐지 관찰·관계·사례는 침해·인과·확정 사고가 아니다.

### Phase 17.1 사용자 직접 확인 — 2026-10-14

위 Phase 17 체크박스는 당시의 미완료 상태를 보존한다. 최신 항목별 결과는 [Phase 17.1 후속 기록](live_monitoring_acceptance_17.md#phase-171-후속-사용자-직접-검수--2026-10-14)을 따른다.

- [x] 사용자가 Safari keyboard-only의 live 일시 정지·재개, 새 결과 적용, visible focus·trap 부재를 `PASS`로 확인했다. 이번 응답은 Tab과 Option+Tab 중 사용한 방식을 특정하지 않는다.
- [x] 사용자가 실제 Safari 페이지 확대 200%와 가능한 최소 창 너비에서 핵심 버튼·네 결과 영역 사용성을 각각 `PASS`로 확인했다. 정확한 CSS viewport 숫자와 320 CSS px는 `NOT_TESTED`다.
- [x] 사용자가 Web Inspector의 새로고침·live 연결·새 결과 적용 범위에서 JS/CSP/MIME 오류, 무제한 중복 EventSource, URL/SSE 민감정보 문제 없음을 `PASS`로 확인했다. 이후 pause·terminal 시점 Inspector 재관찰과 종료 뒤 zombie 요청은 별도 미검증이다.
- [x] 사용자가 실제 Safari pause 중 append의 pending 증가·서버 수집 지속 안내·재개 뒤 수동 적용, 합성 truncation 뒤 terminal 복구 안내를 각각 `PASS`로 확인했다.
- [ ] 실제 Safari replay gap 화면은 안전한 주입을 수행하지 못해 `NOT_TESTED`다. 자동 HTTP·Node·pytest 계약 PASS를 사용자 수동 확인으로 대체하지 않는다.
- [ ] 이번 검수 커밋의 원격 CI와 v0.2.0 tag/Release 실행 승인은 별도 후속 단계다. 이 amend에서는 push·tag·Release를 하지 않는다.

현재 후보 판정은 **CONDITIONAL GO**다. 위 사용자 직접 PASS 범위에서 최소 NO-GO blocker는 보고되지 않았으나 실제 Safari gap·수동 재연결/종료 뒤 Network 관찰이 남는다. VoiceOver 상세와 정확한 320 CSS px만 미검증이라는 이유로 자동 NO-GO를 선언하지 않지만 WCAG 준수도 주장하지 않는다.

## v0.2.0 로컬 릴리스 후보 준비 — Phase 18

이 절만 v0.2.0 후보의 현재 gate다. 위 v0.1.0 및 Phase 17/17.1 체크 상태는 당시 기록으로 보존한다. [Phase 18 Safari 복구 기록](live_monitoring_release_gate_18.md)에서 실제 replay gap·종료 후 수동 복구와 무조작 중 요청 비증가를 사용자와 확인했다. Safari `stream_end` frame 자체·정확한 320 CSS px·VoiceOver 상세는 확인하지 않았다. 로컬 후보 판정은 **CONDITIONAL GO**이며 실제 tag/Release 실행 승인이 아니다.

### 후보 소스와 로컬 검증

- [x] v0.2.0의 버전 단일 출처는 `pyproject.toml`이고 `uv.lock` metadata만 이에 맞춘다. Dependency 집합은 변경하지 않는다.
- [x] 영속적인 [v0.2.0 릴리스 노트](releases/v0.2.0.md), CHANGELOG, README, LICENSE, [SECURITY](../SECURITY.md) 경계를 확인한다.
- [x] 시작 SHA의 원격 CI, 변경 전 전체 회귀, 인증·웹 79/79, Linux 21/21, risk/case 70/70을 확인했다.
- [x] Safari 18.6에서 replay gap의 stale·복구와 정상 종료 뒤 수동 복구 문구, 버튼 무조작 중 요청 비증가를 사용자 직접 확인했다. `stream_end` frame 자체는 미확인이다.
- [ ] 준비 커밋의 별도 clean checkout에서 locked install·전체 회귀·세 평가, 기존 sample/3파일/Linux Audit와 loopback live smoke, privacy canary, listener·FD·임시 자료 정리를 다시 확인한다.
- [x] UTC/KST 동일 focused 32건씩, Node 문법·동작, `uv lock --check`, `git diff --check`, live focused 371건과 전체 회귀 1,995건·기존 경고 2개를 확인했다. 실제 loopback smoke의 종료 후 listener·임시 자료 정리와 기존 runner/worker의 task·SSE slot·tail FD·active lease/proposal 정리 테스트를 구분한다.
- [ ] `uv build` 결과를 별도 기록한다. 기존 flat-layout 문제가 남으면 source checkout만 지원하고 wheel/PyPI는 주장하지 않는다.

### 게시 전 별도 gate — 이번 준비 단계에서는 미수행

- [ ] 최종 준비 커밋을 push한 뒤 **바로 그 SHA**의 GitHub Actions CI 성공과 clean working tree, local/remote `main` 일치를 확인한다.
- [ ] 기존 `v0.2.0` tag·GitHub Release가 없는지 확인하고 annotated tag target을 최종 SHA로 검증한다.
- [ ] GitHub Release body가 [영속적인 릴리스 노트](releases/v0.2.0.md)와 일치하고 asset이 **0개**인지 검증한다.
- [ ] 사용자·유지관리자의 최종 tag/Release 승인과 새로운 blocker 부재를 확인한다. v0.1.0 tag·Release는 변경하지 않는다.

단일 application source의 live analysis, SSH/access detection-only, process-local bounded replay만 포함한다. Cross-source, crash recovery, exactly-once, hosted/multi-tenant, 운영 SLA, WCAG 2.2 AA 완전 준수와 wheel/PyPI 배포는 후보 범위 밖이다.

## 후속 v0.3 SSH checkpoint 수용 후보 — Phase 26.1

이 항목은 위 v0.2.0 역사적 판정이나 공개 Release를 변경하지 않는다. [Phase 26.1 독립 검증 기록](ssh_checkpoint_linux_acceptance_26_1.md)의 새 커밋이 원격에 push된 후에만 다음을 판정한다.

- [ ] Ubuntu 24.04에서 SSH focused와 별도 두 프로세스 lock·재시작·reset CLI smoke 성공.
- [ ] 실제 0700/0600 mode, source/config/sibling 보존, fail-closed 오류·개인정보 비노출 확인.
- [ ] 정확한 최종 SHA의 전체 CI·기존 경고·자원 정리 확인. Mac 수치나 기존 SHA의 CI를 Ubuntu 독립 수용으로 대체하지 않는다.

## v0.3.0 로컬 릴리스 후보 — Phase 27

이 절이 v0.3.0의 현재 gate다. 위 절은 당시 판단 이력이며 [릴리스 노트](releases/v0.3.0.md)의 지원 범위가 우선한다. 준비 커밋은 tag·Release 실행 승인이 아니다.

| Gate | 판정 | 근거와 남은 일 |
| --- | --- | --- |
| Phase 26.1 Ubuntu SSH focused·별도 CLI/server 프로세스 | **PASS** | `9bf8efc2ff998932d7043e2c6e916e24a0cb26b6`의 [원격 CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39202932840): SSH focused 30 passed, 별도 재시작·reset smoke 성공, 전체 2,343 passed·기존 경고 2개 |
| Ubuntu application checkpoint | **PASS** | 같은 CI의 application checkpoint 17 passed; 실제 전원 차단을 검증한 것은 아님 |
| macOS application·SSH checkpoint | **PASS** | Phase 21·26의 로컬 합성 테스트 범위; 다른 filesystem 일반화 금지 |
| Config/checkpoint upgrade·privacy·dependency lock | **PASS** | macOS 전체 2,346 passed·기존 경고 2개, checkpoint/property/API/evidence focused 114 passed, UTC/KST focused 각 77 passed, 합성 79/79·21/21·70/70, bundle runtime 37/dev 57, `uv lock --check` 및 synthetic loopback SSH/application 통과. 최종 clean checkout은 별도 gate |
| 최종 커밋의 detached clean checkout | **PASS** | 별도 detached checkout에서 `uv sync --locked --dev`, `uv lock --check`, 전체 2,347 passed·기존 경고 2개, 세 합성 평가, evidence bundle 37/57, application·SSH CLI/loopback smoke, Safari WebDriver 자동 smoke를 검증. 문서 보정 후 같은 commit 내용으로 재확인 |
| `uv build`와 배포 방식 | **PASS** | 기존 flat-layout 다중 top-level package 발견으로 빌드 실패(exit 2)를 재확인; 지원 방식은 source checkout만이며 wheel/PyPI asset 금지 |
| Safari v0.3.0 application·SSH live 자동 smoke | **PASS** | 실제 Safari WebDriver에서 두 역할 모두 live 영역, 새 결과 적용 전 목록 불변·적용 후 네 영역·pause·개인정보 비노출 확인. Synthetic explicit v1 흐름이며 checkpoint 재시작 화면까지 검증한 것은 아님 |
| Safari v0.3.0 수동 사용자 흐름 | **NOT_TESTED** | 새 SSH live·checkpoint 재시작·reset 이후 화면의 keyboard-only, 200% 확대, 최소 폭, Web Inspector console/CSP/Network, VoiceOver 상세는 v0.2 결과를 승계하지 않음 |
| 최종 SHA 원격 CI: **BLOCKED** | **BLOCKED** | 후보 커밋 push 이후 바로 그 SHA의 CI 성공을 확인해야 함 |
| 기존 v0.1.0·v0.2.0 tag/Release 보존, v0.3.0 부재 | **PASS** | 준비 시작 시 확인; 실제 tag/Release 전 다시 확인 |
| Release asset 첨부 | **NOT_APPLICABLE** | 이번 단계에서는 wheel, binary, SBOM, report를 업로드하지 않음; 별도 승인 필요 |
| 영속 릴리스 노트·SECURITY·LICENSE | **PASS** | 노트와 MIT 저작권 확인. GitHub API `enabled: true`와 공개 Security 화면의 **Report a vulnerability** 진입점 확인. 게시 전 유지관리자 검토는 별도 |

후속 판정은 최종 clean checkout·privacy·lock 검증 결과에 따라 갱신한다. 정확한 최종 SHA 원격 CI와 Safari 수동 검수는 push 전 PASS로 표시할 수 없다. Source checkout 외 설치, 자동 rotation/copytruncate, 다중·cross-source, exactly-once, 무유실, hosted 배포, WCAG 2.2 AA는 후보 범위 밖이다.
