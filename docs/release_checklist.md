# v0.1.0 로컬 공개 릴리스 체크리스트

상태: **NO-GO**. 이 문서는 준비 증거와 공개 전 미완료 gate를 분리한다. `pyproject.toml`의 `0.1.0`은 프로젝트 버전이며 API/평가 schema version이 아니다. 태그·GitHub Release·push·PyPI 배포는 수행하지 않았다.

표시 규칙: `[x]`는 실제 수행한 자동/저장소 검증만 뜻한다. `[ ]`는 미수행, 확인 불가 또는 의사결정 대기다. 이 문서를 작성하는 커밋 자체의 최종 SHA와 CI 원격 실행은 나중에 기록한다.

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
- [x] 평가 `43/43`, parser `129/134` (ignored 2, rejected 3), risk·case `34/34`를 확인했다.
- [x] 반복 JSON SHA-256이 UTC/KST에서 `78584ce961096279ffe76974bfce57e2c0b0932270a7d53e75d8620c717ebe0c`로 같았다.
- [x] 변경 Python 테스트 compile, Node `--check`, documentation/first-user/privacy/API·CLI·HTML tests를 실행했다.
- [x] OpenAPI deprecation, privacy canary, standalone HTML CSP hash와 download byte count는 자동 테스트 범위다.
- [x] Clean checkout의 loopback launcher `--no-browser`에서 health·root·CSS·JS·sample·로컬 3종 분석이 200, 사례 2·독립 관찰 3이었다.
- [x] Ctrl+C 종료 뒤 8000번 port listener 없음, 알려진 staging directory 0건.
- [x] 최종 준비 커밋을 별도 clean checkout하여 `uv sync --locked --dev`, 전체 `1,518 passed, 2 existing warnings`, loopback health·웹 자산·sample·실제 로그 API·보고서 smoke를 다시 확인했다. 종료 후 port listener와 알려진 staging directory는 0건이었다.
- [x] 변경 Python 테스트 `py_compile`, `node --check frontend/app.js`, Node behavior test syntax, `git diff --check`, secret/private-path scan이 통과했다. Node behavior는 기존 pytest harness가 stdin fixture를 제공할 때 검증된다.

## 수동 접근성·사용성

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

현재 go/no-go: 라이선스와 비공개 신고 경로 결정은 완료됐다. Safari 수동 검증과 원격 CI가 미완료이므로 **공개 릴리스 NO-GO**이며, 이번 작업은 문서 준비 커밋까지만 진행한다. Hosted/public 실제 로그 업로드는 별개의 더 강한 no-go다.
