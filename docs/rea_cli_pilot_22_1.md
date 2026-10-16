# Phase 22.1 — REA CLI-only pilot 공급망 gate 결과

판정: **PILOT_BLOCKED_SUPPLY_CHAIN**. 2026-10-16에 Docker 격리와 공식 배포물의 무결성 확인까지 수행했지만, 배포 tarball에서 설계 단계에 확인되지 않은 native addon을 발견했다. 사용자 승인 범위의 중단 조건에 따라 dependency 설치, REA CLI help, `analyze-javascript-application` 실행, 대상 파일 복사 및 결과 비교는 **수행하지 않았다**. 이는 REA가 악성이라는 판정이 아니라 이 pilot의 실행 안전성을 입증하지 못했다는 뜻이다.

## 시작 상태와 격리 gate

시작점은 clean `main`의 `071e37b1f573c7ccfa016a790408b9a9887743f5`이며 `origin/main...HEAD`는 behind 0/ahead 0이었다. 해당 SHA의 [GitHub Actions CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38833675235)는 completed/success였다. Codex 사용자 config에서 REA MCP 등록이 없고 REA skill/plugin 디렉터리도 없는 것을 확인했다. 이름에 `rea`가 포함된 일반 `skill-creator`는 REA 등록이 아니다. 설정 내용이나 credential은 출력하지 않았다.

호스트는 macOS arm64, Docker Desktop 4.95.0 및 Docker Client/Server 29.8.2, Engine 아키텍처 aarch64였다. 처음에는 Engine socket이 응답하지 않아 Docker Desktop 앱을 시작했고, Server 응답을 확인한 다음에만 진행했다. 격리 시험 이미지는 Docker Official `busybox:1.37.0`의 **linux/arm64 manifest** `sha256:d82c2ab94640ded77cf76514ce6a84870761105058a4a9e51b05a8a79be97a6c`로 고정했다. 취득용 Node 이미지는 Docker Official `node:24.11.1-alpine`의 **linux/arm64 manifest** `sha256:f4a1ba23ca013418f51f7d4d4673d8f8797241b68c05436a8825031a84c9f4e6`로 고정했다. Mutable tag만으로 컨테이너를 실행하지 않았다.

격리 시험은 `--platform linux/arm64 --network none --read-only --cap-drop ALL --security-opt no-new-privileges --cpus 0.5 --memory 128m --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=16m`로 실행했다. 컨테이너 안에서 Docker socket과 `/Users`가 보이지 않았고, `/etc` 쓰기가 실패했으며, `/tmp` 쓰기는 가능했다. route 항목이 없고 `CapEff=0`, `NoNewPrivs=1`, `cpu.max=50000 100000`, `memory.max=134217728`, `pids.max=64`를 확인했다. 이 한 컨테이너의 관찰을 일반적인 Docker 보안 보장으로 확대하지 않는다.

## 공식 배포물과 중단 근거

[공식 release](https://github.com/morluto/rea/releases/tag/rea-agents-6.5.0)의 tag `rea-agents-6.5.0`은 source commit `3b79af28e80785afce9f5998d8f03289402a1847`을 가리켰다. 전용 acquisition 컨테이너에서 npm registry metadata와 `rea-agents@6.5.0`의 provenance endpoint를 조회했다. npm의 publish·SLSA attestation payload는 package subject SHA-512와 동일한 값을 담고, SLSA source commit도 위 GitHub SHA를 가리켰다. **서명 자체를 독립 검증한 것은 아니므로** attestation 조회만으로 실행 안전성을 주장하지 않는다.

별도 Docker volume 하나에 `npm pack --ignore-scripts`로 tarball만 받았다. registry의 `dist.integrity`, npm pack 결과, tarball bytes를 독립 계산한 값은 모두 `sha512-C6BG7LyrAdR74mSjertM6PrxJkcNZ2bfQNOJornPo9erDEp2tyPRVYPnV5Yodr+1RqewCQla68WulXlVnveD+A==`로 일치했다. 압축 파일은 5,634,033 bytes, 목록은 1,650개 파일이었다. package bin은 `rea`와 `rea-agents` 모두 `scripts/rea.mjs`, Node engine은 `^22.19.0 || ^24.11.0 || >=26.0.0`이다. package 자체에는 `preinstall`·`install`·`postinstall` script가 없지만 `prepare`·`prepack`을 포함한 다른 script는 있다. `npm pack --ignore-scripts`에서 lifecycle script는 실행하지 않았다.

직접 의존성에는 `@lydell/node-pty@1.1.0`, optional dependency에는 `frida@17.23.2`가 있다. `@lydell/node-pty`는 platform별 native package들을 optional dependency로 선언한다. 더 결정적인 관찰은 실제 tarball에 `package/native/windows/build/rea-windows-x64.node`라는 873,593-byte native addon이 포함돼 있다는 것이다. 이는 Phase 22.0의 tarball 파일 목록 검토 전에 확인되지 않았던 binary이다. Linux/arm64 정적 JavaScript 분석에서 로드되지 않을 가능성은 있으나, **실행 경로와 transitive 설치 부작용을 이번 gate에서 입증하지 못했다**. 사용자 지시의 “예상 밖 binary·native addon” 및 “optional native dependency 불필요성 미입증” 중단 조건을 적용했다. Dependency를 설치하거나 `--omit=optional`의 호환성을 추측해 REA를 실행하지 않았다. Native addon이나 Frida를 설치·실행하지 않았다.

Acquisition의 네트워크 목적지는 Docker Official image registry, GitHub API, npm registry metadata·attestation·tarball에 한정했다. Dependency fetch, lifecycle script, native prebuild 추가 다운로드는 발생시키지 않았다. 분석용 네트워크 차단 컨테이너, REA help, 정적 분석, Process Capture, MCP, setup은 실행하지 않았다.

## 대상·결과·개인정보·정리

승인된 공개 대상 `frontend/live-monitoring.js`는 **복사하거나 컨테이너에 mount하지 않았다**. 따라서 REA 관찰과 `tests/test_live_monitoring_ui.py`/Node 테스트의 비교는 `NOT_TESTED`이며, source에 대한 새 결함 주장도 없다. REA stdout/JSON/Evidence는 생성되지 않았다. 실제 로그, 기본 monitor config, `.env`, credential, 사용자 홈, 저장소 전체, `.git`, Docker socket은 컨테이너에 전달하지 않았다. Privacy canary의 raw REA 출력 검사는 산출물이 없어 `NOT_APPLICABLE`이다. 이를 개인정보 무노출에 대한 도구 전체의 보증으로 표현하지 않는다.

생성이 확인된 acquisition volume은 제거했고 pilot 이름의 컨테이너는 남지 않았다. Tarball·npm cache는 그 volume 안에만 있었으므로 함께 제거됐다. 대상 복사본, raw output, pilot 전용 image build는 없었다. 공식 Busybox/Node base image cache는 공유 Docker image로 남았으며 pilot 전용 산출물이라고 추측해 삭제하지 않았다. Codex MCP·skill·config 및 원본 저장소 파일은 변경하지 않았다. Volume 삭제는 secure erase가 아니며 Docker Desktop cache·filesystem snapshot의 완전 삭제를 주장하지 않는다.

## 후속 gate

현재 REA pilot의 분석 단계는 **NO-GO**다. 재시도하려면 별도 검토에서 (1) tarball 내 Windows native addon의 필요·로드 경로, (2) `@lydell/node-pty`와 Frida를 포함한 transitive native·lifecycle script, (3) `--ignore-scripts --omit=optional`로 정적 JavaScript 명령이 지원되는지, (4) 모든 dependency 다운로드 목적지와 lock/integrity, (5) network-none 실행의 실제 인자·출력 schema를 먼저 입증해야 한다. 새 승인 없이 setup, macOS 호스트 `npx`, production dependency·`uv.lock` 변경으로 우회하지 않는다. Phase 21의 checkpoint·rotation 의미도 이 pilot과 무관하다.
