# Phase 22.1a — REA 정적 JavaScript 실행 경로 공급망 감사

판정: **NO-GO**. `rea-agents@6.5.0`의 `analyze-javascript-application` 경로에서 확인한 native import는 대부분 조건부·지연 실행이지만, 게시된 CLI의 모든 번들 chunk 초기화와 별도 JavaScript analysis worker의 전체 전이 그래프, registry 설치 시 실제 dependency 해석·부작용까지 완전히 증명하지 못했다. `--ignore-scripts --omit=optional`은 안전한 실행을 보증하는 공식 REA 계약이 아니다. 이 단계에서 REA CLI는 실행하지 않았다. REA 및 dependency를 설치하지 않았다. Phase 22.1의 공급망 중단을 해제하거나 pilot 실행을 승인하지 않는다.

시작점은 clean `main`의 `675d2ef69f2c8cf41bbeec8b9d72345d474be7c7`로 `origin/main`과 일치했다. 해당 SHA의 [원격 CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38859744789)는 completed/success다. 변경 전 전체 pytest는 2,193 passed·기존 경고 2개였다. 이 감사에는 공식 source·registry metadata·npm tarball의 **정적 읽기**만 사용했다. npm install, npx, lifecycle script, CLI/help, native addon, Process Capture, setup/MCP는 실행하지 않았다. Production code·production dependency·`uv.lock`·Codex 설정은 변경하지 않았다.

## 고정 artifact와 대조 범위

| 항목 | 정적 증거 | 한계 |
|---|---|---|
| 공식 release/tag | [GitHub tag](https://github.com/morluto/rea/releases/tag/rea-agents-6.5.0) `rea-agents-6.5.0` → commit `3b79af28e80785afce9f5998d8f03289402a1847` | Tag/source 연결은 실행 안전성 보증이 아니다. |
| npm 게시물 | [`rea-agents@6.5.0` metadata](https://registry.npmjs.org/rea-agents/6.5.0): bin `scripts/rea.mjs`, Node `^22.19.0 || ^24.11.0 || >=26.0.0`, integrity `sha512-C6BG7LyrAdR74mSjertM6PrxJkcNZ2bfQNOJornPo9erDEp2tyPRVYPnV5Yodr+1RqewCQla68WulXlVnveD+A==` | Tarball 전체 SHA-512의 독립 계산은 [Phase 22.1 기록](rea_cli_pilot_22_1.md)에 있다. 이번 감사에서 install은 하지 않았다. |
| Source 대 tarball | Tag의 `scripts/rea.mjs`와 [게시 tarball](https://registry.npmjs.org/rea-agents/-/rea-agents-6.5.0.tgz)의 `package/scripts/rea.mjs`는 byte 단위로 일치했다. 게시 `dist/cli-runtime/cli.js`의 command 등록과 service import도 source 구조와 대조했다. | 전체 TypeScript source와 bundler output의 byte 단위 동등성, 모든 chunk의 top-level side effect는 입증하지 못했다. |
| Lock | [공식 tag의 package-lock v3](https://raw.githubusercontent.com/morluto/rea/rea-agents-6.5.0/package-lock.json)는 722 package entry의 정적 조사 자료다. | npm tarball에 `package-lock.json`/`npm-shrinkwrap.json`이 없어 일반 registry 설치의 전이 버전 고정 근거가 아니다. |

## CLI import·dispatch graph

```text
scripts/rea.mjs
  → dist/cli-runtime/cli.js + 출력 chunk 동적 import
  → createCli().serve(args)
  → 모든 command registrar 정적 import·등록
  → analyze-javascript-application handler
  → JavaScriptApplicationService 동적 import
  → JavaScriptArtifactReconstruction → JavaScriptSourceAnalysis
  → 별도 Node JavaScriptAnalysisWorker 프로세스
```

근거: 공식 source의 [`scripts/rea.mjs`](https://raw.githubusercontent.com/morluto/rea/rea-agents-6.5.0/scripts/rea.mjs), [`src/cli.ts`](https://raw.githubusercontent.com/morluto/rea/rea-agents-6.5.0/src/cli.ts), [`src/cli/electronCommands.ts`](https://raw.githubusercontent.com/morluto/rea/rea-agents-6.5.0/src/cli/electronCommands.ts), [`src/cli/javascriptApplicationAnalysis.ts`](https://raw.githubusercontent.com/morluto/rea/rea-agents-6.5.0/src/cli/javascriptApplicationAnalysis.ts), [`JavaScriptApplicationService.ts`](https://raw.githubusercontent.com/morluto/rea/rea-agents-6.5.0/src/application/javascript/JavaScriptApplicationService.ts), [`JavaScriptAnalysisWorker.ts`](https://raw.githubusercontent.com/morluto/rea/rea-agents-6.5.0/src/javascript/analysis/JavaScriptAnalysisWorker.ts)와 게시된 `dist/cli-runtime/cli.js`를 비교했다. Source에서 모든 registrar가 대상 명령과 무관하게 초기 등록된다는 점이 핵심이다. 정적 JS 명령도 별도 Node worker를 생성하므로 “순수 in-process parsing만 수행”한다고 주장할 수 없다. CLI 인자·출력 schema는 실행 금지 조건 때문에 확인하지 않았다.

| 구성요소 | 확인한 import/load/guard | 판정 경계 |
|---|---|---|
| `package/native/windows/build/rea-windows-x64.node` | Tarball 내 873,593-byte Windows addon. [WindowsNativeLoader](https://raw.githubusercontent.com/morluto/rea/rea-agents-6.5.0/src/windows/WindowsNativeLoader.ts)는 `win32/x64`를 먼저 검사하고 나서 manifest·artifact read/require를 한다. 게시 chunk에도 guard가 남아 있다. | Linux/arm64에서 확인한 직접 경로는 차단된다. 단순 포함 파일이지 Linux에서 top-level load된다는 증거는 없다. 다른 동적 참조 전체를 증명한 것은 아니다. |
| `@lydell/node-pty@1.1.0` | [registry metadata](https://registry.npmjs.org/@lydell%2Fnode-pty/1.1.0)상 **필수 direct dependency**, platform별 6개 native package는 optional. REA의 [`ProcessHarness`](https://raw.githubusercontent.com/morluto/rea/rea-agents-6.5.0/src/process/capture/ProcessHarness.ts)와 게시 CLI에서는 Process Capture 시작 때 `import('@lydell/node-pty')`라는 dynamic import다. | node-pty package 자체는 Linux에서 `index.js`→`unixTerminal.js` top-level `requireBinary('pty.node')`를 실행한다. 예상 밖 import 하나라도 있으면 native load가 일어나며 optional binary를 생략하면 실패한다. |
| `frida@17.23.2` | REA의 optional direct dependency. [`FridaInstrumentationManager`](https://raw.githubusercontent.com/morluto/rea/rea-agents-6.5.0/src/frida/FridaInstrumentationManager.ts)의 `import('frida')`는 지연 loader 안에 있다. 모든 CLI 명령 등록 때 manager 객체는 만들어지지만, 확인한 생성자는 Frida를 import하지 않는다. | 대상 명령에서 Frida operation을 호출한다는 근거는 없지만 모든 초기화·worker 전이 경로에 대한 부재 증명도 없다. Frida install script가 있어 기본 설치는 별도 위험이다. |
| 기타 native binary | 게시 REA tarball의 `.node/.so/.dylib/.dll/.exe` inventory는 위 Windows addon 하나였다. `dist/native/*.js`는 JS, `.py/.swift`는 source다. | dependency tarball의 native binary는 별도이다. REA tarball inventory를 전체 설치 inventory로 오해하지 않는다. |

## Lifecycle·추가 다운로드 gate

[`rea-agents@6.5.0`](https://registry.npmjs.org/rea-agents/6.5.0) 자체에는 `preinstall`·`install`·`postinstall`이 없지만 `prepare`·`prepack`·`prepublishOnly`가 있다. 공식 tag lockfile에서 `hasInstallScript=true`인 non-dev 경로는 optional `frida@17.23.2`이며 [registry metadata](https://registry.npmjs.org/frida/17.23.2)의 `install: node scripts/install.js`와 `prebuild-install` 전이 의존성은 native prebuild 추가 다운로드 가능성을 만든다. Lockfile의 다른 script 표시인 `fsevents@2.3.3`과 nested `esbuild@0.25.12`는 dev 경로다. `@lydell/node-pty` 자체의 install script는 없지만 Linux/arm64 optional package에 `pty.node`가 있다. npm의 [`omit`·`ignore-scripts` 문서](https://docs.npmjs.com/cli/v11/commands/npm-install/)는 optional disk install 생략과 lifecycle 억제를 설명할 뿐, REA 명령이 그 구성으로 정상 동작한다고 약속하지 않는다.

따라서 `npm install --ignore-scripts --omit=optional` 또는 package extraction만으로 정적 JavaScript 분석이 동작한다는 근거는 없다. `--omit=optional`은 Frida script와 node-pty platform package 설치를 피하더라도 **node-pty가 import되는 순간 binary 누락 오류**를 일으킬 수 있다. Install-time transitive resolution은 tarball에 lockfile이 없고 실제 install을 하지 않았으므로 고정·검증되지 않았다. Package 일부 삭제나 patch 실행은 대안으로 승인하지 않는다.

## 위협 모델, 판정과 다음 gate

자산은 host 파일·credential·프로세스·개발 분석 결과이며, 진입점은 npm 설치 script, CLI 전체 registrar 초기화, dynamic import, worker spawn, native load다. 격리된 Docker와 `--network none`은 **분석 시** 네트워크·호스트 접근을 제한할 수 있지만, acquisition/install 시 추가 다운로드와 lifecycle side effect를 자동으로 제거하지 않는다. 이번 정적 감사는 정해진 공식 파일만 읽었고 사용자 홈·실제 로그·monitor config·`.env`·credential·저장소 전체를 REA에 전달하지 않았다. Raw REA JSON·Evidence는 생성되지 않았으므로 출력 개인정보 무노출은 `NOT_TESTED`다.

GO에는 정확한 게시 번들의 top-level side effect와 child worker/전이 import graph에서 Process Capture·Frida·Windows native 경로가 호출되지 않음을 완전히 입증하고, native 없이 정적 명령이 동작한다는 공식 install 계약 또는 통제된 별도 승인 실험이 필요하다. CONDITIONAL GO에는 공식적으로 지원되는 별도 package/install 옵션과 다운로드·lifecycle 목록이 있어야 한다. 현재는 둘 다 없어서 **NO-GO**를 유지한다. REA pilot 재개, optional native 허용, host npx/setup/MCP, production dependency 추가는 이 기록으로 승인되지 않는다.

이번 감사의 결과는 REA가 악성이라는 판단도, native가 반드시 실행된다는 주장도 아니다. 실행 경로의 일부가 지연·플랫폼 제한이라는 긍정적 관찰과, 전체 안전성의 **증명 공백**을 분리한 것이다. 제품의 SSH·checkpoint 동작과 무관하며 자동 rotation/copytruncate handoff·두 세대 metadata 확대의 NO-GO도 바꾸지 않는다.

검증은 문서 계약 focused 7 passed, 변경 후 전체 pytest 2,195 passed·기존 경고 2개(새 경고 0개), 합성 인증·웹 79/79, Linux 21/21, risk 70/70, case 70/70이었다. `uv lock --check`, 변경 테스트의 `py_compile`, `git diff --check`도 통과했다. 코드·dependency·lockfile을 바꾸지 않았으므로 REA 동작·성능·개인정보 출력에 관한 runtime smoke나 결과 검증은 수행하지 않았고 PASS로 분류하지 않는다.
