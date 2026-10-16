# Phase 22.0 — REA 개발용 pilot 설계와 실행 전 승인 gate

상태: **설계 전용, 설치·setup·REA 실행 전.** REA는 [`morluto/rea`](https://github.com/morluto/rea)의 Reverse Engineer Anything을 뜻한다. 개발 보조의 잠재 가치만 공개·합성 대상으로 평가한다. 이 저장소의 탐지·상관관계·risk·case 결과 생성, 사용자 기능, production dependency, `uv.lock`, runtime, CI에는 넣지 않는다. Phase 21.8의 [Ubuntu CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38832668732)는 정확한 커밋 `75e09d977ae24631799dfa3e005cbbd8134bd808`에서 Linux 전용 17건과 전체 2176건 통과로 확인됐다. 그 사실을 옮기기 위한 별도 검증 커밋은 만들지 않는다.

## 공급망과 정확한 버전

검토 기준일 2026-10-16의 선택은 공식 GitHub [release `rea-agents-6.5.0`](https://github.com/morluto/rea/releases/tag/rea-agents-6.5.0), 태그의 source commit `3b79af28e80785afce9f5998d8f03289402a1847`, 공식 npm package `rea-agents@6.5.0`이다. [npm registry metadata](https://registry.npmjs.org/rea-agents/6.5.0)의 tarball은 `https://registry.npmjs.org/rea-agents/-/rea-agents-6.5.0.tgz`, `dist.integrity`는 `sha512-C6BG7LyrAdR74mSjertM6PrxJkcNZ2bfQNOJornPo9erDEp2tyPRVYPnV5Yodr+1RqewCQla68WulXlVnveD+A==`이다. [npm provenance](https://registry.npmjs.org/-/npm/v1/attestations/rea-agents@6.5.0)는 해당 source commit에 연결된다. 이 metadata는 배포 연계를 확인하는 출발점이지 실행 안전성 증명은 아니다. GitHub release에는 별도 첨부 binary asset가 없으며 npm tarball이 실제 실행 배포물이다. 정확한 tarball bytes·transitive dependency·lifecycle script는 **실행 전 승인 단계에서 다시 검증**한다. `@latest`, 이름이 비슷한 fork, 무검증 재배포물은 사용하지 않는다.

공식 저장소의 [LICENSE](https://github.com/morluto/rea/blob/rea-agents-6.5.0/LICENSE)는 MIT다. [SECURITY.md](https://github.com/morluto/rea/blob/rea-agents-6.5.0/SECURITY.md)는 최신 배포판만 security fix 대상으로 안내하고 비공개 취약점 신고를 권한다. 따라서 6.5.0 pin은 pilot 재현성을 위한 고정이며 이후 취약점 여부·새 release는 실행 직전에 재평가한다. npm metadata는 37개 direct dependency와 optional `frida@17.23.2`를 선언한다. Frida의 설치 script는 native prebuild를 추가로 가져올 수 있으므로 `npx`의 기본 설치를 네트워크 범위가 registry 한 곳뿐인 동작으로 간주하지 않는다. `--ignore-scripts`·optional dependency 제외가 이 정적 분석에 호환되는지는 아직 입증되지 않았다. 실패하면 실행 gate를 멈추고 별도 승인을 요청한다. 공식 [설치 문서](https://github.com/morluto/rea/blob/rea-agents-6.5.0/docs/installation.md)는 Node 22.19+/24.11+/26+의 지원 범위와 정확한 package version pin을 설명한다.

## 예상 설치 변경과 네트워크

`npx rea-agents setup`은 읽기 전용 명령이 아니다. 공식 [설치 안내](https://github.com/morluto/rea/blob/rea-agents-6.5.0/docs/installation.md)와 [태그의 client mapping](https://github.com/morluto/rea/blob/rea-agents-6.5.0/src/application/SupportedClients.ts)을 기준으로, setup을 Codex에 적용한다면 예상되는 변경은 아래와 같다. **Phase 22.0에서는 모두 미수행**이며, 설정 파일의 실제 변경 목록은 승인 후 dry-run으로 확인해야 한다. 현재 Codex 사용자 설정은 읽거나 변경하지 않았다.

| 후보 동작 | 예상 변경·네트워크 | Phase 22.0 판정 |
|---|---|---|
| Pin된 package 취득 | npm 설정 registry의 metadata, `rea-agents@6.5.0` tarball, transitive package와 별도 지정할 npm cache(예: 그 cache의 `_npx/`); optional native install script의 추가 다운로드 가능 | 미수행; 정확한 목적지·script·integrity 사전 점검 필요 |
| Codex 대상 setup | `$CODEX_HOME/config.toml`(기본 `~/.codex/config.toml`)의 `[mcp_servers.rea]`에 `npx -y rea-agents@6.5.0 mcp` 등록, startup 30초와 계산된 tool timeout; 기존 설정 backup·recovery copy 가능 | pilot 첫 회차에는 하지 않음 |
| 기본 bundled skill | 공유 `~/.agents/skills/reverse-engineer-anything/`의 `SKILL.md`와 references 6개(`connection-and-recovery`, `native-and-artifacts`, `javascript-applications`, `android-applications`, `runtime-observation`, `evidence-workflows`), 기존 항목의 `.rea.backup` 가능; `$CODEX_HOME`만 분리해도 이 경로는 분리되지 않음 | pilot 첫 회차에는 하지 않음 |
| Optional Hopper/Ghidra/provider | 명시적으로 선택하면 별도 다운로드·설치·경로 저장 가능 | 선택 금지; 정적 JavaScript에는 불필요 |
| CLI-only 첫 pilot | pin된 package를 별도 임시 npm cache에 취득·실행하되 Codex MCP·skill은 등록하지 않음; 임시 target·Evidence 출력과 REA-owned `~/.rea` state/cache 생성 가능성도 사전 inventory | **승인 후에만** 후보; 실제 download/install script 감사를 먼저 통과 |

공식 setup은 selected client의 설정과 skill을 바꿀 수 있고 backup을 만든다. `--client codex --skill=false --dry-run`은 나중에 범위를 확인할 수 있는 후보지만, 이것도 REA code 실행이므로 **이번 단계에서 호출하지 않았다**. `--all-detected`, `--yes`에 의한 광범위 적용, `curl | bash`, Hopper 자동 설치, global npm install은 첫 pilot에서 금지한다. Repo의 `pyproject.toml`, `uv.lock`, frontend, production source, GitHub Actions CI는 변경하지 않는다. `npx` package acquisition 자체가 npm registry 및 dependency 호스트에 접근할 수 있으므로 설치·업데이트 때 네트워크 allowlist가 확인되지 않으면 NO-GO다.

## 위협 모델과 개인정보 경계

공식 [REA README](https://github.com/morluto/rea/blob/rea-agents-6.5.0/README.md)는 target 분석이 로컬에서 일어난다고 하지만 agent/MCP로 전달된 결과에는 별도 **모델 제공자** 정책이 적용된다. 로컬 분석이라는 말이 모델 전송 부재를 뜻하지 않는다. CLI raw stdout/Evidence를 Codex 도구 결과에 그대로 실어 보내는 것도 전송 경계이므로, 승인된 실험에서는 private output에만 기록하고 allowlist 안전 요약을 검토한 뒤 전달한다. REA의 [Process Capture](https://github.com/morluto/rea/blob/rea-agents-6.5.0/docs/process-capture.md)는 선택한 명령을 **현재 사용자 권한**과 상속 environment로 실행하고 **sandbox가 아니다**. `filesystem_observation_paths`는 snapshot 선택일 뿐 실제 접근 제한이 아니다. 첫 pilot은 Process Capture, browser/network capture, native decompiler, MCP 호출을 모두 제외하고 정적 JavaScript CLI 한 번만 검토한다. 파일 경로 allowlist는 검토 규칙일 뿐 OS-enforced sandbox가 아니다. 강제 격리가 필요하면 별도 최소 권한 account/container와 filesystem·network 제한을 따로 승인·검증해야 한다.

| 자산·위협 | 진입점과 예방 | 탐지·실패 동작·잔여 위험 |
|---|---|---|
| 실제 로그·계정·IP·원본 path/query·credential 유입 | 대상·cwd·argv·env·출력·Evidence 모두 공개·합성만; `.env`, 기본 monitor config, 실제 로그, 홈 디렉터리, keychain과 credential file 제외 | target 목록과 env key allowlist를 실행 전 검토; 발견 시 pilot 중단·원문 공유 금지 |
| npm 공급망 변조·postinstall network | 공식 tag↔npm provenance·SRI 재확인, exact version pin, lifecycle/dependency 조사; 자동 setup 금지 | 출처·integrity·추가 download 미확인 시 실행하지 않음; 서명/provenance도 무해성 보증 아님 |
| REA/target의 같은 UID 권한 남용 | 별도 임시 공간·최소 env·파일 하나만 복사; 가능하면 별도 저권한 OS 경계 | 경로 allowlist는 차단 장치가 아니므로 host 파일 접근 가능성 잔존; 이상 접근은 NO-GO |
| 모델 제공자·MCP로 Evidence 전송 | 첫 pilot은 CLI-only, raw Evidence를 agent에 붙여넣거나 MCP로 보내지 않음; 검토한 안전 요약만 공유 | 외부 제공자 retention·정책은 REA가 통제하지 않음; 사전 승인 없는 전송 금지 |
| 과대해석·불완전 관찰 | 소스 위치·파일 digest·coverage를 요구하고 pytest·수동 소스와 대조 | 누락·truncation은 `UNKNOWN`, 일치하더라도 runtime·보안성 증명 아님 |
| 임시 산출물·cache 잔존 | private temp와 별도 npm cache inventory, 보고서에는 raw Evidence 미첨부 | backup·filesystem snapshot·crash dump의 secure erase 주장 금지 |

## 첫 read-only pilot

첫 대상은 이 저장소의 공개 [`frontend/live-monitoring.js`](../frontend/live-monitoring.js) **한 파일을 byte-for-byte 복사한 합성/공개 임시 대상**이다. 원본 workspace, source log, repo 전체, 사용자 HOME을 REA target으로 주지 않는다. 임시 디렉터리는 `0700`, 링크·추가 파일 없음, 선택 파일 ≤1 MiB로 검증한다. 분석 출력과 npm cache도 별도 임시 위치에 두고 각 위치를 기록한다. `HOME`·`XDG_CACHE_HOME`·`npm_config_cache`는 승인된 임시 root 아래로 한정하고, 전달할 환경변수 이름을 allowlist로 고정한다. 다만 환경변수를 바꾼 것만으로 같은 UID의 실제 홈 접근이 차단되지는 않는다. CLI의 정적 JavaScript 분석은 REA 공식 [JavaScript artifact 문서](https://github.com/morluto/rea/blob/rea-agents-6.5.0/docs/javascript-artifact-reconstruction.md)에 따르면 대상 JavaScript 코드를 실행하지 않는다. REA 내부 helper는 실행될 수 있으므로 이것을 read-only *프로세스*나 sandbox로 부르지 않는다.

예비 개발 상한은 source 분석 15초, 상위 process 전체 30초, captured stdout/stderr와 Evidence 파일 각각 1 MiB이다. 이 값은 REA 또는 외부 표준의 운영 보장이 아니라 이 한 파일 실험의 중단 기준이다. REA의 source timeout·heap 옵션은 전체 wall time/RSS 상한이 아니므로 독립 감시가 필요하다. 완료되지 않았거나 cap을 넘은 결과는 축약한 성공으로 처리하지 않는다. 승인 전 실행 명령의 정확한 옵션·호환성·부작용을 검증한다. 필요하다면 격리된 별도 사용자 또는 container가 준비될 때까지 pilot을 보류한다.

## 검증 oracle와 판정

REA 결과는 사실의 oracle이 아니다. 원본 복사본의 SHA-256, 파일 수·크기, REA가 표시하는 출처·coverage를 먼저 대조한다. `tests/test_live_monitoring_ui.py`와 `tests/live_monitoring_ui_behavior.cjs`의 Node 테스트, 원본 소스 수동 검토를 독립 oracle로 사용한다. 검증 후보는 status/events URL, EventSource 생성, pending item/byte 상한과 exact validation이다. REA가 이 중 일부만 찾으면 나머지는 `NOT_OBSERVED`; 정적 결과로 실제 브라우저 동작을 확정하지 않는다. 유용성 최소 기준은 소스 위치가 있는 사실 하나 이상을 독립 oracle이 재현하는 것이다. 원본과 다른 해석, 출처 없는 보안 주장, 무단 파일·네트워크 접근, resource cap 초과, 청소 불완전, 개인정보 포함 산출물은 NO-GO다.

Phase 21.8의 Linux checkpoint gate와 이 pilot은 별개다. REA로 detection·correlation·risk·case 의미를 생성·수정하지 않는다. 운영환경 탐지 성능, 접근성, 실제 공격 여부도 추론하지 않는다.

## 제거와 복원

첫 CLI-only pilot에는 Codex MCP·skill 등록을 하지 않으므로 복원할 Codex 설정 변경이 **0개여야 한다**. 실행 전후 해당 파일 identity/digest와 git status를 비교하되 설정의 원문·secret을 보고서에 복사하지 않는다. 임시 target, 출력, 별도 npm cache의 정확한 생성 목록을 확인하고 해당 pilot-owned 경로만 정리한다. 알 수 없는 파일이나 기존 사용자 cache는 삭제하지 않는다. 삭제는 secure erase가 아니다. REA가 예상치 않게 다른 파일을 만들었다면 자동 정리를 추측하지 말고 중단·수동 검토한다.

후속 MCP setup을 별도로 승인받는 경우에만 설정 파일과 managed skill의 사전 사본·mode·digest, setup dry-run의 정확한 delta와 backup 경로를 검토한다. 원상복구는 REA-owned `[mcp_servers.rea]`와 skill만 대상이다. 공식 `rea uninstall`은 등록·skill을 제거하지만 Evidence/capture 및 Node·Hopper는 남기며, `--purge-data`는 `~/.rea` cache/state까지 삭제한다. 여러 client가 쓰는 환경에서 포괄적 uninstall이나 기존 backup 덮어쓰기를 자동으로 실행하지 않는다. 변경 중 오류·새 사용자 변경이 있으면 이전 파일 전체를 무조건 복원하지 않고 충돌을 보고한다. 이것이 rollback 계획이며, 이번 단계에서 rollback 명령을 실행한 것은 아니다. [공식 유지·제거 문서](https://github.com/morluto/rea/blob/rea-agents-6.5.0/docs/installation.md)

## 승인 gate와 금지 범위

**현재 판정: 설계 GO, 실행 PENDING APPROVAL.** 실제 설치 전 (1) 정확한 release/npm tarball·integrity·provenance와 dependency script 재검증, (2) Node/npm 지원 버전, (3) private temp와 최소 권한·네트워크 경계, (4) 대상 파일 한 개와 source SHA-256, (5) 정확한 실행 옵션·timeout·출력 cap, (6) 결과 검토·폐기 책임, (7) 예상 파일 변경·rollback을 사용자에게 보여주고 승인을 받는다. 명령 후보는 pin된 `npx -y rea-agents@6.5.0 analyze-javascript-application <approved-temp-directory> --json`이지만 **승인 전에는 호출하지 않는다**. `npx`는 설치 script와 추가 network를 유발할 수 있으므로 이 한 줄만으로 실행을 승인했다고 간주하지 않는다. `--ignore-scripts`·optional package 제외가 필요한 경우 먼저 호환성 확인·새 승인 gate를 둔다.

Production dependency·`uv.lock`·사용자 UI·API·SSE·CI 편입, Codex 전역 MCP/skill 등록, 실제 로그·기본 설정·`.env`·홈 디렉터리 접근, Process Capture, 외부 LLM에 raw Evidence 전달, 자동 rotation/copytruncate handoff 및 두 세대 metadata 확대는 계속 NO-GO다. 설치·setup·REA 실행은 Phase 22.0에서 수행하지 않았다. 다음 단계는 승인 후의 **별도 실험**이며 이 문서만으로 설치 권한을 확장하지 않는다.
