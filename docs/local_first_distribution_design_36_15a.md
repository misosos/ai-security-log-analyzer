# Phase 36.15A — Local-first 배포·실행 준비도 설계

## 1. Executive Summary

이번 Phase의 결정은 **`STANDALONE_BUNDLE_FIRST`**다. 목표 제품 형태는 사용자가 저장소를 clone하거나 Python, uv, Node, npm 명령을 실행하지 않고 여는 **Chrome/Chromium-first local web application**이다. 현재 `app.local_web`의 loopback 전용 launcher와 FastAPI·고정 frontend 구조를 유지하면서, OS별로 빌드한 self-contained **PyInstaller onedir** 후보를 먼저 검증한다. 한 파일 실행 형식, desktop wrapper, Docker, GitHub Pages 분석 기능은 첫 배포 경로로 선택하지 않는다.

이 결정은 배포 승인이 아니다. installer·bundle·launcher를 만들거나 GitHub Pages를 배포하지 않았고, dependency와 Production 코드를 변경하지 않았다. 현재 공식 실행 방식은 계속 source checkout이다. 실제 사용자 자료·조직 운영·자동 대응은 **`NO_GO`**다.

## 2. 시작 Gate

| 항목 | 확인 결과 |
|---|---|
| 기준 SHA | `9185338c7445a8f801ae00276b9e5d285a98809d` |
| Git | `main`; HEAD, local main, origin/main, GitHub main 일치; working tree clean; behind 0 / ahead 0 |
| exact push CI | [Run 41591617594](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41591617594), `push / completed / success`, head SHA 일치 |
| 전체 pytest | `3638 passed`, 기존 warning 2개 |
| 필수 Linux 단계 | TCP Syslog 기본·80회 reliability·management, JSONL 80회 acceptance, Restricted Report `roles=3 audit_rows=6` 성공 |
| 브라우저·tracked-file | Chromium·axe `states=25 external_requests=0`, tracked-file 검사 성공 |
| Artifact | `artifact 0` |
| v0.4.0 | tag와 GitHub Release target 모두 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지 |

이는 시작 SHA의 원격 증거다. 이 문서 커밋의 Ubuntu CI 결과는 push 전이므로 `NOT_TESTED`다.

## 3. 현재 실행 구조와 수동 단계

현재 Production 로컬 흐름은 `app.local_web` 한 process가 pre-bound `127.0.0.1:8000` socket으로 Uvicorn을 실행하고 준비 확인 뒤 기본 브라우저를 여는 구조다. 단일 worker, reload off, access log off, proxy header off이며 Ctrl+C에서 종료한다. `app.web_ui`가 저장소의 고정 HTML·CSS·JavaScript를 same-origin으로 제공하고 CDN을 사용하지 않는다. 파일·텍스트 API는 loopback client, Host, Origin, forwarded header와 fetch metadata를 검증한다.

### 3.1 처음 실행해 분석 화면을 보기까지

| 순서 | 현재 사용자가 하는 일 | 필요한 도구·지식 | 마찰 또는 실패 경계 |
|---:|---|---|---|
| 1 | GitHub에서 저장소 URL 확인 | 웹 브라우저 | release 설치 파일이 없음 |
| 2 | Python 3.12 이상 설치 | OS별 설치·PATH 지식 | 버전·PATH 불일치 가능 |
| 3 | uv 설치 | shell과 공급망 설치 판단 | 일반 사용자에게 낯선 도구 |
| 4 | `git clone` 후 저장소로 이동 | Git·terminal | clone과 working directory 필요 |
| 5 | `uv sync --locked --dev` | network·terminal | Production에 불필요한 개발 의존성도 설치 |
| 6 | `uv run python -m app.local_web` | terminal | foreground terminal을 닫으면 앱 종료 |
| 7 | 브라우저 자동 열기 또는 `http://127.0.0.1:8000/` 방문 | 브라우저 | port 충돌 시 사용자가 다른 port를 지정해야 함 |
| 8 | 합성 sample 또는 명시적으로 고른 로컬 파일 분석 | 지원 형식 이해 | 형식·크기·UTF-8 제한은 계속 적용 |
| 9 | 실행 terminal에서 Ctrl+C | process 수명 이해 | 강제 종료 시 OS 임시 자료가 남을 수 있음 |

Live monitoring은 별도로 `uv run python -m app.monitor_setup`과 `uv run python -m app.local_web --monitor`가 필요하다. macOS는 사용자 `Library/Application Support`, Linux는 `$XDG_CONFIG_HOME` 또는 `~/.config` 아래 private 설정과 checkpoint를 쓴다. resolver와 descriptor 기반 opener는 그 두 플랫폼만 허용하고 그 밖의 플랫폼은 `UNSAFE_PLATFORM`으로 거부한다. 따라서 Windows에서 live monitoring을 지원한다고 주장할 수 없다.

### 3.2 현재 runtime·development 요구 구분

| 구성 | 현재 용도 | 일반 사용자 bundle 판단 |
|---|---|---|
| Python 3.12 | FastAPI, parser, 분석, launcher runtime | bundle 안에 포함해야 함 |
| uv | locked 개발 환경 동기화·명령 실행 | 최종 사용자에게 요구하지 않음 |
| FastAPI/Uvicorn 및 Python dependencies | Production runtime | OS별 bundle closure에서 고정·감사 필요 |
| Node/npm/Playwright/axe | 개발용 UI·접근성 검사 | 앱 실행에 필요 없음; bundle에 포함 금지 |
| Chrome/Chromium 계열 브라우저 | 주 검증 UI client | 사용자가 설치한 브라우저를 사용; bundle에 브라우저를 포함하지 않음 |
| `GEMINI_API_KEY` | 별도 명시적 LLM helper | 기본 로컬 앱에 필요 없음; 배포 기본 흐름에서 모델·외부 전송 금지 |
| `XDG_CONFIG_HOME` | Linux live 설정 위치 선택 | batch 실행에는 필요 없음; live 지원 시에만 안전하게 해석 |

현재 checkout에서 관측한 `.venv`와 `node_modules` 크기는 개발 의존성이 섞인 한 플랫폼 값이므로 배포 크기 예측으로 사용하지 않는다. OS별 Production closure와 실제 bundle byte 수는 36.15B 이후에 측정한다.

## 4. 목표 사용자와 지원 등급

목표 사용자는 terminal, Git, Python 환경 관리를 모르는 단일 로컬 사용자다. 첫 지원 흐름은 **다운로드 → 무결성·서명 확인 → 압축 해제 또는 OS 표준 설치 → 앱 실행 → 로컬 브라우저 분석 → 명확한 종료**여야 한다. 관리자 권한, system service, PATH 변경, 원격 계정은 요구하지 않는다.

| 영역 | Phase 36.15A 등급 | 근거와 release 전 조건 |
|---|---|---|
| Ubuntu 24.04 x86_64 + Chrome/Chromium | 우선 build·검증 후보 | 현재 CI의 Python·Linux smoke 근거가 있으나 bundle 자체는 `NOT_TESTED` |
| macOS + Chrome | 우선 build·검증 후보 | source launcher와 Chromium 합성 검증은 있으나 서명·notarization·bundle E2E는 `NOT_TESTED` |
| Windows 11 x64 + Chrome/Edge | batch-only 설계 대상, `NOT_TESTED` | OS-native build·loopback·temp·종료 E2E가 필요; live 설정은 현 코드상 지원 불가 |
| Chrome/Chromium | Primary | 현재 Chromium·axe 자동 회귀를 release browser 기준으로 유지 |
| Microsoft Edge | Chromium 계열 보조 대상, `NOT_TESTED` | Windows 실제 bundle과 함께 별도 확인 |
| Safari | Secondary compatibility, `NOT_TESTED` | Safari 미검증은 Chrome-first bundle 연구 자체를 영구 차단하지 않지만 지원을 주장하지 않음 |
| Firefox·실제 모바일 | 지원 범위 밖, `NOT_TESTED` | 별도 승인과 검증 전 지원 주장 금지 |

OS 최소 버전은 bundle 도구와 현재 Chrome vendor baseline, native dependency 호환성, 실제 E2E 결과를 함께 고정해야 한다. 이 설계만으로 임의의 macOS·Windows·Linux 버전을 지원한다고 표시하지 않는다.

## 5. 배포 후보 비교

`낮음/중간/높음`은 상대 비교이며 실제 artifact 측정값이 아니다.

| 후보 | 일반 사용자 난이도 | macOS·Windows·Linux | 크기 | update / rollback | 서명·notarization | loopback 격리 | 자료 수명 | 공급망·재현성 | 구조 변경량 | 결정 |
|---|---|---|---|---|---|---|---|---|---|---|
| 기존 개발자 실행 방식 | 높음 | source 기준 macOS·Linux, Windows 미검증 | 설치 후 큼 | Git/uv 지식 필요 | 배포 서명 없음 | 현재 코드가 강제 | checkout·venv·temp를 사용자가 관리 | uv lock은 강점, 설치 단계가 많음 | 없음 | 일반 사용자 목표 불충족 |
| 단일 launcher script | 중간 | shell·실행 정책이 OS별로 다름 | 낮음 | script 교체는 쉬우나 runtime drift | unsigned script 차단 가능 | 기존 launcher 호출 시 유지 | Python 환경과 cache가 남음 | Python·uv 사전 설치를 제거하지 못함 | 낮음 | `LAUNCHER_FIRST` 기각: 이미 `app.local_web`가 launcher core 역할을 하며 clone/runtime 문제를 해결하지 못함 |
| Python package / zipapp | 중간 | interpreter와 native wheel이 OS별로 필요 | 중간 | package 교체 가능 | OS 실행 신뢰 문제 잔존 | 진입점을 고정하면 유지 | user environment에 package/cache 잔존 | zipapp은 Python이 필요하고 C extension은 archive에서 직접 실행 불가 | 중간 | Python 없는 사용자 목표 불충족 |
| **PyInstaller onedir** 또는 동등 standalone bundle | 낮음 | OS·architecture별 native build 필요 | 높음, 측정 필요 | versioned directory 단위 교체·rollback 가능 | macOS 코드 서명·notarization, Windows 코드 서명 필요 | 기존 launcher와 host 검증 재사용 가능 | onefile 임시 추출 없이 설치 directory + 앱 요청 temp만 관리 | pinned source에서 OS별 재현 build, manifest·SBOM·hash 필요 | 중간 | **`STANDALONE_BUNDLE_FIRST` 선택** |
| local desktop wrapper | 낮음 | wrapper toolchain별 지원 | 매우 높을 수 있음 | installer/update channel 설계 필요 | 모든 OS signing 필요 | navigation·IPC까지 새 경계 | wrapper cache/profile까지 추가 | 새 runtime·dependency·공급망 확대 | 높음 | `DESKTOP_WRAPPER_FIRST` 기각: lifecycle UX는 좋지만 현재 local web 구조에 비해 공격면·변경량 과다 |
| Docker | 중간~높음 | Docker Desktop/Engine 가용성에 의존 | image 큼 | image tag rollback 가능 | image provenance/signing 별도 | 잘못된 `-p`는 외부 공개 | bind mount·volume·image cache 잔존 | image pinning 가능하나 daemon·base image 공급망 추가 | 중간 | 비개발자 기본 경로 기각; 민감 로그 mount와 port 공개 실수 위험 |

`DEFER_DISTRIBUTION`은 선택하지 않는다. 현재 launcher·same-origin assets·loopback API가 standalone feasibility를 시험할 만큼 명확하다. 다만 서명, OS별 build, Windows batch flow, 종료 UX, cleanup 또는 외부 요청 0을 입증하지 못하면 artifact 공개는 중단하고 source checkout으로 rollback한다.

## 6. 선택 근거와 bundle 형식

PyInstaller 공식 문서는 bundle이 interpreter와 modules를 포함해 사용자가 Python을 설치하지 않아도 된다고 설명하며, 결과가 build OS·Python·word size에 종속돼 각 플랫폼에서 각각 만들어야 한다고 명시한다. `onedir`는 수집 파일을 확인하고 문제를 진단하기 쉽다. 반면 `onefile`은 실행 때 OS temp에 `_MEI...`를 풀고 강제 종료 시 남을 수 있다. 현재 프로젝트가 원본 로그와 임시 자료 잔존을 엄격히 다루므로 첫 후보는 **versioned onedir archive/app bundle**로 제한한다.

선택은 PyInstaller 의존성 추가 승인이 아니다. 36.15B가 package closure, license, hidden import, frontend resource, native library, artifact 크기와 deterministic manifest를 먼저 검증해야 한다. 동등 도구가 같은 계약을 더 작은 변경으로 충족하면 비교 후 교체할 수 있다.

## 7. 목표 실행 모델

```text
사용자가 OS별 서명된 bundle 실행
  → 단일 app process가 127.0.0.1 전용 socket pre-bind
  → Uvicorn 1 worker / reload off / proxy headers off
  → bounded readiness 확인
  → 사용자의 기본 브라우저에서 numeric loopback URL 열기
  → same-origin 고정 asset과 로컬 API만 사용
  → 사용자가 명시적으로 고른 파일·텍스트만 bounded 분석
  → 명시적 종료 또는 process 종료
  → listener·worker·요청 temp 정리
```

- host 인자를 사용자 설정으로 노출하지 않고 **`0.0.0.0 금지`**, LAN IP bind 금지를 build/E2E invariant로 둔다.
- loopback socket이 아닌 외부 interface bind 시 launcher는 준비 성공을 표시하지 않고 종료한다.
- 기존 Host/Origin/forwarded-header/fetch-metadata 검증을 bundle에서도 유지한다.
- telemetry 금지, CDN 금지, 자동 update network 요청 금지다. update 확인은 사용자가 release page를 명시적으로 열 때만 수행하는 설계를 우선한다.
- 고정 port 8000과 bounded `--port`의 현 계약을 첫 prototype에서 보존한다. 임의 port 또는 capability URL은 별도 threat model·API/UI migration 없이 도입하지 않는다.
- 기본 브라우저 자동 열기는 Chrome 설치를 강제 탐색하지 않는다. Chrome/Chromium이 Primary라는 지원 문구와 기본 브라우저가 다를 때의 수동 URL 안내를 제공한다.
- bundle에는 browser, Node, npm, Playwright, 실제 로그, checkpoint, `.env`를 넣지 않는다.

## 8. 설치·실행·종료·업데이트·제거

### 8.1 설치

향후 GitHub Release에 OS·architecture별 versioned archive를 게시하는 흐름만 후보로 둔다. artifact manifest, SHA-256, dependency inventory, license와 build provenance를 같이 제공한다. macOS는 Developer ID 서명·Hardened Runtime·notarization·ticket stapling, Windows는 신뢰된 코드 서명과 Smart App Control 검증을 release gate로 둔다. Linux는 supported distribution matrix에서 native library/GLIBC와 executable permission을 검증한다. 관리자 권한이나 system-wide service 설치는 금지한다.

### 8.2 실행과 종료

실행 파일은 `app.local_web`의 foreground ownership을 재사용한다. 준비 성공 뒤 한 번만 브라우저를 열며, 실패하면 fixed error와 loopback URL 또는 복구 행동만 표시한다. 종료 방법은 사용자가 이해할 수 있는 명시적 launcher window/console action을 36.15B에서 결정해야 한다. 브라우저 tab을 닫았다고 server가 자동 종료됐다고 주장하지 않는다. 정상 종료는 listener, worker, monitor lease, 임시 디렉터리 정리를 기다리고 bounded timeout 뒤 실패를 고정 상태로 알린다.

### 8.3 업데이트와 rollback

앱 내부 self-update와 자동 다운로드는 채택하지 않는다. 새 versioned directory를 별도로 설치하고, 서명·hash·합성 E2E를 확인한 뒤 사용자가 전환한다. 이전 version directory는 rollback 검증이 끝날 때까지 보존할 수 있으나 사용자 로그·checkpoint를 bundle directory에 저장하지 않는다. 새 버전이 schema migration을 요구한다면 destructive migration을 자동 실행하지 않고 별도 승인 gate를 연다.

### 8.4 제거

앱 directory 제거와 사용자 데이터 제거를 분리한다. batch-only 사용자는 bundle과 OS가 남긴 일반 cache를 제거한다. live 기능 사용자는 macOS `Library/Application Support/ai-security-log-analyzer` 또는 Linux XDG config 아래 private config/checkpoint를 **명시적 확인 뒤** 별도 삭제한다. 원본 로그는 절대 제거 대상에 포함하지 않는다. Windows live 위치는 아직 없으므로 생성하거나 삭제한다고 문서화하지 않는다.

## 9. 로컬 데이터·임시 파일·port·process 수명

| 자원 | 생성 시점 | 정상 수명 | crash/강제 종료 | 제거 계약 |
|---|---|---|---|---|
| 업로드·텍스트 staging | 사용자가 분석 요청 | 요청 scope의 private temp | 잔존 가능, secure erase 미보장 | 정상 경로 `TemporaryDirectory` 정리; 다음 Phase에서 crash residue audit |
| 브라우저 document-memory 분석·검토 상태 | 분석 결과 설치 | tab/document | reload·tab 종료에서 소멸 | persistent storage 사용 금지 |
| public HTML report/download | 사용자가 명시적으로 다운로드 | 사용자 소유 | 앱 제거와 무관 | 앱이 자동 삭제하지 않음; 민감 자료 안내 유지 |
| live private config/checkpoint | 사용자가 setup/live를 명시 실행 | 재시작 간 유지 | 안전 검증 뒤에만 재사용 | 기존 show/delete/reset의 명시적 승인 계약 유지 |
| listener | app process 시작 | process lifetime | OS가 process 종료 시 회수 | numeric `127.0.0.1` pre-bind; 외부 bind 금지 |
| Uvicorn/worker/child process | app·분석 실행 | bounded request/process | orphan 여부 검증 필요 | 정상 종료·timeout·child cleanup E2E가 release gate |
| bundle files | 설치 | 해당 version 사용 기간 | 그대로 유지 | version directory 단위 제거; user data와 분리 |

앱 로그에는 원문 로그, account, IP, hostname, path, credential, token, request body를 쓰지 않는다. 기본 access log는 계속 끈다. 진단이 필요하면 fixed stage/category와 aggregate만 허용하고 OS crash dump·antivirus log까지 삭제한다고 보장하지 않는다.

## 10. GitHub Pages와 로컬 앱 경계

GitHub Pages는 공식적으로 repository의 HTML·CSS·JavaScript를 게시하는 정적 hosting이다. 따라서 Pages가 Python/FastAPI parser를 실행한다고 가장하거나 local app과 같은 분석 결과를 제공하게 만들지 않는다.

| GitHub Pages 허용 | GitHub Pages 금지 |
|---|---|
| 소개, 설치·보안 문서, release 링크 | **실제 로그 업로드 금지** |
| 원문·식별자가 없는 `read-only synthetic demo` | 실제 parser/detector 결과인 것처럼 보이는 임의 client 분석 |
| 고정 합성 screenshot과 기능 한계 | credential, checkpoint, user file, clipboard 수집 |
| local app과 다른 origin·기능임을 명시 | local loopback API 호출, 외부 AI/telemetry, hosted 분석 |

Pages 방문 자체는 GitHub의 서비스 경계에 있고 local-only 분석과 동일하지 않다. 실제 로그는 사용자의 컴퓨터를 벗어나지 않으며 Pages와 local app 사이에 upload, sync, account, resume 기능을 만들지 않는다.

## 11. 위협 모델과 완화

| 위협 | 영향 | 필수 완화와 차단 조건 |
|---|---|---|
| wildcard/LAN bind | 같은 네트워크에서 로그 API 접근 | host 고정, pre-bind socket 주소 검사, 0.0.0.0/LAN E2E 즉시 실패 |
| DNS rebinding·cross-site mutation | 로컬 API 오용 | numeric loopback URL, Host/Origin/Sec-Fetch/forwarded-header 검증 유지, mutation 회귀 |
| bundle 변조·공급망 오염 | 임의 코드 실행·로그 노출 | locked clean build, manifest/SBOM/hash, OS별 서명, release provenance; 불일치 시 게시 금지 |
| onefile temp extraction | executable residue·권한 문제 | 첫 후보를 onedir로 제한; 관리자 권한 실행 금지 |
| 업로드 temp·crash residue | 원문 일부 disk 잔존 | private temp, bounded lifetime, startup cleanup은 별도 안전 설계, secure erase 비보장 고지 |
| browser/CDN/telemetry egress | 원문 또는 사용 metadata 외부 전송 | external_requests=0, CSP self, CDN 금지, telemetry 금지, 모델 기본 호출 금지 |
| port collision·기존 로컬 process | 잘못된 process UI 접속 | listener를 먼저 소유하고 readiness 검증; 충돌 시 fixed failure, 기존 서비스로 browser를 열지 않음 |
| 여러 app instance | port·checkpoint·상태 경쟁 | monitor lock 유지, batch multi-instance 정책은 36.15B에서 명시; silent sharing 금지 |
| update 실패 | 실행 불가 또는 schema 고립 | side-by-side version, no auto migration, 이전 signed version rollback |
| browser tab 종료를 app 종료로 오해 | server가 남음 | launcher process 상태와 명시적 종료 UX 제공; tab close와 종료를 동일시하지 않음 |
| 관리자 권한 실행 | 과도한 파일 접근 | user-level 설치·실행만 지원; elevated execution을 요구하거나 권장하지 않음 |

## 12. 36.15B 이후 구현 단계

| Phase | 범위 | GO 조건 | rollback / NO_GO 조건 |
|---|---|---|---|
| 36.15B | standalone package closure와 onedir build prototype; Production dependency/resource inventory | clean locked build, launcher·frontend·parser 합성 smoke, Node/dev files 제외, artifact manifest | hidden import/resource 누락, 외부 요청, dependency/lock 임의 변경 |
| 36.15C | Ubuntu·macOS·Windows native build matrix, artifact size·license·SBOM·hash | 각 native OS에서 build·unpack·loopback E2E, batch 기능 parity | cross-build 결과 대체, Windows를 미검증 상태로 지원 표기 |
| 36.15D | 코드 서명·notarization·배포 provenance | macOS notarization과 Windows signature 검증, Linux checksum/provenance, secret 비노출 | unsigned artifact를 일반 사용자 release로 게시 |
| 36.15E | 설치·실행·port 충돌·종료·crash temp·업데이트·제거 E2E | user-level 설치, 외부 bind/요청 0, cleanup과 side-by-side rollback | 원본 로그 삭제, orphan process, temp/privacy 누출 |
| 36.15F | Chrome-first OS/browser matrix 및 접근성 | Primary 조합의 keyboard/reflow/axe와 실제 native artifact 통과 | Safari 결과를 Chrome 증거로 대체하거나 지원 범위 과장 |
| 36.15G | 합성 자료 기반 비개발자 수용 검수 | 설치부터 제거까지 사용자 PASS, 실제 자료 미사용 | 자동 테스트를 사용자 PASS로 대체 |

Live monitoring의 Windows 지원, desktop wrapper, self-update, Pages demo는 각각 별도 threat model과 승인이 필요한 후속 항목이다. 첫 bundle의 batch 기능 성공을 근거로 이들을 자동 승인하지 않는다.

## 13. Research basis

확인일은 **2026-11-03**이다. 외부 제품의 기본값을 복사하지 않고 현재 코드의 실행·privacy 계약에 적용되는 범위만 사용했다.

| 1차 자료 | 확인한 사실 | 이 설계에 적용 | 적용하지 않은 주장 |
|---|---|---|---|
| [Python `zipapp`](https://docs.python.org/3/library/zipapp.html) | 적합한 Python interpreter가 필요하고 C extension은 zip에서 직접 실행할 수 없음 | 일반 사용자 첫 경로에서 package/zipapp 기각 | 모든 Python 앱에서 zipapp이 부적합하다는 일반화 |
| [PyInstaller operating mode](https://pyinstaller.org/en/stable/operating-mode.html) | interpreter·dependencies 포함, OS별 build 필요, onedir/onefile lifecycle 차이 | OS별 onedir feasibility와 onefile temp 위험 gate | 현재 앱이 hook 없이 곧바로 bundle된다는 보장 |
| [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) | HTML·CSS·JavaScript 기반 정적 hosting | 문서·합성 read-only demo로만 경계 | Pages에서 FastAPI 분석 가능 주장 |
| [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/) | host IP 생략 publish는 외부 노출 가능, loopback 명시 필요 | Docker를 비개발자 기본에서 기각하고 외부 bind 위험 기록 | 모든 Docker 구성의 외부 노출 주장 |
| [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution) | 직접 배포 macOS software의 Developer ID 서명·Hardened Runtime·notarization 절차 | macOS artifact release gate | notarization이 앱 안전성을 완전히 증명한다는 주장 |
| [Microsoft application signing](https://learn.microsoft.com/en-us/windows/security/book/application-security-application-and-driver-control) | Windows 11 Smart App Control 사용성에 trusted code signing 권고 | Windows binaries·installer 서명 gate | 서명만으로 코드가 안전하다는 주장 |
| [Chrome system requirements](https://support.google.com/chrome/a/answer/7100626) | OS별 Chrome vendor 지원 범위가 변함 | build 시점 Primary browser matrix를 고정 | 이 앱이 해당 모든 OS에서 이미 작동한다는 주장 |

## 14. 검증 범위와 한계

- TDD RED에서 신규 문서 계약 3개가 문서 부재로 실패했고, 문서·색인 추가 후 3/3 통과했다.
- 관련 queue/workflow/input-quality/checklist/report focused 회귀는 221 passed, 전체 문서 계약은 401 passed였다.
- 변경 후 전체 pytest는 **3641 passed, 기존 warning 2개**였다.
- Phase 36.1은 44/44, Phase 36.2는 24/24, 합성 boundary는 79/79, Linux process 합성 분류는 21/21, risk/case는 각각 70/70이었다. 합성 Linux 분류는 Linux host 실행 증거가 아니다.
- Chromium·axe 최종 반복은 `states=25 external_requests=0`이었다. 첫 로컬 실행은 `pending` sidebar 표시 대기에서 timeout이었고 같은 명령의 즉시 반복은 전체 통과했다. queue, workflow state, navigation, input-quality E2E도 통과했으며 상태 조작의 외부 요청과 자동 checklist POST는 0이었다.
- `uv sync --locked --dev`, `uv lock --check`, `npm ci --ignore-scripts`, Python compile, 전체 tracked JavaScript syntax, `git diff --check`, README 17,000-byte 계약과 변경 파일의 conflict marker·credential·개인 경로 검사가 통과했다. dependency·lockfile·CI workflow는 변경되지 않았다.
- Production Python, API schema, parser, detection, relation, risk, case, checklist, report, frontend와 workflow를 변경하지 않았다.
- launcher·installer·bundle·GitHub Pages를 구현하거나 실행하지 않았다.
- Node는 개발 검증 도구이며 일반 사용자 runtime에 포함하지 않는다는 설계만 고정했다.
- bundle 크기, cold start, memory, signing credential, antivirus reputation, native library compatibility는 `NOT_TESTED`다.
- Ubuntu CI는 source checkout을 검증했으며 새 standalone artifact를 검증하지 않았다.
- macOS signed/notarized artifact, Windows artifact, Safari, Edge, 실제 모바일은 `NOT_TESTED`다.
- 실제 사용자 로그·실제 조직 설치·업데이트·제거·장애 복구·secure erase는 검증하지 않았다.

## 15. 최종 판정

**`PHASE_36_15A_LOCAL_FIRST_DISTRIBUTION_DESIGN_LOCAL_CONDITIONAL_GO`**

이는 `STANDALONE_BUNDLE_FIRST` 방향과 후속 gate를 결정했다는 뜻이다. Production 배포, 실제 사용자 자료 처리, 조직 운영, 자동 대응 승인이 아니다. 실제 자료·조직 운영·자동 대응은 계속 **`NO_GO`**이며 모델 기반 AI는 이 Phase에서 사용하지 않았다.
