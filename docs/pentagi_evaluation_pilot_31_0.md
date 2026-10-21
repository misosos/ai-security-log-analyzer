# Phase 31.0 — PentAGI 격리 평가 pilot 설계 gate

## 판정과 증거 범위

**CONDITIONAL GO — 설계 gate만 통과. PentAGI 실행은 NO-GO.** 이 문서는 별도 개발용 도구의 향후 정적 감사와 격리 가능성을 평가한다. PentAGI를 다운로드·설치·실행하지 않았고, installer·Compose·image pull·LLM/검색 연결·공격 명령·스캔을 수행하지 않았다. 제품 기능, production 코드, dependency, lockfile, CI에는 PentAGI가 없다. 실제 네트워크 격리, image digest, installer hash, 도구 다운로드 통제, 법적 조건은 아직 검증되지 않았다. 이 문서나 자동 테스트를 실행 승인으로 해석하지 않는다.

후속 [Phase 31.1 정적 공급망 감사](pentagi_supply_chain_audit_31_1.md)는 source·registry metadata를 추가 확인했지만 **Phase 31.2 실행형 isolation proof는 NO-GO**로 판정했다. 위 문단은 Phase 31.0 당시 설계 gate의 범위와 증거 수준을 보존한다.

후속 [Phase 31.2A 폐기형 VM 격리 설계](disposable_vm_isolation_31_2a.md)는 기준 SHA의 CI 성공을 확인했으나 준비된 별도 Linux VM이 없어 `BLOCKED_NO_DISPOSABLE_VM`이다. PentAGI 실행 및 Phase 31.2B는 계속 NO-GO다.

기준은 `34e215133428f249ee73994983e017be7e53f098`의 main과 [GitHub Actions run 39591982919](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39591982919) completed/success다. Ubuntu 통합 설정 관리와 전체 회귀가 성공했고 저장된 artifact는 0개였다. v0.4.0 공개 tag·Release는 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`에 유지된다. 보존용 `backup/phase-30-3a-amended` 로컬 브랜치는 존재하지 않아 삭제하지 않았다.

Phase 30 최종 증거: Ubuntu application **PASS**, Ubuntu SSH **PASS**, 사용자 이해도 9개 항목 수정 후 **PASS**, `--show`·reset·delete 문구 수정 후 **PASS**. 여전히 rotation/copytruncate 자동 복구, SIGKILL·전원 차단 복구, exactly-once·무유실, 비협력적 동일 UID 교체 경쟁은 **NO-GO**다. [사용자 수용 기록](monitor_setup_acceptance_30_3.md)은 자동 증거와 실제 사용자 응답을 구분한다.

## 공식 자료에서 확인한 제품 식별과 미확인 항목

조사 시점은 2026-10-21이다. 공식 저장소는 [`vxcontrol/pentagi`](https://github.com/vxcontrol/pentagi)다. 공식 최신 안정 [v2.2.0 release](https://github.com/vxcontrol/pentagi/releases/tag/v2.2.0)의 tag가 가리키는 source commit은 `b611fbebcf55b6deb88ad1fb7bf1f1ce7a357242`다. 이는 평가 후보 식별자이며 실제 실행 승인이나 바이너리 무결성 증명이 아니다.

| 항목 | 공식 자료로 확인한 사실 | 31.1에서 확인할 부분 |
|---|---|---|
| 플랫폼·자원 | [Quick Start](https://pentagi.com/docs/getting-started/quickstart/)는 Docker Engine 20+와 Compose, 최소 2 vCPU·4 GB RAM·25 GB disk를 안내한다. installer는 Linux amd64/arm64, macOS Intel/Apple silicon, Windows amd64용 `pentagi.com/downloads/<platform>/installer-latest.zip`에서 배포한다. | `installer-latest.zip`은 mutable 이름이다. 정확한 archive SHA-256/512, 서명·notarization·provenance와 지원 플랫폼을 version별로 검증하지 못했다. |
| 컨테이너 | 공식 [v2.2.0 Compose](https://github.com/vxcontrol/pentagi/blob/v2.2.0/docker-compose.yml)는 `pentagi`, PostgreSQL/pgvector, postgres-exporter, `scraper`를 구성한다. `pentagi`·`pgvector`·`scraper` 기본 image 변수는 `latest`를 가리킨다. | 각 플랫폼 digest, manifest/layer, base image, entrypoint, native/setuid, SBOM, 설치 스크립트 및 runtime download를 정적 감사해야 한다. `latest`는 pilot 금지. |
| 메모리·관측 | [Architecture](https://pentagi.com/docs/concepts/architecture/)상 pgvector DB에 명령·출력·embedding이 남을 수 있다. Neo4j/Graphiti, Langfuse, Loki·Jaeger·Grafana 등은 선택적 구성이다. | 어떤 데이터가 기본 DB·Docker logs에 남는지 실제 배포 manifest별로 확인한다. optional stack은 첫 pilot에서 끈다. |
| Docker 권한 | [Quick Start](https://pentagi.com/docs/getting-started/quickstart/)의 installer는 Docker API를 사용한다. 기본 [Compose](https://github.com/vxcontrol/pentagi/blob/v2.2.0/docker-compose.yml)는 `pentagi`를 root로 실행하고 Docker socket을 mount한다. [Worker Node](https://pentagi.com/docs/deployment/worker-node/)는 기본 socket이 sandbox의 host 접근으로 이어질 수 있다고 설명한다. | socket mount가 새 privileged container·host path mount를 허용하는지, 제한된 worker API 또는 rootless 대안이 실제 작동하는지 검증한다. |
| 노출·통신 | [Security](https://pentagi.com/docs/configuration/security/)는 웹 UI의 loopback bind와 sandbox callback `28000–29999` 범위의 기본 전체 인터페이스 공개 가능성을 구분한다. server update check를 0으로 꺼도 installer의 image/stack summary 통신은 별도다. proxy가 모든 component·Docker pull을 포괄하지 않는다. | callback bind·DNS·egress·업데이트·telemetry·image/tool download를 실측해야 한다. loopback UI만으로 격리를 증명할 수 없다. |
| LLM·검색 | [LLM Providers](https://pentagi.com/docs/configuration/llm-providers/)는 실제 flow에 최소 하나의 provider를 요구하며 local Ollama 또는 OpenAI-compatible endpoint도 지원한다. [Security](https://pentagi.com/docs/configuration/security/)상 검색·scraper·sandbox 통신은 별도다. | Phase 31.2의 명령 없는 격리 증명은 LLM 없이 가능할 수 있으나 31.4 실제 flow는 고정된 local provider가 필요하다. cloud provider·web search는 보류한다. |

공식 Docker Hub의 [`vxcontrol/pentagi` tags](https://hub.docker.com/r/vxcontrol/pentagi/tags)는 2.2.0의 linux/amd64·linux/arm64 배포를 보여준다. 압축 image 크기 표시만으로 저장 공간 사용량이나 platform digest를 확정하지 않는다. Image·installer digest는 이번 gate에서 확보하지 않았다.

## 라이선스·사용 조건 판정

[v2.2.0 LICENSE](https://github.com/vxcontrol/pentagi/blob/v2.2.0/LICENSE)의 저장소 source는 MIT이며 복사·실질적 부분 재배포 시 copyright/license notice 보존이 필요하다. 공식 [EULA](https://github.com/vxcontrol/pentagi/blob/main/EULA.md)는 승인받은 penetration testing·연구 사용으로 제한하며, prebuilt image와 web UI 사용 조건은 source MIT와 별도로 읽어야 한다. [NOTICE](https://github.com/vxcontrol/pentagi/blob/v2.2.0/NOTICE)는 VXControl Cloud SDK의 AGPL-3.0 특별 예외를 **공식 PentAGI**에 한정해 설명한다. 다른 branch나 현재 SDK의 라이선스가 다를 수 있으므로 해당 버전의 manifest와 원문을 재확인한다. Bundled 도구와 실행 중 내려받는 제3자 보안 도구의 라이선스는 각각 별개다. PentAGI 출력·보고서의 권리·보존 조건은 확인되지 않았다. 아래 판정은 법률 자문이 아니다.

| 사용 방식 | 설계 판정 | 조건·미확인 의무 |
|---|---|---|
| 별도 개발 도구 | **조건부 후보** | 승인된 합성 단일 대상, 격리·고정 배포물·EULA 검토 후에만 실행. |
| 합성 로그 생성 | **조건부 후보** | PentAGI 실행 사실과 target 로그를 독립 대조; 원본 출력은 반입하지 않음. |
| 실행 결과 내부 평가 | **조건부 후보** | 보고서를 ground truth로 삼지 않고 보존·provider 조건 확인. |
| 정제한 합성 fixture 저장소 추가 | **조건부 후보** | 개인 식별·명령·payload 없는 별도 검토 자료만; 제3자 저작권·출력 조건 확인. |
| PentAGI 원본 보고서 커밋 | **NO-GO** | 명령·prompt·대상·민감 정보와 라이선스 위험이 있다. |
| PentAGI 코드 복사 | **이번 범위 NO-GO** | MIT notice와 Cloud SDK 예외·전이 라이선스 별도 검토. |
| Docker image 재배포 | **이번 범위 NO-GO** | image/EULA·bundled tools·notices·provenance 검토 필요. |
| production dependency 포함 | **NO-GO** | 제품 분석 계약과 공급망·권한 경계에 불필요하다. |
| 사용자 기능으로 제공 | **NO-GO** | 승인 범위·권한·오용·데이터 전송 계약을 새로 설계해야 한다. |

## 첫 pilot 후보: 단일 합성 SSH 대상

고정된 합성 SSH target 컨테이너 **1개**와 PentAGI 전용 격리 network를 사용한다. Host SSH, LAN, VPN, 인터넷 대상과 분리하고 실제 credential·로그·HOME·config를 쓰지 않는다. 합성 계정·IP·hostname만 허용한다. 목표는 한 번 승인된 대상에서 짧고 제한된 인증 실패·성공 기록 후보를 관찰하는 것이다. 사람이 실행 전 scope·대상 identity·상한을 확인하며 완전 자동 모드보다 통제 가능한 모드를 우선한다. 실행 시간·tool-call·CPU·RAM·PID·disk 상한을 강제한다. 파일 접근, 권한 상승, persistence, exfiltration, Metasploit/exploit, 웹·브라우저·검색 도구는 제외한다. 성공 로그인 기록은 공격 성공·침해·인과관계의 증거가 아니다. 실제 인증 행동은 **Phase 31.4 이전에 실행하지 않는다**.

### 네트워크·Docker 권한 설계

허용 후보는 control plane의 최소 내부 통신, 고정 container identity의 target, 필요할 경우 고정된 local/self-hosted LLM endpoint뿐이다. Host network, 실제 LAN/VPN route, public target, cloud metadata, 임의 DNS, 인터넷 검색/fetch, 불필요한 Docker socket write, 전체 인터페이스 callback은 금지한다. Docker network 자체는 완전한 sandbox가 아니다. [Docker Engine 보안](https://docs.docker.com/engine/security/)과 [docker group 권한](https://docs.docker.com/engine/install/linux-postinstall/)에 따르면 Docker daemon 접근은 host root 수준 권한과 연결된다. [Compose 서비스 옵션](https://docs.docker.com/reference/compose-file/services/)의 capability 제거·read-only root·`no-new-privileges`·PID 제한과 [rootless Docker](https://docs.docker.com/engine/security/rootless/)의 가능성은 실제 stack에서 작동 확인이 필요하다.

| 환경 후보 | 판정 | 이유 |
|---|---|---|
| 현재 macOS Docker Desktop | **NO-GO 첫 pilot** | host Docker API 및 Desktop VM의 host/LAN egress 경계를 사전에 증명하기 어렵다. |
| disposable Linux VM 내부 Docker | **우선 후보, 미검증** | VM 외부 방화벽·snapshot 폐기·전용 daemon으로 host와 분리할 수 있다. VM에서 실제 격리를 증명해야 한다. |
| 별도 격리 Linux host | **대안, 미검증** | 물리·네트워크 경계가 명확할 수 있으나 관리 비용과 권한 검토가 필요하다. |
| 현재 host 제한 Compose | **NO-GO 첫 pilot** | socket/host mount와 egress를 Compose 옵션만으로 충분히 봉쇄했다고 볼 수 없다. |

Phase 31.2의 명령 없는 사전 test는 allowlist 밖 target, host gateway, 인터넷 egress, metadata address, 임의 DNS가 모두 차단되는지 확인한다. Callback이 loopback/전용 network 밖에 공개되지 않는지, container capability·read-only root·`no-new-privileges`·CPU/RAM/PID/disk/time 상한이 적용되는지, 새 privileged container/host mount가 거부되는지, 종료 후 network·volume·listener가 정리되는지 확인한다. 실패 시 다음 단계 금지. 이는 구성 검증이지 모든 sandbox 탈출 가능성 부재의 증명이 아니다.

### LLM·검색·저장 경계

첫 pilot에는 실제 credential, `.env`, 사용자 HOME·로그·config를 반입하지 않는다. Cloud LLM과 search provider, browser/fetch, optional observability·knowledge graph를 비활성화한다. 실제 flow는 local LLM 필요 여부와 endpoint egress를 별도로 검증한다. Prompt·tool output·target 정보가 provider로 전달될 수 있으므로 local이라는 이름만으로 데이터 비전송을 가정하지 않는다. PostgreSQL/pgvector memory와 Docker logs, screenshots, terminal output, uploaded files, reports, crash dumps, backup/snapshot은 모두 보존·누출 경계다. [Observability 문서](https://pentagi.com/docs/configuration/observability/)의 Langfuse는 prompt/completion을 기록할 수 있다. 합성 canary만 쓰고 raw terminal·prompt·report를 저장소나 CI artifact로 업로드하지 않는다. 최소 보존 기간과 접근 통제를 계획하고 종료 후 볼륨·임시 파일을 제거한다. **Secure erase는 보장하지 않는다.**

## 실행 전 공급망 gate

Phase 31.1에서 source tag→commit, installer archive hash, platform별 image digest·manifest·layer, base image, entrypoint, native/setuid binary, package manager/install script, runtime tool/image download, SBOM, 알려진 취약점 스캔 가능성을 기록한다. 공식 서명·notarization·provenance가 없으면 부재를 명시하고 별도 해시·독립 경로 대조·격리 스캔으로만 부분 보완한다. Compose의 mutable image reference와 runtime fetch를 고정·차단할 수 없으면 실행하지 않는다. `curl | sh`, `latest`, 검증하지 않은 installer의 root 실행은 **NO-GO**다. 현재 SHA·digest·서명·SBOM·image layer 감사를 완료한 것으로 표시하지 않는다.

## 평가 ground truth와 저장 가능한 결과

PentAGI 보고서는 정답이 아니다. 세 출처를 독립 대조한다.

| 증거 | 확인할 것 | 판정 경계 |
|---|---|---|
| A. PentAGI 실행 사실 | 실제 tool call, 명령, 허용 target, UTC 시작·종료, exit status | 계획 또는 보고서 문장만으로 실행 사실을 추정하지 않는다. Raw command history는 저장소에 넣지 않는다. |
| B. 합성 SSH target 로그 | 실제 인증 실패·성공, UTC, 합성 account/source, 중복·누락·순서 | Target의 기록이 A와 일치하는지 독립 확인한다. 성공 기록은 침해 확정이 아니다. |
| C. 우리 분석기 | normalized event, Brute Force·Password Spraying-like, 관계, risk, case, 안전한 publication | 기존 [탐지 평가 계약](detection_evaluation.md)의 threshold·scope를 그대로 적용한다. |

분류는 **명령 미실행**, **실행했으나 target 로그 없음**, **target 로그 있으나 parser 거부**, **parse 성공·탐지 없음**, **탐지·관계·risk·case 생성**, **보고서와 실행 사실 불일치**로 나눈다. 기존 detector threshold를 PentAGI 결과에 맞춰 바꾸지 않는다. 저장소 후보는 합성 입력 fixture, 개인 정보 없는 기대 결과, 실행 환경 manifest, 고정 version/digest, 안전한 count·차이, 한계, 비공격적 재현 test뿐이다. Raw PentAGI DB/prompt/terminal/report, `.env`·API key, 실제 path·IP·hostname, screenshot, Docker volume, exploit/payload/malware, credential은 기본 **금지**다. 프로젝트 README나 사용자 기능에 공격 명령·exploit 절차를 넣지 않는다.

## 위협 모델·중단 조건

| 위협 | 예방 | 탐지·실패 동작 | 잔여 위험 |
|---|---|---|---|
| Host 권한 확대 | disposable VM, 전용 daemon, socket/host mount 금지 정책 | Compose/manifest와 실제 mount·container create 감사; 어긋나면 실행 전 NO-GO | Docker/kernel 취약점과 비협력 privileged 작업 |
| Network 이탈 | VM 경계 egress deny, 고정 allowlist·DNS 차단 | host gateway·LAN/VPN·인터넷·metadata 연결 차단 test; 하나라도 통과하면 NO-GO | 커널/가상화 결함, 새 경로·DNS 우회 |
| Callback 노출 | loopback/전용 network bind | host 외부 interface listen 검사; 공개 시 NO-GO | 포트 publish 규칙 변동 |
| Secret·log 잔존 | 합성 canary만, provider/optional stack off, 최소 보존 | DB·logs·volume·artifact scan; 원문 경계 불명확하면 NO-GO | backup·snapshot·crash dump 및 secure erase 불가 |
| 배포물·도구 변동 | tag/commit·digest pin, 다운로드 차단 | manifest/layer/installer hash·runtime fetch 감사; 불일치 시 NO-GO | 서명·provenance 부재 가능성 |
| 평가 오판 | A/B/C 독립 대조, 기존 detector 불변 | 불일치 별도 상태; 보고서 단독 결론 거부 | 합성 단일 대상의 외적 타당성 제한 |

**Hard stop:** image 또는 installer digest 미확정, 예상 밖 host mount, Docker socket 권한 확대, public callback, egress 차단 실패, 실제 network route 접근, 외부 LLM·검색 전송을 확실히 끌 수 없음, 추가 tool download 통제 불가, raw secret·개인정보 저장 경계 불명확, cleanup 대상 불명확, license/EULA 위반 가능성, target identity 불확실, allowlist 기술 강제 실패, resource budget 강제 실패 중 하나라도 있으면 실행 전 **NO-GO**다.

## 단계별 gate와 최종 판정

| 단계 | 산출물·진입 gate |
|---|---|
| 31.1 공급망·license·image 정적 감사 | version·digest·installer·Compose·전이 도구·EULA 검증. 이 단계도 설치·실행 없음. |
| 31.2 명령 없는 Docker/network isolation proof | 31.1 PASS 후 disposable VM에서 egress·socket·mount·callback·자원 상한을 입증. |
| 31.3 합성 SSH 대상 비공격적 연결 smoke | 31.2 PASS 후 고정 target identity와 분리된 로그 경계 확인. |
| 31.4 승인된 bounded 인증 행동 pilot | 31.3 PASS와 매 실행 사람의 scope 승인 후에만. |
| 31.5 A/B/C 대조 | 31.4 PASS 후 실행 사실·target 로그·분석 결과 독립 비교. |
| 31.6 안전한 fixture 채택 판단 | 31.5 PASS 후 정제 자료·라이선스·개인정보 검토. |

| 판정 항목 | 결과 |
|---|---|
| 외부 개발 도구 사용 | 조건부 후보. 제품 기능·dependency는 NO-GO. |
| 격리 환경 가능성 | disposable Linux VM 우선 후보이나 아직 입증되지 않음. |
| 공급망 준비도 | NO-GO 실행: 정확한 digest·installer 검증 미완료. |
| license/EULA | 합성 승인 범위의 별도 사용은 후보; image/UI/SDK/제3자 도구와 출력·재배포는 별도 검토 필요. |
| 개인정보 경계 | 설계상 합성 자료만 허용; 실제 DB·logs·provider 경계 미검증. |
| 평가 ground truth | A/B/C 독립 비교 계약 정의. 실행 증거 없음. |
| 저장 가능한 결과 | 정제 합성 fixture와 안전한 집계만 조건부 후보. Raw 산출물 금지. |
| Phase 31.1 진행 | **CONDITIONAL GO — 정적 감사만**. 31.2 이후 실행은 각 단계의 별도 gate 필요. |

이 pilot은 SSH 탐지 의미나 분석 pipeline을 바꾸지 않는다. 단일 합성 대상의 결과를 운영 탐지율, 성공한 공격 또는 일반적인 보안 보장으로 확대하지 않는다.
