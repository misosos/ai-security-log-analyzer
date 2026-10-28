# AI Security Log Analyzer

AI Security Log Analyzer는 인증·웹 접근 로그에서 조사할 관찰과 근거를 정리하는 **방어 목적의 로컬 조사 보조 도구**입니다. 탐지 결과는 침해나 공격 성공의 확정이 아닙니다. [v0.4.0 노트](docs/releases/v0.4.0.md)는 작업 화면의 변경 사항을 설명하며, [v0.3.0 Release](https://github.com/misosos/ai-security-log-analyzer/releases/tag/v0.3.0)는 이전 공개 버전입니다.

## 주요 기능

- application·OpenSSH·웹 접근 로그를 배치 분석하고, application 또는 SSH 단일 파일이나 private v3 application+SSH 쌍을 실시간 모니터링합니다.
- 탐지 관찰, 지원 관계, 위험도, 조사 사례를 근거와 판정 한계와 함께 표시합니다.
- 전체 폭 작업 화면에서 시작 행동·분석 결과를 구분하고 조사 사례의 상세 근거를 펼쳐 봅니다.
- application·SSH의 동일 파일을 bounded checkpoint로 재시작할 수 있습니다.
- Linux Audit 프로세스 실행 기록에서 조사 후보를 별도로 요약합니다.
- API·SSE·HTML 보고서에는 개인정보를 제한한 projection을 사용합니다. CLI 출력과 다운로드 파일도 민감한 조사 자료로 취급하십시오.
- 합성 평가, property·API 계약 검사, 개발용 접근성 자동 검사를 제공합니다.
- 자동 수집은 합성 입력의 loopback TCP Syslog pilot 범위만 검증했습니다. 별도 external collector adapter core와 JSON Lines runtime도 합성 application·SSH에 한해 제한된 Ubuntu acceptance를 통과했습니다. Vector 0.60.0의 x86_64와 ARM64 archive는 checksum·archive 정적 검사를 마쳤지만 Vector는 미실행입니다. 기존 ARM64 VM의 NAT·USB가 켜져 있고 공유 경계와 현재 guest 자원 여유를 확인하지 못해 실행 gate는 `USER_ACTION_REQUIRED` (`ISOLATION_BLOCKED`, `RESOURCE_BLOCKED`)이며 config/wire 실행 검증은 **NOT_TESTED**입니다. checksum은 binary provenance가 아니며 credential 형태 문자열 3건은 `UNRESOLVED`입니다. Phase 32 pair truncate 회귀는 cycle budget 경계의 테스트 동기화 결함을 재현해 보정했고 전체 suite 3회 연속 통과했습니다. 원격·실제 사용자 로그 수집은 지원하지 않습니다. 실제 사용자 로그 수집과 조직 운영은 계속 지원하지 않습니다(**NO_GO**). Vector 실행은 미승인입니다. [Phase 35.4A2 ARM64 isolation preflight](docs/vector_arm64_isolation_preflight_35_4a2.md) · [Phase 35.4A artifact preflight](docs/vector_artifact_preflight_35_4a.md) · [Phase 35.4 격리 Vector pilot 계획](docs/vector_isolated_integration_plan_35_4.md) · [Phase 35.4A1 pair truncate 안정성 기록](docs/pair_truncation_stability_35_4a1.md) · [Ubuntu JSON Lines acceptance](docs/collector_jsonl_runtime_linux_acceptance_35_3a.md) · [Phase 34.5 user acceptance](docs/loopback_tcp_syslog_management_acceptance_34_5.md)

## 빠른 시작

macOS 또는 Linux에서 Python 3.12 이상과 [uv](https://docs.astral.sh/uv/)를 설치한 뒤 실행합니다.

```bash
git clone https://github.com/misosos/ai-security-log-analyzer.git
cd ai-security-log-analyzer
uv sync --locked --dev
uv run python -m app.local_web
```

`http://127.0.0.1:8000/`에서 **예시 데이터로 둘러보기** 또는 **내 로그 분석하기**를 선택합니다. 실행한 터미널에서 `Ctrl+C`로 종료합니다. 기본 실행은 loopback·foreground이며 합성 sample과 사용자가 직접 고른 로컬 파일을 분석합니다. 공식 설치 방식은 **source checkout**이며 wheel·PyPI 배포는 지원하지 않습니다. 첫 사용 흐름은 [로컬 웹 시연 안내](docs/final_demo_guide.md)를 참조하십시오.

## 실시간 모니터링

단일 로그 설정은 기존 흐름을 사용합니다. 두 역할을 함께 설정하려면 명시적으로 multi-source wizard를 선택합니다. 두 설정 모두 별도 명령으로 모니터링을 시작합니다.
기존 단일 설정 흐름에서는 애플리케이션 로그인 로그 또는 SSH 인증 로그 하나를 선택합니다.

```bash
uv run python -m app.monitor_setup
uv run python -m app.local_web --monitor
```

두 로그를 함께 설정하려면 wizard를 명시적으로 선택합니다:

```bash
uv run python -m app.monitor_setup --multi-source
```

| 명령 | 의미 |
| --- | --- |
| `uv run python -m app.monitor_setup --show` | 경로를 숨긴 설정·checkpoint 상태 요약 |
| `uv run python -m app.monitor_setup --delete` | 승인 후 기본 설정과 연결된 private checkpoint 삭제; 원본 로그는 보존 |
| `uv run python -m app.monitor_setup --reset-checkpoint` | 승인 후 분석 연속성을 버리고 다음 실행을 새 epoch로 시작; 원본 로그·설정은 보존 |
| `uv run python -m app.monitor_setup --reset-checkpoint --role application\|ssh\|all` | v3 복구 자료를 선택한 역할만 초기화 |

모니터를 정상 종료하면 설정과 checkpoint가 유지됩니다. `--delete`와 `--reset-checkpoint`도 원본 로그를 삭제하지 않습니다.

Multi-source wizard는 역할별 bounded 형식 확인만 수행하고 detector/risk/case/LLM은 실행하지 않습니다. 새 설정은 두 로그의 현재 끝부터 읽습니다. 역할별 checkpoint와 상태는 분리됩니다. 한 역할 실패는 전체 수집을 멈춥니다. Rotation/copytruncate, 두 번째 파일 세대 replay, cross-source 분석, exactly-once는 지원하지 않습니다. 화면의 **새 결과 보기**는 선택한 역할의 staged 결과를 적용하고, 화면 표시 일시 정지는 서버 수집을 멈추지 않습니다. 설정·관리·UI 제한은 [Phase 32.3 안내](docs/multi_source_user_monitoring_32_3.md), Phase 32.4 자동·사용자 수용 상태는 [검증 기록](docs/multi_source_acceptance_32_4.md)을 참조하십시오.

기존 v1/v2의 application·SSH 파일 하나 실행은 `FROM_END`부터 시작하고 bounded checkpoint로 같은 파일 복구를 유지합니다. Rotation·copytruncate의 자동 연결은 없습니다. 기존 화면에서 **새 결과 N건 보기**를 선택해야 대기 결과가 적용되며, 일시 정지는 서버 수집을 멈추지 않습니다. 단일 설정 상세는 [설정 마법사](docs/monitor_setup_20.md), [SSH 설정 구현](docs/monitor_setup_ssh_30_1.md), [checkpoint](docs/live_checkpoint_21.md), [SSH 재시작](docs/ssh_checkpoint_recovery_26_0.md)를 참조하십시오.

## 지원 입력과 관찰

| 입력 | 배치 | Live | Checkpoint | 주요 관찰과 한계 |
| --- | --- | --- | --- | --- |
| application 인증 로그 | 지원 | 단일 파일 | 같은 파일 bounded 복구 | 인증 실패·성공 관찰과 지원 관계; 로그 밖의 사실은 판단하지 않음 |
| OpenSSH 인증 로그 | 지원 | 단일 파일·마법사 설정 | private v2 설정의 같은 파일 bounded 복구 | Brute Force·Spray-like 관찰과 지원 관계; 성공 기록이 계정 탈취 증거는 아님 |
| 웹 access 로그 | 지원 | 수동 설정에서 detection-only | 미지원 | 웹 요청 패턴 관찰; HTTP 응답만으로 exploit 성공을 판단하지 않음 |
| Linux Audit | 별도 조사 흐름 | 미지원 | 미지원 | 프로세스 실행 category·건수와 조사 후보; 악성 실행 판정은 아님 |

주요 탐지 유형은 Brute Force, Password Spraying-like, Path Traversal, SQL Injection-like, XSS-like, Sensitive Resource Probing-like, Web Scanning-like입니다. 인증 실패·Brute Force·Spray 후 성공의 **지원 관계**도 계산합니다. 조건과 한계는 [탐지 평가](docs/detection_evaluation.md), [웹 관찰 설계](docs/web_attack_observation_design.md), [SSH live 분석](docs/ssh_live_analysis_integration_22_3.md)을 참조하십시오.

## 결과 해석

- 탐지는 조사할 관찰이지 침해 확인이 아니며, 결과가 없다고 안전한 것은 아닙니다.
- 상관관계는 시간·조건의 관계이지 인과관계나 동일 행위자의 증명이 아닙니다.
- 로그인 성공은 공격 성공·계정 탈취의 증거가 아닙니다.
- HTTP 200은 파일 내용 반환·데이터 유출의 증거가 아닙니다.
- 위험도와 사례는 기록된 근거에 대한 조사 우선순위이며 자동 사고 판정이 아닙니다.

## 개인정보와 보안 경계

실제 로그는 기본 기능에서 로컬 처리하며 외부 LLM을 호출하지 않습니다. 원본 로그·credential·개인정보를 저장소나 공개 Issue에 올리지 마십시오. 서버는 `127.0.0.1`에서만 사용하고 포트 포워딩하거나 인터넷에 공개하지 마십시오. 인증된 hosted 업로드 서비스가 아닙니다. Phase 33.1의 결정적 lexical retrieval은 조사 사례 안에서 사용자가 요청할 때만 승인된 문서 citation을 보여주는 근거 도움말에 연결됩니다. 이 도움말은 분석 결과를 생성하거나 변경하지 않습니다. Phase 36.1에는 결정적 조사 우선순위 기준선이 추가됐고, Phase 36.2의 citation checklist는 Phase 36.3에서 현재 사례의 불투명 참조를 사용하는 읽기 전용 POST와 명시적 사례 상세 버튼에 연결됐습니다. 버튼 전 자동 요청은 없고 review priority는 기존 risk와 분리됩니다. Phase 36.2A의 사용자 8/8 PASS는 합성 내부 문구 검수 결과이고, Phase 36.3A에서는 실제 합성 API/UI 캡처를 대상으로 10/10 최종 PASS를 별도로 받았습니다. item 7의 최초 FAIL과 수정 기록은 수용 문서에 보존했습니다. Phase 36.3B Safari 검수는 `NOT_TESTED / USER_HOME_ISOLATION_BLOCKED`로 유지됩니다. Phase 36.4는 동일 분석 snapshot의 허용된 source metadata가 일치할 때만 역할 label을 전달하며, 불일치·혼합·누락은 `unknown`으로 남깁니다. 응답은 `investigation-checklist/v2`로 명시적으로 버전 변경됐으며 Phase 36.4 Ubuntu CI 전까지 `CONDITIONAL_GO`입니다. [Phase 36.0 설계](docs/ai_investigation_triage_design_36_0.md), [36.1 구현](docs/deterministic_investigation_triage_36_1.md), [36.2 checklist](docs/lexical_investigation_checklist_36_2.md), [36.2A 수용 기록](docs/investigation_checklist_acceptance_36_2a.md), [36.3 API/UI](docs/investigation_checklist_api_ui_36_3.md), [36.3A 수용 기록](docs/investigation_checklist_acceptance_36_3a.md), [36.3B Safari 수용 기록](docs/investigation_checklist_safari_acceptance_36_3b.md), [36.4 verified role](docs/investigation_checklist_verified_role_36_4.md)를 참조하십시오. 실제 조직 로그와 자동 대응은 **NO_GO**이며, 모델 기반 설명은 **NOT_TESTED**입니다. **Embedding production 통합은 NO_GO**입니다. Phase 33.2B 평가 기록에는 당시 결론이 “production 통합은 보류합니다”로 남아 있으며, 후속 embedding 비교에서도 lexical 기준선 개선 근거가 없어 NO_GO로 유지합니다. Phase 33.3B·33.3C는 `ISOLATION_BLOCKED`, 33.3D는 `SUPPLY_CHAIN_BLOCKED`, 33.3E는 `RESOURCE_NO_GO`, 33.3F는 전용 VM disk와 Ubuntu build closure 검증 전으로 `STORAGE_SETUP_BLOCKED`입니다. 모델 inference는 수행하지 않았습니다. 기존 Gemini helper는 별도 호출 시 IP가 포함된 projection을 Google Gemini로 보내고 자유 문자열을 검증 없이 반환합니다. **Local Gemini 실패 시 fallback은 없습니다.** 이 도움말은 Gemini를 호출하지 않습니다. [Phase 33.0 설계](docs/local_ai_investigation_assistant_33_0.md), [33.1 검증 기록](docs/local_ai_lexical_retrieval_33_1.md), [33.2A gate](docs/local_embedding_supply_chain_gate_33_2a.md), [33.2B pilot](docs/local_embedding_retrieval_pilot_33_2b.md), [33.3A LLM gate](docs/local_llm_supply_chain_gate_33_3a.md), [33.3B](docs/local_llm_pilot_33_3b.md), [33.3C](docs/local_llm_pilot_33_3c.md), [33.3D preflight 결과](docs/local_llm_pilot_33_3d.md), [33.3E artifact·disk gate](docs/local_llm_artifact_closure_33_3e.md), [33.3F 전용 저장공간·closure](docs/local_llm_acquisition_environment_33_3f.md), [33.4 근거 도움말](docs/local_investigation_guidance_33_4.md)를 참조하십시오.

공개 사례·일반 HTML 보고서는 원래 계정·IP·hostname·경로·원문 대신 응답 안에서만 유효한 대상 별칭과 승인된 집계를 표시합니다. 별칭은 원래 식별자가 아니므로 응답 간 상관 키나 영구 ID로 사용하지 마십시오. 제품은 실제 분석 결과로 공개용 안전 보고서를 만들 수 있습니다. [제한된 내부 조사 보고서 CLI pilot](docs/trusted_analyst_report_pilot_33_5b.md)은 합성 입력 전용이며 실제 사용자 자료 export와 조직 운영은 승인되지 않았습니다. 파일은 자동 암호화되지 않습니다. Phase 33.5C Ubuntu CI의 세 역할 smoke와 benchmark는 통과했지만, 이는 합성 pilot 범위의 조건부 검증입니다. Phase 33.5D 안내 수용 검수는 10개 항목 모두 사용자가 PASS했으며 자동화 검증과 별도로 기록했습니다. 실제 자료 사용은 여전히 NO_GO입니다. [수용 기록](docs/trusted_analyst_report_user_acceptance_33_5d.md)을 참조하십시오. Phase 33.4A에서 synthetic IP canary 노출을 발견해 NO_GO로 중단했고, 33.4B 공개 projection에서 수정했습니다. 이전 응답의 변경 사항과 schema 1 소비자 migration은 [개인정보 projection](docs/public_analysis_privacy.md)을, 공개 경계의 Safari 수용은 [수용 기록](docs/public_investigation_privacy_acceptance_33_4c.md)을, 제한 보고서 설계는 [Phase 33.5A](docs/trusted_analyst_report_design_33_5a.md)를 참조하십시오. private config·checkpoint와 CLI 출력에는 그 밖의 민감한 내부 정보가 남을 수 있습니다. 요청 중 임시 자료는 정상 종료 시 정리되지만 비정상 종료 뒤 잔존할 수 있으며 secure erase를 보장하지 않습니다. Checkpoint·SSE에 exactly-once 또는 무유실 보장은 없습니다. 비공개 신고는 [SECURITY.md](SECURITY.md)를 참조하십시오.

## 주요 제한

| 영역 | 현재 경계 |
| --- | --- |
| Live·분석 | 단일 source live, cross-source 결합 없음, access live는 detection-only |
| 파일 연속성 | rotation·copytruncate 자동 handoff 없음; 완전한 crash recovery·exactly-once·무유실 보장 없음 |
| 설정·플랫폼 | 마법사는 application·SSH 단일 source만 지원; Windows 실제 업로드·브라우저 흐름 미검증 |
| 설치·운영 | source checkout만 지원, wheel·PyPI 미지원; SIEM·EDR·WAF·자동 대응 시스템 아님 |
| 접근성 | 자동 검사 결과를 WCAG 2.2 AA 준수로 주장하지 않음 |

## 테스트

```bash
uv run pytest
uv run python -m app.evaluation
npm ci --ignore-scripts --no-audit --no-fund
npm run test:a11y
```

평가는 작은 **합성 시나리오**와 고정된 기대 결과의 일치도를 측정하며 실제 운영환경 탐지율이 아닙니다. axe/Chromium 통과도 실제 Safari, keyboard-only, VoiceOver 또는 WCAG 준수의 증명이 아닙니다. 접근성 테스트에는 [고정 Chromium 설치 절차](docs/ui_accessibility_axe_pilot_28_1.md)가 추가로 필요합니다. [평가 방법](docs/detection_evaluation.md)을 함께 확인하십시오.

## 문서

| 목적 | 시작 문서 |
| --- | --- |
| 시작·사용 | [로컬 웹 시연 안내](docs/final_demo_guide.md) |
| Live monitoring·checkpoint | [설정 마법사](docs/monitor_setup_20.md), [checkpoint](docs/live_checkpoint_21.md) |
| 탐지·평가 | [탐지 평가](docs/detection_evaluation.md) |
| 개인정보·API | [개인정보 projection](docs/public_analysis_privacy.md) |
| Linux Audit | [프로세스 실행 조사](docs/linux_audit_process_execution.md) |
| 근거 도움말 | 조사 사례 상세의 선택형 lexical citation 도움말; [계약과 검증](docs/local_investigation_guidance_33_4.md) |
| 접근성·수용 검증 | [개발용 접근성 검사](docs/ui_accessibility_axe_pilot_28_1.md), [작업 화면 Safari 수용 기록](docs/ui_safari_acceptance_28_5.md), [v0.3.0 Safari 수용 기록](docs/v030_safari_acceptance_27_1.md) |
| 릴리스 | [v0.4.0 노트](docs/releases/v0.4.0.md), [v0.3.0 노트](docs/releases/v0.3.0.md), [변경 이력](CHANGELOG.md) |
| 개발·보안 검증 기록 | [전체 문서 지도](docs/index.md) |

## 라이선스와 보안 신고

[MIT 라이선스](LICENSE) · Copyright (c) 2026 misosos. 취약점은 [SECURITY.md](SECURITY.md)의 비공개 경로로 신고하십시오. 공개 Issue에 실제 로그·credential·개인정보를 올리지 마십시오.
