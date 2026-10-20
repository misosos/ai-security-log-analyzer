# AI Security Log Analyzer

AI Security Log Analyzer는 인증·웹 접근 로그에서 조사할 관찰과 근거를 정리하는 **방어 목적의 로컬 조사 보조 도구**입니다. 탐지 결과는 침해나 공격 성공의 확정이 아닙니다. 최신 안정 버전은 [v0.3.0 Release](https://github.com/misosos/ai-security-log-analyzer/releases/tag/v0.3.0)입니다.

## 주요 기능

- application·OpenSSH·웹 접근 로그를 배치 분석하고, application·SSH 파일 하나를 선택해 실시간 모니터링합니다.
- 탐지 관찰, 지원 관계, 위험도, 조사 사례를 근거와 판정 한계와 함께 표시합니다.
- application·SSH의 동일 파일을 bounded checkpoint로 재시작할 수 있습니다.
- Linux Audit 프로세스 실행 기록에서 조사 후보를 별도로 요약합니다.
- API·SSE·HTML 보고서에는 개인정보를 제한한 projection을 사용합니다. CLI 출력과 다운로드 파일도 민감한 조사 자료로 취급하십시오.
- 합성 평가, property·API 계약 검사, 개발용 접근성 자동 검사를 제공합니다.

## 빠른 시작

macOS 또는 Linux에서 Python 3.12 이상과 [uv](https://docs.astral.sh/uv/)를 설치한 뒤 실행합니다.

```bash
git clone https://github.com/misosos/ai-security-log-analyzer.git
cd ai-security-log-analyzer
uv sync --locked --dev
uv run python -m app.local_web
```

`http://127.0.0.1:8000/`에서 **샘플로 체험하기** 또는 **내 로그 분석하기**를 선택합니다. 실행한 터미널에서 `Ctrl+C`로 종료합니다. 기본 실행은 loopback·foreground이며 합성 sample과 사용자가 직접 고른 로컬 파일을 분석합니다. 공식 설치 방식은 **source checkout**이며 wheel·PyPI 배포는 지원하지 않습니다. 첫 사용 흐름은 [로컬 웹 시연 안내](docs/final_demo_guide.md)를 참조하십시오.

## 실시간 모니터링

application 파일 하나의 private 설정을 만들고 명시적으로 모니터링을 시작합니다.

```bash
uv run python -m app.monitor_setup
uv run python -m app.local_web --monitor
```

| 명령 | 의미 |
| --- | --- |
| `uv run python -m app.monitor_setup --show` | 경로를 숨긴 설정·checkpoint 상태 요약 |
| `uv run python -m app.monitor_setup --delete` | 승인 후 기본 설정과 연결된 private checkpoint 삭제; 원본 로그는 보존 |
| `uv run python -m app.monitor_setup --reset-checkpoint` | 승인 후 분석 연속성을 버리고 다음 실행을 새 epoch로 시작; 원본 로그·설정은 보존 |

설정 마법사는 아직 SSH 설정을 만들지 않습니다. 새 설정은 현재 파일의 끝(`FROM_END`)부터 읽고, 이후 **같은 파일**의 bounded 구간을 이용해 분석 상태를 복구합니다. Rotation·copytruncate의 자동 연결은 없습니다. 화면의 **새 결과 N건 보기**는 대기 중인 결과를 적용하고, **화면 표시 일시 정지**는 서버 수집을 멈추지 않습니다. 자세한 사용법과 SSH 수동 설정 경계는 [설정 마법사](docs/monitor_setup_20.md), [checkpoint](docs/live_checkpoint_21.md), [SSH 재시작](docs/ssh_checkpoint_recovery_26_0.md)에 있습니다.

## 지원 입력과 관찰

| 입력 | 배치 | Live | Checkpoint | 주요 관찰과 한계 |
| --- | --- | --- | --- | --- |
| application 인증 로그 | 지원 | 단일 파일 | 같은 파일 bounded 복구 | 인증 실패·성공 관찰과 지원 관계; 로그 밖의 사실은 판단하지 않음 |
| OpenSSH 인증 로그 | 지원 | 단일 파일·수동 설정 | private v2 설정의 같은 파일 bounded 복구 | Brute Force·Spray-like 관찰과 지원 관계; 성공 기록이 계정 탈취 증거는 아님 |
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

실제 로그는 기본 기능에서 로컬 처리하며 외부 LLM을 호출하지 않습니다. 선택적 개발용 설명 기능만 별도 설정을 요구합니다. 원본 로그·credential·개인정보를 저장소나 공개 Issue에 올리지 마십시오. 서버는 `127.0.0.1`에서만 사용하고 포트 포워딩하거나 인터넷에 공개하지 마십시오. 인증된 hosted 업로드 서비스가 아닙니다.

HTML 보고서·private config·checkpoint와 CLI 출력에는 민감한 조사 정보가 남을 수 있습니다. 요청 중 임시 자료는 정상 종료 시 정리되지만 비정상 종료 뒤 잔존할 수 있으며 secure erase를 보장하지 않습니다. Checkpoint·SSE에 exactly-once 또는 무유실 보장은 없습니다. 공개 API의 개인정보 경계와 이전 응답의 변경 사항은 [개인정보 projection](docs/public_analysis_privacy.md)을, 비공개 신고는 [SECURITY.md](SECURITY.md)를 참조하십시오.

## 주요 제한

| 영역 | 현재 경계 |
| --- | --- |
| Live·분석 | 단일 source live, cross-source 결합 없음, access live는 detection-only |
| 파일 연속성 | rotation·copytruncate 자동 handoff 없음; 완전한 crash recovery·exactly-once·무유실 보장 없음 |
| 설정·플랫폼 | SSH 설정 마법사 미지원; Windows 실제 업로드·브라우저 흐름 미검증 |
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
| 접근성·수용 검증 | [개발용 접근성 검사](docs/ui_accessibility_axe_pilot_28_1.md), [대시보드 비교안](docs/ui_dashboard_prototype_28_2.md), [Safari 수용 기록](docs/v030_safari_acceptance_27_1.md) |
| 릴리스 | [v0.3.0 노트](docs/releases/v0.3.0.md), [변경 이력](CHANGELOG.md) |
| 개발·보안 검증 기록 | [전체 문서 지도](docs/index.md) |

## 라이선스와 보안 신고

[MIT 라이선스](LICENSE) · Copyright (c) 2026 misosos. 취약점은 [SECURITY.md](SECURITY.md)의 비공개 경로로 신고하십시오. 공개 Issue에 실제 로그·credential·개인정보를 올리지 마십시오.
