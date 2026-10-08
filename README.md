# AI Security Log Analyzer

AI Security Log Analyzer는 애플리케이션 인증 로그, OpenSSH 인증 로그, 웹 접근 로그와 선택적인 Linux Audit 레코드를 정규화한 뒤, 결정적인 규칙으로 탐지·상관관계·IP별 위험도를 계산하는 방어 목적의 배치 분석 프로젝트입니다. 보안 로그 조사 흐름을 학습하거나 소규모 환경에서 초기 검토하는 데 사용할 수 있습니다.

현재 지원하는 주요 관찰은 Brute Force, Password Spraying-like, Path Traversal, 인증 실패 후 로그인 성공, Brute Force 후 로그인 성공입니다. 탐지와 상관관계는 조사할 관찰이지 침해의 증명이 아니며, 이 프로젝트는 SIEM·EDR·자동 대응 또는 사고 판정 시스템이 아닙니다.

처리 흐름은 다음과 같습니다.

```text
로그 → 로딩·정규화 → 탐지 → 상관관계 → IP별 위험도 → CLI·HTML·API
```

## 요구 사항과 설치

- Python 3.12 이상(`pyproject.toml`의 `requires-python = ">=3.12"`)
- [uv](https://docs.astral.sh/uv/)

저장소를 받은 뒤 프로젝트 루트에서 개발 의존성까지 동기화합니다.

```bash
uv sync --dev
```

기본 로컬 CLI, HTML 보고서, 개발 API에는 환경 변수가 필요하지 않습니다. 실제 키나 운영 로그를 저장소, `.env`, 명령행 또는 문서에 넣지 마십시오.

Gemini 설명 기능은 `app/analyzer/llm.py`에 있는 선택적 개발 경계입니다. 이를 직접 호출할 때만 `GEMINI_API_KEY`가 필요합니다. 기본 CLI, HTML 보고서, 기본 API와 보안 Linux Audit API는 LLM을 호출하지 않으며, 핵심 시연에도 LLM이나 외부 네트워크가 필요하지 않습니다.

## 빠른 시작

### 1. 도움말 확인

```bash
uv run python -m app.main --help
```

`--linux-audit PATH`와 `--html-report PATH`가 표시됩니다.

### 2. 기본 sample logs 분석

```bash
uv run python -m app.main
```

이 명령은 저장소의 `sample_logs/brute_force.log`, `sample_logs/ssh_auth.log`, `sample_logs/web_shell.log`를 한 번씩 읽어 기존 텍스트 보고서를 출력합니다. 출력에는 탐지 근거, 위험도, 신뢰도와 지원되는 상관관계가 포함됩니다.

### 3. 독립형 HTML 조사 보고서 생성

```bash
uv run python -m app.main --html-report investigation.html
```

macOS에서는 생성된 파일을 다음과 같이 직접 열 수 있습니다.

```bash
open investigation.html
```

CLI가 브라우저를 자동으로 열지는 않습니다. 같은 대상에 다시 쓰지 않으므로 재시연 전에는 아래의 [안전한 정리](#안전한-정리)를 따르십시오.

### 4. 개발 API 실행과 상태 확인

첫 번째 터미널:

```bash
uv run uvicorn app.api:app --reload
```

두 번째 터미널:

```bash
curl --fail --silent http://127.0.0.1:8000/api/health
```

예상 응답은 `{"status":"ok"}`입니다. 기본 개발 API는 인증이 없으므로 인터넷에 공개하지 마십시오.

합성 샘플 조사 API는 파일·본문·query 없이 호출합니다.

```bash
curl -X POST http://127.0.0.1:8000/api/v1/investigations/sample
```

응답은 `합성 샘플 결과`로 표시되는 개인정보 제한 JSON이며 실제 조직의 보안 상태를 뜻하지 않습니다. 이 단계에는 웹 UI, 실제 로그 업로드용 V1 API, HTML 다운로드와 LLM 호출이 없습니다. 샘플 요청 제한은 단일 프로세스 범위이므로 공개 배포용 edge 제한을 대신하지 않습니다.

## 입력 개요

지원 범위는 저장소가 구현하고 테스트하는 다음 형식으로 제한됩니다.

- 애플리케이션 인증 로그: timestamp와 `LEVEL EVENT key=value` 형식
- OpenSSH 인증 로그: password/public-key 성공·실패 레코드
- 웹 접근 로그: common/combined 스타일 레코드
- 선택적 Linux Audit 레코드: 동일 source·node·Audit event ID로 묶을 수 있는 compound event

모든 제품이나 임의의 로그 형식을 지원한다고 가정하지 마십시오. 기본 세 sample 경로는 `app/main.py`에 고정되어 있고, CLI에서 추가할 수 있는 입력은 반복 가능한 `--linux-audit PATH`입니다.

```bash
uv run python -m app.main \
  --linux-audit sample_logs/linux_audit_shared_memory_execution_contract_synthetic.log \
  --linux-audit sample_logs/linux_audit_session_process_co_observation_contract_synthetic.log
```

각 Linux Audit 경로는 서로 다른 비어 있지 않은 일반 파일이어야 합니다. 오류는 입력 번호만 표시하고 경로와 내부 예외는 출력하지 않습니다.

## 출력 개요

- **CLI 텍스트**: IP별 탐지, 위험도, 평가 근거와 상관관계를 출력합니다. Linux Audit 프로세스 관련 출력은 승인된 집계 위주이지만, 일반 인증 상관관계에는 계정 등 조사 필드가 나타날 수 있으므로 CLI도 민감하게 취급하십시오.
- **HTML 조사 보고서**: 한국어 UI, 결정적인 검토 순서, 타입이 지정된 증거, 보고서 로컬 `Account N` 별칭, 해석 한계와 고정 조사 단계를 포함하는 독립형 파일입니다. 원본 로그와 전체 HTTP query는 projection에 포함하지 않습니다.
- **Linux Audit 집계**: 별도 입력이 있을 때 프로세스 관찰, shared-memory 검토 관찰, session/process 동시 관찰 등의 count-only 요약을 제공합니다. 상세 argv·PATH record·command line·`PROCTITLE`·raw record·세션 컨텍스트는 HTML과 공용 API 경계에 내보내지 않습니다.
- **기본 API 응답**: `/api/analyze`는 기존 per-IP 결과, global correlation과 `ai_summary: null`을 반환합니다. HTML 보고서를 반환하는 API route는 없습니다.
- **선택적 LLM 설명**: 개발자가 명시적으로 직접 호출할 때만 결정적 분석 결과를 설명합니다. 탐지·상관관계·위험도를 만들거나 변경하는 분석 권한은 없습니다.

## HTML 보고서 보안

HTML 보고서는 로컬에서 여는 하나의 민감한 파일입니다. JavaScript, 외부 CSS·글꼴·이미지·스크립트 또는 원격 네트워크 요청이 없고, 지원되는 플랫폼에서 `0600` 권한으로 생성됩니다. 대상 부모 디렉터리는 이미 존재하는 실제 디렉터리여야 하며, 파일명은 소문자 `.html`로 끝나야 합니다. 환경 변수와 `~`를 확장하지 않고, 부모를 만들지 않으며, 기존 파일이나 symlink를 덮어쓰지 않습니다.

원본 로그가 projection 밖에 있어도 보고서에는 IP, 위험도와 보안 관찰이 포함되므로 민감합니다. 조직의 접근 통제·공유·증거 보존·삭제 정책에 따라 보관하고 전달하며 제거하십시오. 이 프로젝트는 모든 환경에 적용되는 보존 기간을 정하지 않습니다. 파일시스템 race를 완전히 제거한다고 주장하지 않으므로 신뢰할 수 없는 사용자가 조상 디렉터리를 바꿀 수 없는 위치를 사용하십시오.

## 해석 한계

- 탐지는 침해 확인이 아닙니다.
- 상관관계는 인과관계가 아닙니다.
- 로그인 성공은 공격 성공이나 계정 침해의 증명이 아닙니다.
- HTTP 200은 파일 접근, 파일 내용 반환 또는 데이터 노출의 증명이 아닙니다.
- Password Spraying-like 관찰은 동일한 인증정보 재사용을 증명하지 않습니다.
- Linux Audit 집계는 관찰 수이며 고유 프로세스, 공격자 또는 사고 수가 아닙니다.
- 탐지가 없다는 사실은 악의적 활동이 없다는 뜻이 아닙니다.

## API 계약

기본 개발 애플리케이션은 다음 route만 등록합니다.

- `GET /api/health`
- `POST /api/analyze`

`POST /api/analyze`에는 `application_file`, `ssh_file`, `access_file` multipart 파일 세 개가 모두 필요합니다. 각 파일은 비어 있지 않은 `.log` 또는 `.txt`이고 10 MiB 이하여야 합니다. 응답의 `ai_summary`는 `null`이며 Gemini를 호출하지 않습니다. `/api/upload-test`, `/api/analyze-linux-audit`, `/internal/readiness`는 기본 앱에 없습니다.

보안 Linux Audit API의 `POST /api/analyze-linux-audit`는 명시적인 secured app construction에서만 등록됩니다. 반복 가능한 multipart 필드 이름은 `linux_audit_files`입니다. bearer 인증, `linux-audit:analyze` 권한, audit sink와 용량 제한이 필요하며 응답은 UUID, 완료 상태와 count-only 요약으로 제한됩니다. 기본 시연에서는 이 production 전용 route를 사용하지 마십시오. 자세한 배포 전제는 [Linux Audit API 배포 보안](docs/linux_audit_api_deployment_security.md)을 따릅니다.

운영용 factory target은 `uvicorn app.deployment.asgi:create_linux_audit_api_app --factory`입니다. 이 경계는 `CREDENTIALS_DIRECTORY`, `LINUX_AUDIT_API_PRINCIPAL_ID`, `LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES`와 systemd credential 파일 `linux-audit-api-operator-token`을 사용합니다. 운영 전에는 systemd, journald, Nginx, TLS, host 권한과 보존 정책을 별도로 검증해야 하며 저장소 테스트만으로 Linux production host가 승인되지는 않습니다. Production 전용 `GET /internal/readiness`는 OpenAPI에서 제외되고 내부에서만 사용해야 합니다.

## 테스트

전체 회귀 테스트:

```bash
uv run pytest
```

테스트는 합성 fixture를 사용합니다. 실제 운영 호스트의 TLS, 방화벽, systemd credential 전달, journald 지속성, Nginx 동작, 보존 정책 또는 부하 용량을 승인하지 않습니다.

## 프로젝트 구조

```text
app/main.py                         CLI orchestration
app/analyzer/pipeline.py            로딩·탐지·상관관계·위험도 흐름
app/analyzer/report.py              기존 CLI 텍스트 보고서
app/analyzer/report_projection.py   개인정보가 제한된 불변 HTML projection
app/analyzer/html_report.py         순수 독립형 HTML renderer
app/analyzer/html_report_file.py    검증·0600·no-overwrite 보안 writer
app/api.py                          기본 API와 선택적 secured API 구성
sample_logs/                        비밀이 아닌 합성 sample/fixture
tests/                              단위·경계·통합·수용 테스트
docs/                               설계, 배포 경계와 시연 문서
```

`frontend/`, `docs/architecture.md`, `docs/evaluation.md`, `app/detector/suspicious_file.py`는 비어 있는 placeholder이며 지원 기능이 아닙니다. 실시간·streaming 수집, 웹 dashboard, database, 자동 차단, 자동 incident verdict와 보호된 상세 증거 API는 구현되어 있지 않습니다.

## 안전한 정리

아래 명령은 위 빠른 시작에서 현재 디렉터리에 직접 만든 `investigation.html`만 제거합니다. 다른 보고서나 디렉터리에 사용하지 마십시오.

```bash
rm -- investigation.html
```

## 추가 문서

- [5–7분 최종 시연 가이드](docs/final_demo_guide.md)
- [HTML 조사 보고서 설계](docs/html_investigation_report_design.md)
- [Release readiness](docs/release_readiness.md)
- [Linux Audit 프로세스 실행](docs/linux_audit_process_execution.md)
- [Shared-memory 실행 검토](docs/shared_memory_execution_review.md)
- [Session/process 동시 관찰](docs/linux_audit_session_process_review.md)
- [Linux Audit API 경계](docs/linux_audit_api_design.md)
- [Linux Audit API 보안 설계](docs/linux_audit_api_security_design.md)
- [Linux Audit API 배포 보안](docs/linux_audit_api_deployment_security.md)

보안 이슈에는 합성 데이터로 재현할 수 있는 관찰 증거, 영향받는 입력 또는 route, 재현 단계와 개인정보 영향을 포함하십시오. 실제 credential, 운영 로그, private key 또는 복사한 운영 증거는 포함하지 마십시오.
