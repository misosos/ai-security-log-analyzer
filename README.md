# AI Security Log Analyzer

> 보안 계약 변경: deprecated `/api/analyze`의 상위 구조는 유지하지만 중첩 탐지·상관관계·위험도·전체 상관관계는 개인정보 안전 projection으로 변경되었습니다. 기존 raw nested 값 소비자는 [migration 안내](docs/public_analysis_privacy.md)를 확인하세요. 새 로컬 개발에는 `POST /api/v1/investigations`를 사용하세요. 인증 없는 공개 업로드는 지원하지 않습니다.

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

처음 사용하는 경우 웹 UI부터 시작하십시오. macOS·Linux·Windows에서 Python 3.12 이상과 `uv`를 설치한 뒤 터미널에서 다음 명령을 실행합니다.

```bash
git clone https://github.com/misosos/ai-security-log-analyzer.git
cd ai-security-log-analyzer
uv sync --dev
uv run python -m app.local_web
```

서버가 준비되면 `http://127.0.0.1:8000/`을 안내하고 기본 브라우저를 한 번 엽니다. 브라우저가 열리지 않으면 안내된 주소를 직접 여십시오. 브라우저 자동 열기를 원하지 않으면 `--no-browser`를 붙입니다. 기본 포트는 8000이며, 충돌할 때만 `--port 8001`처럼 1024~65535 사이의 포트를 하나 지정할 수 있습니다. host는 언제나 `127.0.0.1`이고 외부 인터페이스 지정과 `--reload`는 지원하지 않습니다. 종료는 실행한 터미널에서 `Ctrl+C`입니다. 이것은 현재 컴퓨터에서 직접 사용하는 전경 개발 실행기이며 hosted 배포가 아닙니다.

로컬 실제 로그 업로드의 임시 파일 보호는 플랫폼의 `O_NOFOLLOW` 지원을 요구합니다. 지원하지 않는 플랫폼에서는 업로드가 고정 오류로 거부됩니다. Windows에서 전체 업로드·브라우저 흐름은 아직 검증되지 않았으므로 이 문서를 Windows 지원 완료의 근거로 사용하지 마십시오.

첫 화면에서 **샘플로 체험하기**를 누르면 사용자 파일 없이 합성 로그의 조사 사례·Timeline을 볼 수 있습니다. 실제 로그는 **내 로그 분석하기**에서 세 칸에 각각 애플리케이션 인증 로그(`sample_logs/brute_force.log`), SSH 인증 로그(`sample_logs/ssh_auth.log`), 웹 접근 로그(`sample_logs/web_shell.log`) 형식의 UTF-8 파일을 넣습니다. 세 sample 파일로도 로컬 입력 절차를 연습할 수 있습니다. 결과의 **HTML 보고서 다운로드**는 현재 탭의 응답에서 대상별 보고서를 저장하며, 사례 Timeline 전체를 포함하지 않습니다. 샘플 결과는 실제 조직 환경의 보안 상태를 증명하지 않습니다.

입력 한계는 파일당 32 KiB, 합계 80 KiB, multipart 요청 전체 96 KiB, 한 줄 2048바이트, 파일당 512줄입니다. 압축 파일은 지원하지 않습니다. 분석은 외부 LLM을 호출하지 않습니다. 로그·결과·보고서를 서버에 영구 저장하지 않으며 정상·오류·취소·timeout 종료 때 요청별 임시 파일을 정리합니다. 프로세스나 호스트의 비정상 종료 뒤에는 임시 파일 잔존 가능성이 있습니다. 다운로드한 보고서는 민감한 조사 자료이므로 안전하게 저장·공유·삭제하십시오. 이 경로는 공개 인터넷 업로드나 실시간 수집 기능이 아닙니다. 포트 포워딩 및 `0.0.0.0` 바인딩을 하지 마십시오.

첫 실행이 막히면 `uv sync --dev` 완료 여부를 확인하고, 포트 충돌 메시지가 나오면 해당 로컬 서버를 종료하거나 다른 허용 포트를 지정하십시오. 브라우저가 열리지 않으면 출력된 주소를 직접 여십시오. 분석 오류가 나오면 세 입력칸의 파일 종류, UTF-8, 크기·줄 한계를 확인하고 화면의 필드별 오류와 복구 행동을 따르십시오. 결과가 비어 보인다고 안전하다는 뜻은 아닙니다. 실제 Safari·키보드·확대 검증은 사용자 환경에서 별도로 확인해야 합니다.

### 기존 CLI와 개발 API

CLI 도움말:

```bash
uv run python -m app.main --help
```

`--linux-audit PATH`와 `--html-report PATH`가 표시됩니다.

### 기본 sample logs 분석

```bash
uv run python -m app.main
```

이 명령은 저장소의 `sample_logs/brute_force.log`, `sample_logs/ssh_auth.log`, `sample_logs/web_shell.log`를 한 번씩 읽어 기존 텍스트 보고서를 출력합니다. 출력에는 탐지 근거, 위험도, 신뢰도와 지원되는 상관관계가 포함됩니다.

### 독립형 HTML 조사 보고서 생성

```bash
uv run python -m app.main --html-report investigation.html
```

macOS에서는 생성된 파일을 다음과 같이 직접 열 수 있습니다.

```bash
open investigation.html
```

CLI가 브라우저를 자동으로 열지는 않습니다. 같은 대상에 다시 쓰지 않으므로 재시연 전에는 아래의 [안전한 정리](#안전한-정리)를 따르십시오.

### 개발 API를 직접 실행하고 상태 확인

첫 번째 터미널:

```bash
uv run uvicorn app.api:app --host 127.0.0.1 --port 8000 --no-access-log --no-proxy-headers
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

응답은 `합성 샘플 결과`로 표시되는 개인정보 제한 JSON이며 실제 조직의 보안 상태를 뜻하지 않습니다. 같은 분석 결과로 만든 대상별 standalone HTML이 `report_export`에 포함됩니다. 샘플 요청 제한은 단일 프로세스 범위이므로 공개 배포용 edge 제한을 대신하지 않습니다.

### 로컬 웹 체험과 실제 로그 분석

위 명령으로 개발 서버를 `127.0.0.1`에 바인딩한 뒤 `http://127.0.0.1:8000/`을 여세요. **샘플로 체험하기**가 첫 번째 경로입니다. 직접 실행한 로컬 서버에서만 **내 로그 분석하기**의 애플리케이션 인증·SSH 인증·웹 접근 로그를 각각 선택할 수 있습니다. `POST /api/v1/investigations`는 세 multipart field `application_file`, `ssh_file`, `access_file`을 정확히 한 번씩 받고, loopback client와 고정 loopback Host를 확인합니다. 교차 출처 Origin과 forwarding header를 거부합니다. 확장자·MIME·사용자 filename은 신뢰하지 않습니다. Linux Audit, archive와 외부 LLM은 이 경계에서 처리하지 않습니다.

각 파일의 decoded 상한은 32 KiB, 합계는 80 KiB, multipart envelope는 96 KiB, 한 줄은 2048바이트, 파일당 512줄입니다. 업로드 처리와 분석은 각각 10초, 동시 분석은 1개, 요청은 프로세스당 60초에 6회로 제한합니다. 이는 작은 로컬 학습·초기 조사 용도입니다. 기준 측정에서 기존 합성 세 파일은 총 2001바이트·27줄·분석 약 0.05초였고, 20회 반복한 입력은 약 40020바이트·540줄·약 0.22초였습니다. 측정값은 해당 개발 환경의 참고치이지 모든 로그의 처리시간 보장은 아닙니다. 특히 ASGI 서버/프록시가 앱에 넘기기 전 보유한 단일 네트워크 청크에는 앱 제한을 적용할 수 없으므로 공개 업로드 보호로 해석하지 마십시오.

요청별 임시 디렉터리는 `0700`, 고정 내부 파일은 `0600`으로 만들고 정상 응답, 검증·분석·보고서 실패, 취소와 timeout 때 알려진 디렉터리를 정리합니다. timeout의 별도 worker process는 종료하고 정리 후 응답합니다. 프로세스 또는 호스트가 비정상 종료되면 orphan 임시 파일 삭제를 보장하지 않습니다. 로그·분석 결과·보고서는 서버의 영구 저장소에 보관하지 않으며, 결과는 현재 브라우저 탭 메모리에만 둡니다. HTML 다운로드는 사용자 클릭 때 Blob으로 만들고 서버에 재요청하지 않습니다. 현재 형식은 대상별 결정적 조사 보고서이며 사례 Timeline 전체는 포함하지 않습니다. 모든 HTML 보고서는 원래 HTTP 요청 경로와 full query를 표시하지 않지만 Path Traversal 일치 패턴과 승인된 상태 근거는 유지합니다. 다운로드 파일은 민감한 조사 자료로 안전하게 저장·공유·삭제하십시오.

이 local endpoint의 loopback 확인은 인증이나 방화벽을 대신하지 않습니다. 위 실행 명령은 Uvicorn의 URL query가 포함될 수 있는 access log와 proxy-header 신뢰를 끕니다. 다른 실행·프록시 구성을 쓸 경우 동일한 로그 비노출과 client 주소 검증을 다시 입증해야 합니다. 기존 `/api/analyze`는 deprecated이며 상위 구조만 유지하고 nested 값은 개인정보 안전 projection으로 변경되었습니다. 또한 whole-file read, filename suffix, 인증·rate 제한 부재 등 기존 한계가 있으므로 공개용으로 사용하지 마십시오. `0.0.0.0` 바인딩, 포트 포워딩과 무인증 hosted upload는 금지입니다. 실제 Safari·키보드·확대·WCAG 검증은 별도로 수행해야 합니다. 분석 결과는 침해 확정이 아닙니다.

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
- **기본 API 응답**: `/api/analyze`는 기존 per-IP 결과, global correlation과 `ai_summary: null`을 반환합니다. 별도 보고서 route는 없으며 sample 및 loopback-only 조사 API의 같은 응답에 bounded `report_export`가 포함됩니다.
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

`frontend/`는 합성 샘플 Landing, loopback-only 실제 로그 업로드, 결과 개요와 사례·Timeline 상세 및 HTML 다운로드를 지원합니다. `docs/architecture.md`, `docs/evaluation.md`, `app/detector/suspicious_file.py`는 비어 있는 placeholder이며 지원 기능이 아닙니다. 인증된 hosted upload, 실시간·streaming 수집, database, 자동 차단, 자동 incident verdict와 보호된 상세 증거 API는 구현되어 있지 않습니다.

## 오프라인 탐지 평가 기준선

작은 합성 경계 corpus에서 현재 parser·탐지·관계·risk·조사 사례 계약을 분리해 평가합니다.

```bash
uv run python -m app.evaluation
uv run python -m app.evaluation --format json
uv run python -m app.evaluation --scenario brute_success
```

결과는 stdout에만 출력되며 운영 환경 탐지율이나 침해 확률이 아닙니다. 현재 SSH·parser-only·정상 활동 및 모호한 자동화 시나리오를 포함합니다. 모호한 운영 활동은 일반 TP/FP/TN 계산에서 제외합니다. 고정 라벨·metric·한계·외부 데이터셋 검토는 [평가 문서](docs/detection_evaluation.md)에 있습니다. 기존 탐지 임계값과 시간 범위는 유지하며, 여러 로그인 성공 후보의 관계는 가장 가까운 유일한 후속 endpoint를 입력 순서와 무관하게 선택합니다.

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
