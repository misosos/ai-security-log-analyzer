# AI Security Log Analyzer 최종 시연 가이드

## 1. 시연 목적

이 가이드는 약 5–7분 동안 비밀이 아닌 저장소 sample logs만 사용해 CLI 분석, 결정적인 탐지·상관관계·위험도, 개인정보가 제한된 독립형 HTML 조사 보고서를 보여주기 위한 절차입니다. 탐지를 침해 확정이나 자동 사고 판정으로 설명하지 않습니다.

## 2. 사전 조건

- 저장소 루트에서 실행합니다.
- Python 3.12 이상과 uv가 설치되어 있어야 합니다.
- `uv sync --dev`가 성공해야 합니다.
- `investigation.html`이 없어야 합니다. writer는 기존 파일을 덮어쓰지 않습니다.
- 실제 credential, 사용자 로그, LLM 또는 외부 네트워크는 필요하지 않습니다.

## 3. 실행 명령

### 0:00–0:30 — 도움말

```bash
uv run python -m app.main --help
```

### 0:30–2:30 — 기본 sample 분석

```bash
uv run python -m app.main
```

### 2:30–4:30 — HTML 보고서 생성과 수동 열기

```bash
uv run python -m app.main --html-report investigation.html
open investigation.html
```

`open`은 macOS용입니다. 다른 환경에서는 로컬 브라우저의 파일 열기 기능으로 `investigation.html`을 직접 여십시오. CLI는 브라우저를 자동으로 열지 않습니다.

### 4:30–5:30 — 선택 사항: 개발 API 상태 확인

시간이 남을 때만 첫 번째 터미널에서 실행합니다.

```bash
uv run uvicorn app.api:app --reload
```

두 번째 터미널에서 확인합니다.

```bash
curl --fail --silent http://127.0.0.1:8000/api/health
```

## 4. 화면에서 확인할 결과

- 도움말에 `--linux-audit PATH`와 `--html-report PATH`가 보입니다.
- CLI에서 `brute_force`, `password_spraying_like`, `path_traversal`과 레이블이 있는 증거를 확인할 수 있습니다.
- `failed_to_successful_login`과 `brute_force_to_successful_login`은 지원되는 시간 기반 상관관계 예입니다.
- 위험도 `HIGH`, `MEDIUM`, `LOW`와 별도의 confidence가 표시됩니다.
- HTML 생성 후 `HTML investigation report created.`가 표시됩니다.
- HTML 요약에는 분석 대상 10, HIGH 4, MEDIUM 1, LOW 5, 지원 탐지 관찰 4, 지원 상관관계 관찰 3이 표시됩니다.
- 조사 순서의 처음 네 대상은 `10.0.0.5`, `192.168.1.20`, `192.168.1.30`, `192.168.1.60` 순서입니다.
- 분석 대상 상세정보에서 증거, 기존 평가 근거, 유형별 해석 유의사항과 고정된 다음 조사 단계를 확인합니다.
- 상관된 계정은 실제 이름 대신 보고서 내부에서만 유효한 `Account N` 별칭으로 표시됩니다.
- API 상태 응답은 `{"status":"ok"}`입니다.

## 5. 결과별 권장 설명

- **Brute Force**: 한 IP에서 짧은 시간에 단일 계정으로 집중된 인증 실패 관찰입니다. 실패 횟수와 시간 범위를 근거로 보여주되 계정 침해로 단정하지 않습니다.
- **Password Spraying-like**: 짧은 시간에 여러 계정으로 분산된 인증 실패 관찰입니다. 동일한 인증정보 재사용은 현재 로그가 증명하지 못합니다.
- **Path Traversal**: URL decoding 뒤 상위 경로 접근 패턴이 관찰되었습니다. HTTP 200만으로 파일 접근이나 데이터 노출 성공을 판단할 수 없습니다.
- **상관관계**: 인증 실패 뒤 같은 계정의 로그인 성공이 시간 범위 안에서 함께 관찰된 것입니다. 관계는 조사 우선순위를 돕지만 인과관계나 공격 성공을 증명하지 않습니다.
- **위험도와 confidence**: 기존 분석이 계산한 서로 다른 값입니다. HTML 조사 순서는 탐색을 돕는 표시 순서일 뿐 새로운 보안 점수가 아닙니다.
- **다음 조사 단계**: 고정 allowlist의 검토·확인 지침이며 LLM이 생성한 명령이나 자동 차단 권고가 아닙니다.

## 6. 개인정보 및 해석 경고

HTML에는 원본 로그, 전체 HTTP query, 원래 계정 이름, credential, Linux Audit argv·`PROCTITLE`·raw record·실행 경로·세션 상세가 포함되지 않습니다. `Account N`은 한 보고서 안의 상관 참조일 뿐 실제 사용자 신원이나 보고서 간 안정 ID가 아닙니다.

그래도 IP, 위험도, 관찰 내용과 상관관계는 민감합니다. 보고서를 승인된 위치에 저장·공유하고 조직의 보존·삭제 정책을 따르십시오. 탐지는 침해 확정이 아니고, 상관관계는 인과관계가 아니며, 로그인 성공이나 HTTP 200은 공격 성공을 입증하지 않습니다.

## 7. 안전한 정리

API를 실행했다면 해당 터미널에서 `Ctrl-C`로 종료합니다. 다음 명령은 이 시연 절차가 저장소 루트에 새로 만든 `investigation.html` 하나만 제거합니다. 파일이 다른 목적으로 만들어졌다면 실행하지 마십시오.

```bash
rm -- investigation.html
```

디렉터리 전체 삭제, wildcard 또는 재귀 삭제 명령은 사용하지 않습니다.

## 8. 문제 해결

- `uv`를 찾을 수 없으면 공식 uv 설치 안내에 따라 설치한 뒤 `uv sync --dev`를 다시 실행합니다.
- HTML 대상이 유효하지 않으면 소문자 `.html` suffix인지, 부모 디렉터리가 이미 존재하는 실제 디렉터리인지, 대상이 아직 존재하지 않는지 확인합니다. 오류 메시지는 경로나 내부 예외를 노출하지 않습니다.
- Linux Audit 입력이 거부되면 비어 있지 않은 일반 파일인지와 동일 파일을 중복 지정하지 않았는지 확인합니다. CLI 오류는 입력 번호로 식별합니다.
- API가 응답하지 않으면 uvicorn 터미널이 실행 중인지와 `http://127.0.0.1:8000/api/health`를 사용했는지 확인합니다.
- `/api/analyze`는 `.log` 또는 `.txt`인 `application_file`, `ssh_file`, `access_file` 세 multipart 파일을 모두 요구합니다.
- 보고서 생성 실패 뒤에는 성공 메시지나 부분 텍스트 보고서가 출력되지 않습니다. 원인을 확인한 후 새 대상 이름으로 다시 시도하십시오.
