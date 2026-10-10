# 변경 이력

## [0.1.0] - 2026-10-09

첫 로컬 릴리스 후보의 구현 범위다. 태그·GitHub Release·PyPI 배포 완료를 뜻하지 않는다.

### 추가

- Python 3.12·uv 기반 한 명령 로컬 웹 실행, 합성 샘플 체험, 애플리케이션 인증·SSH 인증·NCSA 형식 웹 접근 로그의 세 파일 업로드.
- Brute Force, Password Spraying-like, Path Traversal 및 SQL Injection-like, XSS-like, Sensitive Resource Probing-like, Web Scanning-like 웹 요청 관찰, 인증 실패·성공 상관분석, 가장 가까운 후속 성공의 결정적 선택.
- 기존 위험도·신뢰도·근거·한계, 조사 사례·시간순 조사 흐름·독립 관찰, 대상별 standalone HTML 보고서 다운로드.
- 오프라인 합성·경계 평가 79개 시나리오(기존 43개 ID 유지), 선택적 CLI Linux Audit 집계. 기존 LLM 설명 코드는 핵심 실행 경로와 분리된다.
- Linux Audit의 실행 파일 basename·위치에 근거한 네 가지 **프로세스 실행 조사 후보**를 먼저 CLI에 추가하고 별도 합성 평가 21개 시나리오로 검증한다. 기존 IP 기반 조사 사례·risk·HTML·LLM과 결합하지 않는다.
- 네 범주의 집계만 확인하는 loopback 전용 Linux Audit 로컬 웹 업로드를 별도 endpoint와 화면에 추가했다. 기존 인증·웹 조사 사례와 결합하지 않고 원래 Audit 세부정보를 공개 응답에서 제외한다.

### 보안

- 실제 로그 웹 업로드는 loopback 요청에만 허용하고 multipart envelope·part·파일 크기, UTF-8, binary/archive, 줄 길이·개수와 처리 자원을 제한한다.
- 요청별 임시 디렉터리 `0700`과 고정 내부 파일 `0600`을 사용하며 정상·오류·취소·timeout 경로의 알려진 임시 파일 정리를 검증한다.
- 공개 API·CLI·HTML·LLM prompt에는 명시적인 개인정보 안전 projection을 사용한다. 원래 계정, 원래 HTTP path와 full query를 공개 결과에서 제외한다.
- Standalone HTML은 JavaScript·원격 리소스 없이 검증된 CSP를 사용한다. Deprecated `/api/analyze`는 공개 중첩 값을 안전 모델로 변경했다.
- 새 웹 관찰은 bounded canonicalization과 고정 pattern ID만 공개하며 원래 path/query·payload를 공개 API·웹 UI·HTML에 넣지 않는다. 기존 Path Traversal 의미와 CSP style hash를 유지한다.

### 변경

- `/api/analyze`의 route·상위 응답 경로는 남지만 nested detection·correlation·risk·global 값은 의도적으로 변경되었다. 기존 raw nested 값 소비자는 [migration 안내](docs/public_analysis_privacy.md)를 따라야 한다.
- 프로젝트 버전 단일 출처는 `pyproject.toml`의 `0.1.0`이다. API와 평가의 schema version은 별개다.

### 알려진 제한

- 이 버전은 로컬 조사 보조 도구다. Hosted/public 업로드, 인증·tenant isolation, 실시간 수집·자동 대응, Windows 실제 업로드, PyPI 패키지·운영 SLA는 제공하지 않는다.
- 비정상 프로세스/호스트 종료 뒤 임시 파일 삭제는 보장되지 않는다. 애플리케이션이 ASGI/프록시의 사전 allocation을 완전히 제한하지 못하며, rate limit은 여러 worker를 통합하지 않는다.
- Windows에서 `O_NOFOLLOW`가 없으면 실제 업로드를 거부한다. 합성 corpus 수치는 실제 운영환경의 탐지율이 아니다.
- 새 웹 관찰은 요청만으로 SQL 실행·브라우저 실행·파일 노출·자동화 의도를 확인하지 못하며 WAF 대체품이 아니다. Web Scanning-like 합성 positive support는 3개뿐이며 운영환경 성능으로 일반화할 수 없다.
- Linux Audit 도구 실행은 도구 목적·전송·권한 변경·악성 여부를 확정하지 않는다. `comm` truncation과 `argv[0]` spoofing, Audit 정책의 로그 누락은 남은 한계다.
- HTML은 대상별 형식으로 case Timeline 전체를 포함하지 않는다. Trusted internal analysis에는 계정 원문이 남을 수 있고 Python 메모리의 secure erasure는 보장되지 않는다.
- 라이선스는 MIT(`Copyright (c) 2026 misosos`)이며 GitHub private vulnerability reporting은 사용자 확인에 따라 활성화됐다. Safari의 키보드·확대·screen-reader 수동 검증과 원격 CI는 공개 릴리스 전 남은 gate다.
