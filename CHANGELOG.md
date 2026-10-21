# 변경 이력

## [0.4.0]

### 사용자 화면

- 로컬 웹 화면을 전체 폭 조사 작업 화면으로 정리했다. 왼쪽에서 시작·내 로그 분석·Linux Audit·실시간 모니터링·결과를 선택하면 오른쪽에 해당 작업만 표시한다. 사용할 수 없는 메뉴는 숨기며, 새 live 결과는 사용자가 선택할 때 적용한다.
- 예시 데이터로 둘러보기와 내 로그 분석하기를 구분하고, 현재 상태·다음 행동·결과의 의미를 쉬운 문구로 안내한다. 탐지와 관련 활동은 침해나 공격 성공의 확정으로 표현하지 않는다.
- 결과의 네 요약 지표와 두 열 조사 사례를 한눈에 비교할 수 있게 하고, 기본 사례 카드를 간결하게 만들었다. 관계·근거·KST/UTC 시각·시간순 기록은 “상세 보기”에 보존한다. 선택한 Lucide SVG만 로컬 자산으로 포함하고 외부 아이콘 서비스를 사용하지 않는다.

### 문서와 검증

- README를 처음 사용하는 사람을 위한 시작 페이지로 간소화하고 상세 문서 지도를 추가했다.
- 개발 테스트에 axe-core/Playwright의 합성 Chromium 접근성 회귀를 추가했다. 실제 Safari 18.6에서 메뉴·결과·키보드 Option+Tab·200% 확대·최소 창·VoiceOver 일부·Web Inspector를 별도로 검수했다.
- 정확한 Safari 320 CSS px와 VoiceOver 전체 페이지 읽기는 미검증이다. 자동 검사 통과는 WCAG 2.2 AA 준수 증명이 아니며 합성 평가는 운영 탐지율이 아니다. 설치는 source checkout만 지원하고 wheel/PyPI 배포는 제공하지 않는다.

## [0.3.0] - 2026-10-19

### 추가

- 한국어 설정 마법사로 단일 application 로그의 private 기본 설정을 생성하고, `--show`로 안전한 요약을 조회하거나 명시적 승인 후 `--delete`로 기본 설정을 삭제할 수 있다. `--monitor`는 기본 설정을 명시적으로 사용한다.
- Application과 SSH의 동일 파일 재시작에 bounded checkpoint replay를 제공한다. 파일 교체·축소로 중단됐을 때 `--reset-checkpoint` 승인 후 현재 EOF의 새 분석 epoch를 시작할 수 있다. 기존 설정·로그를 자동 변경하거나 삭제하지 않는다.
- 단일 SSH source의 live 탐지·실패 후 성공 관계·risk·조사 사례를 기존 batch 의미로 계산하고, application/SSH 화면에서 탐지 관찰·관계·위험도·사례를 분리해 단계적으로 표시한다.
- 개발 검증에 bounded Hypothesis 내부 property, Schemathesis API property, deterministic dependency evidence bundle을 추가했다. 이는 운영 탐지율·취약점 부재의 증명이 아니다.

### 보안과 한계

- Private 설정·checkpoint의 권한, 파일 identity, advisory lock을 확인하고 복구 불확실성은 fail closed한다. 공개 API·SSE·UI는 원래 경로·계정·IP·로그 원문 대신 안전한 projection을 사용한다. macOS와 Ubuntu 합성 검증 범위만 확인했다.
- Rotation/copytruncate 자동 복구, 두 파일 세대 replay, 다중 source, cross-source 분석, 외부 collector 연계, hosted 업로드는 지원하지 않는다. 강제 종료·전원 차단의 무유실, exactly-once, 운영 SLA도 보장하지 않는다.
- 공식 설치는 source checkout이다. Wheel/PyPI 배포와 WCAG 2.2 AA 준수를 주장하지 않는다. REA·Semgrep·Vector·OSV 실험은 제품·공식 릴리스 gate에 채택하지 않았다.

## [0.2.0] - 2026-10-14

### 추가

- 승인한 로컬 단일 source 파일을 `--monitor-config`로 지정하는 bounded 실시간 모니터링. `FROM_END`로 시작해 실행 전 기존 줄은 처리하지 않는다. Application·SSH·access 로그의 기존 parser·detector 의미를 재사용한다.
- 제한된 tail poll·queue item/byte 상한, 단일 lease·ack·release, detection proposal과 사전 검증된 commit. Application source에서는 기존 correlation·risk·case를 bounded 전체 prefix에서 재계산해 함께 commit한다. 실패 후 로그인 성공과 반복 인증 실패 후 로그인 성공 관계, 기존 위험도 평가, 결정적 조사 사례를 내부 분석과 안전한 화면 요약으로 연결한다.
- 개인정보 안전 `observation_changes`·`analysis_changes` SSE와 process-local bounded replay. 한 revision의 두 event는 사전 검증한 batch로 게시하고 event ID 순서를 공유한다. 오래된 cursor에는 explicit replay gap을 반환한다.
- 실시간 웹 영역의 탐지 관찰·지원 관계·기존 위험도 평가·조사 사례 분리, **새 결과 N건 보기** 단계적 적용, 화면 업데이트 일시 정지·재개, 수동 복구 안내. 화면 일시 정지는 서버 수집을 멈추지 않는다.
- 정상 종료에서 runner·SSE 연결·tail FD와 알려진 임시 자원을 정리한다. 기존 합성 샘플, 3파일 분석, Linux Audit 별도 흐름과 HTML 보고서는 유지한다.

### 보안과 한계

- 공개 status·SSE·DOM은 allowlist 기반 안전 projection만 사용한다. 원래 계정·IP·path/query·raw line·내부 subject key 및 원본 근거는 trusted 내부 분석에만 남을 수 있다. 탐지·관계·조사 사례는 침해·공격 성공·인과관계를 확정하지 않는다.
- Live analysis는 **단일 application source**만 지원한다. SSH/access는 detection-only이며 cross-source 관계, Linux Audit live 분석, 영구 저장, crash recovery, 여러 process 간 공유, hosted/multi-tenant 용도는 지원하지 않는다.
- Queue ack는 되돌릴 수 없는 경계이고 queue·detection·analysis·publication 전체는 원자적 transaction이 아니다. Exactly-once·운영 무유실·운영 SLA를 보장하지 않는다. Replay eviction은 gap을 만들 수 있고 재시작 시 session과 buffer가 사라진다.
- 기본 실시간 흐름에서 event마다 LLM을 호출하지 않는다. WCAG 2.2 AA 완전 준수, wheel/PyPI 설치를 주장하지 않는다. 공식 설치 경계는 source checkout이다.

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
