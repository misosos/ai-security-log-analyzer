# Phase 8 웹 요청 관찰 계약

확인일: 2026-10-10. 네 유형은 **요청 로그에서 관찰 가능한 신호**이며 공격 성공, 데이터 유출, 코드 실행, 브라우저 실행, 악의적 의도 또는 침해 확정이 아니다. 상용 WAF/CRS를 대체하지 않는다.

## 근거와 관찰 가능 범위

| 공식 출처 | 설계에 반영한 관찰 | 이 로그만으로 확인 불가 |
| --- | --- | --- |
| [OWASP WSTG SQL Injection](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection/) | 요청 입력의 SQL-like 복합 구문을 조사 후보로 분류 | SQL 실행, 데이터 접근 |
| [OWASP WSTG Reflected XSS](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/01-Reflected_Cross_Site_Scripting/) | URI·매개변수의 삽입-like 구문과 percent encoding 고려 | 응답 반사, 저장, 브라우저 실행 |
| [OWASP WSTG Backup/Unreferenced Files](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information/) | 설정·버전관리·백업 범주의 요청을 별도 관찰 | 리소스 존재·내용 노출 |
| [OWASP Automated Threats](https://owasp.org/projects/automated-threats-to-web-applications), [MITRE T1595](https://attack.mitre.org/techniques/T1595/) | 여러 대상에 대한 짧은 요청열은 scanning-like 행동의 후보 | 도구 사용·승인 여부·공격자 신원 |

외부 자료는 taxonomy와 조사 필요성을 뒷받침한다. 아래 6/6/3/60 임계값은 OWASP·MITRE의 규범값이 아니라 이 프로젝트의 **작은 합성 corpus에서 정한 정책**이다. CRS 규칙이나 라이선스가 불명확한 rule corpus를 복사하지 않았다.

## 파이프라인과 원래 데이터 경계

NCSA access parser는 `urlsplit`으로 request target을 path/query로 나누지만 percent decoding, `+` 공백 변환, Unicode 정규화, query parameter 분해를 하지 않는다. `NormalizedEvent.raw`와 `HttpContext.path/query`는 trusted internal 입력에 남는다. 기존 Path Traversal은 반복 `unquote`로 path/query의 `../` 또는 `..\\`를 검사하며 이 의미를 바꾸지 않았다. Phase 8 웹 helper는 새 네 유형에만 적용된다. subject는 source IP, timestamp는 access line의 명시적 timezone을 UTC로 정규화한다. method/status는 원문 로그의 관찰 필드지만 성공 판정은 아니다.

새 helper는 target 길이 2048자, decoded 길이 2048자, subject당 입력 4096 event로 제한한다. 유효한 `%HH`만 허용하고 strict UTF-8 `unquote`를 최대 3개 encoding layer까지 적용하며 4번째 확인 pass가 안정적이어야 한다. 잘못된 percent/UTF-8, control/NUL, 초과 길이는 non-match이며 공격으로 추측하지 않는다. ASCII 대소문자만 접고 `+`는 literal로 유지하며 Unicode normalization은 하지 않는다. parser에 stable ingestion ID가 없으므로 원본 요청을 동일 timestamp·target·status 또는 동일 raw line이라는 이유로 제거하지 않는다. raw target은 탐지 근거에 저장하지 않고 고정 pattern ID·횟수·시간만 저장한다. 다른 의미의 유형은 같은 요청에서 함께 보존하며 입력 순서로 하나를 선택하지 않는다.

| 유형 | pattern ID | 정확한 의미·오탐 경계 |
| --- | --- | --- |
| SQL Injection-like | `SQLI_BOOLEAN_EXPRESSION`, `SQLI_UNION_SELECT`, `SQLI_COMMENT_SEQUENCE` | query의 quote+boolean 숫자 비교, UNION+SELECT, quote+SQL 단어+주석 같은 복합 신호. 단일 SQL 단어·quote·주석은 불충분. DB 종류와 실행은 추측하지 않음 |
| XSS-like | `XSS_SCRIPT_ELEMENT`, `XSS_EVENT_HANDLER`, `XSS_SCRIPT_SCHEME` | query의 script 요소, 태그+event handler, script scheme. 단일 `<`, `script` 단어, asset 이름은 불충분. 응답 본문이 없어 XSS 유형·실행은 모름 |
| Sensitive Resource Probing-like | `SENSITIVE_ENV_FILE`, `SENSITIVE_VCS_METADATA`, `SENSITIVE_CONFIG_FILE` | `.env`, `.git` metadata, 백업/설정 확장자 범주의 특정 요청. `/admin` 한 건·일반 문서는 불충분. 200/404/500 모두 파일 존재·유출을 뜻하지 않음 |
| Web Scanning-like | `WEB_SCAN_DISTINCT_TARGETS` | 같은 IP에서 60초 이내 요청 6건, 서로 다른 canonical target 6개, 4xx 3건 이상을 모두 요구. client-error burst는 **필수** 보조 조건. 단일 404·일반 asset burst는 불충분 |

동일 유형 안에 여러 category가 있으면 첫 시각, 고정 pattern 우선순위의 category 하나와 실제 matching request event 수를 출력한다. 하나의 request가 같은 유형의 여러 pattern에 맞아도 그 유형의 `request_count`에는 한 번만 센다. 이는 per-subject `DetectionResult` 한 슬롯의 현재 구조 때문이다. 같은 request의 서로 다른 유형은 각각 출력된다. Scanning의 `request_count`는 선택된 창 안의 eligible request event 수로, 같은 canonical target·시각·raw line의 반복도 각각 센다. `distinct_target_count`만 canonical `(path, query)`의 서로 다른 수다. 두 count의 의미는 다르며 원문 대상 목록·hash는 공개하지 않는다. 최종 Scanning observation은 subject당 한 건만 생성한다.

Scanning은 canonical UTC로 정렬한 뒤 **가장 이른 적격 시작점에서 끝까지 포함되는 최대 60초 창**을 선택한다. 그 창이 6/6/3을 충족하면 전체 창의 count·첫/마지막 시각을 하나의 집계 관찰로 내고 중첩 창은 추가 생성하지 않는다. 첫 시작점이 미달이면 다음 시작점을 시도한다. 60초 정확한 경계는 포함하고 60초+1µs는 제외한다. 동일 시각의 요청은 집계상 별도 이벤트이며 입력 순서에 좌우되지 않는다. naive timestamp·시간 없는 요청은 새 웹 helper의 eligible request가 아니다. microsecond는 내부 normalized event에서 유지되며 파일 parser 시각은 초 단위다. 이 창 선택은 프로젝트의 결정적 집계 정책이지 외부 표준의 임계값이 아니다.

## Risk, 사례, 공개 출력

SQLi/XSS/sensitive 관찰만 있을 때 likelihood MEDIUM·impact LOW→risk MEDIUM; scanning만 있으면 likelihood LOW·impact LOW→risk LOW다. confidence는 관찰 신호의 명료도인 MEDIUM이며 침해 확률이 아니다. 기존 Path Traversal·인증 risk 우선순위와 60초 인증 상관 창은 그대로다. 새 자동 관계나 case rule은 없다. 네 유형은 모두 **독립 관찰**이며 인증·Path Traversal 사례 또는 다른 웹 관찰에 IP만으로 합쳐지지 않는다.

Incident adapter는 각 새 detection의 exact typed evidence를 검증하고 frozen projection에 승인 scalar만 복사한다. Versioned API, deprecated legacy API, CLI, HTML, 웹 UI는 fixed display name, 한국어 category, count/window, risk/confidence, 고정 한계·다음 단계를 표시한다. 원래 path/query·parameter 값·request line·raw log·target hash·account·credential·cookie·token·internal repr은 어떤 사용자 경계에도 전달하지 않는다. Unknown evidence/type은 partial render가 아니라 고정 오류로 실패한다. HTML은 기존 대상별 6열 표·standalone·no JavaScript/remote resource·동일 CSP style hash를 유지한다. LLM은 기본 호출하지 않으며 선택적 prompt에도 승인 projection만 허용한다.

## 평가와 남은 공백

기존 43개 ID를 변경하지 않고 Phase 8의 34개 시나리오에 서로 다른 Scanning 양성 경계 2개를 보강해 총 **79개**다. Scanning 양성 support=3은 정확한 6/6/3, 7/7/4 초과, 정확한 60초 경계를 별도 라벨로 센다. 반전·permutation, 60초+1µs, 동일 요청 반복은 단위 불변식이며 confusion-matrix support를 늘리지 않는다. negative는 요청 수·고유 대상·4xx 조건 및 정상 asset burst를 분리한다. `uv run python -m app.evaluation`으로 재현한다. 이 corpus의 TP/FP/FN/TN은 구현과 **포함된 라벨**의 일치도이며 실제 운영환경 탐지율이 아니다. Scanning positive support는 여전히 작다. 실제 앱의 query 문맥, 승인된 스캐너, CDN/NAT, 방어 장비 재작성, Unicode·encoding 다양성, 로그 누락, 응답 본문·DB 감사는 평가하지 않는다. 향후 Linux Audit와의 typed 관계도 구현하지 않았다.
