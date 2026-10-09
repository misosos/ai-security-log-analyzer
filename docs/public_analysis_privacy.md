# Trusted analysis와 공개 출력의 개인정보 경계

## 범위와 위협 모델

`analyze()`의 반환값은 trusted internal result다. 탐지 대상 membership, 인증 상관분석의 동일 계정 확인, closest-success 선택, 위험도 context와 case adapter의 일시적 join에는 원래 계정이 필요할 수 있다. 이 내부 dictionary는 공개 DTO가 아니며 직접 출력하거나 `repr()`, `pprint`, 범용 JSON/Pydantic serializer, logger 또는 예외 메시지에 전달해서는 안 된다. 신뢰된 내부 소비자는 기존 계산 의미를 유지한다.

방어하는 경로는 API·CLI·HTML·LLM prompt·평가 text/JSON·OpenAPI·오류와 application log 같은 사용자 경계다. 공개 경계는 원문을 삭제하는 후처리 regex가 아니라 승인 필드만 새 객체에 복사하는 projection을 사용한다. 원래 계정, 원래 HTTP path, full query, raw correlation/risk dictionary, raw log와 Linux Audit private detail은 공개 모델에 넣지 않는다.

내부 result를 명시적으로 열람하는 개발자, debugger, memory dump, 악성 내부 코드, 원본 업로드 자체는 범위 밖이다. Python 메모리의 secure erasure를 보장하지 않는다. 이 변경은 암호화, 완전 익명화, 규정 준수 또는 hosted multi-tenant 보호가 아니다. 인증 없는 실제 로그의 public internet 노출은 계속 no-go다.

## Deprecated legacy API와 migration

`POST /api/analyze`는 제거하지 않고 OpenAPI `deprecated` 및 `Deprecation: true` 응답 헤더를 제공한다. 상위 `analysis_id`, `status`, `summary`, `results`, `global_correlation`, `ai_summary` 경로는 유지한다. `analysis_id`는 영구 저장 ID가 아닌 고정 `not-persisted`다.

변경 전에는 중첩 `correlation`, `risk_factors`, `detections`, `global_correlation`이 trusted raw dictionary를 포함할 수 있었다. 변경 후 `results[*].detections`는 지원 타입별 탐지 여부·승인된 수치·패턴·HTTP method/status/size, `correlation`은 승인 relation type·UTC endpoint·delta·계정 비표시 안내, `risk_factors`는 기존 level/confidence와 고정 limitation만 가진다. `global_correlation`은 승인된 네 범주의 count와 고정 limitation만 가진다. 원래 계정·원래 HTTP path·full query·raw rationale는 없다. Unknown/malformed input은 고정 오류로 실패하며 0건으로 위장하지 않는다.

이는 의도적인 nested-value breaking change다. raw `target_users`, `user`, `risk_factors.account_context`, `global_correlation` record의 exact 값에 의존하는 소비자는 안전 필드로 migration해야 한다. 예를 들어 계정 목록 대신 `target_account_count`, 원문 계정 relation endpoint 대신 `account_reference_available=false`와 `account_notice`를 사용한다. 새 개발은 versioned `POST /api/v1/investigations`를 사용한다. 이 deprecation은 legacy endpoint가 hosted/public upload에 안전하다는 뜻이 아니다. Sunset 날짜는 정하지 않았다.

## HTML·CLI·LLM

기존 대상별 HTML 보고서의 Path Traversal 근거는 승인 pattern, method, status, response size를 보존하지만 모든 원래 HTTP path와 full query를 제거한다. “요청 경로”는 고정 개인정보 보호 안내로 표시한다. 기존 report-local 계정 별칭, 6열 표, standalone HTML, no JavaScript/remote resource와 검증된 CSP style hash는 유지한다. CLI는 원문 계정·path/query·무검증 rationale를 출력하지 않는다. LLM prompt는 raw internal result가 아닌 explicit safe projection만 받는다. 평가 runner와 versioned API는 기존의 공개 allowlist 경계를 유지한다.

## 남은 한계

Trusted internal dictionary의 직접 `repr(raw_result)`은 원문을 노출할 수 있다. 개발자는 이를 로그·exception·테스트 실패 diff·진단 preview에 넣지 않아야 한다. Legacy upload 자체는 기존 whole-file read와 suffix 검사를 유지하므로 public/hosted upload로 사용하지 않는다. 새로운 versioned local endpoint의 loopback·bounded upload 계약과 혼동하지 않는다.
