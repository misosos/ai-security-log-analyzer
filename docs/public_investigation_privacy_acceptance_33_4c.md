# Phase 33.4C — 공개 식별자 보호 수용 검수

Phase 33.4 공개 projection·별칭·lexical guidance 범위: **GO**. 최종 확인 SHA `23c3ff4e782789d5a170dc8ea7d7c3eaf5cb449a`의 Ubuntu push CI는 [run 40170482306](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40170482306)에서 `completed/success`였다. 전체 pytest는 **2667 passed, warning 2개**였고 locked 설치와 Chromium·axe 단계가 성공했다. axe는 14개 상태에서 위반 0건, 외부 요청 0건을 기록했다. 저장 artifact는 0개다. 이전 gate SHA `2fc96a896f155874cc14953a0b003303af2d2d3a`의 [run 40163159684](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40163159684)도 `completed/success`였다. Safari 실제 200% 확대, 정확한 320 CSS px 측정, 전체 페이지 VoiceOver와 Safari Web Inspector는 `NOT_TESTED`이며 WCAG 2.2 AA 준수를 의미하지 않는다.

이 기록은 CI 자동 검증과 Safari 사용자 검수를 구분한다. Chromium·axe 결과는 Safari 동작, 실제 확대, VoiceOver, 사용자 이해도를 대신하지 않는다. 자동 검사는 WCAG 2.2 AA 준수 판정이 아니다.

## 공개 계약과 migration

공개 사례 API와 legacy 분석 응답은 schema 2다. schema 1에서 사용하던 사례 `subject`와 분석 결과 `ip`는 더 이상 공개되지 않으며, 응답 안에서만 유효한 `subject_alias`로 교체됐다. 별칭은 원래 식별자가 아니다. 원래 IP·계정 복구, 응답 간 비교, 영구 저장 또는 상관 키로 사용하면 안 된다. 같은 응답 안의 동일 주체를 사례와 timeline에서 연결하는 표시용 값이다. schema 1 소비자는 schema 2를 명시적으로 지원하도록 migration해야 한다.

Trusted 내부 분석은 분석에 필요한 원래 식별자를 유지할 수 있다. 공개 API·SSE·UI·HTML report는 계정·IP·hostname·경로·raw line·rationale·내부 예외를 노출하지 않는다. schema 2·3 live status/SSE와 Phase 33.1 corpus/citation 계약은 변경하지 않았다. 도움말은 공개 safe case 값과 검증된 lexical citation만 사용하며 분석 결과를 변경하지 않는다. Embedding은 production NO_GO, Phase 33.3F local LLM은 `STORAGE_SETUP_BLOCKED` 상태다.

이번 Safari 수용 환경에서 연 HTML 보고서는 합성 사례로 생성한 검수 자료다. 이는 제품이 합성 데이터만 지원한다는 뜻이 아니다. 제품은 실제 분석 결과로도 보고서를 생성할 수 있으며, 일반 UI와 공개 보고서에는 원래 계정·IP·hostname·경로·원문 대신 응답 범위 별칭과 안전한 요약을 표시한다. 실제 사용자 자료, 기본 설정, checkpoint에는 접근하지 않았고 실제 보고서를 새로 생성하지 않았다. 원래 계정·IP가 필요한 내부 대응용 보고서는 공개 보고서와 별도다. 향후 별도 Phase에서 명시적 승인, 최소 필드, 파일 권한 `0600`, 로컬 전용 저장, 감사 기록을 갖춘 “제한된 조사 보고서”로 설계할 예정이다.

## 원격 자동 증거

| 항목 | 결과 | 근거 |
|---|---|---|
| 시작 branch/SHA/tree | PASS | `main`, 정확한 SHA, clean, origin과 behind/ahead 0/0 |
| Ubuntu locked 설치 | PASS | CI의 `uv sync --dev --locked --no-build` |
| 전체 pytest | PASS | 2665 passed, warning 2개 |
| Phase 33.4B privacy/API/report/guidance | PASS | 전체 pytest에 포함, CI 전체 단계 성공 |
| Chromium·axe | PASS | 14 states, axe 위반 0, 외부 요청 0 |
| 저장 artifact | PASS | 0개 |
| v0.4.0 Release/tag | PASS | Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`, tag object `855a92827a605805b62c627ed719958620150ec4` 유지 |

## Loopback 자동 확인

macOS에서 임시 HOME과 저장소의 합성 sample fixture를 사용하는 서버를 `127.0.0.1`에만 열었다. HTTP smoke는 schema 2 sample 응답, 사례 2개, 사례/timeline 별칭 일치, guidance `AVAILABLE` 및 citation 2개를 확인했다. guidance 전후 sample 응답은 byte-equivalent JSON이었다. OpenAPI의 사례 DTO에는 `subject_alias`만 있고 `subject`는 없다.

Phase 33.4B의 production 경로 canary 테스트는 계정, IPv4/IPv6, hostname, 파일명, 절대 경로, raw line을 application·SSH·access 합성 입력에 넣고 API JSON/repr, 사례/timeline, HTML text·속성·comment, guidance request/response와 로그 경계를 검사한다. 별칭 helper는 허용된 주소 입력만 받고, 응답 안에서 일관된 `대상 A` 형식으로 정규화 중복을 처리하며 별칭에 값·일부 문자열·hash를 인코딩하지 않는다. 서로 다른 response에서 고정 별칭이 반복되는 것은 분석 내 표시 순서가 같을 때의 비식별 표시이며 영구 ID가 아니다.

기존 분석 객체와 공개 projection 간 detection/relation/risk/case 개수·관계·순서는 기존 합성 평가와 endpoint 회귀에서 확인한다. live schema 2/3 status/SSE privacy 회귀도 전체 suite에 포함된다. 실제 browser의 network panel, OS listener/FD inventory 및 Safari DOM은 사용자가 Inspector에서 확인하기 전까지 `NOT_TESTED`다.

## Safari 수동 검수

Safari 18.6에서 합성 sample 화면을 준비했다. 아래 표는 사용자 답변을 받는 순서대로 기록한다. 응답이 없으면 `NOT_TESTED`로 남기며 자동 검사 결과로 승격하지 않는다.

| # | 확인 내용 | 상태 |
|---:|---|---|
| 1 | 합성 보고서가 공개용 안전 요약이며 원본 식별자를 포함하지 않는다는 점 이해 | PASS |
| 2 | 같은 사례의 동일 별칭이 같은 주체를 뜻함 | PASS |
| 3 | 원래 식별자 없이 활동 흐름과 위험 근거 이해 | PASS |
| 4 | HTML·DOM·속성·주석에서 민감 canary 비노출 | PASS |

사용자가 요청한 이번 수용 범위는 위 네 항목이며 모두 PASS다. 4번은 Safari 화면 확인과 함께 자동 HTML/DOM 구조 검사(텍스트, 속성, 주석 포함)로 검증했다. 정확한 320 CSS px 측정, 전체 페이지 VoiceOver, Safari Web Inspector는 수행하지 않았다. 이 문서 갱신 시점에는 최종 SHA의 원격 CI run 40170482306이 통과했다.

## 발견한 stale 도움말 결함

Safari 검수 중 사용자가 “사례 정보가 달라졌습니다. 최신 분석 결과에서 다시 선택하십시오.”라는 화면을 보고했다. API 자체는 안전한 고정 stale 상태를 반환했지만 동일한 현재 사례를 사용자가 다시 선택해도 도움말을 볼 수 없다는 production UI 결함이었다. UI case ID용 canonical JSON은 `supporting_relation_count`를 `supported_detections`·`supported_relations`보다 먼저 직렬화했으나, API는 정렬된 key 순서로 해시했다. 수정 전 production UI와 실제 loopback guidance API를 통과하는 Chromium 회귀가 실패했다. UI key 순서를 API canonical 순서와 일치시킨 뒤 회귀는 실제 citation 응답, 분석 결과 DOM 불변, 버튼 클릭 전 요청 0회·클릭 후 요청 1회를 확인했다. Corpus, citation verifier, 분석 의미는 변경하지 않았다. Safari에서 수정 후 결과는 아직 사용자가 재확인해야 한다.

## 제한

원래 IP·계정이 필요한 대응 화면은 이번 공개 projection 범위가 아니다. 이는 명시적 승인, 최소 필드, `0600` 파일 권한, 로컬 전용 저장, 감사 기록을 갖춘 별도 “제한된 조사 보고서”로 설계할 예정이다. 별칭은 응답 사이의 추적 ID로 사용할 수 없다. 이번 네 항목 밖의 Safari 확대, VoiceOver, Web Inspector 검수는 수행하지 않았다.
