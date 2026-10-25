# Phase 33.4B — 공개 사례·보고서 개인정보 projection

## 판정과 배경

Phase 33.4A의 정확한 시작 커밋 `c70a8190f62bfff7f6c12069ba38a9ccb15fe5fa` push run [40160045789](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40160045789)은 `completed/success`였다. Ubuntu 전체 회귀 2,662 passed·2 warnings, locked 설치, bounded Schemathesis 6 passed·2 warnings, Chromium/axe 14 state의 빈 위반 결과와 외부 요청 0건을 확인했다. 저장 artifact는 0개였고 v0.4.0 Release target도 기존 릴리스 커밋이었다.

33.4A 기록의 `NO_GO` 원인은 실제 합성 application·SSH·access 업로드 응답에서 사례 대상 필드에 원래 IP가 반환된 것이었다. 테스트 우선으로 이 production upload→analysis→case/report 경로를 통과하는 회귀를 먼저 추가했다. 수정 전 테스트는 `cases[].subject`에 합성 IPv4가 그대로 나타나 실패했다. 이후 공개 대상 필드, HTML report와 UI projection을 응답 한정 별칭으로 변경했다.

## Projection과 계약 migration

- `analyze()` 결과와 case assembly의 trusted 내부 식별자는 기존 탐지·상관분석 연결에 필요한 동안 유지한다.
- `/api/v1/investigations`와 `/api/v1/investigations/sample`은 공개 schema를 1에서 2로 올렸다. 사례, timeline, 독립 관찰의 `subject`가 제거되고 `subject_alias`가 추가됐다. Deprecated `/api/analyze`도 response `schema_version=2`를 포함하며 `results[*].ip` 대신 `subject_alias`를 사용한다.
- 별칭은 공개 projection의 기존 정렬에서 처음 만난 정규화 source 주소마다 `대상 A`, `대상 B` 형식으로 만든다. 같은 응답 안에서 사례·timeline·독립 관찰은 같은 주소에 같은 별칭을 쓴다. 별칭에는 source 주소, 일부 문자열 또는 source hash가 들어가지 않는다. 응답 밖에서 안정된 대상 식별자가 아니며 영구·전역 ID가 아니다.
- 응답 모델을 closed schema로 유지한다. 탐지·관계·위험도·신뢰도·사례 개수, 연결, 순서, 의미는 변경하지 않는다.
- 기존 schema 1 소비자는 명시적인 schema 2 migration이 필요하다. `subject`/`ip` 이름을 유지한 채 값만 별칭으로 바꾸지 않았다.

HTML report의 review table, disclosure summary와 heading은 별칭을 표시하고 “공개용 안전 요약이며 원본 식별자는 포함하지 않습니다.” 안내를 포함한다. 원래 filename, path, account, IP, hostname과 raw line은 HTML text/attribute/comment/hidden element에 포함하지 않는다. HTML escaping과 CSP를 유지한다. 분석 결과는 침해 성공이나 확정 사고를 뜻하지 않는 기존 한계를 그대로 표시한다.

Schema 2 단일 source 및 schema 3 multi-source status/SSE는 기존 공개 aggregate만 보내며 source identity를 담지 않는다. Phase 33.4 lexical guidance는 공개 사례의 승인된 scalar만 가져가고 corpus, retrieval, citation 검증을 변경하지 않았다. 도움말 전후의 분석 상태는 동일하다. Embedding, LLM, Gemini는 연결하거나 호출하지 않는다.

원래 IP가 필요한 실제 대응 detail은 이번 공개 projection 범위가 아니다. 인증·권한·감사 기록을 갖춘 별도 trusted detail 기능으로 설계해야 한다.

## 검증

수정 전 real endpoint regression은 `cases[].subject`에서 synthetic IPv4를 확인해 실패했다. 수정 후 focused privacy/API/report/UI/guidance, single/multi-source SSE, citation/refusal/stale/corpus/citation-failure, UTC 반복결정성, UI validator/Chromium/axe와 전체 회귀를 실행한다. 합성 분석 79/79·Linux 21/21·risk/case 70/70은 기존 deterministic evaluation으로 별도 실행한다.

새 커밋 SHA의 원격 Ubuntu CI는 이번 문서 작성 시점에 실행 전이다. 따라서 최종 판정은 **CONDITIONAL_GO**이며 그 CI 성공 전에는 최종 GO가 아니다. Safari 18.6 수동 검수도 **NOT_TESTED**이고 Phase 33.4C로 남긴다. 자동 Chromium 결과를 Safari 검수로 대체하지 않는다.

## 남은 한계

Aliases are presentation labels, not anonymization guarantees. Counts and ordering may still reveal aggregate structure. Trusted internal state, debugger access, memory dumps, malformed infrastructure logs outside the application boundary, and user-provided source data remain outside this public projection contract. This phase does not add an authenticated original-identifier view.
