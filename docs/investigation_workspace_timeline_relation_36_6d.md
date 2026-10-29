# Phase 36.6D — 활동 흐름 Timeline과 Relation 이식

## 시작 gate와 범위

시작 SHA `3a081c9a135535b93ed206fe13dd65efba77ddc9`에서 작업을 시작했다. branch는 `main`, 시작 worktree는 clean, local/remote `main`과 `HEAD`가 동일했고 ahead/behind는 0/0이었다. exact-SHA push run `40818811785`는 `completed/success`, artifact 0개였다. required pytest, locked 설치, Linux TCP Syslog·JSONL·restricted report, Chromium·axe, tracked-file 검사가 통과했다. `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`이다.

이 단계는 production 상세 화면에 접근 가능한 활동 흐름과 비인과적 관계 표시만 추가한다. 확인할 작업 상세, citation/evidence disclosure, checklist 결과 UI, backend/API/schema, 분석 pipeline, HTML report, SSE, checkpoint/publication, prototype asset 및 기존 renderer 제거는 범위 밖이다. rollback switch `USE_WORKSPACE_DETAIL_SHELL_36_6B`를 유지한다.

## 입력 데이터와 adapter 계약

입력은 이미 검증된 동일한 공개 analysis response snapshot의 case timeline이다. 공개 timeline validator는 허용된 case 필드, category enum, category label, timestamp, 기존 sequence, case alias 연결 및 relation count를 확인한다. 서버가 만든 sequence를 UI에서 재정렬하지 않는다. 동일 시각 tie-break도 원래 sequence 그대로 유지한다.

`investigation-workspace-ui/v1`의 기존 19개 필드는 변경하지 않았다. 별도 내부 adapter가 `investigation-workspace-timeline-ui/v1`의 immutable snapshot을 만든다. adapter는 case reference, 표시 순서, 관찰/탐지/관계 유형, 안전한 고정 제목·설명, 검증된 KST/UTC timestamp만 보유한다. 원문 fact, evidence, alias, parser 문구, 내부 ID는 timeline adapter에 복사하지 않는다. `fact`는 검증된 category별 고정 문구와 정확히 일치해야 하며 임의 문자열이나 canary는 공개 validator에서 거부된다.

허용 category는 기존 `OBSERVED_FACT`, `DETECTION_OBSERVATION`, `SUPPORTED_RELATION`이다. title과 detection/relation 이름은 기존 allowlist 및 고정 한국어 mapping으로 변환한다. unknown key/category, sequence 불일치·중복, case identity 불일치, timestamp 형식/순서 오류, count 불일치, category와 title/name의 모순은 일반화된 고정 오류 `WORKSPACE_TIMELINE_INVALID`로 거부한다. 시간이 없는 항목은 `시간 정보 없음`으로 표시하고 임의 시각을 만들지 않는다.

## Timeline과 relation 표현

관찰과 탐지 관찰은 기존 순서의 semantic `<ol>` 항목으로 표시하며 각각 `확인된 사실`, `탐지된 활동` label을 제공한다. 검증된 timestamp는 KST `<time datetime>`으로 렌더링한다. relation은 새 관찰 카드로 복제하지 않고 같은 ordered list 안의 구분된 inline relation 항목으로 표시한다. 텍스트 `분석상 연결 · 인과관계 미확정` 및 점선 구분을 사용하고 색상만으로 의미를 전달하지 않는다. 원인, 침해, 공격 성공을 확정하지 않는다.

개요와 활동 흐름만 tab으로 구현했다. `tablist`/`tab`/`tabpanel`, `aria-selected`, `aria-controls`, roving tabindex, 좌우 화살표 및 Home/End 이동을 제공한다. 비활성 panel은 숨기며 탭 전환은 checklist/guidance 요청이나 analysis 실행을 하지 않는다.

## TDD와 검증 결과

생산 코드 전 브라우저 계약을 추가하고 실행했을 때 `WORKSPACE_TIMELINE_VIEW_OR_CLOSED_ADAPTER_MISSING`으로 실패했다. 공개 timeline `fact` 검증의 privacy gap을 별도로 고정한 뒤 `tests/test_web_ui.py::test_renderer_logic_with_sample_contract_and_malformed_nested_data`는 canary fact를 거부하지 못해 `false !== true`로 실패했다. 고정 category 문구 계약 및 UI adapter 구현 후 해당 focused 테스트와 case summary 회귀는 `3 passed`였다.

브라우저 계약은 19필드 projection 불변, immutable timeline key 집합, snapshot/case 결합, sequence 유지, 동일 timestamp tie-break 유지, untimed 표현, observation/detection 구분, relation 중복 부재, relation 의미/count 보존, malformed 입력 거부, case 전환 격리, 만료 route, rollback renderer, 키보드/ARIA, no-call, responsive 및 canary 검사를 포함한다. `npm run test:a11y`는 Chromium 23 상태에서 axe 위반 0, 외부 요청 0으로 통과했다. Timeline 상태의 순회는 5개 입력 항목과 3개 관찰/2개 관계를 그대로 유지했다.

Dashboard→상세, back/forward, overview→timeline, stale/direct-entry, legacy renderer rollback에서 checklist POST 0, guidance 요청 0, analysis 재요청 0이었다. checklist는 기존 명시적 버튼 계약에만 남아 있다. 공개 API, SSE, HTML report, guidance, checkpoint, publication 및 분석 값에 대한 Python 회귀는 전체 pytest 범위에서 확인한다.

로컬 검증 호스트는 macOS 15.7.7 arm64였다. 이 호스트에서 TCP Syslog smoke, bounded reliability(80/80 lifecycle 첫 시도 성공, cleanup failure 0), management smoke 및 JSONL local dry-run(80 runs, leaks 0)을 실행해 통과했다. Linux 전용 `--linux-bounded`, JSONL Linux acceptance 모드, Linux-only restricted-report smoke는 macOS에서 실행하지 않았다. 시작 exact-SHA CI gate의 Linux 단계는 통과했지만 새 로컬 변경 SHA에 대한 Ubuntu CI는 아직 수행되지 않았다.

## 반응형과 접근성

Chromium CSS viewport 1440, 1024, 768, 390, 320px에서 document 및 timeline panel 가로 overflow는 0이었다. 200% equivalent text reflow에서도 새 timeline panel overflow가 없었다. Timeline 탭의 실제 hit area는 모든 검사 viewport에서 최소 44×44px였다. keyboard ArrowLeft/ArrowRight/Home/End, tab/panel 연결, semantic list 순서, `datetime`, 화면 reader용 유형 label을 확인했다. reduced-motion 설정에서는 애니메이션에 의존하는 동작을 추가하지 않았다. 이는 Chromium 자동 검증이며 Safari·실제 모바일·VoiceOver 검증이 아니다.

## 개발용 합성 benchmark

Chromium에서 warm-up 10회, 표본 100회로 측정했다. 수치는 해당 개발 환경의 관측값이며 운영 SLA가 아니다.

| 항목 수 | Adapter median/p95/max (ms) | 실제 shell render median/p95/max (ms) | 입력/adapter 출력 (bytes) | 렌더 DOM / HTML bytes |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 0.0 / 0.1 / 0.2 | 0.2 / 0.3 / 0.3 | 2,858 / 357 | 45 / 3,584 |
| 32 | 0.2 / 0.3 / 0.3 | 0.6 / 0.7 / 0.7 | 20,459 / 8,068 | 231 / 19,077 |
| 256 | 1.3 / 1.5 / 1.8 | 3.6 / 3.9 / 4.1 | 147,849 / 64,001 | 1,575 / 131,235 |

현재 5항목 timeline panel은 37 descendant DOM node, 3,514 serialized bytes였다. Overview↔timeline tab 전환은 warm-up 10회 후 100개 왕복 표본에서 median/p95/max 0.2/0.3/0.3ms였다. 전체 overview shell은 73 descendant DOM node, 6,154 HTML bytes였다. 동일 실행의 dashboard→상세 측정은 warm-up 10회, 표본 30회에서 median/p95/max 69.563/98.250/98.752ms였다. 비교 기준인 이전 상세 화면은 153 DOM node, 7,920 HTML bytes였다. 브라우저 렌더 수치는 고정 합성 입력과 측정 환경에 한정된다.

## 다음 단계와 남은 경계

Phase 36.6E는 확인할 작업·citation·근거/한계와 명시적 checklist 결과 UI를 다룬다. 36.6F는 확대·target-size 및 전체 접근성 수용을 계속 차단 기준으로 유지하고, 36.6G는 사용자 최종 수용과 기존 renderer 제거 여부를 결정한다.

Safari와 실제 모바일 기기 `NOT_TESTED`; 실제 사용자 자료·조직 운영·자동 대응 `NO_GO`; 모델 기반 AI `NOT_TESTED`; Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`이다. 기존 분석 authority와 privacy boundary는 변경하지 않았다.
