# ER-2E — Counterfactual Evidence Review 사용자 수용 체크리스트

이 양식은 ER-2D-C의 고정 합성 평가 화면을 사람이 직접 확인하기 위한 것입니다. 검토 결과는 실제 보안 사건, 운영 탐지 정확도 또는 공격 성공 여부에 관한 판단이 아닙니다.

## ER-2F 검수 준비 기록

- 준비 기준 SHA: `e87099c4aa00bae2ad6ec893504ca3fb9cc34f61`
- Exact CI: `42189370675`, `push / completed / success`, Artifact 0개
- 자동 준비 검증: Chromium/WebKit Workspace와 Evaluation Viewer, axe, 전체 pytest 및 Evaluation Runner 성공
- 설치 확인: macOS Safari 18.6
- 실제 Desktop Safari, VoiceOver, iPhone/iPad 및 사용자 이해도 검수: `NOT_TESTED`
- 준비 판정: `ER_2F_ACCEPTANCE_PREPARATION_LOCAL_CONDITIONAL_GO`
- 사용자 수용 상태: `ER_2F_USER_ACCEPTANCE_PENDING`

자동 브라우저 검증 결과를 아래 수동 항목의 PASS로 전환하지 않습니다.

## ER-2F Desktop Safari 사용자 피드백 기록

- 검수 기준 SHA: `c56fd375b0bcb8effc03a51cc772a7e916b7fb04`
- Exact CI: `42199657196`, `push / completed / success`, Artifact 0개
- 사용자 피드백: “다 괜찮은것같아.”
- 확인 범위: 합성 평가 화면의 디자인과 가독성, Summary 및 Comparison 정보 이해도, 검색·필터·정렬·상세 보기 사용성, 사용자가 직접 창 크기를 변경했을 때의 UI 표시
- 범위 판정: 위 네 가지 Desktop Safari 항목은 `PASS`
- 전체 판정: Keyboard, 정확한 viewport별 반응형 측정, VoiceOver, 모바일 실기기, 기존 Investigation 왕복 및 장애 상태가 남아 있어 `ER_2F_USER_ACCEPTANCE_PENDING`

이 기록은 사용자가 제공한 정성적 피드백 범위에 한정한다. 조작 횟수, 정확한 창 크기, 확대 비율, 성능 수치 또는 별도로 언급되지 않은 기능의 PASS를 추정하지 않는다. Playwright WebKit 자동 검증과 실제 Safari 사용자 피드백도 서로 다른 증거로 유지한다.

## Safari 검수 환경

현재 checkout에서 다음 명령으로 명시적인 Evaluation ON 서버를 시작합니다. 일반 Local Launcher의 기본값은 계속 OFF입니다.

```bash
uv run python -c 'import uvicorn; from app.api import create_app; uvicorn.run(create_app(enable_evidence_review_viewer=True, evidence_review_port=8000), host="127.0.0.1", port=8000, workers=1, proxy_headers=False, reload=False)'
```

Safari에서 `http://127.0.0.1:8000/`을 열고 `합성 평가` 메뉴를 선택합니다. 고정 합성 Snapshot만 사용하며 실제 사용자 로그를 붙여 넣지 않습니다. 검수가 끝나면 터미널에서 `Ctrl+C`로 서버를 종료합니다.

## 검수 기록

- 실행 환경 / 브라우저 버전: macOS Safari 수동 확인; 설치 확인 버전 18.6
- 화면 크기 및 확대 비율: 사용자가 창 크기 변경 후 긍정적으로 평가; 정확한 수치 및 확대 비율은 `NOT_TESTED`
- Safari 키보드 탐색 설정: `NOT_TESTED`
- 날짜 및 검수자 기록(선택): 2026-11-06, 식별 정보 미기록
- 사용한 코드 SHA: `c56fd375b0bcb8effc03a51cc772a7e916b7fb04`
- 사용한 자료: 고정 합성 Snapshot만

각 항목의 기본 상태는 `NOT_TESTED`입니다. 실제로 해본 뒤 `PASS` 또는 `FAIL`로 바꾸고 관찰 내용, 재현 방법, 화면 캡처 필요 여부를 기록합니다. 검수자 신원이나 화면 캡처가 포함된 응답 원본은 공개 저장소에 커밋하지 않습니다.

## Desktop Safari

| 확인 항목 | 상태 | 관찰 내용 | 재현 방법 | 화면 캡처 |
|---|---|---|---|---|
| Evaluation 화면 진입 및 디자인·가독성 | PASS | 사용자가 실제 Safari 화면을 확인하고 긍정적으로 평가 | 합성 평가 화면 확인 | 미요청 |
| Summary 가독성 | PASS | Summary 정보 이해도에 대한 긍정적 피드백 | Summary 확인 | 미요청 |
| 여섯 Comparison 분포 이해 | PASS | Comparison 정보 이해도에 대한 긍정적 피드백 | Comparison 영역 확인 | 미요청 |
| Scenario 검색·필터·정렬 | PASS | 검색·필터·정렬 사용성에 대한 긍정적 피드백 | Scenario 탐색 | 미요청 |
| Scenario 상세 보기 | PASS | 상세 보기 사용성에 대한 긍정적 피드백 | Scenario 상세 확인 | 미요청 |
| Scenario 상세에서 목록 복귀 | NOT_TESTED | 별도 피드백 없음 |  | 필요 여부 기록 |
| 기존 조사 화면으로 이동·복귀 | NOT_TESTED |  |  | 필요 여부 기록 |
| Snapshot 재확인 결과 반영 | NOT_TESTED |  |  | 필요 여부 기록 |

수치 확인 기준은 Development 16건, Holdout 14건, 전체 30건, 비교 가능 24건, 비교 제외 6건입니다. Comparison 분포는 `PRESERVED 7`, `LOST 10`, `GAINED 5`, `UNCHANGED_ABSENT 2`, `INCOMPARABLE 6`, `UNDETERMINED 0`입니다. 이 값은 현재 고정 합성 Snapshot의 구성이고 운영 성능 지표가 아닙니다.

## Scenario 탐색

| 확인 항목 | 상태 | 관찰 내용 | 재현 방법 | 화면 캡처 |
|---|---|---|---|---|
| Scenario ID 검색 | NOT_TESTED |  |  | 필요 여부 기록 |
| Corpus 필터 | NOT_TESTED |  |  | 필요 여부 기록 |
| Detector 필터 | NOT_TESTED |  |  | 필요 여부 기록 |
| Comparison 필터 | NOT_TESTED |  |  | 필요 여부 기록 |
| 정렬 및 결정적인 순서 | NOT_TESTED |  |  | 필요 여부 기록 |
| 필터 초기화 | NOT_TESTED |  |  | 필요 여부 기록 |
| Scenario 상세와 `ER-1D 설명 자료 없음` 안내 | NOT_TESTED |  |  | 필요 여부 기록 |
| 목록 복귀 | NOT_TESTED |  |  | 필요 여부 기록 |

## 좁은 화면 및 확대

| 확인 항목 | 상태 | 관찰 내용 | 재현 방법 | 화면 캡처 |
|---|---|---|---|---|
| 사용자가 직접 창 크기를 변경했을 때 UI 표시 | PASS | 창 크기 변경 시 UI 표시에 대한 긍정적 피드백 | 정확한 폭 미측정 | 미요청 |
| 1440px 폭 | NOT_TESTED |  |  | 필요 여부 기록 |
| 1024px 폭 | NOT_TESTED |  |  | 필요 여부 기록 |
| 768px 폭 | NOT_TESTED |  |  | 필요 여부 기록 |
| 390px 폭 | NOT_TESTED |  |  | 필요 여부 기록 |
| 320px 폭 | NOT_TESTED |  |  | 필요 여부 기록 |
| 200% 확대 또는 동등한 reflow | NOT_TESTED |  |  | 필요 여부 기록 |
| 긴 Scenario ID·Reason Code 줄바꿈 | NOT_TESTED |  |  | 필요 여부 기록 |
| 필터 결과 없음 및 오류 상태 가독성 | NOT_TESTED |  |  | 필요 여부 기록 |

## Keyboard

| 확인 항목 | 상태 | 관찰 내용 | 재현 방법 | 화면 캡처 |
|---|---|---|---|---|
| Tab으로 Evaluation Navigation 이동 | NOT_TESTED |  |  | 필요 여부 기록 |
| Enter로 진입·Scenario 열기 | NOT_TESTED |  |  | 필요 여부 기록 |
| 검색·필터 조작 | NOT_TESTED |  |  | 필요 여부 기록 |
| Escape로 상세 닫기 | NOT_TESTED |  |  | 필요 여부 기록 |
| 상세를 닫을 때 Scenario 버튼에 Focus 복원 | NOT_TESTED |  |  | 필요 여부 기록 |
| 화면을 나갔다 다시 열 때 Focus 상태 초기화 | NOT_TESTED |  |  | 필요 여부 기록 |

Safari 설정에 따라 Tab 탐색 범위가 달라질 수 있습니다. 검수 전에 설정을 임의로 바꾸지 말고 현재 설정을 위 검수 기록에 적습니다.

## 기존 Investigation 왕복 흐름

실제 사용자 로그 대신 저장소의 합성 Sample Analysis만 사용합니다.

| 확인 항목 | 상태 | 관찰 내용 | 재현 방법 | 화면 캡처 |
|---|---|---|---|---|
| 시작 화면으로 이동 | NOT_TESTED |  |  | 필요 여부 기록 |
| 합성 Sample Analysis 실행 및 결과 표시 | NOT_TESTED |  |  | 필요 여부 기록 |
| 검토 사례 상세와 개요 확인 | NOT_TESTED |  |  | 필요 여부 기록 |
| 활동 흐름 확인 | NOT_TESTED |  |  | 필요 여부 기록 |
| 확인할 작업 확인 | NOT_TESTED |  |  | 필요 여부 기록 |
| 근거와 한계 확인 | NOT_TESTED |  |  | 필요 여부 기록 |
| 목록 복귀 후 Evaluation 재진입 | NOT_TESTED |  |  | 필요 여부 기록 |
| Evaluation 수치가 Investigation 건수에 합산되지 않음 | NOT_TESTED |  |  | 필요 여부 기록 |

## VoiceOver 및 모바일 실기기

| 확인 항목 | 상태 | 관찰 내용 | 재현 방법 | 화면 캡처 |
|---|---|---|---|---|
| VoiceOver가 제목과 landmark를 읽음 | NOT_TESTED |  |  | 필요 여부 기록 |
| Evaluation 메뉴와 검색창 이름을 읽음 | NOT_TESTED |  |  | 필요 여부 기록 |
| Radio group 이름과 선택 상태를 읽음 | NOT_TESTED |  |  | 필요 여부 기록 |
| Scenario 상세 이동과 오류 상태를 읽음 | NOT_TESTED |  |  | 필요 여부 기록 |
| 목록 복귀 동작을 이해할 수 있음 | NOT_TESTED |  |  | 필요 여부 기록 |
| 실제 iPhone/iPad Safari | NOT_TESTED |  |  | 필요 여부 기록 |

VoiceOver나 모바일 실기기를 실제로 사용하지 않았다면 해당 항목은 `NOT_TESTED`로 유지합니다. 자동 axe 또는 WebKit 결과를 이 항목의 PASS 근거로 사용하지 않습니다.

## Security UX 및 의미

| 확인 항목 | 상태 | 관찰 내용 | 재현 방법 | 화면 캡처 |
|---|---|---|---|---|
| `합성 평가 전용 · 실제 보안 사건 아님` 안내가 보임 | NOT_TESTED |  |  | 필요 여부 기록 |
| 사람 검토 `INDEPENDENT_HUMAN_REVIEW_PENDING` 표시 | NOT_TESTED |  |  | 필요 여부 기록 |
| 운영 상태 `NOT_APPROVED` 표시 | NOT_TESTED |  |  | 필요 여부 기록 |
| LOST/GAINED/미탐지를 공격·안전 확정으로 오해하지 않음 | NOT_TESTED |  |  | 필요 여부 기록 |
| 검증 오류 시 이전 Snapshot 결과가 제거됨 | NOT_TESTED |  |  | 필요 여부 기록 |
| 실제 사건 목록과 분리된 평가 화면임을 이해함 | NOT_TESTED |  |  | 필요 여부 기록 |

Snapshot 오류 시 이전 결과 제거는 자동 회귀가 보호합니다. 수동 검수자는 Snapshot 파일이나 Trusted Pin을 변조하지 않습니다.

## 결함 분류

FAIL은 `SECURITY_BLOCKER`, `FUNCTIONAL_FAILURE`, `ACCESSIBILITY_FAILURE`, `RESPONSIVE_FAILURE`, `USABILITY_IMPROVEMENT`, `DOCUMENTATION_ISSUE` 중 하나로 분류합니다. 화면, 조작 순서, 기대 결과, 실제 결과, Safari 버전, 화면 크기와 재현 가능 여부를 기록합니다.

## 문제 기록

각 `FAIL` 또는 `NOT_TESTED` 항목에 대해 Scenario/화면, 조작 순서, 기대 결과, 실제 결과, 재현 여부와 안전한 합성 화면 캡처 필요 여부를 적습니다. 오류 메시지에 실제 자료, 계정, IP, 내부 경로 또는 예외 내용이 보이면 원문 자료를 복사하지 말고 해당 사실만 기록합니다.

이 체크리스트가 완료되어도 별도의 독립 Label 검토나 운영 승인을 자동으로 부여하지 않습니다.
