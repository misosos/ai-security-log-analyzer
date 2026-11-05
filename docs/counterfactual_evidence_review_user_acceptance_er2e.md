# ER-2E — Counterfactual Evidence Review 사용자 수용 체크리스트

이 양식은 ER-2D-C의 고정 합성 평가 화면을 사람이 직접 확인하기 위한 것입니다. 검토 결과는 실제 보안 사건, 운영 탐지 정확도 또는 공격 성공 여부에 관한 판단이 아닙니다.

## 검수 기록

- 실행 환경 / 브라우저 버전:
- 화면 크기 및 확대 비율:
- 날짜 및 검수자 기록(선택):
- 사용한 코드 SHA:
- 사용한 자료: 고정 합성 Snapshot만

각 항목의 기본 상태는 `NOT_TESTED`입니다. 실제로 해본 뒤 `PASS` 또는 `FAIL`로 바꾸고 관찰 내용, 재현 방법, 화면 캡처 필요 여부를 기록합니다. 검수자 신원이나 화면 캡처가 포함된 응답 원본은 공개 저장소에 커밋하지 않습니다.

## Desktop Safari

| 확인 항목 | 상태 | 관찰 내용 | 재현 방법 | 화면 캡처 |
|---|---|---|---|---|
| Evaluation 화면 진입 | NOT_TESTED |  |  | 필요 여부 기록 |
| Summary 가독성 | NOT_TESTED |  |  | 필요 여부 기록 |
| 여섯 Comparison 분포 이해 | NOT_TESTED |  |  | 필요 여부 기록 |
| Scenario 검색·필터·정렬 | NOT_TESTED |  |  | 필요 여부 기록 |
| Scenario 상세와 목록 복귀 | NOT_TESTED |  |  | 필요 여부 기록 |
| 기존 조사 화면으로 이동·복귀 | NOT_TESTED |  |  | 필요 여부 기록 |
| Snapshot 재확인 결과 반영 | NOT_TESTED |  |  | 필요 여부 기록 |

## 좁은 화면 및 확대

| 확인 항목 | 상태 | 관찰 내용 | 재현 방법 | 화면 캡처 |
|---|---|---|---|---|
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

## Security UX 및 의미

| 확인 항목 | 상태 | 관찰 내용 | 재현 방법 | 화면 캡처 |
|---|---|---|---|---|
| `합성 평가 전용 · 실제 보안 사건 아님` 안내가 보임 | NOT_TESTED |  |  | 필요 여부 기록 |
| 사람 검토 `INDEPENDENT_HUMAN_REVIEW_PENDING` 표시 | NOT_TESTED |  |  | 필요 여부 기록 |
| 운영 상태 `NOT_APPROVED` 표시 | NOT_TESTED |  |  | 필요 여부 기록 |
| LOST/GAINED/미탐지를 공격·안전 확정으로 오해하지 않음 | NOT_TESTED |  |  | 필요 여부 기록 |
| 검증 오류 시 이전 Snapshot 결과가 제거됨 | NOT_TESTED |  |  | 필요 여부 기록 |
| 실제 사건 목록과 분리된 평가 화면임을 이해함 | NOT_TESTED |  |  | 필요 여부 기록 |

## 문제 기록

각 `FAIL` 또는 `NOT_TESTED` 항목에 대해 Scenario/화면, 조작 순서, 기대 결과, 실제 결과, 재현 여부와 안전한 합성 화면 캡처 필요 여부를 적습니다. 오류 메시지에 실제 자료, 계정, IP, 내부 경로 또는 예외 내용이 보이면 원문 자료를 복사하지 말고 해당 사실만 기록합니다.

이 체크리스트가 완료되어도 별도의 독립 Label 검토나 운영 승인을 자동으로 부여하지 않습니다.
