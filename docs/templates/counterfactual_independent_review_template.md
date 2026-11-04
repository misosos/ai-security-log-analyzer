# ER-1C-R 독립 검토 응답 양식

검토자는 가능하면 기존 Label 및 Replay 작성에 참여하지 않은 사람이어야 합니다. 기존 Label/Detector/Comparison 결과는 검토를 끝내기 전에 열람하지 마세요. 저장소에 기존 답이 공개되어 있어 완전한 기술적 블라인드는 보장되지 않습니다. 열람 여부를 정직하게 표시합니다.

검토 자료는 합성 사례만 포함합니다. 판단 대상은 입력의 관찰 패턴이며 실제 공격, 침해, 안전성 또는 운영 탐지 성능이 아닙니다. 각 Scenario ID마다 아래 블록을 복사해 작성하세요. 이름·서명·날짜는 실제 검토자가 직접 기록하며 미리 채우지 않습니다.

## 검토자 기록

- 검토자 이름: [직접 작성]
- 서명: [직접 작성 또는 조직 절차에 따라 별도 보관]
- 완료 날짜: [직접 작성]
- 독립성 선언: [기존 Label/Replay를 보지 않았음 / 보았음 / 판단 불가]
- 기존 Label 또는 Replay 열람 여부: [예 / 아니요]
- Packet SHA-256: [전달된 고정값]

## Scenario 응답 (각 사례마다 복제)

- Corpus ID:
- Scenario ID:
- Baseline Pattern Label: `PATTERN_PRESENT` / `PATTERN_ABSENT` / `PATTERN_UNDETERMINED`
- Variant Pattern Label: `PATTERN_PRESENT` / `PATTERN_ABSENT` / `PATTERN_UNDETERMINED`
- 검토 상태: `NOT_REVIEWED` / `REVIEWED` / `NEEDS_CLARIFICATION` / `DISAGREEMENT` / `INSUFFICIENT_EVIDENCE`
- 입력 사실 검토:
- 정책 조건 계산 근거:
- Parser 검증 가능 범위: 충분 / 부분 / 거부 / 판단 불가
- 부족하거나 불명확한 Evidence:
- 검토 의견:

`REVIEWED`는 해당 입력 패턴을 검토했다는 뜻만 가집니다. 자동 해결·안전 판정·승인 의미가 아닙니다. Parser 범위가 충분하지 않다면 `PATTERN_UNDETERMINED` 및 `INSUFFICIENT_EVIDENCE`를 사용하고, 반드시 PRESENT/ABSENT 중 하나를 고르지 않습니다.

## 제출 후 비교 기록

비교기는 고정된 Packet digest에 결합된 응답만 받아들입니다. 일치 여부는 `MATCH`, `DISAGREEMENT`, `NEEDS_CLARIFICATION`, `INSUFFICIENT_EVIDENCE`, `NOT_REVIEWED`로 구분합니다. 불일치는 기존 Manifest를 자동 수정하지 않습니다. 입력 사실, 정책 해석, Parser 범위, 독립 Label 근거를 사람이 따로 검토하고 수정 전후 digest와 결과 차이를 기록합니다.

이 파일은 빈 템플릿입니다. 실제 reviewer identity, 서명, 검토 결과 또는 완료 상태를 저장소에 작성하지 마세요. 실제 검토 원본은 승인된 비공개 로컬 절차로 관리합니다.
