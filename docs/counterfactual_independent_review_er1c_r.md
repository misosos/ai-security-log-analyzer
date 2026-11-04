# ER-1C-R — 독립 사람 검토 준비 및 승인 Gate

## 1. 목적과 범위

이 단계는 ER-1A Development Corpus 16건과 ER-1C Holdout 14건, 총 30개의 합성 시나리오를 별도 사람이 검토할 수 있도록 Label-Blind Packet과 응답·비교 절차를 준비한다. Packet 생성은 독립 검토가 아니며, 자동 일치 비교도 사람의 검토 또는 승인을 증명하지 않는다.

범위는 오프라인 합성 자료뿐이다. Production Parser/Detector, API/UI, 기존 Corpus/Label, dependency, workflow는 변경하지 않는다. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`다.

## 2. 시작 SHA와 CI

- 시작 SHA / local `main` / `origin/main` / GitHub `main`: `755c74d7934aeb1499077b5b620e86f079be135a`
- Exact [push CI Run 41818608175](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41818608175): 정확한 SHA, `completed / success`; 필수 Linux, Restricted Report, Chromium/axe, tracked-file 검사 성공; artifact 0개.
- 시작 tree clean, ahead/behind `0/0`; `v0.4.0` Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지.
- 시작 기준 ER-0/1A/1B/1C 자료는 변경되지 않았다.

이는 시작 Gate의 증거이며 이번 변경 커밋의 원격 CI 결과는 아니다.

## 3. 검토 대상 Corpus

고정된 두 경로만 사용한다.

| Corpus ID | 저장 위치 | 사례 수 | Manifest SHA-256 |
|---|---|---:|---|
| `er1a_development` | `sample_logs/counterfactual/` | 16 | 생성된 Packet의 `source_corpora` 값 참조 |
| `er1c_independent_holdout_v1` | `sample_logs/counterfactual_holdout/` | 14 | `392127d5ad7fb61cfca361d0b9c21a6c349d94313c14bd3c1f4ead48f9393739` |

이번 구현의 결정적 Packet: SHA-256 `12988ec065c66901eb4036454fb24e52ef52c2bc435e65ea73b42d9846957c92`, canonical 크기 113,718 bytes. Development Manifest SHA-256 `a0d81f404b99e19acb15458fe80fada677dab846db79cb3682b1f7359b70d062`. Holdout Manifest SHA-256은 위 표의 값이다. Packet에는 fixture별 baseline 및 변형 입력의 SHA-256이 scenario마다 기록된다. Packet을 커밋하지 않으며, 이 고정 digest는 현재 소스와 fixture에서 생성된 검토용 snapshot을 식별한다.

Holdout의 fixture별 digest는 [ER-1C 검증 기록](counterfactual_holdout_validation_er1c.md)의 Corpus Provenance 표와 `sample_logs/counterfactual_holdout/hashes.json`에 있다. Development fixture digests 및 두 Manifest digest는 매번 생성된 고정 Packet의 `source_corpora` 필드에 포함된다. Packet digest는 전체 canonical Packet에서 `packet_sha256` 자기 필드를 제외한 바이트의 SHA-256이다. 이 digest는 변경 탐지용이지 외부 사전 등록, 서명 또는 비공개 blind holdout의 증명이 아니다.

30건의 상세 입력은 고정 CLI로 생성한다.

```bash
uv run python -m app.evaluation.counterfactual_review_packet_cli > review-packet.json
```

생성 파일은 검토 전달용 비공개 로컬 산출물로 취급하고 Git에 추가하지 않는다. Packet은 raw 로그 대신 제한된 정규화 이벤트 사실과 관계 보존 그룹을 제공한다.

## 4. Blind Packet 생성 방식

`app/evaluation/counterfactual_review_packet.py`는 두 고정 Corpus의 안전한 파일 읽기 및 기존 Mutation을 사용한다. Manifest는 UTF-8 strict·duplicate-key·closed-key·크기 검사를 거친 뒤 필요한 corpus/scenario/detector/source/fixture/mutation 필드만 읽는다. Expected label, label basis, parser 기대값 및 operational context 값은 DTO로 만들거나 의미 검증하지 않는다. 판단용 이벤트 목록은 실제 합성 Fixture bytes → Mutation bytes → 기존 Parser에서 만든다. Detector replay 출력 및 Comparison 결과는 Packet builder 경로에 없다. `BlindScenarioInput`은 corpus/scenario/detector/source/fixture 식별과 baseline/variant bytes 및 digest만 허용한다.

Packet에는 corpus/scenario/detector/source profile/mutation 종류, baseline·variant의 parser disposition, 입력 행 수·정규화 이벤트 수·매핑되지 않은 행 수, 상대 시각, 입력 순서와 시간 순서, 불투명 Source/Account 그룹, 인증 결과 유형, 직접 변경 종류, 파생 관찰 및 정책 설명이 있다. 원본 IP와 계정명은 `Source Group A`, `Account Group 1`처럼 사례 안의 동일성만 보존하는 이름으로 치환된다.

상대 시각은 baseline의 가장 이른 검증 이벤트를 0초로 놓고 정확한 초 간격을 유지한다. Variant 시간이 기준보다 이르면 음수도 보존된다. 시간 순위와 원래 입력 순서는 별도 필드다. Parser가 PARTIAL이면 누락/미매핑 행 수와 한계를 표시한다. REJECTED이면 정규화 이벤트를 만들지 않고 미매핑 입력 수와 거부 한계를 표시한다. 원문을 추측해 복원하지 않는다.

기존 Label이 공개 저장소에 이미 있으므로 **기술적 완전 블라인드는 보장되지 않는다**. 검토자는 실제 절차에서 기존 Label/Replay를 사전에 보지 않았다고 스스로 확인해야 한다. 자동 도구는 그 주장을 검증할 수 없다.

## 5. 정책 및 입력 근거

검토자에게 별도 [정책 요약](templates/counterfactual_review_policy_er1c_r.md)을 제공한다. 현재 프로젝트 정책은 Brute Force에서 같은 IP·알려진 동일 계정의 선택 sliding window, 실패 5회 이상, 60초 이하이며, Password Spraying-like에서는 같은 IP 전체 실패, 실패 4회 이상, 알려진 계정 3개 이상, 전체 span 60초 이하이다. Spray는 Production whole-span이다. 수치는 외부 표준의 보편 임계값이 아니다.

Packet은 정책 조건에 대한 사실 입력을 보여줄 뿐 공격 의도나 침해를 판단하지 않는다. Detection은 침해 확정이 아니고, Correlation은 인과관계가 아니며, `PATTERN_ABSENT`는 안전을 뜻하지 않는다. 판단 자료가 부족하면 검토자는 미결정/근거 부족을 선택한다.

## 6. Reviewer Instructions

1. Packet digest와 Corpus digest를 확인하고 30건이 있는지 확인한다.
2. 정책 요약과 Packet만 사용해 각 baseline/variant의 입력 사실 및 적용 가능한 조건을 독립 계산한다.
3. 가능하면 기존 Label 또는 Replay 작성에 참여하지 않은 검토자가 맡는다.
4. 검토를 마치기 전 ER-1A/ER-1C manifest의 정답, ER-1B/ER-1C replay 결과를 열지 않는다. 저장소 공개 상태 때문에 이를 기술적으로 막을 수 없으므로 열람 여부를 솔직히 기록한다.
5. 판단할 수 없으면 `PATTERN_UNDETERMINED` 및 `INSUFFICIENT_EVIDENCE`/`NEEDS_CLARIFICATION`으로 남긴다.
6. 실제 공격 성공, 계정 탈취, 회피 성공 또는 운영 정확도를 판단하지 않는다.
7. [빈 응답 양식](templates/counterfactual_independent_review_template.md)을 사용한다. 실제 이름·서명·날짜는 검토자만 기입한다.
8. 개인 식별 정보가 있는 원본 응답은 비공개 로컬 승인 절차로 보관하고 공개 Git에 커밋하지 않는다.

## 7. Human Review Submission Contract

비교 CLI는 파일 경로를 받지 않고 표준 입력에서 최대 128 KiB의 UTF-8 JSON을 받는다.

```bash
uv run python -m app.evaluation.counterfactual_review_packet_cli --compare-submission < private-review.json
```

고정 schema는 `schema_version`, `packet_sha256`, reviewer의 임의 비개인 `reviewer_ref`/독립성 자기선언/기존 Label 열람 여부, 그리고 시나리오별 상태·baseline/variant label·parser scope·bounded 의견을 받는다. Duplicate JSON key, unknown field/status/label, 중복·알 수 없는 scenario, 잘못된 packet digest, 과도한 입력은 거부한다. 출력에는 자유 의견, reviewer 이름, 서명, raw 입력, IP, 계정, timestamp, 경로 또는 예외 원문이 포함되지 않는다.

자동 비교 결과는 `MATCH`, `DISAGREEMENT`, `NEEDS_CLARIFICATION`, `INSUFFICIENT_EVIDENCE`, `NOT_REVIEWED`를 구분한다. 이는 기존 expected pattern과 제출된 사람 라벨을 비교한 요약일 뿐이다. 응답이 모두 REVIEWED이어도 결과 상태는 항상 `INDEPENDENT_HUMAN_REVIEW_PENDING`, 독립성은 `SELF_REPORTED_NOT_VERIFIED`, 승인은 `MANUAL_APPROVAL_REQUIRED`다. 기계는 사람 작성 여부나 이해관계를 확인하지 못한다.

## 8. Label Adjudication Rules

불일치 시 기존 Manifest/Label을 자동 변경하지 않는다. 별도 사람이 입력 bytes와 그룹 관계, timestamp, Parser 범위, 정책 조건 계산을 재검토한다. 결과 범주는 Label 일치와 독립성/승인을 분리한다. 제출이 없거나 미완료인 사례는 `NOT_REVIEWED`; 부족한 자료는 `INSUFFICIENT_EVIDENCE`; 질문이 남으면 `NEEDS_CLARIFICATION`으로 유지한다. Parser scope가 충분하지 않으면 일치 비교는 근거 부족으로 분류한다.

검토자가 `DISAGREEMENT`로 표시한 것은 사람의 의견 상태이며, 자동 비교기가 계산한 `DISAGREEMENT`는 기존 Label과의 차이다. 양자를 혼동하지 않는다. 입력 사실·정책 해석·Parser scope·기대값 provenance를 각각 분석한 뒤 별도 승인자가 변경을 승인해야 한다. 자동 수정 금지다.

## 9. Integrity / Provenance

- Packet은 두 Corpus 각각 manifest SHA 및 fixture별 SHA-256을 담고, Packet digest는 자기 자신을 제외해 계산한다.
- Packet 직렬화는 고정 key 정렬·UTF-8 canonical JSON·512 KiB 상한을 사용한다. 같은 입력은 같은 digest와 bytes를 낸다.
- fixture, manifest, 결과물 digest는 변경 탐지용이다. 신뢰된 외부 서명이나 사전등록이 아니며 Blind 상태를 증명하지 않는다.
- 응답은 Packet digest에 결합된다. 다른 Packet에 대한 응답은 거부된다.
- 미제출 또는 자동 생성 테스트 응답은 human completion으로 승격되지 않는다.

## 10. Security / Privacy

합성 fixture만 처리하고, 임의 경로/Corpus를 CLI에서 받지 않는다. Packet은 raw log, 실제 account/IP, 원문 label, replay/comparison 결과, 내부 run context를 출력하지 않는다. Parser 이벤트에는 source/account 그룹만 넣는다. 자동화는 네트워크·LLM/API를 호출하지 않는다. 오류는 fixed category만 출력한다. 실제 검토 원본과 reviewer 식별정보는 공개 저장소에 넣지 않는다.

## 11. Automated Test Results

TDD RED: Packet 모듈 부재로 신규 구현 테스트가 `ModuleNotFoundError`로 실패했고, 문서 계약은 문서 파일과 index 링크 부재로 2개 실패했다. 이후 ER-0/1A/1B/1C 및 ER-1C-R focused suite는 **121 passed**였다. 최종 수정 뒤 전체 `uv run pytest -q`는 **3,752 passed, 2 기존 deprecation warning**으로 통과했다.

순차 실행한 `uv run python -m app.evaluation`: synthetic boundary 79/79, risk 70/70, case 70/70, synthetic Linux process 21/21. 이는 기존 별도 evaluation이며 ER counterfactual 점수와 합산하지 않는다. Packet CLI는 30건을 생성했고, 비어 있는 검증용 제출을 받은 comparison CLI는 30건 `NOT_REVIEWED`, `INDEPENDENT_HUMAN_REVIEW_PENDING`을 반환했다. 이 제출은 테스트 합성 자료이며 실제 사람 응답이 아니다. `uv lock --check`, Python compile, `git diff --check` 통과; dependency/lockfile 변경 없음. Socket 연결 차단 테스트에서 네트워크 시도 0.

자동 검증 성공은 사람의 PASS가 아니다. 테스트는 Label 노출 금지, 그룹/시간/순서 보존, parser 불완전성, packet 결정성, digest 결합, 엄격한 제출 schema, PENDING 보존, canary 비노출 및 네트워크 0을 고정한다.

## 12. Human Review Status

- 자동 계약 검증: 실행 증거에 따라 기록
- 독립 사람 검토: `INDEPENDENT_HUMAN_REVIEW_PENDING`
- 실제 reviewer, 완료 날짜, 서명: 없음
- 30건 사람 검토 완료 근거: 없음

Codex는 사람 검토를 수행하지 않았고, 자동 비교는 승인하지 않는다. 실제 독립 검토가 끝나기 전 `COMPLETED`를 기록할 수 없다.

## 13. ER-1D Entry Gate

ER-1D 기능 개발 전 반드시 별도 사람 검토, 30건 범위 완결, 의견 및 불일치 처리, Packet/Corpus digest 확인, 독립성 확인 근거, 누락 항목 처리 및 승인 기록을 확보한다. 검토자는 기존 결과 열람 여부를 명시한다. 새 구현 커밋도 exact SHA CI 성공을 확인한다. 어느 하나라도 미완료면 ER-1D는 HOLD다.

## 14. Limitations

- 공개 저장소의 Expected Label 때문에 완전한 기술적 blind를 보장하지 못한다.
- 자동 검증은 reviewer identity·독립성·사람 작성 여부를 증명하지 못한다.
- Corpus는 제한된 합성 사례이고 외부 holdout/사전등록이 아니다.
- Parser 정규화는 입력 자체의 진실성이나 로그 수집 완전성을 증명하지 않는다.
- 소규모 합성 사례에서 실환경 탐지 정확도·공격 회피율·안전성은 추정할 수 없다.
- macOS 로컬 자동 검증은 새 Ubuntu CI, 다른 OS, screen reader, 사람의 이해도 검수를 대체하지 않는다.

## 15. Final Decision

검토 패킷과 절차가 구현되고 자동 회귀가 통과하면 `ER_1C_R_REVIEW_PACKET_LOCAL_CONDITIONAL_GO`는 자료 준비 및 자동 계약 검증에만 적용한다. 독립 사람 검토는 `INDEPENDENT_HUMAN_REVIEW_PENDING`이며 ER-1D 진입은 승인되지 않았다.

실제 사용자 자료: `NO_GO` · 실제 조직 운영: `NO_GO` · 자동 대응: `NO_GO`
