# 결정적 탐지 평가 기준선 (Phase 6)

## 목적과 범위

`uv run python -m app.evaluation`은 오프라인 `synthetic_boundary_corpus`에서 **현재 구현**의 parser·탐지·상관관계·risk·조사 사례 계약을 서로 분리해 검사한다. `--format json`과 `--scenario <고정 ID>`를 지원한다. 결과는 stdout에만 쓰고 네트워크·LLM·현재 시각·환경변수·난수·DB를 사용하지 않는다. 실패 시 종료 코드 1, 라벨·fixture 오류 시 2다. `--scenario`는 정확한 ID만 허용한다. JSON은 고정 필드와 정렬된 키, 고정 6자리 소수 문자열을 사용한다.

이 수치는 **합성·경계 시나리오에서의 구현 정확도**다. 실제 운영환경의 공격 탐지율이나 침해 확률이 아니다. 탐지는 침해 확정이 아니고 상관관계는 인과관계가 아니며 조사 사례는 incident verdict가 아니다.

## 현행 계약 확인표

| 계층 | 코드에서 확인한 기준 | 경계·제한 |
| --- | --- | --- |
| Brute Force | IP별 실패 5회 이상, 대상 계정 정확히 1개, 전체 실패 폭 60초 이하 | 5·60 포함; 전체 폭 기준, 부분 슬라이딩 창 아님 |
| Password Spraying-like | IP별 실패 4회 이상, 대상 계정 3개 이상, 전체 실패 폭 60초 이하 | 4·3·60 포함; 같은 계정 반복은 계정 수 증가 아님 |
| Path Traversal | 반복 percent-decode 후 path 또는 query에 `../` 또는 `..\` 포함 | HTTP status와 무관하게 관찰; 200은 파일 접근 성공 증거 아님 |
| Failed Login → Successful Login | 동일 IP·계정, 실패가 성공보다 **앞**, 60초 이하 | 0초/역전 제외, 60초 포함, 60초+1µs 제외 |
| Brute Force → Successful Login | Brute 탐지 선행, 동일 IP·계정, 마지막 실패 뒤 성공 60초 이하 | 동일 경계; 탐지 시작부터의 전체 사례 범위는 별도 case 최대 120초 |
| Spray → Successful Login | 탐지와 동일 IP·계정 실패 뒤 성공 60초 이하 | production relation은 있지만 typed target membership이 없어 Spray case는 no-go |
| 정규화 | application·SSH는 `Asia/Seoul`; access는 로그 내 `%z`; 내부 UTC aware | 파일 parser는 초 단위 시각; 직접 normalized-event 테스트로 µs 경계 검사 |
| 중복·순서 | 실패 이벤트는 중복도 횟수에 포함; subject ordering은 case assembler의 IPv4/IPv6 numeric 순서 | 동일 subject에 여러 성공 후보가 있으면 correlation의 첫 matching success 선택은 입력순서에 영향받을 수 있음. corpus는 이 모호성을 피함 |
| Risk/confidence | HIGH/MEDIUM/LOW categorical; likelihood×impact matrix와 별도 confidence | 새로운 score 없음; 1~2 실패 후 인증 관계만 있는 경우 risk LOW, confidence MEDIUM 가능 |
| Case | Brute-success가 generic auth 관계에 우선; Path Traversal 독립 | Spray-success no-go, 미지원 관계는 자동 결합하지 않음 |

위 표는 Phase 6 시작 시 코드 기준이다. 기존 문서와 상충하는 경우 이 평가에서 규칙을 바꾸지 않았다. 파일 시각이 초 단위라는 점 때문에 파일 fixture만으로 `+1µs`를 표기할 수 없으며, 이를 별도 normalized-event 단위 테스트로 분리했다.

## Typed 라벨과 fixture

`app/evaluation/corpus.py`의 frozen `EvaluationScenario`는 고정 ID·설명·source·고정 fixture 이름·`ExpectedParser`·`ExpectedDetection`·`ExpectedRelation`·`ExpectedRisk`·`ExpectedCase`·독립 관찰 수·경계 근거·한계를 담는다. fixture는 `sample_logs/evaluation/`의 작은 UTF-8 합성 로그만 사용한다. 예약 IP 대역과 합성 계정을 사용하며 실제 credential/token/cookie는 없다. account 원문은 fixture 내부 join에만 존재하고 CLI 출력·JSON에는 들어가지 않는다. raw line·query·fixture 경로도 결과에 복사하지 않는다. 중복 ID, 모르는 type/level, naive label timestamp, 잘못된 fixture 이름은 평가 전 fail closed다.

고정 시나리오 21개: `login_only`, `brute_below`, `brute_exact`, `brute_over_window`, `brute_success`, `brute_other_account`, `brute_success_late`, `spray_exact`, `spray_success`, `spray_below_accounts`, `spray_over_window`, `auth_transition`, `auth_transition_late`, `traversal`, `normal_web`, `brute_above`, `low_failures`, `spray_below_failures`, `success_before`, `traversal_raw`, `traversal_false_like`. 기대값은 승인된 threshold·relation·case 계약과 명시적 음성 경계에서 작성했고 실행 결과를 golden으로 복사하지 않았다.

## 계층별 비교와 metric

Parser는 line/parsed/ignored/failed 수, event type·subject·account 존재 여부·HTTP method/status·첫/마지막 canonical UTC를 비교한다. Detection은 시나리오의 고정 subject별 type 존재와 승인된 failure count·target count·window·시간 범위를 비교한다. Correlation은 type과 정확한 failure/success endpoint를 비교한다. Risk는 기존 risk level·confidence와 likelihood/impact/confidence rationale 및 evidence 필드 존재를 비교한다. Case는 규칙·순서·최고 위험도·supporting relation·기대 observation 수·독립 관찰 수와 Timeline 내 관찰/관계 수 일치를 비교한다. 지원되지 않은 Spray case는 만들지 않는다. 실패를 0건의 정상 분석으로 변환하지 않는다.

Detection별 TP/FP/FN/TN은 시나리오당 각 type의 기대·실제 존재로 계산한다. support=TP+FN. Correlation은 relation type별 TP/FP/FN만 계산하며 TN·accuracy는 정의하지 않는다. 두 계층을 합쳐 점수화하지 않는다.

```text
precision = TP / (TP + FP)
recall = TP / (TP + FN)
F1 = 2 × precision × recall / (precision + recall)
```

분모 0은 `not_applicable`이다. F1은 동치인 `2TP/(2TP+FP+FN)`으로 계산한다. 이 작은 fixture의 support를 운영 데이터로 일반화할 수 없고 같은 fixture로 규칙을 조정한 뒤 같은 fixture로 평가하면 과적합된다.

## Phase 6 baseline (2026-10-09)

21/21 시나리오 통과, parser 75/75 line parse(ignored 0, failed 0), risk 21/21, case 21/21. 실패 시나리오 없음.

| Detection | TP | FP | FN | TN | precision | recall | F1 | support |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Brute Force | 6 | 0 | 0 | 15 | 1.000000 | 1.000000 | 1.000000 | 6 |
| Password Spraying-like | 2 | 0 | 0 | 19 | 1.000000 | 1.000000 | 1.000000 | 2 |
| Path Traversal | 2 | 0 | 0 | 19 | 1.000000 | 1.000000 | 1.000000 | 2 |

| Relation | TP | FP | FN | precision | recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Failed Login → Successful Login | 3 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| Brute Force → Successful Login | 1 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| Password Spray → Successful Login | 1 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |

## 외부 공개 데이터셋 조사 (공식 출처, 2026-10-09 확인)

| 후보/공식 배포처 | 형식·라벨·시각 | 크기·라이선스/개인정보 | 현재 parser 적합성 |
| --- | --- | --- | --- |
| [UNB CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | 2017년 7월 5일 PCAP 및 timestamp/IP/protocol/attack label이 있는 network-flow CSV; SSH brute와 web attack 포함 | 일별 11+11+13+7.8+8.3 GB; 재배포·인용 조건은 배포처 정책 재확인 필요; packet payload 개인정보 검토 필요 | **직접 비교 불가**: 현재 auth/access parser의 계정·HTTP path 라벨과 flow 라벨이 다름. 변환기만으로 의미 동등성 보장 불가 |
| [UNB CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) | PCAP/flow CSV와 일부 로그, attack/benign label·시각 | 대용량 AWS 배포, 정확한 선택 파일 크기 확인 전 다운로드 보류; 원본 payload 개인정보·재배포 조건 검토 필요 | **변환기·라벨 검증 필요**; 현 parser 직접 입력 불가 |
| [Loghub HDFS/BGL](https://github.com/logpai/loghub) | HDFS/BGL 시스템 로그의 anomaly label·timestamp | HDFS v1 약 1.47 GiB, BGL 약 709 MiB; 공개 repository의 dataset별 사용/재배포 조건과 비식별화 확인 필요 | **라벨 의미가 달라 비교 불가**: 인증 실패·성공, traversal label이 아님 |
| 공개 SSH auth 로그 | 현재 공식 배포처·정확한 account 단위 label·라이선스가 검증된 후보 없음 | 크기·개인정보 미확인 | **보류**. 이름만 보고 corpus에 편입하지 않음 |

외부 데이터셋을 자동 다운로드하거나 이 커밋에 포함하지 않는다. 위 자료의 공격 라벨은 이 프로젝트의 5회/4회/60초 임계값을 승인하는 외부 표준이 아니다.

## 한계와 Phase 6.1 절차

21개 파일 fixture 외에 normalized-event 단위 테스트는 다중 IP 관계 분리, IPv4/IPv6 순서, 입력 순서 반전, 60초+1µs, naive timestamp 거부, 중복 실패 이벤트 계수, HTTP 5xx에서의 Path Traversal 관찰, Spray relation의 사례 no-go를 확인한다. 이들은 CLI corpus metric의 support에 포함하지 않는다.

현재 파일 fixture는 parser 실패·ignored line, SSH, 다중 subject 파일, 모든 URL pattern, 동일 relation 중복, 여러 성공 후보 입력순서, 실제 운영 오탐/미탐을 완전히 포괄하지 않는다. 보완은 새로운 **독립 라벨**과 작은 합성 fixture를 먼저 추가한 뒤 수행한다. 특히 다중 성공 후보의 순서성은 현 production correlation의 계약 위험으로 분리해 기록한다. parser 파일 시각은 초 단위이므로 µs 단위는 normalized-event 테스트로만 측정한다.

Phase 6.1에서 실패가 나면 `scenario / expected / actual / affected layer / likely cause / privacy-safe reproduction / recommended follow-up`을 기록하고, telemetry 근거와 오탐·미탐 tradeoff를 검토한 별도 커밋에서만 규칙을 바꾼다. 이 Phase 6은 detector threshold, correlation window, risk, parser 의미, case grouping을 변경하지 않았다.
