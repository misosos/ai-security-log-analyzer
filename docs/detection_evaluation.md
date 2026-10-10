# 결정적 탐지 평가 기준선 (Phase 6)

Phase 6.2는 평가 수치나 trusted internal `analyze()` 계산 의미를 변경하지 않는다. 내부 원래 계정은 join을 위해 남을 수 있지만 평가 text/JSON은 승인된 scalar만 출력한다. Deprecated legacy API와 HTML 보고서의 공개 출력 migration은 [개인정보 경계 문서](public_analysis_privacy.md)에 기록한다.

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
| 중복·순서 (Phase 6 당시) | 실패 이벤트는 중복도 횟수에 포함; subject ordering은 case assembler의 IPv4/IPv6 numeric 순서 | 동일 subject에 여러 성공 후보가 있으면 correlation의 첫 matching success 선택은 입력순서에 영향받았음. Phase 6.1 수정은 아래 참조 |
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

## Phase 6.1 — SSH·parser 경계와 결정적 관계 선택

2026-10-09 기준 고정 ID 21개를 유지하면서 22개를 추가해 총 **43개**다. SSH 13개는 실제 `ssh` registry/parser 경로를 사용한다. 정상 publickey 성공, password 실패 1회·4회·5회/60초, 같은/다른 계정 성공, 성공 선행, 파일 입력 순서와 다른 두 성공 후보를 평가한다. SSH의 `Failed|Accepted password|publickey for ... from ...`만 positive 라벨이며, 지원하지 않는 문구는 timestamp가 맞으면 `event_type=None`인 parsed event다. 새 SSH 문법은 추가하지 않았다.

Parser-only 9개는 production `analyze()`를 호출하지 않는다. SSH unsupported/잘못된 timestamp/whitespace/extra text/잘못된 IP, application 잘못된 timestamp·IP 누락, access 불완전 요청·빈 line을 직접 parser에 전달한다. `parsed`는 `NormalizedEvent` 반환, `ignored`는 `None`, `rejected`(`failed` JSON 필드)는 parser/UTC 정규화 예외를 뜻한다. SSH unsupported와 잘못된 IP, application의 IP 누락은 **parsed지만 attribution이 되지 않거나 후속 adapter에서 거부**될 수 있다. Invalid UTF-8은 decode·loader 또는 로컬 업로드 경계에서 parser 전에 거부되므로 parser 통계로 세지 않는다. 줄별 typed 기대 disposition과 실제를 비교해 `unexpected_parse_count`, `unexpected_rejection_count`를 별도로 낸다. Parser-only의 분석 결과를 정상 0건으로 위장하지 않는다.

정상 활동 중심 추가 항목은 같은 IP의 다수 성공·같은 시각 성공, 한 번 실패 후 정상 재시도, 모니터링 계정 성공, 집중된 웹 health/metrics 요청과 정상 query·점·percent·HTTP 404/500이다. 정상 재시도도 기존 **인증 관계는 positive**이며 탐지만 negative다. `automation_ambiguous`는 현재 규칙상 Brute 관찰이지만 승인된 자동화 여부가 로그에 없으므로 `ambiguous_operational`로 분리한다. 분석·risk·case 계약은 비교하되 detection/correlation confusion matrix에서는 제외하고 고정 이유와 개수를 출력한다. 이는 실제 FP를 0으로 단정하기 위한 조치가 아니다.

### 성공 후보 선택 정책

수정 전에는 세 인증 관계 함수가 `ip_logs` 입력 순서의 첫 matching success에서 반환했다. 테스트는 같은 실패 뒤 10초·20초 성공에서 20초 기록이 먼저 입력되면 20초 endpoint를 고르는 실패를 먼저 재현했다. 현재는 per-IP 입력의 동일 subject·정확한 account, 실패가 성공보다 엄격히 앞서고 기존 60초 범위 안인 **모든 쌍**의 delta를 비교해 가장 작은 양의 delta 쌍 하나를 선택한다. Production pipeline timestamp는 parser가 canonical UTC로 정규화한다. 직접 호출하는 오래된 단위 테스트의 naive timestamp는 기존 함수 계약을 유지하되, naive/aware 혼합은 후보에서 제외한다. 60초 포함, 0초·역전 제외와 120초 case 상한은 변경하지 않았다.

최소 delta의 완전히 같은 event 쌍(모든 내부 필드가 같은 duplicate)은 한 endpoint fact로 접는다. 같은 최소 delta에서 source·auth context·raw record 등 내부 event 내용이 다른 쌍이나 서로 다른 timestamp 쌍은 안전한 유일 후보를 입증할 수 없어 관계 없음으로 fail closed한다. Raw record는 동률 판별에서 **정확한 중복 여부 확인에만** 쓰고 선택 key·반환값·평가 출력에 복사하지 않는다. UUID/hash/object identity/입력 위치는 쓰지 않는다. 이는 외부 보안 표준의 새 임계값이 아니라 기존 관계에서 입력순서 비결정성을 제거하기 위한 프로젝트 선택 정책이다. 정상 단일-success fixture의 출력은 유지된다.

후보가 모호해 관계가 없어지면 기존 risk의 correlation signal과 case 존재 여부도 달라질 수 있다. 이것은 새 risk 계산이나 case 규칙이 아니라 부정확한 관계를 fail closed한 결과다. Raw 내부 correlation dict는 기존 adapter join 때문에 원래 account와 rationale을 포함하므로 **그 객체의 직접 `repr()`은 개인정보 안전 경계가 아니다**. CLI 평가 text/JSON, case assembly/projection, bounded error에는 원래 account·raw line·query·경로를 넣지 않는다. 내부 dict를 로그에 출력해서는 안 된다.

### 갱신된 baseline

43/43 시나리오 통과. Parser는 입력 134줄 중 parsed 129, ignored 2, rejected 3; unexpected parse/rejection 각 0이다. SSH 시나리오 13개. Parser-only 9개를 제외한 risk·case는 각각 34/34. Ambiguous operational 1개는 confusion matrix에서 제외해 labeled denominator는 33개다.

| Detection | TP | FP | FN | TN | precision | recall | F1 | support |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Brute Force | 11 | 0 | 0 | 22 | 1.000000 | 1.000000 | 1.000000 | 11 |
| Password Spraying-like | 2 | 0 | 0 | 31 | 1.000000 | 1.000000 | 1.000000 | 2 |
| Path Traversal | 2 | 0 | 0 | 31 | 1.000000 | 1.000000 | 1.000000 | 2 |

| Relation | TP | FP | FN | precision | recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Failed Login → Successful Login | 6 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| Brute Force → Successful Login | 3 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| Password Spray → Successful Login | 1 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |

외부 근거: [NIST SP 800-92의 rule-based event correlation 정의](https://csrc.nist.gov/glossary/term/Rule_Based_Event_Correlation)는 timestamp, IP, event type 등 관찰 가능한 필드의 결합을 설명하지만 특정 closest-success 정책이나 60초를 지정하지 않는다. [OpenSSH 공식 매뉴얼](https://www.openssh.org/manual.html)과 [sshd_config의 인증·로그 설정](https://man.openbsd.org/sshd_config)은 password/publickey 및 logging 설정의 배경이다. 실제 `Failed`/`Accepted` 줄 해석은 저장소의 SSH parser regex에 한정한다. 두 자료를 이 프로젝트 임계값의 권위로 사용하지 않는다.

남은 공백: 실제 운영 로그·승인 활동 ground truth, 여러 source의 동시각 distinct event identity, parser 이전의 invalid UTF-8/업로드 검증, 모든 parser 오류 형태, cross-worker·live 순서, 성공·실패 시각이 동률인 일부 데이터 품질 문제. 합성 수치의 운영 일반화는 금지한다.

## Phase 8 — 웹 요청 관찰 확장 (2026-10-10)

기존 43개 ID·라벨·계산 의미를 유지하고 36개 작은 NCSA fixture를 추가해 **79/79** 시나리오다. 새 fixture는 SQLi-like·XSS-like·민감 리소스 요청의 명확한 category와 일반 단어/문서/asset/단독 quote·주석/잘못된 percent encoding의 음성 경계를 분리한다. Scanning 양성은 임계값 정확 충족(`web_scan_exact`), 초과(`web_scan_above`), 60초 정확 경계(`web_scan_boundary`)를 독립 라벨로 평가한다. request 수 부족, 중복 대상, 정상 asset burst는 음성 라벨이다. 파일 parser는 초 단위이므로 60초+1µs·입력 permutation·같은 요청 반복 및 복합 유형은 별도 normalized-event 불변식 테스트이며 support에 포함하지 않는다. 이 수치는 포함 라벨에만 유효하고 실제 운영환경 precision/recall이 아니다. 상세 관찰 계약과 공식 자료는 [웹 요청 설계](web_attack_observation_design.md)에 있다.

Parser: 200줄 중 parsed 195, ignored 2, rejected 3, 예상 밖 parse/rejection 0. Risk·case는 각각 70/70. Ambiguous operational 1개는 기존과 같이 confusion matrix에서 제외한다. 기존 인증 관계 TP는 6/3/1, FP/FN 0으로 유지됐다.

| Detection | TP | FP | FN | TN | precision | recall | F1 | support |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Brute Force | 11 | 0 | 0 | 58 | 1.000000 | 1.000000 | 1.000000 | 11 |
| Password Spraying-like | 2 | 0 | 0 | 67 | 1.000000 | 1.000000 | 1.000000 | 2 |
| Path Traversal | 2 | 0 | 0 | 67 | 1.000000 | 1.000000 | 1.000000 | 2 |
| SQL Injection-like | 5 | 0 | 0 | 64 | 1.000000 | 1.000000 | 1.000000 | 5 |
| XSS-like | 5 | 0 | 0 | 64 | 1.000000 | 1.000000 | 1.000000 | 5 |
| Sensitive Resource Probing-like | 4 | 0 | 0 | 65 | 1.000000 | 1.000000 | 1.000000 | 4 |
| Web Scanning-like | 3 | 0 | 0 | 66 | 1.000000 | 1.000000 | 1.000000 | 3 |

특히 Scanning support=3도 작은 합성 표본이므로 이 1.0 수치를 일반화할 수 없다. `request_count`는 선택된 60초 창의 실제 eligible request event 수로 반복 target·동일 raw line도 각각 세며, `distinct_target_count`만 canonical target identity 수다. stable ingestion ID가 없어 원본 event는 중복 제거하지 않는다. 가장 이른 적격 시작점의 최대 60초 창에서 최종 observation 하나만 생성한다. 승인된 스캐너와 NAT/proxy, 운영 로그 누락, Unicode/encoding 변형 및 실제 악성/정상 ground truth는 평가 공백이다.

## Phase 9 — 별도 Linux 프로세스 실행 분류 평가 (2026-10-10)

기존 **79/79** IP 기반 parser·detection·correlation·risk·case 시나리오와 위 confusion matrix는 변경하지 않는다. `linux_process_execution_evaluation`은 별도 합성 Linux Audit fixture **21/21**개를 parser → normalized process event → 기존 count-only aggregate와 새 typed classifier 순서로 확인한다. 셸 4건, 네트워크 전송 도구 4건, 권한·소유권 변경 도구 3건, 임시 디렉터리 실행 4건의 category 관찰이 라벨과 일치한다. `linux_temp_curl`과 `linux_temp_bash`는 한 실행이 두 category에 속하므로 category 합계 15는 classified unique execution 수와 같은 의미가 아니다. 이름 유사·경로 sibling·CWD-only·식별 불일치 등 non-match는 별도 unclassified로 남는다. Outcome·aggregate consistency는 각각 21/21이다.

Linux category metric은 expected/actual observation 수, false/missed category assignment, expected unique execution 수를 별도로 제시한다. Category assignment의 precision·recall은 포함된 라벨에서만 계산하고 분모가 0이면 `not_applicable`이다. TN universe가 정의되지 않아 IP 탐지의 TN·accuracy를 재사용하지 않는다. CLI text와 JSON은 같은 고정 수치를 담고 JSON은 정렬된 key와 결정적 순서로 출력한다. `--scenario`는 기존 79개 IP 시나리오만 필터링하며 Linux 21개 section은 독립적으로 유지된다. 평가 fixture 안의 argv·path·node·serial 원문은 결과에 복사하지 않는다. 같은 fixture에서 만든 합성 라벨은 운영환경 악성 탐지율이 아니며 정상 관리·자동화 사용, Audit 정책의 누락, `comm` truncation, `argv[0]` spoofing은 남은 평가 공백이다. 분류·보호 경계는 [Linux Audit 프로세스 실행 문서](linux_audit_process_execution.md)를 참고한다.

Phase 9.1 로컬 웹 화면은 같은 Phase 9 분류기와 별도 privacy-safe 범주 집계를 사용한다. 기존 79개 인증·웹 시나리오 및 Linux 21개 오프라인 시나리오의 라벨·metric을 변경하지 않는다. 웹 UI가 추가되어도 합성 평가 일치도를 운영환경 악성 탐지율로 일반화할 수 없다.
