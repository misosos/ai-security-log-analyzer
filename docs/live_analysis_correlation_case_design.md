# v0.2.0 Phase 16 — live correlation·risk·조사 사례 의미 보존 설계

상태: **설계·계약 검증만 완료**. 현재 production은 Phase 12~15의 단일-source tail→parse→detection→publication→SSE/UI만 수행한다. 이 문서는 correlation·risk·case, API/SSE schema 또는 화면에 새 기능을 연결하지 않는다. 판정은 기존 코드의 **각 committed event prefix**와 같은 결과를 만들 수 있는 범위에 한정한다. 관계는 인과관계가 아니고 탐지·높은 위험도·로그인 성공은 침해 확정이 아니다.

## 1. 현재 production 계약과 관찰 가능한 입력

| 층 | 현재 코드·테스트에서 확인한 사실 | live 설계 결과 |
| --- | --- | --- |
| 입력 | `auth_log.py`는 event token을 그대로 보존하여 `login_failed`, `user_login`, `file_access`를 만들 수 있다. `ssh_auth.py`는 인식한 Failed/Accepted를 실패/성공으로 만들고 그 외 메시지는 event type `None`이다. `access_log.py`는 `http_request`만 만들고 일부 줄은 `None`이다. 세 경로는 registry timezone과 UTC 정규화를 거친다. | application의 후속 file-access 관계는 **실제 file_access 줄이 있을 때만** 후보. SSH는 인증 관계만, access는 인증 관계 없음. ignored/rejected 줄은 event history에 들어가지 않되 처리 결과 count로 남는다. |
| 탐지 | `pipeline.detect_attacks()`는 IP별 전체 event prefix를 묶고 feature와 7개 detection slot을 산출한다. `LiveDetectionAccumulator`가 이미 전체 PARSED prefix로 같은 함수를 재실행한다. | detector threshold·evidence·입력 순서를 바꾸지 않는다. |
| IP별 관계 | `pipeline.correlate_attacks()`는 각 IP에 `authentication`, `post_authentication`, `brute_force_to_success`, `password_spray_to_success`를 넣는다. 앞의 인증·brute·spray 전이는 같은 IP·같은 원래 account, failure < success, **60초 포함**을 요구한다. Brute/spray 전이는 해당 detection도 필요하다. `_closest_authentication_pair()`는 전체 후보의 최소 delta 한 쌍을 고르고, 완전 동일 event 쌍만 중복 제거하며, 최소 delta의 서로 다른 사실이 둘 이상이면 관계 없음으로 fail closed한다. | session history의 event와 **같은 prefix의 detection**을 입력으로 네 IP별 함수를 그대로 호출한다. 동률을 live에서 임의 해소하지 않는다. |
| post-auth | `correlate_post_authentication_activity()`는 같은 IP prefix의 `user_login`과 `file_access`에서 같은 account·성공 후 60초 이내의 가장 가까운 성공을 찾고, 입력 file-access 순서에서 첫 qualifying 항목을 반환한다. 인증 `_closest_authentication_pair()`와 달리 동률의 명시적 ambiguity check는 없다. | application에서만 조건부. 이 관계를 강한 attack chain이나 case anchor로 확대하지 않는다. 입력 순서 의존성을 batch 그대로 기록한다. |
| global | `correlate_attacks()`의 multi-IP·distributed-success·Linux Audit 관계는 `global_correlation`에 따로 있다. | **V1 live에는 호출·사용하지 않는다.** 단일 source라도 여러 IP의 global 관계를 per-IP risk/case에 주입하지 않는다. |
| risk | `assess_risk()`는 각 IP의 feature, detection, 네 관계, 로컬 `data/account_metadata.json`의 대상 account context로 likelihood·impact·confidence·structured evidence를 만든 뒤 likelihood×impact matrix로 risk level을 정한다. Path Traversal은 우선 분기이며 HTTP 200도 exploit 성공이 아니다. 새 웹 관찰은 기존 request-only 분기만 따른다. | per-IP full-prefix 결과를 기존 risk 함수로 계산한다. account metadata는 trusted 내부에만 두고 동일 버전의 batch prefix와 비교한다. 위험도와 confidence를 혼동하지 않는다. 원래 rationale/evidence를 그대로 public 전송하지 않는다. |
| typed case | `IncidentCaseSubjectInput`은 subject IP, 원래 target account tuple, typed detection/correlation, risk와 confidence를 받는다. 기존 raw-dict adapter는 이를 검증·생성한 뒤 `assemble_incident_cases()`와 `build_investigation_case_projection()`을 호출한다. `CASE-BRUTE-SUCCESS-01`이 `CASE-AUTH-TRANSITION-01`보다 우선한다. | Phase 16.1은 raw analysis dictionary를 public 경유하지 않고 **검증된 typed bridge**를 설계·구현해야 한다. 기존 adapter와 동일한 feature/evidence/account/timestamp 검증 및 출력 동등성을 입증하기 전에는 case 연결을 허용하지 않는다. |
| case membership | Brute case는 detection target account가 relation account와 정확히 일치하고 failure endpoint가 detection range에 있으며 detection 시작부터 success까지 **120초 포함**이어야 한다. 정확히 같은 account·failure/success endpoint·delta의 generic relation만 supporting으로 흡수한다. 부분 overlap은 independent, 모호한 중복 소속은 bounded `ambiguous_membership` 오류다. Spray case는 `NO_GO_UNTYPED_PRODUCTION_TARGET_MEMBERSHIP`. Path Traversal·새 웹 탐지는 independent다. | observation은 최대 한 case에만 소속하고 endpoint fact를 복제하지 않는다. Spray·웹·global·Linux Audit는 case로 억지 결합하지 않는다. |
| projection privacy | 기존 `InvestigationCaseProjection`의 account alias는 `ACCOUNT_REFERENCE_UNAVAILABLE`이며 “계정 별칭을 안전하게 생성할 참조가 없어 표시하지 않습니다.”를 사용한다. **그러나 기존 case projection에는 `subject_ip`가 실제로 포함된다.** | 기존 projection은 trusted 내부 parity 대상일 뿐 live public DTO가 아니다. 승인된 필드만 새로 투영하기 전 SSE/API/UI에 전달하면 개인정보 경계 위반이다. |

근거: [`pipeline.py`](../app/analyzer/pipeline.py), [`attack_chain.py`](../app/correlation/attack_chain.py), [`risk.py`](../app/analyzer/risk.py), [`incident_case.py`](../app/analyzer/incident_case.py), [`incident_case_adapter.py`](../app/analyzer/incident_case_adapter.py), [`incident_case_projection.py`](../app/analyzer/incident_case_projection.py), `tests/test_correlation_determinism.py`, `tests/test_incident_case.py`, `tests/test_incident_case_adapter.py`, `tests/test_incident_case_projection.py`. 이 문서는 위 production 의미를 변경하지 않는다.

## 2. 핵심 질문 판정

| # | 질문 | 판정·근거 |
| ---: | --- | --- |
| 1 | 단일 application 인증 관계 | **CONDITIONAL GO** — 실패·성공에 account/IP/UTC가 실제로 있고 기존 60초·closest·동률 계약을 충족할 때만. application `file_access`가 실제 기록되면 기존 post-auth 관계도 별도 independent로 계산 가능. |
| 2 | 단일 SSH 인증 관계 | **CONDITIONAL GO** — 인식된 Failed/Accepted 줄만 동일 조건으로 연결. SSH parser가 만들지 않는 `file_access`는 no-go. |
| 3 | 단일 access 인증 관계 | **NO-GO** — parser는 `http_request`만 만들고 인증 성공·실패/account endpoint가 없다. 기존 웹 탐지와 batch-defined request-only risk만 독립 유지. |
| 4 | 현재 config의 cross-source 관계 | **NO-GO** — 승인된 source는 정확히 한 개. 다른 source의 부재를 추측해 관계를 만들 수 없다. |
| 5 | detection history만으로 batch correlation | **CONDITIONAL GO** — 전체 PARSED `NormalizedEvent` tuple은 per-IP 재계산에 충분하고 detection state도 있다. Global 관계·누락된 입력·history overflow 이후까지 동등하다고 주장하지 않는다. |
| 6 | 기존 risk 동일 의미 | **CONDITIONAL GO** — 같은 prefix의 네 per-IP 관계와 feature/detection, 같은 account metadata일 때 기존 함수 재사용으로 가능. Metadata 변경·원본 rationale 공개는 별도 통제. |
| 7 | raw dictionary 없는 typed case | **CONDITIONAL GO** — 공개 typed assembler는 존재하지만 production adapter가 수행하는 엄격한 검증·target account 전달을 typed bridge가 보존해야 한다. 기존 projection을 그대로 public화하면 IP 노출이므로 no-go. |
| 8 | session 안의 stable case ID | **CONDITIONAL GO** — review order가 아닌 rule+trusted anchor relation에 ordinal ID를 할당하고 merge/split ambiguity를 fail closed할 때만. 아직 구현·parity 미검증. |
| 9 | 뒤따른 event로 기존 결과 변경·소멸 | **GO** — full-prefix brute/spray window, nearest-success, risk matrix와 case precedence상 가능하다. 소멸은 해결/안전/공격 종료가 아니다. |
| 10 | 상한 뒤 부분 history로 계속 계산 | **NO-GO** — 현재 256 PARSED event/256KiB history의 silent eviction은 batch prefix 의미를 바꾼다. |

V1은 **application 인증 관계와 기존 risk, generic/brute typed case**를 우선한다. SSH는 같은 계약의 후속 확장 후보이고 access는 기존 웹 탐지·risk 독립 관찰만 유지한다. Application의 post-auth 및 spray relation은 기존 결과와 parity를 측정하되 자동 case anchor가 아니다. Global correlation, cross-source, Linux Audit live는 제외한다.

## 3. Batch-prefix 동등성·시간·history

각 ack가 예정된 PARSED prefix `P1 … PN`에 대해 batch 기준을 `detect_attacks(Pi)` → **네 per-IP correlation 함수만** → `assess_risk({"results": ..., "global_correlation": {}})` → 검증된 typed subject → `assemble_incident_cases()` → `build_investigation_case_projection()`으로 정의한다. 이것은 `correlate_attacks()`가 global 함수를 함께 실행한다는 이유로 live에서 그 함수를 그대로 호출하지 않기 위한 **범위 제한**이며, 각 per-IP 결과는 batch의 `results`와 완전 equality 또는 IP/account/UTC/evidence/rationale/ordering을 빠뜨리지 않는 trusted canonical equality로 비교한다. Raw 결과를 실패 메시지·snapshot에 출력하지 않는다. Projection parity는 기존 IP를 포함한 trusted 내부 객체에서 검증하고 live public DTO parity는 별도로 검증한다.

테스트 corpus는 application·SSH·access 각각의 prefix, 정상/오류/공백 줄, timestamp 입력 순서·역순·순열, microseconds, 같은 timestamp, 실패/성공 여러 후보, 가장 가까운 후보, 최소 delta 동률, 정확히 60초와 초과, brute/spray threshold 경계, application file_access, no-time observation, 웹 독립 관찰을 포함한다. `IGNORED`·`REJECTED`는 sequence/counter에는 남지만 normalized prefix에는 넣지 않는다. 현재 post-auth의 첫 file-access 선택처럼 batch가 입력 순서에 의존하면 live가 timestamp 정렬로 고치지 않고 characterization test와 한계로 남긴다. Endpoint는 timezone-aware UTC만 허용하고 naive 시간·processing clock으로 메우지 않는다. KST는 기존 projection의 표시 전용이며 microseconds를 보존한다.

| 전략 | 의미·비용 | Phase 16.1 |
| --- | --- | --- |
| A. bounded 전체 prefix 재계산 | 기존 nearest/tie, 사라지는 detector/relation/risk/case 결과를 가장 직접적으로 재현. History 증가에 따라 CPU·allocation·event-loop stall 증가. | **권장**. 기존 live accumulator의 256 event/256KiB 개발 상한을 공유하고 계측·parity gate 적용. |
| B. 증분 correlation 상태 | 새 event만 갱신하면 빠를 수 있으나 늦게 도착한 failure/success가 기존 closest endpoint와 case를 바꿀 수 있음. | 보류. 완전 parity 입증 없이 도입 금지. |

`LiveDetectionAccumulator`의 상한은 현재 launcher에서 **256 PARSED event·256KiB encoded `raw`**다. Analysis는 같은 전체 history를 빌려 쓰되 별도 축약/rolling eviction을 하지 않는다. 초과는 prepare 단계의 `HISTORY_LIMIT_EXCEEDED`: proposal 취소, lease release, worker `DEGRADED`, 자동 resume 없음. 정상 0건으로 보이지 않는다. V1의 유일한 실용 복구는 사용자 검토 후 process 재시작이며 `FROM_END`이므로 중단 중 append의 복구/무유실을 주장하지 않는다. 추가 derived state와 projection 자체에도 benchmark 후 item/byte 상한이 필요하며 무제한 journal은 금지한다.

## 4. 제안·ack·commit 경계

권장 순서: `parse → detection proposal → correlation/risk/case proposal → 두 proposal 및 safe publication envelope 사전 검증 → queue ack → detection state reference swap → analysis state reference swap → publication commit → worker safe summary`. Ack가 point of no return이다. Allocation, per-prefix 계산, case projection 및 safe JSON 크기 계산은 ack 전에 끝내고 뒤에는 최소한의 사전 검증된 참조 교체만 한다. 그래도 Python process memory의 여러 객체를 하나의 원자적 transaction으로 만들 수 없고 crash/exactly-once도 보장하지 않는다. `analysis_revision`은 성공한 detection revision과 1:1로 맞추고, ignored/rejected-only batch도 처리 완료 revision을 증가시키되 change가 없으면 event를 게시하지 않는다.

| 실패 지점 | proposal·lease | worker/무결성·재시도 |
| --- | --- | --- |
| correlation 또는 risk prepare, case assembly/projection, safe envelope 검증 | analysis가 있으면 abort → detection abort → lease release. 미반영/미ack. | 모두 성공적으로 정리되면 `DEGRADED`, 명시적 resume만 허용. Abort/release 자체가 실패하면 `FAILED`; raw 오류 비노출. |
| queue ack 실패 | analysis·detection abort 시도. **lease release를 추측하지 않음**. | `FAILED`; 성공 count 증가 금지, close만 허용. |
| ack 후 detection commit 실패 | rollback/release 금지. | `FAILED`; ack된 lease count를 잠재적 미반영 count에 더하고 재시도 금지. |
| detection commit 후 analysis commit 실패 | detection rollback·lease release 금지; publication 금지. | terminal `FAILED`; `analysis_uncommitted_after_ack_record_count`와 불일치 revision을 안전 count/code로 기록. 정확한 부분 적용을 추측하지 않는다. |
| analysis commit 후 publication 실패 | 두 committed state 유지, 자동 재게시·release 금지. | terminal `FAILED`; 잠재적 미게시 revision count 표시, close만 허용. |
| publication 성공 후 worker summary 실패 | 이미 게시된 event를 되돌리거나 다시 내보내지 않음. | terminal `FAILED`; snapshot에 고정 집계 불확실성 code, close만 허용. |

Phase 16에서는 이 순서를 **설계만** 한다. 현 worker·ack·publication 순서는 바꾸지 않는다.

## 5. Session-local identity·변화 의미

외부 ID는 현재 session의 monotonic ordinal `LIVE-REL-000001`, `LIVE-RISK-000001`, `LIVE-CASE-000001`이다. UUID·clock·IP·account·timestamp·그 hash에서 만들지 않으며 restart 뒤 동일성은 없다. 내부 trusted slot은 public `repr`/오류/log에 나오지 않는다. ID는 공격자·캠페인 식별자가 아니다.

| 종류 | trusted anchor와 변화 | public 상태·한계 |
| --- | --- | --- |
| Relation | `relation type + canonical subject IP + 원래 account + UTC failure/success endpoint`(post-auth는 success/file_access). 동일 anchor에서 승인된 전체 의미만 바뀌면 같은 ID `UPDATED`; nearest-success anchor가 바뀌면 이전 것은 `NO_LONGER_MATCHES`, 새 anchor는 `CREATED`. 최소 delta의 서로 다른 후보 동률은 기존 batch처럼 관계 없음. 동일 session의 같은 anchor 재등장은 ID 재사용, revision +1. | `ACTIVE` / `NO_LONGER_MATCHES_CURRENT_RESULT`. 해소·인과·침해 의미 없음. Original rationale 및 endpoint는 public 금지. |
| Risk | canonical subject IP당 ID 하나. Level, factor, confidence의 기존 전체 의미가 바뀌면 `UPDATED`·revision +1. 같은 subject가 남으면 risk가 HIGH→LOW로 내려가도 ID 유지. Subject가 실제 결과에서 사라질 때만 `NO_LONGER_PRESENT`(full-history V1에서는 일반적으로 발생하지 않음). | 낮아진 risk는 안전/해결 아님. 기존 rationale은 trusted 내부; 고정 승인 문구·level만 public. |
| Case | `rule_id + anchor relation ID`를 기준으로 하고 review order와 분리. 구성 observation/supporting relation/risk/confidence 변경은 같은 ID `UPDATED`; anchor가 바뀌면 옛 case `NO_LONGER_MATCHES`·새 case `CREATED`. 같은 anchor 재등장은 ID 재사용·revision +1. | `CURRENT` / `NO_LONGER_MATCHES_CURRENT_RESULT`. Generic→brute precedence로 rule이 바뀌면 옛 generic case를 새 brute case와 동일시하지 않는다. Merge/split은 억지 identity 승계 없이 bounded 검증; 모호하면 fail closed. |

Observation 소속은 매 prefix의 기존 assembler 결과가 출처다. 하나의 observation은 최대 한 case에만, 정확한 endpoint generic relation만 brute case supporting으로, 부분 overlap은 independent로 둔다. 새 event로 소속이 변하면 옛 case의 `UPDATED`/`NO_LONGER_MATCHES`와 새 case의 `CREATED`/`UPDATED`를 같은 analysis revision에서 표현하되 endpoint fact를 복제하지 않는다. Spray case no-go, 웹끼리의 자동 결합, 웹과 인증 결합, global correlation, Linux Audit 결합은 허용하지 않는다.

## 6. 향후 public DTO와 publication/UI 계약 — 이번 단계 미구현

기존 `InvestigationCaseProjection`은 IP를 포함하므로 **public live projection으로 재사용 금지**. 아래는 별도의 frozen·tuple 기반, closed schema v1 후보이다. 모든 정수는 bool을 거부하는 0 이상 signed-64, ID·enum은 exact allowlist, unknown key는 거부한다. `repr`/오류/serializer도 같은 안전 필드만 허용한다.

| DTO | exact field (허용 enum) |
| --- | --- |
| `LiveAnalysisSnapshot` | `schema_version="1"`, `analysis_revision`, `detection_revision`, `state=CURRENT\|DEGRADED\|INTEGRITY_FAILURE`, `source_role=application\|ssh\|access`, `active_relation_count`, `current_risk_count`, `current_case_count`, `independent_observation_count`, `relations: tuple[LiveRelationSummary,...]`, `risks: tuple[LiveRiskSummary,...]`, `cases: tuple[LiveCaseSummary,...]`, `independent_observation_ids: tuple[str,...]`, `fixed_warning_codes: tuple[str,...]` |
| `LiveRelationSummary` | `relation_id`, `relation_revision`, `state=ACTIVE\|NO_LONGER_MATCHES_CURRENT_RESULT`, `relation_type=failed_to_successful_login\|brute_force_to_successful_login\|password_spray_to_successful_login\|successful_login_to_file_access`, `evidence_count` (승인된 숫자만) |
| `LiveRiskSummary` | `risk_id`, `risk_revision`, `state=CURRENT\|NO_LONGER_PRESENT`, `risk_level=HIGH\|MEDIUM\|LOW`, `confidence_level=HIGH\|MEDIUM\|LOW` |
| `LiveCaseSummary` | `case_id`, `case_revision`, `state=CURRENT\|NO_LONGER_MATCHES_CURRENT_RESULT`, `rule_code=CASE-AUTH-TRANSITION-01\|CASE-BRUTE-SUCCESS-01`, `included_highest_risk`, `included_highest_confidence`, `observation_count`, `supporting_relation_count` |
| `LiveAnalysisChange` | `analysis_revision`, `category=RELATION_CREATED\|RELATION_UPDATED\|RELATION_NO_LONGER_MATCHES\|RISK_CREATED\|RISK_UPDATED\|RISK_NO_LONGER_PRESENT\|CASE_CREATED\|CASE_UPDATED\|CASE_NO_LONGER_MATCHES`, `public_id`, `item_revision` |

모든 tuple은 item·serialized byte 상한이 필요하다. Public에는 raw event/detection/relation/risk/case, 원래 rationale/evidence, subject key/hash, account/IP, HTTP path/query, argv, 파일 경로, timestamp 원문, global/Linux detail이 없다. 기존의 account alias unavailable 상태와 개인정보 보호 문구는 유지하되 alias를 임의 생성하지 않는다. Trusted join·case assembly·기존 projection에는 원래 account/IP가 필요하고 내부 dataclass `repr`에도 IP가 있을 수 있으므로 **절대 public object나 log로 취급하지 않는다**.

향후 전송은 한 successful worker step의 detection+analysis 안전 change를 **하나의** `analysis_changes` event로 묶는 안을 권장한다. Detection revision과 analysis revision은 같은 committed step 번호를 공유하고 event ID는 별도의 게시 순서다. Empty change revision은 snapshot watermark만 전진하며 event 없음. 이 안은 기존 `observation_changes` schema를 바꾸므로 Phase 16.2에서 기존 SSE/API/JS consumer를 한 번에 이행하고 replay item/16KiB byte 예산, 느린 client gap을 재검증해야 한다. Phase 16.1에서는 publication/SSE 변경 없음. UI는 연결 상태 → 탐지 관찰 → 지원되는 관계 → 현재 위험도 변화 → 조사 사례 변화 → 독립 관찰 → 한계/복구 순서를 권장하되 **현재 Phase 15 화면에 섞지 않는다**. 문구는 “지원되는 관계”, “포함된 최고 위험도”, “현재 결과에서 더 이상 일치하지 않음”을 사용하고 인과·공격 성공·안전·해결을 말하지 않는다.

## 7. Phase 16.1 최소 구현 제안과 no-go

**Phase 16.1 권장: 단일 `application` source만**. 기존 256/256KiB full-prefix history에서 auth·brute·spray·실제 file_access의 per-IP 관계를 기존 함수로 재계산하고, 기존 risk 및 typed assembler/projection을 trusted 내부에서 재사용한다. Generic/brute case만 실제 생성한다. Typed proposal/commit/abort와 안전 내부 snapshot, session-local relation/risk/case ID, 모든 prefix의 batch parity를 추가하되 worker·ack·publication·API·SSE·UI에는 아직 연결하지 않는다. SSH는 같은 모델의 후속 parity 확장, access는 독립 웹 관찰/risk 연구를 유지한다. 현재 config를 두 source로 넓히지 않는다. 계산 시간·peak memory·event-loop stall은 작은 합성 benchmark로 측정하고 운영 SLA로 일반화하지 않는다.

명시적 **no-go**: partial/rolling history로 조용히 계속 계산; processing time을 event time으로 사용; IP/account/hash를 public ID에 넣기; batch와 다른 closest/tie 선택; ambiguous relation 또는 merge/split을 추측; 관계 소멸/위험도 하향을 해결·안전으로 표시; observation 다중 case 소속/endpoint 복제; typed 근거 없는 Spray membership; 웹끼리·웹과 인증 자동 결합; global correlation 사용; raw relation/risk/case SSE 전송; ack 이후 rollback 주장; unbounded history/journal; event마다 LLM 호출. 이 중 하나가 필요하면 구현을 중단해 의미·privacy 계약을 다시 설계한다.

## 8. Research basis → observable evidence mapping → limitations

외부 자료는 **조사 원칙**의 근거이고 프로젝트의 60초 correlation·120초 case·brute/spray threshold와 grouping rule을 정한 자료가 아니다. 수치와 case precedence는 위 production의 프로젝트 정책으로만 취급한다.

| 1차 자료 | 발행·확인한 사실 | 이 설계에 미친 영향 |
| --- | --- | --- |
| [NIST SP 800-61 Rev.3, Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final), 2025-04 final | 사고 대응을 더 넓은 위험 관리 활동에 통합하는 지침이며 개별 로그 관계를 침해 확정으로 바꾸지 않는다. | live case를 조사 후보로만 명명하고 analyst 확인·불확실성 문구를 유지. |
| [NIST SP 800-92, Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final), 2006-09 final | 보안 로그의 수집·관리·분석을 위한 상위 실무 지침. 2023 Rev.1은 현재 initial public draft이므로 이 설계의 구현 수치 근거로 쓰지 않음. | source 범위·누락·gap·보존 한계를 표시하고 prefix history를 조용히 축약하지 않음. |
| [MITRE ATT&CK T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/), 2026-05 수정본 | 반복 인증 시도와 실패가 관찰 신호일 수 있지만 그 자체로 credential 획득을 입증하지 않는다. | 실패·성공 event의 동일 account/IP/UTC 관계만 계산하고 공격 성공 결론을 금지. |
| [MITRE ATT&CK T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/), 2025-10 수정본 | 여러 계정에 적은 수의 비밀번호를 시도하는 기법 설명. | 현재 로그에는 **동일 비밀번호 사용 사실이 없으므로** 기존 `password_spraying_like` 명칭과 Spray case no-go 유지. |

Observable mapping: 위 ATT&CK 행동 설명 → 필요한 인증 결과·원래 account·source IP·event time → application/SSH parser의 `event_type/user/src_ip/timestamp`와 기존 detection evidence → production의 60초·closest·동률 조건 → 구조화된 **관계 관찰**. 비밀번호 값·계정 소유권·세션 지속성·실제 파일 열람/유출·공격자 의도는 관찰되지 않는다. 정상 사용자의 재시도, 공유/NAT IP, 테스트 계정, 관리 자동화는 비슷한 패턴을 만들 수 있다. 느린 시도, 다른 source, 누락/rotation/crash, out-of-order 도착, account 이름 불일치는 관계를 놓치거나 prefix 결과를 바꿀 수 있다. 추가 검증에는 서비스별 인증 감사, 세션·계정 소유권, 실제 파일/응답 내용과 승인된 운영 맥락이 필요하지만 이번 live V1은 이를 자동 수집하지 않는다.
