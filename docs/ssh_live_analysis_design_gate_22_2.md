# Phase 22.2 — SSH live 분석 설계·prefix parity gate

판정: **기존 SSH batch 의미 재사용은 조건부 GO, 현재 live 분석 공개 연결은 NO-GO.** 이 단계는 새 correlation/risk/case 규칙을 만들지 않고 실제 계약과 실패 지점을 검증했다. `application`용 analysis accumulator·worker·publication·브라우저 exact validator의 source guard만 풀어 SSH를 활성화해서는 안 된다. SSH durable checkpoint도 현재 지원하지 않는다. Production 코드·API·SSE·UI·checkpoint 형식은 변경하지 않았다.

시작점은 clean `main`의 `035f03e16ed8f16207a62ec47561def2eff0893d`, `origin/main...HEAD` behind 0/ahead 0이었다. 정확한 SHA의 [원격 CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38835181349)는 completed/success로 확인됐다. Phase 22.1 REA pilot은 `PILOT_BLOCKED_SUPPLY_CHAIN`에서 닫고 REA CLI·setup·MCP는 실행하지 않았다. 변경 전 전체 `uv run pytest -q`는 2,181 passed, 기존 경고 2개였다.

## Research Basis와 Observable Evidence Mapping

| 공식 근거 | 적용 가능한 사실 | 저장소의 관찰 필드와 결정 |
|---|---|---|
| [OpenBSD `sshd_config(5)`](https://man.openbsd.org/sshd_config.5), 2026-10-16 확인 | `sshd`는 password·publickey 등 여러 인증 방법과 설정 가능한 로그 수준을 갖는다. 로그 포괄성은 설정에 따라 달라진다. | `parse_ssh_auth_log()`가 지원하는 `Failed`/`Accepted` password·publickey 문구만 기존 `login_failed`/`user_login`으로 정규화한다. 미지원 문구를 임의로 인증 성공·실패로 해석하지 않는다. |
| [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/), 2026-05-12 갱신판 | SSH 반복 인증 실패와 가능한 후속 성공은 조사할 수 있는 관찰이다. ATT&CK 기술명이 침해 증거는 아니다. | 기존 `src_ip`·`user`·UTC timestamp·failure/success event와 detector evidence만 사용한다. 새 threshold나 ATT&CK 기반 판정은 만들지 않는다. |
| [MITRE ATT&CK T1110.003](https://attack.mitre.org/techniques/T1110/003/), 2026-10-16 확인 | 다계정 인증 실패 관찰만으로 동일 비밀번호 재사용을 알 수 없다. | 기존 spray-like detection/relation은 유지하되 spray case는 계속 NO-GO이며 credential reuse를 주장하지 않는다. |

연구가 선택한 수치는 없다. **60초 relation·120초 brute case 범위와 5회 brute threshold는 기존 프로젝트의 평가·production 계약**이며 OpenSSH나 MITRE의 보편 기준이라고 주장하지 않는다. 정상 사용자의 재시도, NAT·공유 IP, 자동화, 불완전한 로그, 서로 다른 인증 방법이 같은 패턴을 만들 수 있다. `Accepted` 로그는 해당 인증 기록의 성공이지 계정 탈취·동일 행위자·후속 세션 행위를 증명하지 않는다.

## 현재 코드와 batch-prefix oracle

| 계층 | 현재 SSH 의미와 gate 결과 |
|---|---|
| Parser | `app/parser/ssh_auth.py` → `app/live_monitoring/parser_adapter.py`: 기존 parser와 `Asia/Seoul` 설정을 사용해 UTC로 정규화한다. 원문 timestamp는 **초 단위만** 지원한다. 공백은 `IGNORED`, 잘못된 timestamp와 raw microseconds는 `REJECTED`, timestamp가 정상인 미지원 sshd 문구는 `event_type=None`의 `PARSED`다. |
| Detection | `LiveDetectionAccumulator`는 SSH의 전체 bounded PARSED prefix에 기존 `detect_attacks()`를 적용한다. 256 event/256 KiB를 넘기면 조용히 eviction하지 않는다. 기존 `tests/test_live_detection_equivalence.py`와 새 `tests/test_ssh_live_analysis_gate.py`의 매 prefix 비교가 일치했다. |
| Correlation | `correlate_authentication_transition()`·`correlate_brute_force_to_success()`·`correlate_password_spray_to_success()`는 source-agnostic per-IP production 함수다. 정확히 같은 계정·IP, 실패보다 뒤의 성공, 60초 이내, 최소 delta의 유일한 endpoint를 요구한다. 정확한 중복 fact는 하나로 보고 서로 다른 최소 delta 동률은 관계 없음이다. File-access는 SSH parser가 만들지 않으므로 post-auth relation은 제외한다. Global·web·cross-source도 live case로 옮기지 않는다. |
| Risk | 기존 `assess_risk()`는 SSH failure feature, detection, auth relation 및 승인된 account metadata를 사용한다. SSH 전용 새 score는 필요하지 않다. Live 연결 시에는 application과 동일하게 사전 주입된 metadata snapshot을 써야 하며 경로/원문을 public DTO에 넣어서는 안 된다. |
| Case | 기존 `IncidentCaseSubjectInput` adapter와 `assemble_incident_cases()`는 SSH generic/brute 관계에도 적용된다. `CASE-BRUTE-SUCCESS-01`이 동일 endpoint generic relation을 supporting으로 묶고 120초 범위를 유지한다. Partial overlap은 독립, spray case는 없음. 기존 public case projection의 `supporting_relation_count`는 이 합성 사례에서 **2**, live safe DTO의 `relation_count-1`은 **1**이므로 필드명을 같게 보아 임의로 교환하지 않는다. |

새 테스트는 매 SSH prefix의 live detection을 production detector와 비교하고, 동일 prefix를 production `correlate_attacks()`·`assess_risk()`·case projection에 넣어 batch oracle을 만든다. 5회 임계값, 실패→성공, brute/generic, spray 독립, 가까운 성공, input order, 동률, 동일 계정·IP 경계, 성공 선행, 60초 정확한 경계·초과, typed microseconds, 공백·malformed·미지원 문구를 확인했다. Raw SSH microseconds는 parser가 거부하므로 typed timestamp 주입의 관계 결정성만 검증했으며 원문 지원으로 표현하지 않는다. 기존 batch oracle과 아직 존재하지 않는 SSH live analysis 결과의 parity를 주장하지 않는다.

`src_ip=not-an-ip` 형태의 SSH 문구는 현재 parser·detection까지 통과하지만 case adapter의 canonical IP 검증에서 `unsupported_result_shape`로 고정 실패한다. 값이 오류에 포함되지는 않는다. SSH live 분석을 연결한다면 이 입력을 **ack 전에 fail closed**하고 기존 detection-only 동작과의 차이를 사용자에게 설명해야 한다. 이를 임의로 조용히 버리거나 IP로 추정하지 않는다.

## 설계 gate와 수정 전 실패 증거

수정 전 `LiveAnalysisAccumulator(LiveDetectionAccumulator("ssh", ...), ())`가 성공할 것을 기대한 집중 테스트는 `LIVE_ANALYSIS_UNSUPPORTED_SOURCE`로 실패했다(다른 batch-prefix 테스트 3건은 통과). 이는 구현 누락을 재현한 것이며 최종 suite에는 지원된 척하는 실패 테스트를 남기지 않고 기존 SSH detection-only 경계를 확인하는 테스트로 고정했다.

| 영역 | 현재 불변식 | SSH 연결 전에 필요한 검증 |
|---|---|---|
| Internal analysis | `analysis_accumulator.py`의 snapshot·proposal·constructor·prepare가 `application`만 허용 | source enum을 `application|ssh`로 **명시적으로** 넓히되 production correlation/risk/case mapping을 복제하지 않음; SSH file-access/unknown relation fail closed; trusted prefix identity와 revision 일치 |
| Worker/transaction | `worker.py`는 SSH analysis가 `None`, application만 analysis prepare→publication prepare→ack→commit | SSH에 동일 pre-ack 계산·cross-proposal 검사·abort/release FIFO·post-ack terminal failure를 독립 fault matrix로 증명. Step 재진입·두 worker 공유 금지 |
| Publication/API/SSE/UI | `publication.py`의 analysis event 및 `frontend/live-monitoring.js`의 status·snapshot·event exact validator가 application만 허용 | safe DTO와 schema 2의 모든 소비자를 함께 이행; detection `observation_changes` 불변, 같은 revision의 두 event batch 원자성, 단일 replay cursor/gap, SSH source/session 검증 |
| Privacy | 현재 SSH는 detection-only safe snapshot; 새 테스트의 account/IP/path canary는 worker `repr`, step result, snapshot JSON에서 비노출 | SSH analysis가 연결된 뒤 status·snapshot·analysis_changes·replay·gap·DOM·console·storage·OpenAPI에서 raw 계정/IP/path/query/evidence/예외를 다시 검증. 사용자 문구는 관계≠인과·성공≠침해 |
| Restart | v2 기본 config와 private checkpoint schema·replay는 `application` 전용; SSH 명시적 v1 config는 재시작마다 `FROM_END` | **SSH durable restart는 이번 gate의 NO-GO.** 별도 승인된 config/checkpoint 계약, private metadata 범위, source binding, bounded replay, old publication 억제, crash window 검증 전 활성화 금지. Application same-file checkpoint 회귀만 별도로 통과 |

Checkpoint를 SSH에 확장하려면 private 파일에 최소한 `source_role=ssh`, config/source binding, file identity, replay start·committed byte offset, revision·bounded history 검증 metadata가 필요하다. 이 값은 사용자 공개 경계에 나가면 안 되고 config/checkpoint 삭제까지 private로 보존된다. 현재 단계에서는 저장 범위·형식을 변경하거나 SSH 로그를 replay하지 않았다. Automatic rotation/copytruncate handoff와 두 파일 세대 metadata 확대는 계속 NO-GO다.

개인정보 경계는 trusted 내부 원본과 공개 allowlist를 분리하는 것이다. 원래 account·IP·raw line·source path와 relation rationale은 내부 계산에는 필요할 수 있지만, 공개 snapshot·SSE·DOM·일반 오류에 복사하지 않는다. 현재 SSH detection-only canary 검사만 PASS이며, SSH 분석 상세의 공개 비노출은 아직 검증되지 않았다.

향후 SSH 화면의 승인 후보 문구는 “같은 계정·IP와 시간 조건에 일치하는 SSH 인증 기록입니다. 이 관계는 인과관계, 계정 탈취 또는 동일 행위자를 확정하지 않습니다.”이다. 위험도는 기존 로그 관찰의 검토 우선순위로만, 조사 사례는 함께 검토할 관찰 묶음으로만 표현한다. 이 문구는 아직 UI에 연결되지 않았으며 Safari 접근성 검증도 받지 않았다.

## 검증 범위와 후속 분리

합성 host 테스트는 현재 SSH worker가 **detection-only**임을 재확인하고, account·IP·source-path canary가 현재 safe snapshot·직렬화·`repr()`에 없음을 확인했다. `tests/smoke_ssh_live_gate.py`는 기존 파일에서 `FROM_END`로 시작해 합성 SSH 실패 5회·성공 1회를 append하고 live worker detection과 같은 prefix의 **별도 batch** 관계·risk·case를 검사했다. macOS와 Docker Linux/arm64의 격리 실행(`--network none`, read-only root, capability 제거, no-new-privileges, resource 상한)에서 통과했다. Docker에는 `app`과 이 스크립트만 임시 volume으로 전달했고 원본 로그·홈·저장소 전체는 mount하지 않았다. 전용 container·volume은 제거했다. 이는 SSH live relation/risk/case·UI smoke가 **아니다**.

기존 application checkpoint same-file replay·brute relation/risk/case·UTC/KST safe verification 집중 테스트 3건은 통과했다. SSH checkpoint restart, SSH `analysis_changes`, Safari 사용자 흐름은 `NOT_TESTED/NOT_SUPPORTED`이다. 다음 단계는 먼저 **in-memory SSH analysis accumulator의 trusted prefix parity**를 독립적으로 입증하고, 그 뒤 worker/publication/공개 exact schema를 한 묶음으로 이행하는 편이 안전하다. SSH checkpoint는 별도 저장·복구 설계와 승인 gate로 남긴다. 분석 결과가 침해 확정이라는 문구, 조용한 gap, 새 file-access/global/cross-source 관계가 나타나면 NO-GO다.

검증 결과: 변경 전 전체 2,181 passed, 변경 후 전체 2,193 passed이며 두 실행 모두 기존 경고 2개뿐이다. 관련 focused 159 passed, SSH 관계 결정성 UTC·Asia/Seoul·반복 실행 각각 22 passed, 기존 application checkpoint 재생 집중 3 passed였다. 인증·웹 79/79, Linux 21/21, risk 70/70, case 70/70 평가가 유지됐다. `uv lock --check`, 변경 Python `py_compile`, Node 문법·동작 테스트, `git diff --check`도 통과했다. 호스트와 Docker Linux/arm64 smoke는 합성 입력만 사용한 개발 검증이며 운영 성능·정확도·무유실 보장이 아니다. Docker 검증은 전용 컨테이너·volume을 제거했지만 공유 image cache의 secure erase를 주장하지 않는다. Dependency와 `uv.lock`은 바꾸지 않았다.
