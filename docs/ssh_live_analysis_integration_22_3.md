# Phase 22.3 — 단일 SSH source live analysis 결합

현재 범위: 명시적 v1 `--monitor-config`의 **SSH 파일 하나**를 `FROM_END`로 열고, 기존 SSH parser·detector와 batch production correlation·risk·case 함수를 같은 bounded prefix에 적용한다. Application live 계약은 유지하고 access는 detection-only다. 기본 설정 마법사·v2 private checkpoint는 application 전용이며 SSH checkpoint 재시작은 지원하지 않는다. 이 문서는 공개된 v0.2.0 릴리스 노트의 과거 범위를 소급 변경하지 않는다.

## Research Basis와 observable mapping

[Phase 22.2 설계·parity gate](ssh_live_analysis_design_gate_22_2.md)는 [OpenSSH `sshd_config(5)`](https://man.openbsd.org/sshd_config.5), [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/)·[T1110.003](https://attack.mitre.org/techniques/T1110/003/)을 기존 observable SSH telemetry에 매핑했다. 이번 단계는 새로운 security 의미나 threshold를 만들지 않는다. 기존 parser가 받아들이는 `Failed`/`Accepted` password·publickey 기록의 `user`, `src_ip`, timezone-aware UTC timestamp와 detection evidence만 production 함수에 공급한다. `Accepted`는 해당 인증 기록의 성공이지 계정 탈취·동일 행위자·인과관계의 증거가 아니다. 기존 5회 brute threshold, 60초 관계 범위, 120초 case 범위는 프로젝트의 기존 계약이지 외부 표준의 보편 수치가 아니다.

## Public/internal 계약

| 계층 | Phase 22.3 계약 |
|---|---|
| Source | `LiveAnalysisAccumulator`는 exact `application|ssh` detection accumulator 하나에만 바인딩된다. `access`·unknown은 거부한다. SSH에서는 production post-auth/file-access 결과가 참일 수 없고 나타나면 fail closed한다. Global·web·cross-source와 Spray case는 만들지 않는다. |
| Prefix | 매 prepare에서 detection proposal의 같은 전체 bounded candidate prefix(최대 **256 PARSED event / 256 KiB**)를 참조한다. Parser·detector·correlation·risk·case 규칙을 복제하지 않는다. History eviction 대신 상한 실패다. |
| Trusted parity | 각 SSH prefix에서 기존 `detect_attacks()`와 `assess_risk(correlate_attacks(...))`, `project_investigation_cases_from_analysis()` 결과와 직접 비교한다. 원래 account/IP와 timestamp·delta·risk·case membership은 trusted 테스트 내부에서만 비교한다. 공개 safe DTO의 supporting count는 batch public case row count와 다른 뜻이므로 동일 수치로 치환하지 않는다. |
| 공개 schema | Status schema `2`, SSE snapshot schema `2` 및 내부 analysis snapshot schema `1`의 **기존 닫힌 필드명은 그대로**다. `analysis_available=true`는 application 또는 SSH, access에서는 false다. 안전한 `analysis_changes.source_role`은 `application|ssh`; SSH 관계는 실패→성공, brute→성공, spray→성공만 허용한다. File-access 관계는 SSH에서 거부한다. |
| 브라우저 | 단일 공통 `LIVE-EVENT-*` cursor에서 `observation_changes` 다음 `analysis_changes`를 같은 revision의 서로 다른 event ID로 받는다. 기존 staged 32 event / **16 KiB** pending과 사용자 선택 적용, pause/replay gap 복구를 유지한다. SSH event의 source 역할이 현재 status와 다르거나 private/unknown 필드가 있으면 전체 event를 거부한다. |

공개 snapshot·SSE·UI·worker result에는 원래 account, IP, raw line, source/config path, evidence, rationale, hash, 내부 offset·identity나 예외 원문을 넣지 않는다. Trusted accumulator `_state`에는 원본 값이 존재할 수 있으므로 public 경계로 직렬화하지 않는다. ID는 session-local ordinal이며 재시작 뒤 연속성을 뜻하지 않는다. Risk는 기존 로그 관찰의 검토 우선순위이고 조사 사례는 함께 검토할 묶음이지 확정 사고가 아니다.

## Transaction과 실패 의미

SSH worker는 단일 caller로 `poll → lease → parse → detection prepare/prevalidate → analysis prepare → 두-event publication prepare/직렬화·상한·source/revision/prefix identity 검증 → source identity probe → queue ack → detection commit → analysis commit → publication reference swap → 안전 worker summary`를 실행한다. Ack 전 실패는 analysis·detection·publication proposal을 abort하고 lease를 release해 FIFO를 복구한 뒤 `DEGRADED`로 멈춘다. 명시적 resume 전 자동 처리하지 않는다. Ack 실패는 release를 추측하지 않고 `FAILED`다. Ack 뒤 detection/analysis/publication 실패는 queue rollback·자동 재게시·동일 revision 재시도 없이 terminal `FAILED`다. 두 publication event 중 하나만 buffer에 남는 부분 게시를 허용하지 않는다. 이는 원자적 transaction, exactly-once 또는 무유실이 아니다.

SSH parser가 syntax상 받아들인 비정규 `src_ip`라도 case adapter가 canonical subject로 투영할 수 없다면 **ack 전에** 고정 `ANALYSIS_PREPARE_FAILED`와 FIFO release로 fail closed한다. 오류에는 해당 값이나 내부 예외가 없다. 정상 종료 시 worker가 analysis·publication·tail을 닫고 FD를 해제한다.

## 검증과 한계

수정 전 `LiveAnalysisAccumulator(ssh)`를 기대한 두 테스트는 `LIVE_ANALYSIS_UNSUPPORTED_SOURCE`로 실패했다. 이후 새 집중 테스트는 SSH 매 prefix의 trusted batch-prefix parity, brute/generic supporting case, nearest-success, 순서 역전, tie refusal, Spray case no-go, 다른 계정/IP, ignored/rejected 문구와 안전 DTO를 검증한다. Fault injection은 SSH correlation/publication prepare, ack, detection/analysis/publication commit의 queue·revision·상태·원문 비노출을 각각 확인한다. Status, snapshot, `observation_changes`/`analysis_changes` SSE, 공통 replay/gap, 브라우저 exact validator·staged apply와 synthetic append→관계·risk·case smoke를 확인한다. Application 전체 회귀와 access detection-only는 그대로 유지한다.

이번 단계는 SSH durable checkpoint, 재시작 중 append 복구, rotation/copytruncate handoff, 두 파일 세대 metadata, cross-source, Linux Audit live, file-access SSH 관계, 새로운 detector·risk·case 규칙을 구현하지 않는다. SSH 명시적 v1 실행은 재시작마다 `FROM_END`이고 이전 SSE replay·session-local ID는 이어지지 않는다. 실제 Safari 수동 keyboard·확대·VoiceOver 및 운영 성능은 이 자동 테스트로 PASS라고 주장하지 않는다. 개발용 합성 평가의 점수도 운영 탐지율이 아니다.

최종 검증에서 SSH·worker·publication 집중 **116 passed**, 전체 **2,217 passed**였고 변경 전부터 있던 의존성 deprecation 경고 2개 외 새 경고는 없었다. 합성 인증·웹 **79/79**, Linux **21/21**, risk·case 각각 **70/70**을 유지했다. UTC·Asia/Seoul·반복 실행의 SSH 집중 결과는 각각 **31 passed**였다. Node 브라우저 동작 테스트, 실제 loopback SSH append/SSE/종료 테스트와 별도 합성 smoke, `uv lock --check`, 변경 Python `py_compile`, `git diff --check`도 통과했다. 이는 고정 합성 입력의 검증이지 운영 SLA·실제 Safari 검수를 대체하지 않는다.
