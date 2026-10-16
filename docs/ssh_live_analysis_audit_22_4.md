# Phase 22.4 — SSH live analysis 독립 수용·장애·개인정보 감사

판정: **CONDITIONAL GO**. 단일 SSH v1 source의 합성 자동 수용 흐름에서 새로운 blocker는 확인되지 않았다. 이는 실제 Safari 수동 접근성, 운영 로그의 정확도, 무유실 또는 운영 SLA 승인이 아니다. REA 실행형 pilot은 별도 **NO-GO**이며 이번 감사에서 설치·실행하지 않았다.

## 기준선과 범위

`main` 시작 SHA `1686ffc6e72673e56f7d181864146618620e7d8b`는 원격 `main`과 같고 clean이었다. [해당 SHA CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38863289136)는 completed/success였다. v0.2.0 annotated tag와 공개 Release는 `2520e317475f96d48b4bfeef8f7ee04d63720308`을 유지했다. 변경 전 전체 pytest는 **2,217 passed**, 기존 Starlette/httpx·AnyIO deprecation 경고 **2개**였다.

이 감사에서는 탐지·correlation·risk·case 규칙과 공개 schema를 바꾸지 않았다. 명시적 v1 `--monitor-config`의 SSH 파일 하나만 `FROM_END`로 실행한다. Application은 기존 live 분석, access는 detection-only이며 SSH checkpoint 재시작은 없다.

## 증거별 추적성

| 검수 항목 | 판정 | 근거와 한계 |
|---|---|---|
| 기존 줄 미처리 → 실패 append → brute 관찰 → 성공 append → 관계 2개·risk·`CASE-BRUTE-SUCCESS-01` | PASS | 합성 loopback HTTP/SSE smoke와 Safari 18.6 WebDriver staged UI. 성공 로그는 침해 성공으로 표시하지 않는다. 사람의 이해도는 NOT_TESTED. |
| 버튼 전 네 결과 목록 불변, 버튼 뒤 탐지·관계·위험도·사례 분리 | PASS | Safari WebDriver의 DOM 상태·버튼 적용. DOM click은 keyboard-only 검수가 아니다. |
| SSH batch/live 각 prefix의 trusted detection·correlation·risk·case 의미 | PASS | Phase 22.3 prefix oracle과 이번 전체 회귀. 60초 정확/초과·microseconds·nearest success·후보 동률·순서 역전·중복·ignored/rejected·다른 계정/IP를 분리한다. 고정 합성 범위 밖은 미검증. |
| SSH file-access 관계 금지, Spray case no-go, access detection-only | PASS | 기존 prefix·source 정책 테스트와 UI exact validator. Cross-source 추론 없음. |
| Parse~summary 개별 worker fault와 ack 전 FIFO·ack 후 terminal 의미 | PASS | 같은 worker 구현을 application·SSH 각각에 대해 **23 fault ID**로 실행. SSH 전용 correlation, publication, ack, 각 commit 시험도 별도 유지. Ack 후 rollback·자동 재게시·재처리를 주장하지 않는다. |
| 두-event publication의 직렬화·item/byte·snapshot byte cap 실패 | PASS | SSH 전용 6개 fault case: 모두 ack 전 release, revision 0/0, 부분 게시 0. 기존 공통 batch swap fault 회귀도 통과. |
| SSE event 순서, 단일 cursor, 정상 replay와 gap | PASS | 실제 SSH loopback `snapshot → observation_changes → analysis_changes`, 서비스 replay/gap 테스트. 과거 event를 안전/0건으로 추측하지 않는다. |
| Pending 32건/16 KiB, 중복 ID, NO_LONGER 및 risk 하향 문구 | PASS | 공통 Node exact validator·staged queue 테스트와 SSH source별 수용·file-access 거부 테스트. 실제 Safari에서 overflow를 수동 재현한 것은 NOT_TESTED. |
| SSH trusted history 256-event 상한 | PASS | 256개 확정 후 257번째 parsed event는 ack 없이 FIFO로 되돌아가며 `DEGRADED`; 일부 history를 조용히 버리지 않는다. |
| 개인정보 safe DTO, status, SSE, OpenAPI, DOM, 오류·repr·asdict·JSON·stdout/stderr | PARTIAL | 서로 다른 합성 account/IP/path/내부 예외 canary를 SSH worker·publication·loopback·Node에서 검사했고 노출은 없었다. 모든 경계를 모든 canary로 교차 검증하거나 Safari Web Inspector 콘솔·Network를 수동 감사한 것은 아니다. Trusted 내부 prefix에는 원래 값이 존재할 수 있다. |
| 정상·DEGRADED·FAILED 종료의 FD·proposal·listener·SSE slot·runner task | PARTIAL | SSH 정상 loopback SIGINT 뒤 listener 해제, session FD 닫힘. fault matrix의 DEGRADED/FAILED close 뒤 FD 닫힘·proposal 상태와 서비스 SSE slot 반환을 확인했다. 별도 SSH runner의 모든 terminal task cancellation race와 crash kill은 미검증이다. |
| Safari keyboard-only, 실제 200% 확대, Web Inspector JS/CSP, VoiceOver | NOT_TESTED | Safari 18.6 WebDriver DOM click은 수동 검증을 대체하지 않는다. |

`NO_LONGER_MATCHES`와 risk 하향은 현재 누적 결과의 불일치·검토 우선순위 변화이며 해결·안전·공격 종료가 아니다. SSH 인증 성공도 계정 탈취, 동일 행위자 또는 인과관계를 증명하지 않는다.

## 개발용 성능과 결정성

macOS 15.7.7 arm64, Python 3.12, 합성 SSH prefix **256 PARSED event / 23,042 raw bytes**(탐지 1·관계 2·risk 1·case 1)에서 `tests/benchmark_ssh_live_analysis_22_4.py`를 실행했다. Warm-up 1회, 측정 8회, `tracemalloc` 없음. 단위는 ms이며 p95는 작은 표본의 nearest-rank 값이다.

| 구간 | median | p95 | max |
|---|---:|---:|---:|
| 256-prefix 마지막 worker step | 7.789 | 9.033 | 9.033 |
| analysis prepare | 5.113 | 6.251 | 6.251 |
| publication prepare | 0.290 | 0.508 | 0.508 |
| publication commit | 0.009 | 0.011 | 0.011 |

Runner 활성 중 in-process TestClient status HTTP는 warm-up 1회·40요청, median **1.919ms**, p95 **2.475ms**, max **5.490ms**였고 실제 worker step과 겹친 요청은 1개였다. 0.5초 polling interval 이내였지만 이는 운영 SLA나 최악 입력 보장이 아니다. SSH·Phase 22.3 gate 집중 테스트를 UTC·Asia/Seoul·반복 실행 각각 31개 통과시켰고 safe result와 JSON 계약의 결정성을 확인했다.

## 정리와 남은 경계

Safari 18.6 WebDriver smoke는 합성 SSH append 후 버튼 적용 전 네 목록이 비어 있고 적용 뒤 모두 채워짐을 확인했다. Account canary가 DOM에 없었고 loopback status/SSE/OpenAPI·서버 stdout/stderr에도 원문 canary는 나타나지 않았다. WebDriver session, loopback listener, tail FD, 임시 config/source는 정상 종료 뒤 정리됐다. 강제 종료 후 crash recovery나 secure erase는 시험·주장하지 않는다.

SSH durable checkpoint·rotation/copytruncate handoff·두 파일 세대 metadata·cross-source 분석은 계속 미지원이다. 실제 Safari 수동 keyboard-only·확대·콘솔/CSP/Network 감사, 다양한 운영 로그 표본, terminal race 추가 검증이 남아 있으므로 최종 사용자 수용성은 조건부다. REA는 공급망 **NO-GO**를 유지한다.

검증 후 집중 pytest **123 passed**, 전체 pytest **2,249 passed**였다. 변경 전후 모두 의존성 deprecation 경고 2개이고 새 경고는 없다. 합성 인증·웹 **79/79**, Linux **21/21**, risk·case 각각 **70/70**을 유지했다. Node 문법·동작, `uv lock --check`, 변경 Python `py_compile`, `git diff --check`도 통과했다. Production 코드·의존성·lockfile·공개 schema는 변경하지 않았다.
