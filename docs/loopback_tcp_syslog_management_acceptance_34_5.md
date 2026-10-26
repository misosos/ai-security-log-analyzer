# Phase 34.5 — loopback TCP Syslog management 사용자 수용

## 범위와 판정

이 검수는 임시 HOME과 합성 application/SSH 메시지로 setup, show, run, endpoint reveal, lock 충돌, delete 안내를 확인했다. 실제 사용자 로그·설정·checkpoint에는 접근하지 않았다. endpoint 표시 검수에 사용한 loopback 주소와 port는 임시 환경에서만 사용하고 종료 후 폐기했다. 성공 제한 보고서나 실제 사용자 자료는 만들지 않았다.

사용자는 명령을 직접 조작하지 않았다. 실제 CLI를 실행해 캡처한 화면을 한 항목씩 보고 이해 여부를 응답했다. 아래 사용자 PASS는 자동 테스트와 구분되며 실제 운영 사용의 승인으로 해석하지 않는다.

**Phase 34 종료 판정:** 합성 loopback 관리 pilot: `GO`. 10개 안내 항목의 최종 사용자 응답은 모두 `PASS`다. 이 GO는 Phase 34.5 시작 SHA의 CI 및 캡처 화면 기반 사용자 수용 범위에 한정한다. 실제 사용자 자료·조직 운영·원격 수집은 계속 `NO_GO`다. Phase 35.0의 다음 아키텍처 제안은 별도 프로세스 Vector 합성 연동 후보만 `CONDITIONAL_GO`이며 기능 구현·설치 승인은 아니다. 상세 비교는 [Phase 35.0 설계](enterprise_log_collection_architecture_35_0.md)를 참조한다.

실제 사용자 자료·조직 운영: `NO_GO`.

## 시작 gate와 Ubuntu CI 증거

- branch `main`, start SHA `961e279c19ae848d405724cc09d71bfba5cfbb38`, local `main` = `origin/main`, `origin/main...HEAD` = behind 0 / ahead 0, working tree clean을 검수 시작 때 확인했다.
- push CI run `40308485200`은 해당 SHA의 `push` run이며 `completed/success`였다. Ubuntu 24.04 locked install과 모든 필수 workflow 단계가 성공했다.
- 전체 pytest: **2861 passed, 기존 warning 2개**.
- 기존 SSH checkpoint ownership, unified monitoring, TCP basic smoke, TCP reliability 및 management smoke, restricted report, synthetic report benchmark, Node 설치, Chromium·axe, tracked-file immutability 단계가 모두 성공했다.
- 로그의 안전한 완료 표식:
  - `TCP_SYSLOG_SMOKE_COMPLETE roles=2 subprocesses=4 synthetic=1`
  - `TCP_SYSLOG_LINUX_RELIABILITY_PASS roles=2 runs=80 synthetic=1 leaks=0`
  - `TCP_SYSLOG_MANAGEMENT_SMOKE_PASS roles=2 synthetic=1 leaks=0`
- Chromium·axe: `states=14 external_requests=0`.
- CI artifact: **0**. `v0.4.0` tag target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 그대로였다.

이는 해당 SHA의 Ubuntu 자동 검증 증거다. 사용자 이해도 판정은 CI 결과가 아니라 아래의 직접 응답이다.

## 사용자 응답 기록

| 항목 | 캡처한 실제 CLI 경계 | 최초 응답 | 수정·재확인 | 최종 응답 |
|---|---|---|---|---|
| 1. 기능 목적 | setup 시작 안내: 로컬 프로그램의 합성 로그를 기존 결정적 분석기로 처리 | PASS | 없음 | PASS |
| 2. loopback 범위 | 같은 컴퓨터만 연결, 원격 호스트 미지원, IPv4 loopback 선택 안내 | PASS | 없음 | PASS |
| 3. 인증·암호화 | 송신자 미인증, TLS/mTLS 없음, 실제 장비/원격 미지원 | PASS | 없음 | PASS |
| 4. 역할 선택 | `application` 또는 `SSH` 중 하나를 고르는 setup prompt | PASS | 없음 | PASS |
| 5. 메시지 형식 | setup에 있던 길이 기반 메시지 한 줄 안내 | FAIL | 수정 전 계약 테스트 실패. 길이-prefix 예시와 잘못된 형식의 연결 거부 안내를 추가하고 같은 항목 재확인 | PASS |
| 6. endpoint 보호 | 일반 show와 실행 요약에는 주소/port 없음; 별도 승인 후 임시 loopback endpoint 및 공유 주의 문구 표시 | PASS | 임시 listener/config 정리 | PASS |
| 7. 상태와 count | 합성 frame 1건 처리 뒤 실제 count 요약 | FAIL | 수정 전 계약 테스트 실패. 수신/거부/내용 인식/형식 미인식/분석 완료/처리 중 폐기 뜻과 탐지·침해 없음·무유실 보장 부재를 시작 안내에 추가하고 `내용 인식` count 표시. management subprocess smoke 통과 후 재확인 | PASS |
| 8. 재시작과 유실 | setup/show/정상 종료 안내: 이전 메시지 및 대기열 복구 없음, 재전송 중복 가능, 무유실 보장 없음 | PASS | 없음 | PASS |
| 9. 종료와 충돌 | Ctrl+C 정상 종료, 같은 file monitor의 ownership 오류, file↔TCP 및 TCP↔TCP busy 안내 | PASS | 기존 ownership/category 계약 유지 | PASS |
| 10. 설정 삭제 | 삭제 승인 화면: TCP config만 삭제, file 설정/checkpoint·원본 자료·분석 결과 보존 | FAIL | 수정 전 계약 테스트 실패. 다시 사용하려면 setup이 필요하다는 안내 추가 후 실제 CLI에서 삭제 취소하고 재확인 | PASS |

항목 5, 7, 10의 최초 `FAIL`은 그대로 기록한다. 문구 수정은 CLI 사용자 안내에만 적용했다. framing, parser, 분석, counts의 의미, 설정 schema, checkpoint ownership, public API/SSE/UI는 바꾸지 않았다. 테스트의 초기 실패와 수정 후 통과는 아래에 명시하며 사용자 응답으로 대체하지 않는다.

## 자동 회귀와 로컬 합성 검증

이 수용 중 직접 확인한 사용자용 합성 흐름:

- setup 시작, loopback/role/framing 안내, endpoint 없는 일반 show, 승인형 endpoint reveal.
- 합성 application frame 한 건 처리 뒤 안전한 count 요약.
- 합성 SSH file monitor 중복은 기존 `CHECKPOINT_ALREADY_OWNED`를 유지하고, file/TCP 상호 배제와 두 번째 collector 실행은 busy 안내를 반환했다.
- SIGTERM 뒤 정상 종료 문구를 확인했다. 설정 삭제는 승인 전 화면을 보여준 뒤 취소했다.
- 검수용 listener, subprocess, 설정, lock과 임시 HOME을 각 capture 뒤 정리했다. endpoint를 기록 자료에 저장하지 않았다.

수용 과정에서 추가한 문구 계약 테스트는 각각 수정 전에 실패함을 확인했다. 수정은 setup의 byte 길이 예시와 잘못된 형식의 연결 거부 안내, run count의 뜻·한계와 내용 인식 수치, delete 후 재설정 안내에 한정했다.

- 집중 회귀: **284 passed, 기존 warning 2개**. 포함 항목은 Phase 34.1/34.2 core·runtime·management, SSH checkpoint ownership, unified monitoring, 공개 상태·privacy/guidance·restricted report, 관련 문서 계약이다.
- 전체 pytest: **2867 passed, 기존 warning 2개**. 기존 API/SSE/UI/HTML, schema 2/3, checkpoint/publication, Hypothesis/Schemathesis 및 privacy 회귀가 전체 suite에서 통과했다.
- 세 synthetic subprocess: SSH checkpoint smoke, unified monitoring smoke, TCP basic smoke가 각각 통과했다. management smoke 표식은 `TCP_SYSLOG_MANAGEMENT_SMOKE_PASS roles=2 synthetic=1 leaks=0`이다.
- 로컬 macOS 반복 검증: application·SSH lifecycle matrix **80/80 첫 시도 통과**, 첫 시도 실패 0, 임시 자료 cleanup 실패 0. 두 역할의 256 frame soak는 각 accepted/parsed/analyzed 256, rejected/parser-rejected/dropped 0; 종료 후 FD 기준선 복귀, task 0, listener 해제 및 port 재사용을 확인했다. 이는 macOS 합성 결과이며 Ubuntu 추가 CI나 운영 SLA가 아니다.
- 평가 기준선: synthetic detection corpus **79/79**, Linux process evaluation **21/21**, risk **70/70**, case **70/70**.
- 시간대 회귀: UTC **142 passed**, Asia/Seoul **142 passed**. Python `compileall`, axe 스크립트 `node --check`, `uv lock --check`, `git diff --check` 통과.
- `npm ci --ignore-scripts --no-audit --no-fund` 성공. Chromium·axe 자동 검사는 **14 states, external_requests=0**으로 통과했다. 이는 WCAG 준수 주장이 아니다.
- 시작 gate의 원격 Ubuntu CI `40308485200`에서 restricted report 단계가 성공했다. 해당 smoke는 Linux 전용이라 이번 macOS 로컬 반복에서 다시 실행하지 않았다.
- 이 Phase 변경 SHA는 아직 push되지 않았으므로 이 SHA의 Ubuntu CI 결과는 `NOT_TESTED`다. 시작 gate의 run은 그때 검수한 정확한 SHA에 대한 증거로만 사용한다.
- dependency·`uv.lock` 변경 없음. 변경 파일의 민감정보·개인 경로 정적 점검과 최종 `git diff --check`를 완료했다.

## 기존 CI 실패 이력과 한계

Phase 34.4 run `40292029527`의 기존 SSH ownership 회귀는 공용 collector lock이 checkpoint ownership 오류를 가린 문제였으며, 이후 `CHECKPOINT_ALREADY_OWNED` 우선순위를 복구했다.

그 뒤 run `40299125326`에서 application/SIGTERM subprocess smoke가 실패했다. 당시 wrapper는 내부 stage를 일반 오류 하나로 축약했다. 로컬 macOS에서 readiness marker의 생성/부분 읽기 race를 재현해 atomic marker publish를 적용했지만, 그 과거 Ubuntu 실패가 동일 원인이었다고 단정하지 않는다. 이후 run `40308485200`에서는 basic TCP smoke, Ubuntu reliability 80회, management smoke가 성공했다. 이는 해당 SHA의 성공을 입증할 뿐 과거 실패 원인을 소급 확정하지 않는다.

과거 macOS SSH/SIGTERM 단발 실패는 `UNEXPLAINED_NON_REPRODUCED`로 유지한다. 다음 한계도 유지한다.

- 실제 사용자 자료와 조직 운영: `NO_GO`.
- 인증 없는 원격 수집: `NO_GO`; TLS/mTLS 미지원.
- durable spool/checkpoint, 재시작 복구, exactly-once·무유실 미지원.
- crash, SIGKILL, 전원 장애 recovery와 장시간 운영 부하는 검증하지 않았다.
- Chromium·axe 자동 상태 검사는 WCAG 적합성 보증이 아니다.
- 사용자 검수는 캡처 화면 판단이며 사용자가 실제 환경에서 명령을 조작한 검사는 아니다.

## 최종 수용 상태

사용자 최종 응답은 **10/10 PASS**다. 최초 FAIL은 5/10, 7/10, 10/10이었고, 각 수정 화면을 다시 제시한 뒤 같은 항목에서 PASS를 받았다. 사용자 판정은 캡처 화면에 대한 응답이며 실제 사용 승인이나 운영 안전성 증거가 아니다.
