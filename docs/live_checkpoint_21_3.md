# Phase 21.3 — 실제 프로세스 재시작과 SSE 세션 경계

상태: 기본 private v2 설정의 단일 `application` 로그를 **서로 다른 두 loopback 서버 프로세스**에서 실행해 checkpoint 재구성과 HTTP/SSE 경계를 검증했다. 분석 규칙, checkpoint 스키마, API·SSE 필드, frontend는 변경하지 않았다.

## 사용자 가치와 확인된 결함

이전 publication 세션 번호는 프로세스마다 `1`부터 시작했다. 프로세스가 재시작되면 오래된 `Last-Event-ID`가 새 세션의 같은 번호와 충돌할 수 있었고, 이를 반드시 `FOREIGN_SESSION` replay gap으로 분류한다는 계약을 지키지 못했다. 수정 전 실제 두 프로세스 테스트에서 두 session ID가 모두 `LIVE-SESSION-000001`로 나와 실패했다.

현재는 프로세스 최초 publication buffer에서 OS 난수 기반 번호 영역을 한 번 정하고 그 프로세스 안에서 단조 증가시킨다. 기존 `LIVE-SESSION-<숫자>` 및 `LIVE-EVENT-<세션 숫자>-<게시 숫자>` 형식, 단일 replay cursor, event 순서, snapshot/replay gap schema는 유지한다. 숫자는 브라우저의 정확한 정수 범위(`2^53-1`) 안에 둔다. IP·계정·경로·timestamp·hash에서 ID를 만들지 않는다. **프로세스 사이의 충돌 확률을 낮추는 방식이지 전역 유일성 보증은 아니다.** ID의 난수성은 인증·권한 경계가 아니다. 충돌이 실제로 관찰되면 현재 계약만으로 완전한 식별이 불가능하므로 영구 세션 ID나 인증된 cursor 같은 별도 설계가 필요하다. 관계·위험도·사례 ID도 여전히 session-local이며 재시작 뒤 같은 ID가 된다고 주장하지 않는다.

## 실제 restart 검증 계약

합성 로그의 기존 줄에서 시작한 첫 서버는 `FROM_END`로 revision 0을 보인다. 새 인증 실패 5줄을 한 번의 step으로 처리하면 detection·analysis revision이 같고 `observation_changes` 다음 `analysis_changes`가 나온다. 정상 SIGINT 뒤 listener가 닫히고 private checkpoint가 남는다. 두 번째 서버는 같은 regular file의 bounded 원본 구간을 재생해 두 accumulator의 revision과 안전한 analysis snapshot을 복구하지만 이전 event를 새 publication으로 다시 보내지 않는다(`published_total=0`). 첫 서버의 cursor로 재연결하면 `FOREIGN_SESSION` gap과 최신 snapshot을 받는다. 이후 성공 줄은 다음 revision에 새 `analysis_changes`를 만들고 failed→success, brute→success 관계 및 `CASE-BRUTE-SUCCESS-01` 의미를 안전한 DTO로 표시한다. 과거 observation event는 재전송하지 않는다.

테스트는 실제 `run_local_web` loopback 서버 두 프로세스, 임시 기본 config resolver, 합성 파일, HTTP status/OpenAPI, SSE, SIGINT를 사용한다. Path·account·IP·raw line canary는 public bytes와 stdout/stderr에 없어야 한다. Checkpoint 파일 자체는 private device/inode·offset metadata를 가질 수 있으며 trusted 원본 history에는 계정·IP가 있을 수 있다. 종료 후 listener 해제, checkpoint mode `0600`, temp artifact 부재를 확인한다. 브라우저 Safari 수동 조작, 실제 전원 손실, Linux 호스트, rotation/truncation, 두 프로세스의 강한 동시 실행 보장은 이 테스트로 검증하지 않았다.

## 보존한 실패 의미

Checkpoint 이후 crash window에서는 같은 원본 구간의 중복 처리 또는 gap이 가능하다. Queue ack, detection, analysis, publication, checkpoint는 하나의 원자적 transaction이 아니며 exactly-once·무유실을 주장하지 않는다. Restart replay는 옛 event를 브라우저에 재게시하지 않지만, 과거 publication을 사용자가 받았는지까지 확인하지 못한다. File identity·size·bounded range·safe semantic verification 실패는 `FROM_END`로 조용히 fallback하지 않고 중단한다. Rotation/truncation 자동 복구는 다음 단계로 남긴다.

이 테스트의 시간은 개발용 loopback integration 표본이지 운영 SLA가 아니다. 실제 Safari에서 재시작 전 열린 EventSource가 어떻게 표시되는지는 별도 수동 수용성 검증이 필요하다.
