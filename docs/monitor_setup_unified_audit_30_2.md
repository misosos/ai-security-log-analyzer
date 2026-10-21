# application·SSH 설정 관리 및 복구 통합 감사

## 현재 사용자 흐름

`uv run python -m app.monitor_setup`에서 애플리케이션 로그인 로그 또는 SSH 인증 로그 하나를 고르고, 제한된 형식 검사를 거쳐 private v2 설정을 승인 저장한다. `uv run python -m app.local_web --monitor`는 기존 줄을 건너뛰고 현재 파일 끝부터 새 줄을 처리한다. 정상 종료 뒤 같은 파일의 bounded checkpoint에서 안전 요약과 분석 상태를 복구하지만 과거 SSE 알림을 새 알림으로 다시 게시하지 않는다.

| 명령 | 설정 | 연결 checkpoint | 원본 로그 |
|---|---|---|---|
| 모니터 정상 종료 | 유지 | 유지 | 유지 |
| `--reset-checkpoint` 승인 | 유지 | 하나 삭제; 다음 시작은 새 분석 연속성 | 유지 |
| `--delete` 승인 | 기본 설정 하나 삭제 | 연결된 하나 삭제 | 유지 |
| 취소·빈 입력·EOF | 유지 | 유지 | 유지 |

관리 명령은 실행 중 monitor의 advisory lock과 충돌하면 거부한다. `--show`는 schema, 읽기 쉬운 로그 종류, `FROM_END`, checkpoint·rotation 정책, 권한·source 사용 가능 여부, checkpoint 부재·정상·검토 필요 상태만 요약한다. 경로, 파일 identity, 원문, 계정, IP, hostname, 내부 예외는 일반 출력에 싣지 않는다. `--monitor`의 설정 누락·손상·role/identity 불일치는 sample-only 실행이나 조용한 새 epoch로 대체하지 않는다. 명시적 `--monitor-config`의 v1/v2 계약과 일반 sample·업로드 API의 live 격리는 유지한다.

## 수정 전 실패와 최소 수정

두 역할의 실제 CLI setup→`--show` 계약을 먼저 추가해 실행했다. 두 경우 모두 기존 `--show`가 내부 역할 코드 `application`/`ssh`만 보여 읽기 쉬운 로그 종류를 표시하지 못해 실패했다. `app.monitor_setup`의 조회 문구에 `애플리케이션 로그인 로그`/`SSH 인증 로그`와 checkpoint의 부재·정상·검토 필요 설명을 추가했다. 기존 코드 값은 호환성을 위해 함께 남겼다. 탐지, 분석, API, SSE, UI schema는 변경하지 않았다.

## 자동 계약과 별도 프로세스 검증

- 기존 회귀는 source와 설정의 승인 대기 중 교체, symlink·권한·손상, 두 reset, 두 monitor, monitor와 reset/delete 충돌, private 권한, 256 event·256 KiB bounded prefix, 257번째 parsed event의 ack 전 거부, publication 후 checkpoint 갱신을 검사한다. 같은 파일 identity와 role만 복구하며 source 교체·truncation·rotation·잘못된 checkpoint는 fail-closed다.
- `tests/test_monitor_setup_unified_30_2.py`는 두 역할의 실제 setup·show와 출력 canary 비노출을 검사한다. `tests/smoke_unified_monitor_management_30_2.py`는 역할별로 별도 monitor 프로세스를 띄워 기존 줄 미처리, 새 실패·성공 처리, 관계·위험도·사례, 정상 종료·재시작, 이전 SSE 미재게시, reset 취소·승인, revision 0의 새 epoch, delete 취소·승인, listener·임시 파일 정리를 검사한다. 두 setup 프로세스의 no-clobber 경쟁과 두 reset 프로세스의 lock 경쟁도 확인한다. 기본 설정 parent `0700`, config·checkpoint·lock `0600`도 검사한다.
- 합성 경로·계정·IP canary를 setup/show/reset/delete 출력, monitor stdout/stderr, status·SSE에 대조한다. 신뢰된 private config/checkpoint와 내부 처리에는 source path와 원문이 존재할 수 있다. 테스트 실패 시에도 원문 canary를 assertion 메시지나 pytest node ID에 넣지 않는다.
- macOS 별도 프로세스 smoke: **PASS**. Ubuntu 24.04 CI에는 같은 focused 테스트와 smoke를 실행하는 단계를 추가했다. 새 로컬 커밋의 Ubuntu 결과는 push 전이므로 **NOT_TESTED**다. 로그·config·checkpoint·raw report를 CI artifact로 업로드하지 않는다.

## 잔여 위험과 판정 경계

Advisory lock을 따르지 않는 같은 UID 프로세스의 최종 교체 race를 완전히 막지 못한다. Config와 checkpoint의 삭제는 원자적 묶음도 secure erase도 아니다. 백업·snapshot·crash dump와 이미 읽힌 메모리의 잔존은 별개다. rotation/copytruncate 자동 handoff, crash recovery, exactly-once·무유실, 다중 source·cross-source 분석은 제공하지 않는다. macOS application/SSH 흐름과 개인정보·lock 경계가 통과해도 Ubuntu 새 단계의 원격 CI가 확인되기 전 판정은 최대 **CONDITIONAL GO**다.
