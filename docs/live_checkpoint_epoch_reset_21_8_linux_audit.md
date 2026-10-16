# Phase 21.8 — Linux checkpoint reset 독립 검증

상태: **검증·테스트만 보강, production 의미 불변.** 이 문서는 macOS 실행과 Linux 실행을 구별한다. Phase 21.7 시작 코드의 커밋 `75715514fd675fff30b69298ea50fe606a92af66`은 [GitHub Actions run 38761273093](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38761273093)의 `ubuntu-24.04`/Python 3.12.7 job에서 `completed/success`, 전체 `2173 passed`, 기존 `2 warnings`였다. 그 전체 suite에는 실제 별도 프로세스의 monitor/reset/재시작 흐름인 `test_cli_explicit_checkpoint_reset_starts_a_new_epoch`가 포함되어 있었다. 다만 당시 workflow는 개별 테스트명을 출력하지 않아 해당 결과를 별도 Linux step의 성공이라고 표현하지 않는다. **Phase 21.8 커밋의 Linux CI는 push 후에만** 실행 가능하며, 로컬 macOS 통과를 그 대신으로 취급하지 않는다.

## 독립 검증 경계

| 계약 | 기존 Ubuntu 전체 회귀에서 실행된 근거 | Phase 21.8의 별도 Linux gate | 남은 한계 |
|---|---|---|---|
| Private parent `0700`, checkpoint·advisory lock `0600` | `test_checkpoint_epoch_reset.py`, runtime smoke | 두 reset 프로세스 테스트가 실제 mode와 소유 파일을 검사 | 다른 UID의 권한·ACL/네트워크 FS는 NOT_TESTED |
| 실행 중 monitor의 reset 거부 | 별도 `local_web`와 `monitor_setup` 프로세스 smoke | 동일 smoke를 이름이 보이는 CI step에서 재실행 | `flock`은 advisory; 비협력적 동일 UID 교체를 막지 않음 |
| 승인 대기 중 두 reset 프로세스 충돌 | 기존 in-process 중첩 reset만 검증 | 첫 CLI가 `[y/N]`에서 lock 보유 시 두 번째 CLI의 `CHECKPOINT_RESET_ACTIVE`와 checkpoint 불변, 첫 취소 후 `y/yes` 삭제를 검증 | 새 테스트의 Ubuntu 결과는 Phase 21.8 push 전 NOT_TESTED |
| 승인 삭제의 범위 | unit은 checkpoint 하나만 unlink하고 config·source·sibling 보존 | separate-process smoke와 두 reset 경쟁 테스트로 재확인 | secure erase, backup 제거는 보장하지 않음 |
| 새 분석 epoch의 `FROM_END` | 별도 loopback server가 파일 교체 후 fail closed, 취소/승인 뒤 현재 파일의 기존 줄을 건너뛰고 새 append만 처리 | 동일 smoke를 Linux 전용 step에서 재실행 | 중단 중 기록 복구·ID 연속성·exactly-once는 없음 |

새 CI step은 `sys.platform == 'linux'`를 먼저 확인한 뒤 checkpoint reset unit, 두 reset 프로세스 경쟁, 실제 loopback monitor→reset→`FROM_END` 재시작 테스트를 실행한다. 이어 전체 회귀가 그대로 실행된다. 이 step은 성공 결과가 생기기 전까지 **검증 장치**이지 Phase 21.8 커밋의 Linux 검증 완료 증거가 아니다. 별도 Linux 호스트·VM·컨테이너 실행은 이 로컬 환경에서 NOT_TESTED다.

## 장애·개인정보·판정

승인 없이 derived checkpoint를 삭제하지 않는다. Lock이 이미 사용 중이면 두 번째 reset은 고정 오류로 거부되고 첫 프로세스의 승인 절차와 checkpoint는 유지된다. `y/yes` 승인 뒤에만 연결된 checkpoint 하나를 삭제하며 config·원본 로그·parent·sibling은 보존한다. 재시작은 새 session과 현재 EOF `FROM_END`이므로 이전 detection·correlation·risk·case·SSE 기록이 이어지지 않는다. 확인되지 않은 rotation/copytruncate handoff, 두 파일 세대 replay, checkpoint private metadata 확대는 **NO-GO**다.

CLI stdout/stderr와 public snapshot에는 source/config 경로, 로그 account·IP·원문, checkpoint identity·offset을 넣지 않는다. Private checkpoint 내부의 기존 identity/offset metadata와 shell history·filesystem backup 잔존은 별도 trusted/운영 경계다. 이 검증은 전원 차단, 극단적인 최종 TOCTOU, network filesystem lock, 완전한 crash recovery 또는 운영 무유실을 입증하지 않는다.
