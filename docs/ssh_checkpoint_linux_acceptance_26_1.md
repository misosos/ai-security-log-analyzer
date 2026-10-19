# Phase 26.1 — SSH checkpoint Ubuntu 독립 수용 gate

**판정: CONDITIONAL GO.** Phase 26.0의 원격 SHA `fc6f74a726c0d83dc93ff6b33e5dd6721daf817b`에 대한 [Ubuntu 24.04 CI run](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39201600155)은 completed/success였고 전체 pytest는 **2,333 passed, 기존 deprecation 경고 2개**였다. SSH checkpoint 테스트는 전체 suite에 포함됐고 새 파일에는 skip/xfail·OS별 우회가 없다. 하지만 해당 run의 명시적 Linux 단계 17건은 기존 application reset/process 계약이며, **SSH 별도 프로세스 lock·CLI restart smoke를 실행하지 않았다.** 따라서 이 run 하나로 Phase 26.1의 독립 Ubuntu 수용을 PASS라고 표시하지 않는다.

Phase 26.1 SHA `6a0146321d7b74d0fbabaffad138a0c5097f68a3`의 [첫 Ubuntu CI run](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39202433190)은 **completed/failure**였다. SSH focused는 **30 passed**였으나 후속 실제 process smoke가 `SMOKE_SERVER_START_FAILED:DEFAULT_CONFIG_MISSING`으로 첫 서버 시작 전에 실패했다. 따라서 process lock·권한·재시작·reset 및 전체 회귀 단계는 그 run에서 **NOT_TESTED**다. 원인은 테스트 harness가 macOS의 `Library/Application Support`에 config를 하드코딩한 반면 Linux launcher는 `~/.config`의 기본 경로를 사용한 것이다. Production resolver·checkpoint 동작의 결함으로 판단할 증거는 없다. 실패를 CI 재실행이나 skip으로 숨기지 않고, Linux/macOS 기본 위치를 고정하는 수정 전 실패 테스트를 기록한 다음 smoke에서 production resolver를 그대로 재사용하도록 고쳤다. 수정 커밋의 Ubuntu 결과는 아직 확인되지 않았다.

## 실행 경계와 증거

| 항목 | 현재 증거 | 판정 |
|---|---|---|
| SSH v2 private config·동일 파일 replay·batch prefix parity | 이전 Ubuntu 전체 pytest에 포함된 SSH focused 테스트, 로컬 macOS 재실행 | PASS (그 테스트 범위) |
| malformed/schema/role/offset/digest, file replace/shrink/missing, permission/symlink | SSH focused의 실제 임시 regular file과 mode bit 검사; 기존 일부만 이전 Ubuntu 전체 suite에 포함 | PASS (로컬), 추가분 Ubuntu CI 대기 |
| 257번째 parsed event·partial UTF-8/LF | 신규 SSH focused에서 ack/checkpoint가 앞서지 않음을 검사 | PASS (로컬), Ubuntu CI 대기 |
| 실제 두 프로세스 advisory lock·active reset 거부 | 확장된 합성 CLI smoke에서 첫 server·경쟁 server·관리 CLI를 별도 PID로 실행 | PASS (macOS), 첫 Ubuntu smoke는 경로 오류로 미도달; 수정 CI 대기 |
| 정상 종료→중지 중 append→재시작→관계/사례→cancel/approved reset→새 `FROM_END` epoch | 합성 CLI smoke, private HOME 및 loopback listener 사용 | PASS (macOS), 첫 Ubuntu smoke는 경로 오류로 미도달; 수정 CI 대기 |
| 0700 config parent, 0600 config/checkpoint/lock, sibling·원본 보존 | CLI smoke의 실제 `stat` mode bit와 파일 내용 검사 | PASS (macOS), Ubuntu CI 대기 |
| 과거 SSE 미재게시·새 append만 publication | SSH worker/publication focused 테스트; 별도 프로세스 SSE framing 재검사는 하지 않음 | PARTIAL |
| 전체 transaction fault matrix, ack 전 release·ack 후 terminal | 기존 application fault matrix와 SSH checkpoint write-failure/257 테스트 | PARTIAL: 모든 지점의 별도 SSH subprocess fault는 미실행 |
| Ubuntu 1/16/64/128/256 복구 성능 | 이번 SHA의 Ubuntu benchmark step 없음 | NOT_TESTED |
| 다른 UID owner mismatch, SIGKILL/전원차단, NFS/overlay 일반화 | 비권한 CI에서 안전하게 재현하지 않음 | NOT_TESTED |

현재 workflow에 Ubuntu 24.04 전용 `Verify Linux SSH checkpoint recovery and process ownership` 단계를 추가했다. `sys.platform == 'linux'` 확인 뒤 SSH focused와 `tests/smoke_ssh_checkpoint_26_0.py`를 실행한다. 이는 기존 full suite에서 SSH 단위 테스트가 한 번 더 실행되는 소량의 중복이지만, 별도 PID·loopback·권한 smoke가 전체 suite에 없다는 공백을 명시적으로 채운다. 이 단계의 **미래 CI 성공은 이 문서 작성 시점에 주장하지 않는다.** workflow의 checkout/setup action은 기존 commit SHA pin과 `contents: read` 권한을 유지한다.

## 실패·개인정보·자원 의미

Checkpoint schema, source role, file identity, offset, mode, symlink, source 부재와 의미 digest 오류에서 조용한 `FROM_END` fallback을 허용하지 않는다. SSH 257번째 parsed event는 ack 전 거부되어 detection/analysis revision과 durable checkpoint가 전진하지 않는다. Partial UTF-8은 LF 전에 commit하지 않으며 malformed 완성 줄은 실패다. Ack 후 checkpoint persist 실패는 이미 확정된 메모리·publication을 되돌리지 못하고 terminal이다. 개별 고장 지점 전부를 Ubuntu subprocess에서 주입한 것은 아니므로 그 범위는 PARTIAL이다.

CLI smoke의 계정·IP·source/config/checkpoint 경로는 전부 합성 임시 canary다. Private 원본 로그와 내부 reconstructed event에는 raw 값이 존재할 수 있지만 checkpoint JSON과 safe result·CLI stdout/stderr·status/SSE/UI에는 공개하지 않는다. Smoke는 path·계정·IP의 CLI 출력 비노출, checkpoint/lock mode, PID 정상 종료, 활성 listener 부재, 원본·config·sibling 보존, 임시 디렉터리 삭제를 확인한다. Secure erase나 crash recovery·exactly-once·무유실을 주장하지 않는다. OS의 `TIME_WAIT`와 활성 listener는 다르므로 재시작은 새 loopback port를 사용한다. 실제 운영 로그·기본 사용자 설정은 사용하지 않는다.

Phase 26.0 macOS 개발 측정의 256줄 total recovery median/p95/max는 **38.142/40.701/40.701 ms**였다. Phase 26.1 같은 호스트 재측정은 1/16/64/128/256줄에서 각각 **1.341/1.458/1.458**, **1.669/1.703/1.703**, **3.370/3.599/3.599**, **5.882/6.044/6.044**, **13.955/14.215/14.215 ms**였다. 256줄 내부 단계 median은 checkpoint load 0.047, file replay read 0.013, parser 2.986, detection prepare 3.744, analysis prepare 5.236, safe digest 0.075, status 0.034 ms였다. 128줄 다음 append step median은 2.196 ms이고 256줄은 상한에 도달해 측정하지 않았다. 합성 99-byte 줄, warm-up 1·표본 3, 측정 wrapper overhead가 포함된다. 두 macOS 측정 간 차이는 다른 호스트 부하·cache/계측 환경에서 나온 개발 표본이며 성능 개선으로 단정하지 않는다. 이번 Phase의 Ubuntu 수치는 **NOT_TESTED**이고 CI hardware와 macOS를 단순 비교하지 않는다. 성능은 운영 SLA가 아니다.

다음 push 후 이 커밋의 정확한 SHA에 대해 새 Ubuntu focused step, process smoke, 전체 regression과 경고 수를 확인해야 최종 GO를 판정할 수 있다. Source-checkout 범위, application checkpoint, 명시적 v1 SSH `FROM_END`, 기존 public API schema는 변경하지 않았다. Rotation/copytruncate handoff, 두 세대 replay, cross-source, 강제 종료 무유실 및 Vector 자동 대체는 계속 NO-GO다.
