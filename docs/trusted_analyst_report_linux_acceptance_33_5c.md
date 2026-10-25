# Phase 33.5C — 제한 조사 보고서 Linux 파일·장애 수용 기록

## 판정

**검증 대기 — Linux 전용 새 smoke와 benchmark는 새 커밋의 Ubuntu CI에서 아직 실행되지 않았다.** Linux 수용 결과를 PASS나 CONDITIONAL_GO로 기록하지 않는다. 실제 사용자 자료 export와 운영 사용은 계속 **NO_GO**다. report 파일은 자동 암호화되지 않습니다.

## 시작 gate 증거

- 시작 SHA: `e5340f9916eb977ae1ef46ad51c5adf63192ba1d`. 시작 시 `main`, clean working tree, local `main`=`origin/main`, behind 0/ahead 0을 확인했다.
- [push CI run 40174710982](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40174710982): 정확한 SHA의 `push`, `completed/success`.
- run의 Ubuntu 24.04 job은 `uv lock --check`, `uv sync --dev --locked --no-build`, 전체 pytest **2690 passed, 2 warnings**, `npm ci`, Chromium·axe **14 states**, `external_requests=0`을 통과했다. Phase 33.5B 테스트는 전체 pytest에 포함되어 성공했다. CI 저장 artifact는 0개였다.
- 이 gate run에는 Phase 33.5C 전용 Linux report smoke·benchmark step이 아직 없었다. 해당 run을 Linux report acceptance 근거로 사용하지 않는다.
- v0.4.0 tag/Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`이었다.

## 변경 사항과 재현 테스트

수정 전 실패를 확인했다. 취소/EOF/SIGINT가 `cancelled` audit 파일을 만들었고, 기존 report 재시도는 파일은 보존해도 audit에 실패 row를 추가했다. 새 CI workflow smoke 계약도 없었다. 취소·EOF·SIGINT와 이미 존재하는 대상을 거부할 때 report와 audit를 만들거나 변경하지 않도록 고쳤다.

Audit row의 부분 write와 fsync 실패는 원래 길이로 되돌리고, 새 audit 파일이면 제거를 시도한다. report 게시 후 audit 실패 시 report 삭제를 시도한다. 삭제가 실패해 report가 남을 수 있으면 사용자 출력에 경로·원문 없이 저장 폴더를 확인하고 파일을 열거나 공유하지 말라는 고정 복구 안내를 표시한다. JSON serialization과 report label/identifier projection도 closed contract로 재검증한다.

`.github/workflows/ci.yml`에는 전체 pytest와 별도로 Ubuntu 24.04에서 합성 파일만 쓰는 `Verify restricted analyst report on Linux` step 및 1·32·256건 benchmark step을 추가했다. smoke는 private temporary directory와 격리 HOME을 만들며 report, audit, log를 artifact로 업로드하지 않는다. 성공 출력은 `RESTRICTED_REPORT_LINUX_SMOKE_PASS`와 role/audit 개수 및 filesystem 유형뿐이다. 실패 시에는 고정 실패 표식만 출력한다.

## 증거 상태

| 항목 | 상태 | 근거 |
|---|---|---|
| 시작 커밋 Ubuntu locked 설치·전체 회귀·Node/Chromium/axe | PASS | run 40174710982의 실제 job log |
| 시작 커밋 artifact 0개·v0.4.0 불변 | PASS | Actions artifact API, tag 및 Release target |
| 33.5C 전용 Ubuntu subprocess smoke | NOT_TESTED | 새 step은 이 로컬 변경 후 추가됐으며 새 SHA CI 미실행 |
| Ubuntu runner 실제 filesystem 유형·mount 특성 | NOT_TESTED | 새 smoke가 유형만 출력하도록 준비됨; 실제 로그 없음 |
| Ubuntu에서 세 role 성공·취소·EOF·SIGINT/SIGTERM·no-clobber | NOT_TESTED | Linux smoke는 아직 실행되지 않음 |
| Linux 권한·atomic publish·동일 target 경쟁·audit fault | NOT_TESTED | 해당 OS/filesystem에서 실행된 새 SHA CI 근거 없음 |
| 로컬 파일-operation fault injection | PASS (macOS 개발 host) | test-only fault tests; Linux 동작 근거로 승격하지 않음 |
| 공개 API/SSE/UI/HTML 개인정보 회귀 | PASS (macOS 개발 host) | 변경 전부터 있던 전체 회귀/Phase 33 privacy suite; 공개 producer는 수정하지 않음 |

Linux smoke는 application·SSH·access 각각 승인 보고서, schema·식별자와 audit report ID 연결, `0700`/`0600`, private output, no-clobber retry 불변성 및 새 output 재실행을 확인하도록 작성했다. 거절·EOF·SIGINT는 report와 audit를 만들지 않아야 한다. 느슨한 umask 아래서도 파일 mode를 확인한다. 파일 descriptor 수를 실행 전후 비교하고 임시 directory가 제거된 뒤에만 PASS 표식을 쓴다. 현재는 이 코드를 Linux에서 실행하지 않았으므로 위 항목은 전부 NOT_TESTED다.

## 로컬 검증과 fault 범위

macOS 개발 host에서 Phase 33.5B subprocess, Linux smoke workflow/document contract, privacy/guidance 회귀와 fault injection focused 묶음을 실행했다. 최종 focused 결과는 **75 passed, 2 warnings**이고 전체 pytest는 **2721 passed, 2 warnings**다. 합성 평가 묶음은 **101 passed**다. Chromium·axe는 **14 states**, `external_requests=0`으로 통과했다. 이는 macOS host에서 확인한 결과이며 Ubuntu PASS가 아니다.

주입한 fault는 serialization, temp open/write, file/directory fsync, publish, audit open/write/fsync/close, ENOSPC test double, rollback unlink, parent/input 경계, input identity/size 변경 및 audit row/byte 상한이다. 주입 실패는 성공 반환을 만들지 않고 fixed exception boundary를 유지한다. 성공 audit 이후 report rollback이 실패할 수 있는 경우에는 CLI가 결과 상태를 확인하라는 고정 경고를 제공한다.

- 실제 filesystem ENOSPC: **NOT_TESTED**; runner/root filesystem을 채우지 않았다.
- 실제 Linux `SIGKILL`, power loss, 실제 directory/file fsync 장치 오류, network filesystem, overlayfs/tmpfs의 실제 운영 동작: **NOT_TESTED**.
- Test double ENOSPC와 실제 filesystem ENOSPC는 별도다. 어느 fault test도 전원 장애 atomicity를 입증하지 않는다.
- NFS를 모사한 mountinfo test double은 거부된다. Linux 구현에서 ext4/xfs/btrfs/tmpfs/overlay만 허용 후보이며 network filesystem은 거부한다. 현재 Ubuntu runner 유형은 미확인이다.

macOS 개발 host benchmark는 warm-up 1회, 표본 5회다. 전체 export median/p95/max는 1건 **7.319/9.570/9.570 ms**, 32건 **10.112/12.015/12.015 ms**, 256건 **33.246/35.060/35.060 ms**였다. 출력 크기는 각각 **1270/5083/28152 bytes**였다. 분석 준비 median은 **0.285/2.160/15.774 ms**, 직렬화 median은 **0.025/0.072/0.331 ms**, file fsync median은 **0.693/0.726/0.712 ms**, audit write median은 **0.199/0.222/0.220 ms**였다. process high-water RSS 관찰값은 OS별 단위 차이가 있어 macOS에서만 각각 **34,652,160 / 34,996,224 / 37,650,432 platform units**로 남긴다. 이 작은 개발 표본은 운영 SLA가 아니며 Linux 수치로 해석하지 않는다.

## 동시성·결정성·분석 경계

동일 target 경쟁에 대한 기존 별도 프로세스 테스트는 하나의 report만 publish되고 report JSON이 완전한지 확인한다. race에서 loser가 target 확인 전에 도착했을 때만 failure audit가 생길 수 있으므로 1~2 audit row를 허용한다. 이미 존재하는 target을 미리 확인한 재시도는 report byte와 audit byte를 모두 보존한다. 새 smoke/benchmark에 대한 Linux 경쟁 결과는 **NOT_TESTED**다.

기존 33.5B 회귀는 UTC·Asia/Seoul에서 canonical content digest 동일성, 시간 의미 보존, report ID의 비충돌을 검사한다. 공개 API/SSE/UI/HTML은 변경하지 않았고 subject_alias 계약, Phase 33.1 lexical guidance/citation도 그대로다. 보고서 export는 checkpoint, queue, publication 또는 SSE cursor를 사용하지 않는다.

## Benchmark

새 Ubuntu CI benchmark는 1·32·256 합성 event에 warm-up 1회와 5표본을 사용하고 분석 준비, JSON serialization, file fsync, audit write, 전체 export, payload byte와 process high-water RSS를 기록하도록 연결했다. 이는 개발 runner의 작은 표본이며 운영 SLA가 아니다.

Phase 33.5C Ubuntu benchmark 결과: **NOT_TESTED** — 새 step은 추가됐지만 해당 변경 SHA의 CI가 아직 실행되지 않았다. 이전 Phase 33.5B macOS 숫자를 Linux 수치로 재사용하지 않는다.

## 남은 경계

- 새 커밋의 Ubuntu workflow와 smoke는 push CI에서 확인해야 한다. 이 검증 단계에서는 push하지 않는다.
- 실제 사용자 자료, 조직 운영 승인, encryption, retention, authentication/RBAC, backup/cloud-sync 취급은 계속 **NO_GO**다.
- report는 로컬 파일이지만 자동 암호화되지 않는다. audit는 강한 인증이나 변조 방지 기록이 아니다.
- SIGKILL, 전원 차단, 실제 filesystem ENOSPC 및 network filesystem의 완전한 정리를 보장하지 않는다.
