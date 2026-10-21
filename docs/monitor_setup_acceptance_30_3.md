# application·SSH 통합 설정: Ubuntu 및 사용자 수용 기록

## 기준과 증거의 범위

- 기준 commit: `a8f046485d923db8b0f24e0c11e38054b76d7775`.
- Phase 30.3a 시작 commit: `07d8be7560920686ab6e740e392b810bb46b6246`. [GitHub Actions run 39585667955](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39585667955)는 정확한 SHA에서 `completed/success`였고, Ubuntu 통합 관리 전용 단계와 전체 회귀 단계가 성공했다.
- [Ubuntu 24.04 CI run 39558109981](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39558109981): `completed/success`; job `Locked Python 3.12 regression`의 `Verify Linux unified application and SSH setup management` step 성공. Step 로그에서 focused pytest **46 passed**와 `UNIFIED_MONITOR_MANAGEMENT_SMOKE_PASS application_ssh_cleanup`를 확인했다. 전체 pytest **2413 passed, 기존 경고 2개**, locked 설치, Node 설치, Chromium hash 검증, axe 13개 상태도 성공했다. GitHub Actions API의 저장 artifact 수는 **0**이다.
- CI step은 `tests/test_monitor_setup_unified_30_2.py`, `tests/test_monitor_setup_management.py`, `tests/test_checkpoint_epoch_reset.py`와 `tests/smoke_unified_monitor_management_30_2.py`를 실제 실행한다. Step 이름만으로 항목별 성공을 추정하지 않고 해당 script의 assertion과 완료 표식을 함께 확인했다. CI 로그에는 합성 account·IP·hostname·원문·임시 경로 canary가 나타나지 않았다.
- macOS 15.7.7 arm64에서 임시 HOME, 합성 application·SSH 로그, 기본 위치를 분리해 CLI 출력과 별도 프로세스 smoke를 확인했다. 대화형 CLI 입력은 임시 환경에서 자동으로 제공해 실제 문구를 캡처했다. **사용자가 직접 명령을 입력한 검수로 확대하지 않는다.** 실제 사용자 판단은 아래 표에서 별도로 기록한다.

Ubuntu PASS는 위 두 **원격 기준 commit의 CI 증거**다. 아래 Phase 30.3a 사용자 문구 수정이 포함된 새 로컬 커밋은 push하지 않으므로 그 SHA의 Ubuntu CI 결과는 아직 없다.

## Ubuntu 자동 검증 판정

| 경계 | 판정 | 실행 근거 |
|---|---|---|
| application 설정·조회·monitor | PASS | 별도 프로세스 smoke의 application 흐름 |
| SSH 설정·조회·monitor | PASS | 같은 smoke의 SSH 흐름, bounded dry-run |
| 권한 | PASS | parent `0700`, config·checkpoint·lock `0600` assertion |
| 기존 줄 미처리·새 줄 처리 | PASS | 최초 revision 0, append 후 detection·analysis 증가 |
| checkpoint 복구 | PASS | 종료·재시작 뒤 revision 및 관계·risk·case 복구, 과거 SSE 재게시 0 |
| advisory lock | PASS | 두 monitor, 실행 중 reset/delete, 두 reset 승인 경쟁 거부 |
| reset/delete 보존 | PASS | 취소·승인, 새 epoch revision 0, 원본·sibling·lock·parent 보존; reset은 config 보존, delete는 config 제거 |
| 개인정보 | PASS | stdout/stderr·status·SSE 및 CI log canary 검사 |
| 정리 | PASS | listener·child process·임시 HOME 및 파일 정리 assertion; artifact 0 |

Ubuntu 판정은 위 CI의 실행 조건에 한정된다. 비협력적 같은 UID 프로세스, network filesystem, 전원 차단, SIGKILL 뒤 복구, rotation/copytruncate 자동 복구, exactly-once·무유실은 검증하거나 보장하지 않는다.

## macOS 실제 문구와 사용자 판단

합성 application과 SSH 설정의 실제 안내는 로컬 처리, 브라우저 원문 비표시와 내부 메모리 잔존 가능성, private 설정의 경로 저장, 외부 LLM 자동 전송 부재를 먼저 설명한다. 이어 `1` 애플리케이션 로그인 로그 또는 `2` SSH 인증 로그를 선택하고, 제한된 형식 검사 건수와 탐지율·침해 판단이 아니라는 경계를 보여 준다. 저장 전 `y/N` 승인과 저장 후 경로 없는 `uv run python -m app.local_web --monitor` 실행 명령을 표시한다. `--show`는 로그 종류와 복구 상태를 요약한다. 입력 경로·원문·계정·IP는 캡처한 일반 출력에 없었다.

앞선 Phase 30.3의 사용자 직접 판정은 **NOT_TESTED**였다. Phase 30.3a에서는 실제 합성 CLI 출력을 사용자에게 한 화면씩 제시하고, 답을 받은 뒤에만 다음 질문으로 진행했다. 사용자는 출력의 **이해도**를 직접 판정했다. 명령 입력과 파일 선택은 임시 HOME의 자동 준비이며 사용자의 직접 CLI 조작 PASS로 확대하지 않는다.

| 번호 | 사용자 과업 | 첫 응답 | 수정 후 재확인 | 최종 사용자 직접 판정 |
|---|---|---|---|---|
| 1 | application 첫 안내: 로컬 처리·역할 선택 | PASS | 해당 없음 | PASS |
| 2 | application 형식 검사: 제한적 의미·탐지율 비보장 | PASS | 해당 없음 | PASS |
| 3 | SSH 형식 검사: 개인정보 비노출·새 줄 시작 | PASS | 해당 없음 | PASS |
| 4 | 저장 승인과 모니터링 실행 명령 | PASS | 해당 없음 | PASS |
| 5 | application·SSH `--show`: 종류·설정·복구 상태 | FAIL | PASS | PASS |
| 6 | 손상 복구 자료: 확인 불가·수동 검토 | PASS | 해당 없음 | PASS |
| 7 | reset: 원본·설정 보존, 과거 분석·알림 연속성 폐기 | FAIL | PASS | PASS |
| 8 | delete: 설정·연결 복구 자료 삭제, 원본 로그 보존 | FAIL | PASS | PASS |
| 9 | 실행 중 reset 거부: 정상 종료 후 재시도 | PASS | 해당 없음 | PASS |

5번 최초 FAIL은 `--show`에 내부 역할 코드, 정책 코드, `True/False`가 보여 다음 행동이 어렵다는 판정이었다. 7번 최초 FAIL은 reset 안내의 `epoch`, `FROM_END`, `SSE`, `exactly-once`가 삭제 범위와 재시작 시점을 흐리게 한다는 판정이었다. 8번 최초 FAIL에서 사용자는 `schema 2`, `application`, `FROM_END`가 불필요하고 “결과는 삭제하지 않습니다”가 모호하다고 명시했다. 8번 안내는 제안대로 “애플리케이션 로그인 로그용 기본 설정과 연결된 복구 자료를 삭제합니다. 원본 로그 파일은 삭제하지 않습니다.”로 바꿨다. 세 항목 모두 **수정 전 실패 계약 테스트**를 확인한 다음 문구만 수정했고, 실제 새 합성 CLI 출력을 제시해 사용자 PASS를 다시 받았다. 다른 여섯 항목은 최초 PASS였다.

합성 오류 출력은 자동으로 재현했다. 기존 설정은 no-clobber, source 불가·잘못된 역할·UTF-8·긴 줄은 고정 오류, 실행 중 reset은 lock 거부, 검토 필요 checkpoint는 수동 확인 안내다. 자동 reset·delete·덮어쓰기는 없었다. 이 자동 확인은 **사용자의 문구 이해도 PASS가 아니다**.

## 로컬 자동 재검증

Phase 30.3 기준 커밋에서는 macOS focused 관리·checkpoint 계약 **47 passed**, 전체 문서 계약 **235 passed**, 전체 pytest **2415 passed, 기존 경고 2개**였다. Hypothesis·Schemathesis를 포함한 핵심 계약은 UTC와 Asia/Seoul에서 각각 **13 passed**였다. 별도 프로세스 application·SSH smoke도 정리 완료 표식으로 통과했다. 인증·웹 합성 평가 **79/79**, Linux Audit **21/21**, risk/case **70/70**이었다. `npm ci`, axe **13개 상태·외부 요청 0건**, `uv sync --locked --dev`, `uv lock --check`, Python·Node 문법 검사와 `git diff --check`를 통과했다. Node UI harness는 필요한 fixture를 넘기는 pytest 경로로 검증했다. Dependency·lockfile·버전은 변경하지 않았다.

Phase 30.3a 문구 수정 후 macOS focused setup·show·reset·delete·checkpoint·문서 계약은 **53 passed**, 전체 pytest는 **2420 passed, 기존 경고 2개**였다. 첫 전체 실행에서 기존 runtime 테스트가 출력에 내부 문자열 `application`을 요구해 1건 실패했다. 사용자용 표시 계약에 맞춰 그 assertion을 바꾼 뒤 같은 실제 CLI 수명주기 테스트가 통과했고, 전체 회귀를 다시 실행해 2420건 모두 통과했다. 합성 평가는 인증·웹 **79/79**, Linux Audit **21/21**, risk/case **70/70**이었다. application·SSH 통합 관리, SSH 설정 마법사, SSH checkpoint의 별도 프로세스 smoke는 각각 완료·listener 정리 표식으로 통과했다. `uv lock --check`, 변경 Python 문법 검사, `git diff --check`, production·문서 diff의 민감 경로·credential·canary 검사도 통과했다. 임시 HOME은 각 실행의 종료 처리에서 삭제됐고 실제 사용자 HOME·로그·기본 설정은 입력에 사용하지 않았다. 이번 변경은 Node/UI와 dependency·lockfile·CI를 건드리지 않았다.

## 발견한 결함과 최소 수정

검토가 필요한 checkpoint와 사용 가능한 원본 로그를 함께 만든 경우, 이전 `--show`는 원본 로그 접근을 확인하라고 안내하고 checkpoint 파일이 실제로 있는데도 `존재 False`라고 표시했다. 사용자에게 잘못된 복구 대상을 가리키고 부재로 오해시킬 수 있어 수정 전 `CHECKPOINT_REVIEW_GUIDANCE_FAILED`, `CHECKPOINT_REVIEW_FALSE_ABSENCE` 실패 테스트를 각각 확인했다. 이후 `NEEDS_REVIEW`에서는 존재·이력을 **확인 불가**로 표시하고 복구 자료의 수동 검토를 안내한다. 손상된 checkpoint를 자동 reset하거나 삭제하지 않는다. 변경은 `app.monitor_setup --show`의 문구에 한정되며 parser·분석·API·SSE 의미와 dependency는 그대로다.

첫 수정 전 실패 테스트는 pytest의 기본 traceback에 **합성** 경로·계정·IP가 들어 있는 fixture 소스 줄을 로컬 출력했다. 이를 발견한 뒤 실패를 고정 코드와 `pytrace=False`로 바꾸고 같은 실패를 다시 재현해 출력에 canary가 남지 않음을 확인했다. 이 출력은 CI artifact로 저장·업로드하지 않았다. 실제 사용자 자료는 테스트에 사용하지 않았다.

Phase 30.3a의 세 문구 결함은 `--show`, reset 승인, delete 승인 출력에서만 재현했다. 수정 전 계약 테스트는 각각 실패했고, 수정 후에는 역할별 표시·삭제 대상·원본 보존·내부 용어 부재·개인정보 비노출을 검사한다. Parser, detector, 분석, config schema, checkpoint 동작, API·SSE는 바꾸지 않았다. 새 로컬 커밋의 Ubuntu CI는 push 전이므로 아직 미검증이다.

## 판정과 남은 확인

Ubuntu application **PASS**, Ubuntu SSH **PASS**는 기준 SHA의 CI 결과다. Phase 30.3a에서 제시한 9개 합성 CLI 화면의 사용자 이해도는 수정 후 모두 **PASS**다. 이는 전체 오류 유형의 사용자 수용이나 실제 운영 로그 호환성 검증을 뜻하지 않는다. 원래 Phase 30.3 오류 목록 중 기존 설정, source 불가, 잘못된 역할·UTF-8·긴 줄의 개별 사용자 이해도는 **NOT_TESTED**다. 개인정보 경계와 자원 정리는 로컬 자동 검사 결과와 별도로 기록한다. Secure erase는 주장하지 않는다.
