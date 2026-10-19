# Phase 27.1 — v0.3.0 Safari 수동 수용 기록

이 기록은 v0.3.0 후보 `a3c753a396dbdcd4991212be276caa90f55641e9`의 새 SSH live·checkpoint·reset 사용자 흐름을 검수한다. v0.2.0에서 검수한 일반 배치 화면을 반복 판정하지 않는다. 탐지·관계·위험도·사례는 침해나 인과관계의 확정이 아니다.

## 사전 gate

| 항목 | 결과 | 근거 |
| --- | --- | --- |
| 후보 working tree와 원격 main | PASS | 시작 시 clean; local `main`, `origin/main`, 원격 `refs/heads/main`이 모두 후보 SHA와 일치 |
| 정확한 후보 SHA CI | PASS | [GitHub Actions run 39205243243](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39205243243) completed/success. Ubuntu Python 3.12 전체 2,347 passed·기존 경고 2개 |
| Ubuntu SSH 별도 process | PASS | 같은 run의 SSH focused 30 passed 및 `SSH_CHECKPOINT_CLI_SMOKE_PASS restart_reset_fresh_epoch_cleanup` |
| 버전·잠금 | PASS | `pyproject.toml`과 `uv.lock` root package 모두 0.3.0; `uv lock --check` 통과 |
| tag·Release | PASS | 원격 `v0.3.0` tag와 Release 없음. 기존 `v0.1.0`·`v0.2.0` tag 대상은 로컬과 일치하고 기존 Release 두 개가 유지됨 |
| 비공개 취약점 신고 | PASS | GitHub private vulnerability reporting API `enabled: true` |
| 로컬 변경 전 회귀 | PASS | `uv run pytest -q`: 2,347 passed·기존 경고 2개 |

## 격리된 검수 환경

macOS 15.7.7, Safari 18.6 (20621.3.11.11.3). `127.0.0.1`의 임시 포트에서 실행했다. OS 임시 디렉터리 아래에 SSH와 application의 HOME·XDG_CONFIG_HOME·합성 로그·private v2 기본 설정을 각각 분리했다. 실제 사용자 기본 config·로그·checkpoint는 읽거나 수정하지 않았다. 두 source 모두 서버 시작 전에 합성 줄을 한 줄 배치하고 `--monitor --no-browser`로 실행했다. SSH·application 초기 status는 role이 정확하고 detection/analysis revision 0이었다. 두 역할 모두 health 200 및 SSE 첫 `snapshot`을 확인했다. WebDriver의 click은 수동 PASS 증거로 사용하지 않는다.

## Safari 수동 결과

`PASS`는 사용자가 Safari 화면에서 직접 확인한 범위만 뜻한다. 자동 status·SSE·단위 테스트와 분리한다.

| 항목 | 판정 | 수동 범위 |
| --- | --- | --- |
| SSH 역할과 기존 줄 | PASS | `로그 유형: SSH 인증 로그`가 명확하고, 시작 전 줄 미처리 안내를 이해함 |
| 실패 5줄 append·새 결과 | PASS | 새 결과 버튼이 나타남. 버튼 전 목록 불변, 선택 뒤 Brute Force 관찰 표시 |
| 성공 기록 append | PASS | 관계·위험도·사례가 별도 영역에 표시. 성공 기록을 침해 확정으로 읽지 않음 |
| SSH 결과 화면 개인정보 | PASS | 사용자에게 보인 화면에서 원래 계정·IP·원본 경로·raw line 비노출 |
| 재시작 후 과거 SSE 알림 | PASS | 사용자가 Safari에서 과거 알림 재분출이 없음을 확인. 자동 SSE 첫 프레임은 snapshot |
| 복구된 SSH 결과·개인정보 | PASS | 새 Safari 화면에 관찰 1·관계 2·위험도 1·사례 1이 복구 상태로 보이고, 계정·IP·로그 경로·원문 노출이 보이지 않음을 사용자가 확인 |
| 재시작 후 새 SSH 줄 | PASS | 새 결과 버튼과 선택 뒤 기존 관계·위험도·사례에 이어진 결과를 사용자 확인 |
| 복구 상태 안내 | PASS | 사용자가 복구된 상태와 새 분석을 혼동하지 않음을 확인 |
| 침해 해결 오해 | PASS | 재시작 화면이 침해 해결·위험 소멸을 확정하지 않음을 사용자 확인 |
| reset 후 새 epoch 화면 | PASS | 이전 관찰·관계·위험도·사례를 복구했다고 표시하지 않고 빈 새 분석으로 보임 |
| reset 의미 | PASS | 사용자가 원본 로그 삭제가 아니라 checkpoint와 분석·SSE 연속성 초기화 및 다음 실행의 현재 EOF 시작으로 이해함 |
| Keyboard-only live 기본 조작 | PASS | 사용자가 실제 Safari에서 **Option+Tab**으로 live 영역 이동, 일시 정지·재개, 새 결과 적용을 조작. Visible focus와 keyboard trap 부재를 함께 확인. WebDriver click 증거로 대체하지 않음 |
| Keyboard-only 재연결 | PASS(사용자 일괄 확인) | 사용자가 나머지 수동 항목도 실제 확인했다고 답함. 합성 FAILED 화면에서 Option+Tab으로 재연결 버튼에 접근 가능함을 다시 확인. 버튼 활성화 뒤 정상 연결 복귀는 fault가 유지되므로 별도 PASS로 주장하지 않음 |
| Live disclosure | NOT_APPLICABLE | 현재 live 결과에는 전용 펼침 요소가 없음. 다른 화면의 disclosure는 이번 새 범위의 검수 대상이 아님 |
| Safari 200%·최소 창 너비 | PASS(사용자 일괄 확인) | 실제 Safari 페이지 확대와 최소 창 너비에서 live 상태·새 결과·관계·risk·case·checkpoint/recovery/reset 안내의 사용성을 확인했다는 사용자 응답. 합성 fault 주입 **이후** 오류 버튼을 200%로 다시 확인한 증거와 폭 수치는 없어 그 세부와 정확한 320 CSS px는 NOT_TESTED |
| Web Inspector | PASS(사용자 일괄 확인) | JS/CSP/MIME 오류, 중복 EventSource, URL/query/header 민감정보, 종료·terminal 뒤 무한 요청 여부를 실제 확인했다는 사용자 응답. 개별 Network 항목이나 계측 자료는 전달받지 않았고 합성 fault 주입 뒤의 Inspector 재검수는 NOT_TESTED |
| VoiceOver 상세 | NOT_TESTED | 선택적 비차단 항목으로 수행 여부를 특정하지 않음; WCAG 2.2 AA 준수 주장 없음 |

## 재시작 자동 증거

재시작 전 SSH 분석 revision 2, 관찰 1·관계 2·위험도 1·사례 1이었다. SIGINT 정상 종료 후 서버를 멈춘 동안 합성 실패 줄을 추가했다. 같은 private v2 config로 새 loopback 포트에서 시작한 뒤 revision 3, 관찰 1·관계 2·위험도 1·사례 1을 확인했다. 새 SSE 첫 프레임은 `snapshot`이고 합성 계정·IP·원본 경로 canary가 없었다. 중단 중 새 줄의 publication은 이전 SSE replay와 구분한다.

재시작 후 추가한 합성 SSH 실패 줄은 서버의 detection/analysis revision을 4로 올렸다. Safari에서도 새 결과 적용을 사용자 확인했다.

## Checkpoint reset 자동 증거

서버 SIGINT 종료 후 `--show`는 원본 경로 없이 `RECOVERABLE`, bounded 이력 8건을 요약했다. `--reset-checkpoint`에서 `no`를 입력하면 source·config·checkpoint 세 파일의 내용 digest가 그대로였다. `yes` 승인 뒤에는 연결 checkpoint 하나만 없어졌고 source·config 내용 digest는 유지됐다. Lock 파일은 남았으며 reset은 원본 로그를 삭제하지 않았다. 같은 private 설정으로 재실행한 새 epoch는 현재 파일 끝의 `FROM_END`에서 detection/analysis revision 0, 관찰·관계·위험도·사례 0건으로 시작했다. 이 확인은 secure erase나 전원 차단 보장이 아니다.

새 epoch의 키보드 수동 검수용으로 합성 SSH 실패 줄 5개를 추가했고 revision 1·관찰 1건이 준비됐다. 이는 reset 이전 관찰의 복구가 아니라 새 epoch 입력이다.

## 합성 오류와 개인정보

새 epoch의 임시 합성 SSH 파일만 같은 inode에서 truncation했다. Server status는 `FAILED`, analysis state도 `FAILED`이며 고정 복구 안내를 제공했다. 기존 관찰을 정상 0건으로 바꾸지 않았고 checkpoint도 자동 삭제하지 않았다. HTTP status에서 계정·IP·원본 경로·내부 inode·offset·예외 문자열이 검출되지 않았다. 사용자는 Safari 화면에서 FAILED·복구 안내·키보드로 접근 가능한 수동 재연결을 확인했고 원문·내부 값 노출이 없다고 답했다. 사용자는 화면 또는 연결된 안내에서 명시적 `--reset-checkpoint` 절차를 찾을 수 있다고 답했다. Live 화면 자체에는 reset 명령을 직접 표시하지 않는다.

새 epoch의 HTML·status·SSE 첫 snapshot에 대한 별도 자동 canary 검사에서는 합성 계정·IP·filename·config/log/checkpoint path가 검출되지 않았다. Safari DOM/Web Inspector의 수동 확인은 사용자 일괄 답변 범위이며, 자동 결과를 수동 확인으로 대체하지 않는다.

## 종료·정리와 판정

네 번 실행한 loopback server는 각각 SIGINT 뒤 exit 0을 확인했다. 사용한 네 포트의 listener는 모두 없어졌다. 별도 WebDriver 프로세스는 시작하지 않았고 사용자 Safari 앱은 종료하지 않았다. 임시 검수 트리에는 삭제 전 파일 8개, socket·HTML/PDF/ZIP download 0개였으며 트리 전체를 제거하고 부재를 확인했다. 사용자 기본 설정·원본 운영 로그는 환경 변수로 분리해 접근하지 않았다. 프로세스 종료로 server FD·task가 해제되는 범위와 기존 자동 자원 정리 테스트를 근거로 하며, OS 전원 장애나 secure erase는 검증하지 않았다.

**판정: CONDITIONAL GO.** 정확한 후보 SHA의 CI, SSH live·재시작·reset, 키보드 기본 조작, 사용자 일괄 200%·Web Inspector 확인, 합성 오류·개인정보 및 cleanup에서 blocker는 보고되지 않았다. 다만 VoiceOver 상세, 정확한 320 CSS px, fault 주입 뒤 200% 오류 버튼과 Inspector 재검수, 개별 Network 계측은 `NOT_TESTED`다. 사용자의 일괄 PASS에는 항목별 기록이 없어 자동 증거보다 넓은 수동 증거로 일반화하지 않는다. WCAG 2.2 AA 준수나 운영 로그 탐지율을 주장하지 않는다. 이 판정은 tag·GitHub Release·PyPI 실행 승인이 아니다.
