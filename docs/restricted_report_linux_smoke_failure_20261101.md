# Restricted Report Ubuntu smoke 실패 원인 분석

## 요약

실패 분류는 `SMOKE_HARNESS_REGRESSION`이다. Production Report, 파일 권한, audit, 승인, no-clobber 구현은 변경하지 않았다.

실패한 smoke의 SSH 합성 줄은 유효 인증 메시지의 `ssh2` 뒤에 구분자 없이 canary 텍스트를 덧붙였다. Phase 36.11B에서 기존 SSH 메시지까지 전체 문자열로 확인하도록 강화한 결과, 이 문자열은 더 이상 인증 성공/실패 이벤트가 되지 않는다. 이는 임의의 후행 필드를 인증 근거로 삼지 않는 Parser 동작이다. smoke는 이전의 관대한 접두부 매칭을 전제로 계정/IP가 보고서 subject로 만들어질 것을 기대했고, 그래서 승인 export 단계가 실패했다.

Canary는 기존 Parser가 지원하는 `ssh2: <message>` 형태의 명시적 trailing message로 옮겼다. Parser 동작이나 검증 조건을 되돌리거나 완화하지 않았다.

## 시작 상태와 최초 실패

- 저장소: `misosos/ai-security-log-analyzer`
- 시작 SHA: `1a04b010f3e6c9223fc787bb4bafd039f73ee043`
- Branch: `main`
- Local HEAD / `origin/main`: 동일
- Ahead/behind: `0/0`
- 시작 working tree: clean
- v0.4.0 tag target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` (불변)
- GitHub Actions Run: `41272856003`, `push`, `completed`, `failure`
- 실패 Job: `Locked Python 3.12 regression`
- 실패 Step: `Verify restricted analyst report on Linux`
- 실행: `uv run python tests/smoke_restricted_report_33_5c.py`
- 당시 출력: `RESTRICTED_REPORT_LINUX_SMOKE_FAIL`
- 같은 Job에서 전체 pytest는 `3559 passed, 2 warnings`; TCP Syslog smoke/reliability/management 및 JSONL Linux acceptance도 성공했다.
- 후속 accessibility와 tracked-file 단계는 실패 이후 건너뛰었다.
- Artifact: 0

최초 로그에는 실패 marker만 있어 개별 assertion 단계가 드러나지 않았다. 이 Run에서 정확히 어떤 assertion이 실패했는지는 사후 로그만으로 직접 확인할 수 없다. 아래 원인은 fixture 및 parser 계약으로 결정적으로 재현한 실패 경로이며, 새 Ubuntu CI에서 단계 marker로 확인해야 한다.

## 재현과 원인 분류

기존 SSH fixture의 메시지는 다음 구조였다: `... port 22 ssh2 host-canary-5c ...`. Parser에 직접 넣으면 `event_type`, 사용자, IP, AuthenticationContext가 생성되지 않았다. 같은 줄에서 `ssh2:` 뒤로 canary를 이동한 경우에는 `login_failed`, 합성 계정, 문서용 IPv6 및 인증 문맥이 정확히 생성됐다.

기존 fixture로 restricted-report subprocess를 실행했을 때 보고서와 audit 파일이 만들어지지 않고, CLI가 고정 오류로 실패했다. 수정 fixture로 `_role_case` helper를 실행하면 application/ssh/access 세 역할 모두 보고서 생성, 승인, 파일 권한, audit, no-clobber, 두 번째 export와 임시 파일 정리 계약을 통과했다. macOS helper 실행 결과는 역할 3개, 성공 audit row 6개였다.

이는 새 RFC5424 header 처리와 직접 연관된 실패가 아니다. 36.11B에서 ISO SSH에도 공통으로 적용된 full-message matching 변화가 기존의 비정상 trailing text를 인증 메시지로 추출하지 않게 했다. smoke가 해당 비정상 줄에 기대고 있었으므로 harness fixture를 지원 문법으로 맞추는 것이 최소 수정이다. 임의 suffix를 받아들이도록 Production Parser를 다시 느슨하게 하면 false acceptance 경계를 약화할 수 있어 수정하지 않았다.

배제한 가설:

- Restricted Report의 권한/no-clobber/audit 회귀: macOS subprocess helper에서 세 역할의 계약이 통과했고, 해당 코드는 변경하지 않았다.
- RFC5424 UTC 처리 오류: 실패 fixture는 기존 ISO-style SSH 형식이다.
- TCP Syslog/JSONL 간섭: 동일 Run에서 이 smoke 이전 단계가 통과했고 smoke는 별도 subprocess와 임시 폴더를 사용한다.
- 일시적 CI 문제: malformed fixture의 직접 재현이 있어 transient로 분류하지 않는다. 다만 실제 Ubuntu에서 수정 후 실행은 아직 수행하지 않았다.

## 안전한 진단 개선

smoke는 실패 시 고정 stage와 category만 출력한다. 예: `RESTRICTED_REPORT_LINUX_SMOKE_FAIL stage=ssh_approved_export category=process`. stage 이름은 코드 내 고정 단계/허용 role 조합이며 category는 고정 allowlist다. 원문, canary, 개인/임시 경로, 입력 내용 및 예외 문자열은 출력하지 않는다. 성공 marker의 형식은 유지했다. non-Linux 실행은 `stage=linux_platform category=platform`으로 안전하게 종료한다.

검증된 stage에는 role setup, 취소/EOF, signal cleanup, 승인 export, permissions, report schema/privacy, audit, CLI 출력, no-clobber, second export, temporary cleanup, descriptor 및 root cleanup이 포함된다.

## TDD 및 수정

새 smoke 계약 테스트를 먼저 추가했다. 수정 전 두 검증이 실패했다: SSH fixture 상수/지원 문법 계약이 없었고, smoke 실패 출력에 stage/category가 없었다. 이후 지원 가능한 fixture와 고정 진단을 추가하고, 구형 비구분 suffix는 인증 이벤트로 처리되지 않는다는 확인을 포함했다.

Production Parser, restricted-report 구현, 권한 정책, privacy 검사, count 조건, 승인 흐름, dependency 및 lockfile은 변경하지 않았다.

## 검증 결과

- 전체 baseline: `3559 passed, 2 warnings` (수정 전)
- focused smoke/SSH/restricted-report/privacy/documentation tests: `86 passed, 2 warnings`
- 수정 fixture를 사용하는 subprocess helper: macOS 반복 3회 통과 (총 9 role cases / 18 성공 audit rows)
- TCP Syslog 기본 smoke와 management smoke: macOS 합성 실행 통과
- JSONL runtime smoke: macOS 합성 실행 통과
- JSONL local dry-run acceptance: 80회, 두 role, `leaks=0` 통과
- Chromium/axe: 25 states 통과, `external_requests=0`; UI3 Navigation E2E 통과
- 평가 CLI: synthetic boundary `79/79`, Linux process evaluation `21/21`, risk/case 각 `70/70`
- 전체 pytest: `3563 passed, 2 warnings`
- Linux 전용 smoke 직접 반복: macOS 플랫폼 guard에서 3회 종료; 이는 Linux 실행으로 인정하지 않음
- Ubuntu Linux smoke: `NOT_TESTED` (현재 세션은 Darwin arm64, Docker daemon 없음)

새 exact-SHA Ubuntu CI가 필요하다. 다음 push 이후 `Verify restricted analyst report on Linux` 단계가 `RESTRICTED_REPORT_LINUX_SMOKE_PASS roles=3 audit_rows=6 ...`을 내는지 확인하고, 이어서 `Measure bounded synthetic report export on Linux`, Chromium/axe, tracked-file 검사도 확인해야 한다. 진단 marker가 실패하면 고정 stage/category만으로 다음 원인을 분리한다.

## 남은 경계

- macOS helper 성공은 Linux `/proc/self/fd`, mountinfo/filesystem type, Linux signal/process 동작의 수용 근거가 아니다.
- 최초 실패 Run은 상세 stage를 출력하지 않아, 당시의 실제 assertion은 사후 원문 로그에서 식별할 수 없다. 확인한 원인 경로는 malformed SSH fixture에 대한 결정적 재현이다.
- 실제 사용자 자료, 조직 운영, 자동 대응은 계속 `NO_GO`다.
