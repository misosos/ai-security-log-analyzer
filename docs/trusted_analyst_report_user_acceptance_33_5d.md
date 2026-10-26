# Phase 33.5D — 제한 조사 보고서 사용자 안전장치 수용 기록

## 범위와 현재 판정

이 검수는 합성 입력으로 CLI 승인 전 안내의 이해도를 한 항목씩 확인한다. 실제 로그·계정·주소·hostname·설정·checkpoint는 사용하지 않는다. 사용자 안내 화면 확인은 임시 HOME과 합성 application 입력으로 CLI를 실행하고 취소해 수행했다. application·SSH·access 성공·취소 및 파일 경계는 별도 자동 subprocess 테스트로 검증했다. 최초 응답은 1/10과 3/10이 `PASS`, 나머지가 `FAIL`이었고, 수정된 안내에 대한 최종 사용자 응답은 10개 모두 `PASS`다. 자동 회귀는 별도로 실행하며 사용자 이해도 응답과 혼합하지 않는다.

실제 사용자 자료 export와 조직 운영 사용은 계속 **NO_GO**다. 합성 입력 전용 CLI pilot의 자동 Linux 검증은 범위 제한 **CONDITIONAL_GO**다. 자동화된 검사는 사용자의 이해도나 실제 조직의 안전성을 증명하지 않는다.

## 자동 CI 증거

- 시작 SHA: `310922e17429f11f41d876d0ab8baec933503e80`; 시작 시 `main`, clean tree, local/remote 동일, behind 0/ahead 0.
- [push CI run 40179564268](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40179564268): exact SHA, `completed/success`.
- Ubuntu locked 설치와 전체 pytest **2722 passed, 2 warnings** 통과.
- Linux smoke: `RESTRICTED_REPORT_LINUX_SMOKE_PASS roles=3 audit_rows=6 fs=ext4`.
- Linux benchmark: warm-up 1회, 5 samples, 1/32/256 synthetic events; [Linux acceptance record](trusted_analyst_report_linux_acceptance_33_5c.md)에 결과를 기록했다.
- Chromium·axe 14 states 통과, external requests 0; tracked files unchanged; CI artifacts 0.
- 관찰된 runner filesystem은 이 CI run의 `ext4`뿐이며 다른 유형으로 일반화하지 않는다. 실제 filesystem ENOSPC, SIGKILL, 전원 장애, network filesystem은 `NOT_TESTED`다.
- v0.4.0 tag/Release target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

## 사용자 응답 뒤 자동 회귀

- 수정 전 사전 안내 계약 테스트는 2/10, 4/10, 5/10, 6/10, 7/10, 8/10, 9/10, 10/10의 누락 문구 각각에서 실패했다. 문구를 고친 뒤 4개 관련 CLI/documentation 테스트가 반복해서 통과했다.
- 현재 변경 기준 Phase 33.5B/C 및 33.5D focused suite **51 passed**. 이 실행은 sandbox가 AF_UNIX bind를 막아 두 기존 socket 테스트를 실패시킨 뒤, 같은 suite를 sandbox 외부 권한으로 재실행해 통과한 결과다. 검증을 skip하지 않았다.
- 전체 `uv run pytest -q`: **2725 passed, 2 warnings**. 두 warning은 기존 Starlette/httpx 및 anyio deprecation이다.
- 기존 합성 평가는 `synthetic_boundary_corpus` **79/79**, Linux Audit **21/21**, risk **70/70**, case **70/70**.
- `npm ci` 통과. Chromium·axe 재실행: **14 states**, `external_requests=0` 통과. Sandbox 내 재시도는 일반 실패 표식을 반환했으며, loopback browser 검사를 sandbox 외부에서 성공적으로 재검증했다.
- `uv sync --locked --dev`, `uv lock --check`, Python `compileall`, Node `--check`, `git diff --check` 통과. `pyproject.toml`, `uv.lock`, `package.json`, `package-lock.json` 변경 없음.
- 각 사용자 확인용 CLI 실행은 synthetic application 한 건을 사용하고 취소했다. 성공 report/audit는 만들지 않았다. 임시 HOME·입력·출력 디렉터리는 종료 뒤 정리했다. 외부 네트워크 요청·AI 호출·listener는 사용하지 않았다.
- 문구 변경은 안내 출력에 한정된다. 실제 사용자 자료와 조직 운영 사용은 여전히 **NO_GO**다.

이 CI 증거는 자동 검사다. 아래 표는 사용자 응답만 기록하며 자동 테스트 결과로 채우지 않는다.

## 사용자 검수

검수 대상은 임시 HOME, mode `0700` 임시 디렉터리, 합성 application·SSH·access 입력뿐이다. 외부 네트워크·LLM·Gemini·embedding을 사용하지 않는다. 실제 파일 경로와 report/audit 내용은 이 문서에 기록하지 않는다. 종료 시 확인된 합성 파일과 임시 디렉터리를 정리하며 secure erase를 주장하지 않는다.

| 항목 | 확인할 내용 | 최초 응답 | 최종 응답 |
|---|---|---|---|
| 1/10 | 제한 내부 보고서의 목적 이해 | PASS | PASS |
| 2/10 | 포함 식별자와 제외 데이터 범위 이해 | FAIL | PASS |
| 3/10 | 정확한 명시 승인 필요성 이해 | PASS | PASS |
| 4/10 | 자동 암호화 부재와 0600 권한의 차이 이해 | FAIL | PASS |
| 5/10 | private 저장 위치와 directory 권한 경계 이해 | FAIL | PASS |
| 6/10 | 기존 파일 no-clobber 이해 | FAIL | PASS |
| 7/10 | audit 최소 기록 범위 이해 | FAIL | PASS |
| 8/10 | 공개 별칭 보고서와의 차이 이해 | FAIL | PASS |
| 9/10 | 보관·삭제·backup/cloud-sync 책임 이해 | FAIL | PASS |
| 10/10 | 합성 pilot 한계와 운영 미승인 상태 이해 | FAIL | PASS |

### 항목별 응답 기록

1/10 최초/최종 응답: 사용자 `PASS`. CLI가 기능을 제한된 내부 보고서라고 표시하며, 사용자는 공개용 안전 요약과의 목적 차이를 이해한다고 확인했다. FAIL 및 문구 수정은 없었다.

2/10 최초 응답: 사용자 `FAIL`. 최초 실제 CLI 사전 화면은 역할과 사례·관계·관찰 수, account/IP/hostname 개수를 보여주고 원문 로그 제외를 알렸지만 파일 경로·인증 정보·내부 예외 제외를 별도로 명시하지 않았다. 생산 경로를 통과하는 문구 계약 테스트를 추가했고, 수정 전 해당 테스트는 실패했다. 사전 안내에 제외 항목을 명시하도록 문구를 고쳤다. 관련 테스트 4개 통과 후 실제 CLI 합성 실행으로 갱신된 화면을 다시 보여주었고, 사용자 재응답은 `PASS`다. 최종 응답은 `PASS`다.

3/10 최초/최종 응답: 사용자 `PASS`. 실제 CLI는 고정 승인 문구를 입력해야 진행하고 그 외 문구는 취소한다고 표시했다. 이번 확인에서는 취소 입력으로 끝냈으며 보고서나 감사 파일을 만들지 않았다.

4/10 최초 응답: 사용자 `FAIL`. 기존 사전 화면은 자동 암호화되지 않는다고만 말하고 로컬 저장 및 `0600` 권한과 암호화의 차이는 설명하지 않았다. 해당 내용을 검사하는 생산 경로 문구 계약 테스트를 추가했고 수정 전 실패를 확인했다. 갱신한 CLI 화면에 로컬 파일 저장, 자동 암호화 부재, `0600`은 암호화가 아니라는 문구를 추가했다. 수정 후 사용자 재확인 전이므로 최종 응답은 `NOT_TESTED`다.

4/10 재확인: 문구 계약 테스트 4개 통과 뒤 실제 CLI를 합성 입력과 취소 응답으로 다시 실행했다. 수정 문구가 표시되었고 파일은 생성하지 않았다. 사용자 최종 응답은 `PASS`다.

5/10 최초 응답: 사용자 `FAIL`. CLI 안내는 경로를 반복 출력하지 않았지만, 사용자가 지정한 output parent가 owner-only `0700`이어야 하며 다른 사용자가 읽을 수 있는 directory는 거부된다는 점을 안내하지 않았다. 생산 경로 문구 계약 테스트를 추가했고 수정 전 실패를 확인했다. private directory 조건과 안전하지 않은 directory 거부, 경로를 안내에 표시하지 않는다는 문구를 추가했다. 갱신 화면 사용자 재확인 전이므로 최종 응답은 `NOT_TESTED`다.

5/10 재확인: 문구 계약 및 관련 회귀 4개 통과 후 합성 CLI 화면을 다시 보여주었다. 사용자는 private directory와 권한 경계를 이해한다고 `PASS`했다. 파일은 생성하지 않았다.

6/10 최초 응답: 사용자 `FAIL`. 사용자는 현재 화면에서 기존 파일을 덮어쓰지 않는다는 사실과 충돌 시 새 출력 이름을 지정해야 한다는 다음 행동을 알기 어렵고 승인 전에 명시하는 것이 좋다고 답했다. 이를 검사하는 생산 경로 문구 테스트를 추가했고 수정 전 실패를 확인했다. 사용자 재응답 전까지 최종 응답은 `NOT_TESTED`다.

6/10 재확인: 사전 문구 계약 테스트 4개 통과 후 합성 CLI 화면에서 no-clobber와 새 이름 안내를 다시 제시했다. 사용자는 `PASS`했다. 확인 실행은 취소되어 보고서·감사 파일은 생성하지 않았다.

7/10 최초 응답: 사용자 `FAIL`. 현 CLI 사전 화면은 별도 감사 기록의 존재와 필드를 알리지 않아 사용자가 실제 식별자·경로 비기록 경계를 확인하기 어렵다. 감사 요약 문구를 요구하는 생산 경로 테스트를 추가했고 수정 전 실패했다. 사용자 재확인 전까지 최종 응답은 `NOT_TESTED`다.

7/10 재확인: 감사 요약 문구를 보여주는 실제 합성 CLI 실행과 관련 테스트 4개 통과를 확인했다. 사용자는 범위를 이해한다고 `PASS`했다. 확인 실행은 취소되어 파일을 생성하지 않았다.

8/10 최초 응답: 사용자 `FAIL`. 사용자는 기존 문구만으로 제한 보고서와 공개 UI·API·HTML 보고서의 차이를 알기 어렵고, 공개 경로는 보호된 별칭을 유지하며 제한 보고서의 실제 식별자는 공개 화면이나 도움말로 전달되지 않는다는 문구를 승인 전에 명시하라고 요청했다. 이를 검사하는 사전 안내 테스트를 추가했고 수정 전 실패했다. 최종 응답은 재확인 전까지 `NOT_TESTED`다.

8/10 재확인: 요청한 공개 별칭 및 비전달 경계 문구를 실제 합성 CLI 화면에서 확인했다. 관련 문구 계약 테스트 4개 통과 후 사용자 응답은 `PASS`다. 실행은 취소되어 파일은 만들지 않았다.

9/10 최초 응답: 사용자 `FAIL`. 사용자는 기존 문구만으로 도구가 보관 기간·삭제 시점·backup·cloud sync를 자동 관리하지 않는다는 점이 불분명하다고 했고, 전달·보관 기간·삭제·백업·클라우드 동기화를 자동 관리하지 않으며 사용자와 조직 정책에 따라 관리해야 한다는 문구를 승인 전 안내에 명시하도록 요청했다. 해당 문구를 검사하는 생산 경로 테스트를 추가했고 수정 전 실패했다. 재확인 전 최종 응답은 `NOT_TESTED`다.

9/10 재확인: 요청한 자동 관리 부재와 사용자·조직 정책 책임 문구를 실제 합성 CLI 화면에서 확인했다. 관련 테스트 4개 통과 뒤 사용자는 `PASS`했다. 실행은 취소되어 파일은 생성하지 않았다.

10/10 최초 응답: 사용자 `FAIL`. 사용자는 현재 화면에서 합성 pilot 전용, 실제 자료·조직 운영 미승인, 실제 사용 전 암호화·보존 정책·인증/RBAC 검토 필요 여부를 알기 어렵다고 했다. 세 경계 문구를 검사하는 생산 경로 테스트를 추가했고 수정 전 실패를 확인했다. 수정 후 재확인 전이라 최종 응답은 `NOT_TESTED`다.

10/10 재확인: 세 가지 지원 상태 및 후속 정책 검토 경고를 실제 합성 CLI 화면에 표시했다. 관련 문구 계약 테스트 4개 통과 뒤 사용자는 `PASS`했다. 실행은 취소되어 보고서·감사 파일은 만들지 않았다.

## 최종 경계

최초 사용자 응답은 1/10 `PASS`, 2/10 `FAIL`, 3/10 `PASS`, 4/10 `FAIL`, 5/10 `FAIL`, 6/10 `FAIL`, 7/10 `FAIL`, 8/10 `FAIL`, 9/10 `FAIL`, 10/10 `FAIL`이다. 수정 후 재확인 최종 응답은 1–10 모두 사용자 `PASS`다. 2/10, 4–10 문구 결함은 각각 실패 테스트를 먼저 확인한 뒤 CLI 사전 안내만 수정했다. 사용자 응답과 테스트 증거는 별개로 기록했다.

최종 사용자 안전장치 판정은 사용자 응답 10/10 `PASS` 및 자동 회귀 통과에 따라 합성 pilot 안내 범위에서 **CONDITIONAL_GO**다. 이는 합성 pilot의 안내 수용 범위만 다룬다. 실제 사용자 자료 export는 **NO_GO**다. 암호화, retention, 인증/RBAC 정책 전 조직 사용은 **NO_GO**다.

Phase 33 종료 상태는 이 범위로 확정한다: 제한 보고서의 합성 안내 10/10은 사용자 `PASS`이며 그 안내 범위만 `CONDITIONAL_GO`다. 실제 자료 export와 조직 사용은 `NO_GO`; embedding production 통합은 `NO_GO`; local LLM 실행·production 연결은 `STORAGE_SETUP_BLOCKED`다. Phase 34 수집 설계는 이 보고서·embedding·LLM 범위를 확대하지 않는다.
