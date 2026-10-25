# Phase 33.5B — 합성 전용 제한 조사 보고서 CLI pilot

상태: **CONDITIONAL_GO — 합성 입력 전용 macOS CLI pilot 구현**. 실제 자료 export: **NO_GO**. 이 결과는 실제 사용자 자료를 내보내거나 조직에서 운영하는 것을 승인하지 않는다. 정확한 새 SHA의 Ubuntu 별도 프로세스 CI와 정책 검토가 남아 있다.

## 범위와 시작 gate

- 시작 SHA `5a21f42edef5982b9bff7fccde89e8286a663fd6`; branch `main`, working tree clean, local/origin 일치, behind 0/ahead 0이었다.
- [push CI run 40171736043](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40171736043)은 해당 SHA의 `push`, `completed/success`다. Ubuntu 24.04.5에서 locked install, Linux checkpoint focused step, 전체 `2670 passed, 2 warnings`, `npm ci`, Chromium·axe 14 states와 `external_requests=0`을 통과했고 artifact는 0개였다. Phase 33.4 privacy/guidance와 33.5A 문서 계약은 전체 pytest에 포함됐다.
- v0.4.0 tag/Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`로 유지됐다.
- 변경 전 로컬 전체 기준선은 `2670 passed, 2 warnings`였다.
- 테스트 우선: 새 CLI 호출 4개 테스트 중 구현 전 2개가 모듈 부재로 실패했다. 이후 새 문서 계약 4개는 문서 작성 전 모두 실패했다.
- 모든 입력은 임시 디렉터리에서 만든 합성 application·SSH·access line이다. 실제 사용자 HOME의 로그, monitor config, checkpoint, credential, 운영 자료에는 접근하지 않았다.

## CLI 계약

명시적 별도 명령:

```text
uv run python -m app.restricted_report \
  --source-role application|ssh|access \
  --input /absolute/path/to/synthetic.log \
  --output /absolute/path/to/private/report.json
```

입력과 출력 경로, 단일 source role이 모두 필수다. 기본 경로, 비대화형 승인 bypass, API, OpenAPI, SSE, 일반 UI, HTML, 브라우저 다운로드는 추가하지 않았다. CLI는 입력이 합성인지 자동 판별하지 못한다. 이번 pilot에서 합성 입력만 허용한다는 운영 규칙을 지켜야 하며, 실제 자료에 사용할 수 있는 제품 기능으로 문서화하지 않는다.

승인 전에는 source role, case/relation/observation 및 account/IPv4/IPv6/hostname 개수, 원문 미포함, 자동 암호화 없음, 외부 network/AI 전송 없음과 보존 책임을 표시한다. 다음 문구와 정확히 일치해야 한다.

> 제한된 내부 보고서 생성을 승인합니다

다른 입력, EOF, Ctrl+C는 취소다. stdout/stderr에는 입력·출력 경로, 원래 식별자, 원문, 내부 예외를 표시하지 않는다. 성공 출력은 report ID 앞 8자리, schema, byte 수, canonical content digest 앞 12자리뿐이다. digest는 report 전체의 canonical serialization에서 `report_id`와 `generated_at`을 제외해 계산하므로 같은 분석 내용 비교용이다. 원본 input byte digest는 만들거나 기록하지 않는다. digest는 암호화나 접근 통제가 아니다.

## 입력·분석과 JSON 계약

입력은 소유자 UID가 현재 사용자이고 일반 파일이며 hard link가 하나뿐이고 group/other 권한이 없는 경우에만 읽는다. symlink와 symlink 경로 구성요소를 거부하고 `O_NOFOLLOW` 및 `fstat`을 사용한다. 읽기 전후 device/inode/size/mtime/ctime을 비교한다. 같은 UID의 비협력 프로세스나 kernel/filesystem 결함을 완전히 막는다고 주장하지 않는다.

선택된 기존 parser와 `detect_attacks` → `correlate_attacks` → `assess_risk` → 기존 case projection을 사용한다. 원본 event는 내부 처리 중에만 존재한다. 위험도는 기존 계산이며 보고서 전용 탐지나 관계를 만들지 않는다. 프로젝트의 고정 account metadata 입력은 기존 production risk path와 동일하게 사용하며, 사용자의 HOME/config/checkpoint는 읽지 않는다.

출력은 `restricted-investigation-report/v1` 닫힌 JSON이다. 최상위 필드는 `schema_version`, `report_id`, `generated_at`, `source_role`, `classification`, `encryption_status`, `limitations`, `subjects`, `observations`, `relations`, `risks`, `cases`, `audit_summary`로 제한한다. `subjects`는 report 안에서만 유효한 순번 ID와 typed identifier 목록으로 구성하며, 같은 source IP에서 관찰한 account를 묶는다. 각 case는 해당 subject의 report-local ID를 참조한다. 이 순번은 원래 값/hash에서 계산하지 않으며 서로 다른 보고서 간 상관 키로 사용하면 안 된다. 생성 후 중첩 key/type/enum/count를 재검증하고 `allow_nan=False`, UTF-8 strict, key 정렬·고정 separator로 직렬화한다.

`subjects`에는 parser가 실제로 제공한 account, canonical IPv4/IPv6, hostname만 포함한다. 값이 없는 hostname은 추정하지 않고 identifier count 0과 limitation으로 표현한다. account 형태 값은 JSON string data로 보존할 수 있지만 HTML로 렌더링하지 않는다. `observations`, `relations`, `risks`, `cases`는 기존 분석의 고정 display type, 개수, 심각도/신뢰도 및 UTC 시간 범위만 선택한다. 원문 line, 파일명·절대 경로, query, 전체 rationale/evidence, checkpoint, 내부 exception, credential, HTTP 전체 내용, argv는 제외한다.

- 입력 전체: 2 MiB, 완성 line 최대 256개, line당 16 KiB.
- 식별자: UTF-8 256 bytes; report output: 1 MiB.
- 보고서 생성 처리: 5초; audit: 64 KiB 또는 128 event에서 중단하고 자동 rotation하지 않는다.
- 초과·불량 입력을 조용히 잘라내지 않고 전체 export를 실패시킨다. production parser가 인식하지 않는 줄은 기존 parser 의미에 따라 무시될 수 있다.
- `generated_at`은 현재 로컬 timezone offset을 포함한 ISO 형식이다. event 시간은 parser의 기존 timezone 해석 뒤 UTC `Z`로 직렬화한다.
- random UUID report ID는 식별자나 입력 digest에서 유도되지 않는다. 입력 ID의 per-subject 연결 별칭은 만들지 않는다.

파일은 **자동 암호화되지 않는다**. `0600`은 암호화된 파일이 아니다. 승인 화면에 자동 암호화가 없음을 표시한다. 로그인 사용자, 같은 UID 프로세스, 관리자, 백업·Time Machine·cloud sync, crash/SIGKILL/전원 장애에 대한 보호나 secure erase를 주장하지 않는다.

## 저장과 감사

이미 존재하는 출력 parent는 실제 directory, 현재 UID 소유, 정확히 mode `0700`, symlink 없는 path여야 한다. macOS에서는 local APFS/HFS, Linux에서는 허용된 local filesystem만 인정한다. 출력 `.json`은 같은 directory의 random `0600` temp에 serialize → write loop → file `fsync`한 뒤, POSIX atomic no-replace hard link로 publish하고 temp unlink 및 directory `fsync`를 시도한다. 기존 파일·symlink·hard-link·special target은 덮어쓰지 않는다. `link`/directory sync/cleanup에 실패하면 고정 오류로 종료하고 cleanup을 시도한다. audit 기록 실패 후에는 published output 제거를 시도한다.

`<output parent>/.restricted-report-audit.jsonl`은 mode `0600`이고 parent는 `0700`이다. advisory file lock 아래 최대 128개의 closed-schema row/64 KiB를 허용한다. row는 success/failure, UTC 시각, schema, role, random report ID, 식별자 종류별 개수, case/relation/observation aggregate만 기록한다. 잘못된 승인·EOF·Ctrl+C와 이미 존재하는 destination의 사전 거부는 report와 audit를 만들거나 바꾸지 않는다. 경로·account/IP/hostname/raw/error는 audit에 넣지 않는다. 손상·초과·permission 오류 시 fail closed하며 자동 rotation은 없다. audit는 단일 사용자 도구의 best-effort local record이지 강한 인증, RBAC, append-only 변조 방지, 두 파일 간 원자 transaction이 아니다. post-publish audit 실패에서 output 삭제를 시도하고, 실패하면 fixed 복구 안내를 제공하지만 crash 또는 동일 UID race 상황의 완전한 rollback을 보장하지 않는다.

POSIX/macOS local runner에서 hard-link no-replace, permissions, file/directory `fsync` smoke를 수행했다. 다른 filesystem/OS는 지원 근거가 없으면 거부한다. 네트워크 파일시스템, SIGKILL, power loss에서 임시 파일·보고서·audit의 정리를 보장하지 않는다.

## 검증·fault 결과

- 변경 후 새 CLI 및 연관 문서 focused 묶음: **24 passed**. 최종 전체 `uv run pytest -q`: **2690 passed, 2 warnings** (44.47s). 경고는 기존 Starlette/httpx 및 anyio deprecation이다.
- 환경 검증: `uv sync --locked --dev`, `uv lock --check`, `npm ci --ignore-scripts --no-audit --no-fund`, Python compileall, `git diff --check` 통과. dependency manifest와 `uv.lock`은 변경하지 않았다.
- 검증: 취소, exact approval, 0700/0600, closed schema, 기존 output no-clobber, input symlink/hardlink/permission, parent mode, 상한 초과, audit closed schema, publish fault, markup-shaped account의 JSON data 보존, 세 role 실제 subprocess, 동시 동일 destination에서 최대 하나만 publish.
- 합성 report/audit에서 file path, raw line, input account/IP는 audit·CLI output에서 제외됐다. 승인된 최소 account/IP는 report JSON에만 포함됐다. public API/SSE/UI/HTML producer는 이번 변경에서 수정하지 않았다. 기존 public privacy/guidance suite도 통과했다.
- macOS 별도 프로세스 smoke는 취소·성공·기존 파일 재시도·동시 실행과 역할별 입력으로 실행했다. listener는 생성하지 않는다. 종료 후 해당 private temp 안의 report/audit만 남았고 `.restricted-*.tmp`는 0개였다.
- 새 SHA의 Ubuntu CI와 Linux에서 새 restricted CLI subprocess를 실행한 증거는 아직 없다: `NOT_TESTED`. macOS smoke를 Linux PASS로 대체하지 않았다.
- disk full, 실제 `fsync`/directory `fsync` 실패, audit storage failure, timeout, SIGTERM, SIGKILL, power loss, macOS Finder/Time Machine/cloud backup 잔존은 fault injection하지 않았다: `NOT_TESTED`.
- 이 pilot은 audit/output의 multi-file crash consistency를 입증하지 않는다. cleanup 실패를 성공으로 표시하지 않도록 고정 오류를 반환한다.

## 합성 benchmark

실행 명령: `uv run python tests/benchmark_restricted_report_33_5b.py`. 환경: macOS local workspace, Python 3.12, 1 warm-up 후 5 samples. 아래 값은 development observation이며 `operational_sla=false`다. p95는 5 samples의 nearest-rank 값이며 사실상 max다. RSS는 프로세스 high-water (`ru_maxrss`, macOS bytes)라 case별 peak가 아니다.

| events | output bytes | 분석 median/p95/max ms | JSON median/p95/max ms | file+directory fsync median/p95/max ms | audit median/p95/max ms | 전체 median/p95/max ms | peak RSS bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1,270 | 0.221 / 0.245 / 0.245 | 0.028 / 0.030 / 0.030 | 0.579 / 0.639 / 0.639 | 0.147 / 0.220 / 0.220 | 4.870 / 5.333 / 5.333 | 33,865,728 |
| 32 | 5,083 | 2.203 / 2.266 / 2.266 | 0.076 / 0.087 / 0.087 | 0.718 / 0.755 / 0.755 | 0.224 / 0.230 / 0.230 | 8.977 / 9.402 / 9.402 | 33,980,416 |
| 256 | 28,152 | 12.848 / 13.864 / 13.864 | 0.311 / 0.330 / 0.330 | 0.622 / 0.678 / 0.678 | 0.178 / 0.217 / 0.217 | 24.244 / 26.320 / 26.320 | 36,552,704 |

## 판정과 남은 gate

**CONDITIONAL_GO**: 합성-only macOS CLI pilot 범위에서 진행할 수 있다. 새 SHA Ubuntu locked CI와 분리된 Linux process smoke, 실제 조직의 authorization/retention/encryption 정책은 미검증이다. 실제 사용자 자료 export와 운영 지원은 계속 **NO_GO**다. Public API/SSE/UI/HTML alias 계약은 그대로고 제한 보고서로 우회하지 않는다. embedding은 production `NO_GO`; local LLM/llama.cpp는 `STORAGE_SETUP_BLOCKED`; Gemini는 사용하지 않았다.

운영용 실제 식별자 보고서는 별도 gate가 필요하다. 암호화 정책, retention, 인증/RBAC, 감사 무결성, 실제 사용자 승인과 공유/backup 취급을 검토하기 전 실제 자료를 넣지 않는다.

## Phase 33.5C 상태

시작 gate의 Ubuntu run 40174710982는 해당 SHA에서 성공했지만, 그 run에는 제한 보고서 전용 Linux subprocess step이 없었다. 이후 workflow에 전용 smoke와 합성 benchmark를 추가했으며 새 SHA CI 실행을 기다리고 있다. Linux 파일 permission·atomic publish·동시성 acceptance는 아직 **NOT_TESTED**다. 취소·EOF·SIGINT와 이미 존재하는 destination 거부는 report와 audit 파일 모두를 만들거나 변경하지 않도록 후속 수정했으며, audit 부분 write/fsync는 rollback을 시도한다. 최신 변경 및 증거 경계는 [Phase 33.5C 수용 기록](trusted_analyst_report_linux_acceptance_33_5c.md)에 기록한다.
