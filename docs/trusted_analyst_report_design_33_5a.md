# Phase 33.5A — 제한된 내부 조사 보고서 설계 gate

상태: **CONDITIONAL_GO — 합성 입력 CLI pilot 계약 진행 가능**. 이번 단계는 설계와 문서 계약 테스트다. production 구현, 실제 보고서 생성, 실제 로그 접근은 하지 않았다. 실제 사용자 데이터의 운영 사용이나 보호된 배포를 승인하지 않는다.

## 판정과 경계

- 공개 API·SSE·UI·일반 HTML report는 계속 schema 2의 `subject_alias`와 안전한 집계만 사용한다. 실제 식별자를 공개 DTO에 되돌리지 않는다.
- 다음 pilot 후보는 **명시적 CLI 전용, 닫힌 JSON** export다. 브라우저, API, 자동화, 예약 실행, 외부 전송은 지원하지 않는다.
- 별도 local report 파일은 실제 account·IP·hostname을 포함할 수 있는 민감 자료다. `0700` 디렉터리와 `0600` 파일은 다른 일반 사용자 접근을 줄일 뿐, 같은 UID의 악성 프로세스·관리자·백업·동기화·악성코드로부터 보호하지 않는다. 암호화되지 않은 민감 로컬 파일임을 승인 전에 명시한다.
- 첫 pilot은 합성 자료만 허용한다. 실제 자료 적용은 별도의 승인·암호화·보존 검토 뒤로 미룬다.
- 공개 report나 내부 결과를 LLM, Gemini, embedding, RAG corpus에 전달하지 않는다. 네트워크·telemetry·원격 저장은 없다.

## Phase 33.4 종료 판정

Phase 33.4의 공개 projection·응답 범위 별칭·lexical guidance 계약은 기준 SHA `23c3ff4e782789d5a170dc8ea7d7c3eaf5cb449a`의 [push CI run 40170482306](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40170482306)이 `completed/success`였으므로 **GO**다. Ubuntu locked 설치와 전체 회귀 2,667 passed, warning 2개, Node·Chromium·axe 14개 상태의 violation 0, 외부 요청 0, 저장 artifact 0을 확인했다. v0.4.0 tag/Release target은 기존 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`을 유지한다.

Safari 사용자 확인 네 항목은 `PASS`였다: 합성 report가 공개용 안전 요약임을 이해, 같은 사례 내 별칭 의미 이해, 원 식별자 없이 활동 흐름과 위험 근거 이해, HTML/DOM/속성/주석 canary 비노출. 해당 화면과 report는 합성 사례만 사용했다. 200% 확대, 전체 VoiceOver, Web Inspector는 `NOT_TESTED`다. WCAG 2.2 AA 준수를 주장하지 않는다. 수용 근거는 [Phase 33.4C 기록](public_investigation_privacy_acceptance_33_4c.md)을 참조한다.

Phase 33.2 embedding은 production `NO_GO`; Phase 33.3F local LLM은 `STORAGE_SETUP_BLOCKED`로 유지한다.

## 지원 범위와 비지원 범위

| 지원 후보 | 범위 |
|---|---|
| 한 분석 실행의 사례별 현장 확인 | 사건 대응에 필요한 최소 subject 식별자와 기존 분석 결과만 포함 |
| 로컬 파일 생성 | 사용자가 명시한 로컬 경로의 닫힌 JSON 한 개 |
| 별도 오프라인 도구 입력 | 생성 후 분석가가 수동으로 다룸 |

| 명시적 비지원 | 이유 |
|---|---|
| 원본 로그 줄, normalized event 전체, source 파일 복제 | 데이터 최소화와 분석 결과 경계 유지 |
| 자동·주기 export, 브라우저 다운로드, API endpoint | 실수·원격 우회 경계 |
| 이메일·cloud·외부 API·공유 링크·원격 조회 | 외부 전송과 다중 사용자 권한 모델 부재 |
| credential, token, cookie, 환경변수, request body/header 전체, argv 전체 | 대응에 필요하지 않고 유출 영향이 큼 |
| public DTO/report에서 원 식별자 노출 | 공개 schema 2 별칭 계약 유지 |
| LLM/RAG 자동 등록 | 민감 자료가 모델 입력·corpus로 넘어가는 것을 방지 |
| 인증·RBAC, 브라우저 trusted view, 암호화, 자동 retention, 조직 감사 연동 | 별도 gate 대상 |

## 최소 데이터 계약 후보

후보 schema ID는 `restricted-investigation-report/v1`이며 JSON `schema_version`은 고정값 `1`이다. top-level과 nested object는 모두 closed schema이며 추가 필드는 거부한다. `report/run ID`는 매 export마다 CSPRNG 기반 불투명 값으로 새로 만든다. 이 값은 분석 run의 영구 ID가 아니며, 같은 분석을 다시 export해도 새 값이다.

| 필드 후보 | 필요한 이유 | 민감도 | 기본 포함 / 별도 승인 | 안전한 대체 | 보존·삭제 권고 | 공개 report와 차이 |
|---|---|---|---|---|---|---|
| report schema version | 오해 없는 parsing/migration | 낮음 | 기본 포함 / 승인 문구에 report 전체 승인 | 고정 상수 | report와 함께 삭제 | 공개 schema version과 다른 전용 schema |
| created_at, local timezone label | 시간 맥락과 재현성 | 낮음 | 기본 포함 / 전체 승인 | UTC 시각 + numeric offset; timezone 이름은 알 수 없으면 생략 | 필요 종료 후 즉시 삭제, 권고 최대 30일은 프로젝트 운영 heuristics | 공개 report는 대응 파일 생성 시각을 별도 기록하지 않을 수 있음 |
| report/run ID | 한 파일 내 명시적 식별 | 낮음~중간, 추적 가능성 | 기본 포함 / 전체 승인 | 매번 무작위 opaque ID | 파일과 감사 기록에서 같은 보존 기준 | public alias보다도 제한된 파일 내부에서만 사용 |
| source role | 로그 종류 확인 | 낮음 | 기본 포함 / 전체 승인 | 승인 enum: application/ssh/access | report와 함께 삭제 | 공개 결과에도 안전한 role만 허용 |
| case ID | report가 가리키는 사례 | 중간, 연결 가능성 | 기본 포함 / 전체 승인 | 무작위 export-local case ID; 내부 ID 미사용 | report와 함께 삭제 | public case ID를 외부 상관키로 복사하지 않음 |
| risk level·confidence | 기존 판단과 신뢰도를 분리해 전달 | 중간 | 기본 포함 / 전체 승인 | 승인 enum 및 bounded numeric/enum | report와 함께 삭제 | 값은 동일하지만 public projection의 안전 요약으로만 공개 |
| relation/observation type 및 승인된 설명 | 이유와 시간 흐름을 이해 | 중간 | 기본 포함 / 전체 승인 | allowlist 기반 label/template; free-form rationale 제외 | report와 함께 삭제 | 원문 rationale/evidence 없음 |
| account | 식별된 대상 대응 | 높음 | 기본은 해당 사례의 최소 필요값만 포함; 민감 범위 승인 필수 | 값이 없는 경우 `unavailable` 상태 코드 | 업무 필요 종료 후 삭제; 정책 우선 | 공개 alias만 제공 |
| IP (IPv4/IPv6) | source/target 네트워크 대응 | 높음 | 해당 사례의 최소 주체만 포함; 민감 범위 승인 필수 | `unavailable`; 부분 마스킹은 사용하지 않음 | 업무 필요 종료 후 삭제; 정책 우선 | 공개 alias만 제공 |
| hostname | 호스트 대응 | 높음 | 사례 근거가 지원할 때만; 민감 범위 승인 필수 | `unavailable` | 업무 필요 종료 후 삭제; 정책 우선 | 공개 alias만 제공 |
| 사건 시간 범위 | 사건 순서와 범위 확인 | 중간 | bounded 범위 기본 포함 / 전체 승인 | timezone offset 포함 시작·종료 시각 | report와 함께 삭제 | 안전한 제한 범위만 public에 표시 |
| limitation codes | 해석상 한계 명시 | 낮음 | 기본 포함 / 전체 승인 | enum: `incomplete_evidence`, `not_causal`, `not_confirmed_compromise`, `source_gap`, `unsupported_source` | report와 함께 삭제 | 공개 한계보다 구체적일 수 있지만 allowlist만 허용 |
| source file digest | 입력 파일 동일성 검증 후보 | 중간~높음, 알려진 로그의 fingerprint | **기본 제외**; 필요성 별도 gate 없이는 금지 | 없음 | 기록하지 않음 | 공개 report에도 없음 |
| absolute path, checkpoint metadata, raw line, full rationale, internal exception, credential | 대응에 불필요하거나 원문/환경 노출 | 매우 높음 | 영구 제외 | 없음 | 저장하지 않음 | public과 내부 report 모두 금지 |

포함 수는 현재 분석 결과에 실제 존재하는 관찰/관계/사례를 넘지 않는다. 보고서는 기존 결과의 닫힌 allowlist projection이며 detector/correlation/risk/case 객체를 다시 실행하거나 수정하지 않는다. 원문 로그는 읽기 입력일 수 있으나 출력에는 복사되지 않는다.

### JSON 계약

- 한 JSON object만 기록하고 duplicate key를 거부한다. 모든 object key는 고정 집합, 모든 enum은 승인 값, 문자열/배열/전체 직렬화 크기는 제한한다.
- 초안 상한은 report 1 MiB, cases 256, case당 relations 64, observations 256, 식별자 문자열 UTF-8 512 bytes, 설명 label 256 bytes다. 이는 운영 표준이 아니라 합성 pilot의 개발 상한이며 평가 후 고정한다.
- UTF-8과 LF, canonical key order, 정수/decimal 표현을 고정한다. UTC 또는 local offset을 명시하고 host locale에 따라 날짜 의미가 바뀌지 않게 한다.
- HTML은 첫 pilot에서 제공하지 않는다. JSON은 HTML/script active content가 없고 구조적 검증 및 offline tool 연결이 명확하다. 그러나 JSON도 민감정보 유출·잘못된 공유·fingerprinting 위험은 남는다.

## CLI와 승인 UX 후보

전용 module 후보:

```text
uv run python -m app.restricted_report export \
  --application-log <explicit-path> [--ssh-log <explicit-path>] \
  [--access-log <explicit-path>] --case-id <current-case-id> \
  --output <explicit-local-path>
```

이는 설계 예시이며 CLI는 구현되지 않았다. `--monitor`, `--monitor-config`, 기존 report exporter와 분리한다. 기본 HOME/Desktop/config/checkpoint를 탐색하지 않는다. source input, 현재 사례 선택값, output을 사용자가 명시한다. network filesystem, mount/volume이 local임을 식별할 수 없는 경로는 fail closed 한다. 경로를 일반 성공/error/log에 출력하지 않지만, CLI argv를 `ps`나 shell history에서 관찰할 수 있는 OS 한계는 숨기지 않는다. 후속 구현은 output path를 prompt로 받는 방식도 평가한다.

### 사전 요약과 승인 문구

사전 요약은 경로를 제외한 안전 집계만 보여준다. 예: “사례 1건, 탐지 2건, 관계 1건, 계정 1개·IP 2개·호스트 이름 1개가 보고서에 들어갈 수 있습니다.” 존재하지 않는 값을 0으로 오해하지 않도록 `사용 불가`와 `없음`을 구별한다.

생성 직전에는 선택한 output 위치를 명시적으로 보여줘 사용자가 목적지를 확인하게 한다. 정확한 승인 문구 후보:

> 제한된 내부 조사 보고서를 생성합니다. 이 파일에는 실제 계정·IP·호스트 이름과 기존 분석 요약이 포함될 수 있습니다. 원본 로그 전체는 포함하지 않습니다. 파일은 로컬에 암호화 없이 저장되며, 자동 외부 전송은 없습니다. 공유·백업·동기화를 주의하고 사용 후 직접 삭제해야 합니다. 위 내용을 이해하고 이 위치에 저장하려면 `민감정보 포함 보고서 생성 승인`을 정확히 입력하세요.

- 비어 있는 응답, y/yes, 잘못된 문구, EOF, Ctrl+C: `생성을 취소했습니다. 파일은 만들어지지 않았습니다.` 성공/감사 성공으로 기록하지 않는다. Phase 33.5C 구현 판정에서는 취소 자체가 파일을 생성·변경하지 않으며 audit 행도 남기지 않는다.
- 성공: `제한된 보고서를 로컬에 생성했습니다. 파일에는 민감정보가 포함될 수 있습니다. 공유하지 말고 업무 종료 후 삭제하세요.` 출력은 경로 대신 case 수, field kind/count, report SHA-256, opaque report ID만 허용한다. 민감 값은 stdout/stderr에 출력하지 않는다.
- 오류: 고정 문구 `보고서를 안전하게 완성하지 못했습니다. 지정한 위치와 권한을 확인하고, 남은 임시 파일이 없는지 직접 확인하세요.` 원문 예외, 경로, 부분 JSON을 출력하지 않는다.

승인은 단일 실행의 명시적 의사 확인이다. OS 계정은 사용자 신원을 강하게 인증하지 않고, 이 도구에 RBAC가 없으므로 “권한 있는 사용자만 접근 보장”이라고 표현하지 않는다.

## 파일시스템, no-clobber, atomic completion

후속 구현 후보 계약:

1. `umask 077`; parent는 현재 UID 소유의 신규 또는 검증된 private 디렉터리, mode `0700`, symlink 없는 경로여야 한다. 경로 구성 요소를 가능한 경우 directory FD 기준 `openat`/`O_NOFOLLOW`로 순회한다. 안전한 parent를 자동 chmod로 바꾸지 않고 요구조건을 거부/설명한다.
2. network filesystem·공유 mount·확인 불가한 filesystem은 거부한다. 기존 output은 symlink/hard-link/regular file 여부와 무관하게 덮어쓰지 않는다. output 자체는 exclusive create로만 새로 게시한다.
3. basename에 대해 `O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW`와 mode `0600`을 사용한다. `fstat`로 regular file, 현재 UID, `st_nlink == 1`, 예상 권한을 확인한다. FIFO, device, socket, symlink, hard link를 거부한다. 기존 파일이 발견되면 그대로 둔다.
4. 내용은 목적지와 같은 private directory 안에서 난수 이름의 숨김 임시 파일을 `0600`으로 생성하고, 제한된 bytes를 모두 쓴다. `flush` 후 `fsync(file)`, 재-open/parse 검증, atomic no-replace publish 후 `fsync(parent directory)`를 시도한다.
5. Python 표준 `os.replace`는 destination 교체를 허용하므로 no-clobber 용도로 직접 사용하지 않는다. portable 임시 파일 + atomic hard-link publish 계약을 후보로 둔다: 완성된 temp inode에 no-replace hard link를 destination으로 만들고 directory를 sync한 뒤 temp name을 unlink한다. Link 수가 1이 아닌 파일과 unsupported filesystem은 fail closed. 플랫폼별 syscall 지원·directory fsync semantics가 검증되지 않으면 해당 플랫폼 구현은 보류한다. 링크 후 temp unlink 실패는 “성공, 정리완료”로 축소하지 않고 고정 cleanup 경고와 잔존 항목 있음으로 보고한다.
6. partial write, ENOSPC, serialization/validation failure, signal interruption에서는 destination을 만들지 않는다. temp FD를 닫고 temp를 unlink한다. cleanup 실패 시 실패 단계 코드만 내부 진단으로 세고 원문 경로/예외는 남기지 않는다. hard crash/SIGKILL/전원 차단은 cleanup 보장 밖이며 사용자가 hidden temp를 확인해야 한다.
7. 동일 UID 비협력 프로세스가 parent를 동시에 바꾸거나 권한이 있는 동안 파일을 읽는 공격까지 막는다고 주장하지 않는다. Directory FD, `O_NOFOLLOW`, `O_EXCL`, `fstat`는 race를 좁히지만 동일 UID malware, 관리자, kernel, filesystem 결함을 해결하지 않는다.

저장 디렉터리와 output 경로는 명시적으로 요청하되 일반 성공 로그/감사에서 숨긴다. 최종 승인 직전 사용자에게 목적지를 보여준다. `0600`은 권한 통제이지 암호화가 아니다.

## 최소 감사 기록

첫 실제 사용자 기능 전에는 export 성공·실패·취소의 최소 local audit이 유용하나, 합성 pilot에서는 감사 저장 기능도 구현하지 않는다. 후보 record는 closed JSONL: timestamp+offset, event enum, report schema, field kinds 및 count, case count, opaque report ID, 고정 failure stage enum. account/IP/hostname/path/raw data/exception은 금지한다. report digest는 같은 보고서의 외부 추적이나 지문 결합을 쉽게 하므로 persistent audit에는 넣지 않고, CLI가 성공 시 report SHA-256을 직접 표시하는 방안을 pilot에서 평가한다.

감사 경로는 별도 private directory `0700`, 파일 `0600`, exclusive append, record 최대 2 KiB, 총 1 MiB 제한 후보를 둔다. 자동 rotation은 첫 구현에서 하지 않고 cap 도달 시 새로운 export를 fail closed 한다. 권한·크기·regular-file·link count를 검사한다. JSONL append는 partial line/ENOSPC 위험을 갖고, hash-chain도 같은 UID가 파일을 다시 쓰면 변조 방지 증명이 되지 않는다. 따라서 audit는 운영자 편의 기록이며 부인 방지·조직 규정 준수·침해 방지 보장이 아니다. audit write 실패 시 report 생성도 실패시키는 fail-closed 후보를 택하되, report commit 이후 audit failure가 발생하면 이미 게시된 report를 자동 삭제해 원자적 transaction처럼 표현하지 않는다. 그 경우 fixed “생성 결과 확인 필요”로 종료하고 opaque ID만 재확인한다.

사용자는 OS 프로세스 UID와 같다고 가정하지 않는다. 관리자 권한·악성코드·같은 UID 프로그램·백업/동기화 사용자는 파일을 볼 수 있다.

## 위협 모델과 실패 동작

| 위협 | 자산/진입점 | 예방 | 탐지/실패 동작 | 잔여 위험 |
|---|---|---|---|---|
| 공개 파일 대신 제한 report 공유 | CLI 승인, output 파일 | 별도 명령/파일명·경고, 정확한 승인 문구, private mode | preview와 schema marker, 취소는 파일 생성 전 종료 | 사용자가 승인 후 잘못 공유 가능 |
| output 경로/파일명 노출 | argv, terminal, logs | 일반 로그·audit에서 경로 제외, error 고정화 | stdout/stderr canary test | shell history, process list, terminal recording |
| symlink/hard-link | parent, destination | dirfd traversal, O_NOFOLLOW, O_EXCL, st_nlink 검사 | 유형·UID·mode 검사 실패 시 거부 | 플랫폼별 flag semantics 차이 |
| TOCTOU, 동일 UID 협력하지 않는 process | directory entry 및 audit | held dirfd, exclusive create, same-directory temp | commit 전후 file identity 확인 | 동일 UID attacker가 권한 있는 순간 관찰/변경할 수 있음 |
| unsafe parent/network FS | output parent | owner/mode/local FS 요구 | 식별 불가 시 중단 | 일부 FS 특성 판정이 플랫폼 의존 |
| partial write/disk full | temp/destination | byte bound, temp+atomic no-replace publish, fsync | destination 없음 보장; temp cleanup best effort | crash 이후 temp 잔존, fsync durability 차이 |
| temp residue | temp file | unpredictable name, 0600, cleanup finally | 내부 단계 코드/count만 기록 | SIGKILL/전원 차단 후 잔존 가능 |
| digest/audit linkage | report id/digest | audit에 output digest/path 제외 | field allowlist 검사 | CLI SHA 출력은 사용자가 보관하면 연결 가능 |
| Safari/API bypass | HTTP routes, UI | report export route/button 없음, CLI separate module | route/OpenAPI invariant test | OS process를 직접 실행할 권한 있는 사용자는 CLI 접근 가능 |
| HTML/script injection | JSON values, consumers | HTML 형식 제외, JSON closed schema, escaping downstream | `<script>` 등 adversarial string remains inert data; schema/size tests | offline tool이 잘못 렌더링할 수 있음 |
| account/IP/hostname 정보 노출 | case projection | 최소 필요한 subject만 allowlist, approval, 1 MiB bound | JSON parsed fields canary tests | 저장·화면 캡처·공유 후 회수 불가 |
| 오래된 파일·Time Machine/cloud sync | local storage/backup | 저장 책임/삭제 주의, sync 경로 거부 시도 | preflight 안내 | 기존 backup, cloud client, Trash, snapshots에 복제될 수 있음 |
| crash/SIGKILL/power loss | temp/report/audit | commit ordering, fsync | 재실행 후 temp/output inventory 테스트 | cleanup/durability 보장 불가 |
| malware/same UID/admin | report at rest | mode 0600, FileVault/full-disk encryption 환경 권고 | 별도 OS 보안 점검 | 열린 세션/동일 UID에서 plaintext 접근 |
| 사용자 수동 외부 AI 업로드 | 생성된 JSON | 강한 경고, AI integration 부재 | 도구가 외부 전송 안 함 | 사용자가 수동 업로드하는 잔여 위험 |

성공 조건은 “로컬에서만 자동 처리”까지다. 백업, OS indexing, crash recovery, user-initiated copy/upload를 막았다고 말하지 않는다.

## 암호화 결정

첫 합성 CLI pilot은 report 자체 암호화를 구현하지 않는다. 직접 암호 primitive, passphrase prompt, key file, 자동 keychain 연동도 추가하지 않는다. 보고서 승인 문구는 **“로컬 파일이지만 자동 암호화되지 않습니다”**라고 말한다. 로컬 시스템을 실제 사용하면 저장 volume의 OS 전체 디스크 암호화와 backup encryption 상태를 운영자가 확인하라고 권고할 수 있으나, 그것은 report 자체의 end-to-end encryption이 아니며 로그인된 사용자, 같은 UID malware, 관리자, malware-in-memory를 방어하지 않는다.

macOS는 FileVault와 Time Machine backup encryption이 각각 별도의 control임을 안내한다. NIST SP 800-209는 저장 암호화를 민감 data protection으로 다루며 key/retention 비용을 함께 설명한다. pilot에서 key 생성·보관·복구·분실 시나리오를 검증하지 못하므로 application-level encryption은 별도 gate로 남긴다. 운영 사용에 필요한 조직 암호화 정책을 확인할 수 없다면 실제 식별정보 export는 보류한다.

## 실패 처리

| 조건 | 결과 |
|---|---|
| 승인 미입력/취소, 입력 부재, case stale/범위 불일치 | fixed 취소/거부; 파일 없음 |
| destination 존재, symlink, hard-link, FIFO/device/socket, unsafe parent, nonlocal FS | no-clobber 거부; 기존 항목 변경 없음 |
| malformed trusted analysis, duplicate key, schema/size 초과, serialization 오류 | fixed 실패; temp만 cleanup 시도; public report fallback 금지 |
| permission/ENOSPC/fsync/link/rename/cleanup 오류 | fixed failure stage; 원문 예외·경로 비노출; 존재 결과를 성공으로 가정하지 않음 |
| Ctrl+C/SIGTERM | child/process 없음; 열린 FD 닫기, temp 삭제 시도; terminal에는 고정 취소 메시지 |
| SIGKILL/kernel crash/power failure | 보장 없음; temp file 잔존 가능성을 설명하고 다음 수동 확인 필요 |
| audit 저장 실패 | audit-required mode라면 export 시작 전 거부; report commit 후 기록 실패는 원자 성공으로 표현하지 않음 |

어떤 경우에도 공개용 safe report를 대체 산출물로 만들지 않는다. 원 분석 result와 detection/risk/case 객체는 immutable input으로 취급한다.

## Phase 33.5B 테스트 계약

실패 주입 테스트를 production 구현보다 먼저 작성한다. 모두 합성 application·SSH·access event만 사용한다.

1. 승인 미입력은 거부하고 report가 없다.
2. 기존 destination은 보존하고 덮어쓰지 않는다.
3. symlink/hard-link/FIFO/device/socket destination과 unsafe parent를 거부한다.
4. 새 directory/file mode `0700`/`0600`, owner, `st_nlink`, regular type를 검증한다.
5. account·IPv4·IPv6·hostname 허용 최소 필드와 승인 전 preview count를 검증한다.
6. raw lines, absolute paths, full rationale, credentials, internal exceptions, argv 전체를 제외한다.
7. public API/SSE/UI/HTML report에 식별자가 계속 없어야 한다.
8. closed JSON schema, duplicate/unknown key, oversized fields/arrays/bytes를 거부한다.
9. HTML/script canary가 JSON data로만 직렬화되며 HTML은 생성되지 않는다.
10. partial write, disk full, fsync, atomic publish, serialization failure 후 완성 report가 남지 않는다.
11. Ctrl+C/SIGTERM 및 반복 호출은 temp/FD 상태를 검증한다. SIGKILL은 cleanup 보장을 주장하지 않고 residue probe로 한계를 시험한다.
12. audit record에서 계정/IP/hostname/path/exception canary가 없고 size/permission cap을 지킨다.
13. report SHA-256은 정확한 최종 bytes를 대상으로 계산한다. random ID와 generated_at 때문에 동일 분석 재실행 report digest는 달라질 수 있음을 고정한다.
14. UTC/Asia/Seoul은 같은 UTC instant와 explicit local offset 의미를 보존한다.
15. application/SSH/access 각각의 합성 event source를 다룬다.
16. schema 2 single-source, schema 3 pair 상태에서 선택 사례의 안전한 분석 결과를 유지한다.
17. export 전후 trusted analysis snapshot byte-equivalent임을 확인한다.
18. 실제 원본 로그를 사용하지 않는 별도 subprocess smoke를 돌린다.
19. 종료 뒤 temp, listener, task, owned FD가 남지 않는지 확인한다.

## 성능·resource 계획

`1`, `32`, `256` event/case 합성 fixture로 serialization, JSON validation, file write+fsync, atomic publish, cleanup을 측정한다. warm-up과 sample count, median/p95/max, output bytes, peak RSS를 기록한다. 후보 상한은 report 1 MiB, selected cases 256, worker timeout 5초이며 실제 benchmark 이전의 개발용 제한이다. 이 수치는 운영 SLA 또는 최악 입력 보장이 아니다. 메모리는 test subprocess RSS와 parent가 가진 bounded DTO size로 관찰하며 시스템 전체 FD 수를 비교하지 않는다.

## 근거와 관찰 가능성

- **Research basis:** Python 3.12 `tempfile`은 `mkstemp`가 OS exclusive-create 동작에 의존해 race를 줄이고 creator-only 접근으로 파일을 만들며, caller가 cleanup 책임을 갖는다고 명시한다. Python `os` 문서는 `fsync`가 buffered file에서는 flush 뒤 호출되어야 한다고 설명한다. Linux `openat(2)` 문서는 `O_NOFOLLOW`의 symlink 동작을 정의한다. 그래서 dirfd/`O_NOFOLLOW`/`O_EXCL`/`fstat`/flush+fsync를 계약 후보로 두되, OS와 filesystem마다 publish/dir-fsync 차이가 있으므로 platform-specific 검증 전에는 구현 승인으로 보지 않는다.
- **Observable mapping:** 사용할 원 분석 구조에서 필요한 값은 case projection의 existing relation/observation/risk labels 및 대응에 필요한 allowlisted account/IP/hostname 값뿐이다. 보고서에 raw event line, file path, private rationale, checkpoint identity를 복사하지 않는다. 원 자료가 없으면 `unavailable`/limitation code를 쓰고 추론으로 채우지 않는다.
- **Encryption basis:** NIST storage guidance는 at-rest encryption과 key/retention 관리의 이점을 다루며, Apple FileVault와 Time Machine 문서는 시작 디스크와 backup encryption을 구분한다. 따라서 `0600`을 encryption으로 부르지 않고 backup/Time Machine/cloud sync 잔여 위험을 승인 화면에서 고지한다.
- **Limitations:** 단일 UID CLI는 신원 인증/RBAC가 아니며 same UID process와 관리자 방어를 제공하지 않는다. User-space atomic publish와 fsync는 모든 filesystem의 crash durability를 보장하지 않는다. 파일 삭제는 backup/SSD/스냅샷에서 secure erase가 아니다. 여러 OS/filesystem을 대상으로 한 실제 syscall 동작 시험은 Phase 33.5B에서 해야 한다.

참고 자료:

- [Python 3.12 `tempfile`](https://docs.python.org/3.12/library/tempfile.html)
- [Python 3.12 `os`](https://docs.python.org/3.12/library/os.html)
- [Linux man-pages `openat(2)`](https://man7.org/linux/man-pages/man2/openat.2.html)
- [NIST SP 800-209, Security Guidelines for Storage Infrastructure](https://csrc.nist.gov/pubs/sp/800/209/final)
- [Apple: Protect data on your Mac with FileVault](https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785/mac)
- [Apple: Keep your Time Machine backup disk for Mac secure](https://support.apple.com/guide/mac-help/keep-your-time-machine-backup-disk-secure-mh21241/mac)

## Phase 33.5B 진입 판정

**CONDITIONAL_GO — 합성 전용 CLI JSON pilot 설계 가능.** 먼저 실패 테스트, closed schema, atomic no-replace publish를 구현·검증한다. 실제 자료 사용, application-level encryption, RBAC, audit integrity, macOS/Linux filesystem별 crash guarantees는 통과했다고 가정하지 않는다. 브라우저 trusted view, encrypted report, 자동 retention, 조직 audit, 원격 저장과 공유 workflow는 별도 승인 gate 전까지 `NO_GO`다.

## Phase 33.5B 구현 결과

합성 입력만 받는 별도 명령 `python -m app.restricted_report`를 구현했다. 명시적 role/input/output, 정확한 한국어 승인 문구, closed JSON, private parent/report/audit permission과 no-clobber 저장 계약은 [33.5B pilot 기록](trusted_analyst_report_pilot_33_5b.md)에 있다. **실제 사용자 자료 export는 승인되지 않았다.** 이 구현은 실제/합성 자료를 자동 분류하지 못하며 운영 지원 선언이 아니다. Linux 별도 프로세스 CI와 조직 authorization/retention/encryption 정책 검토가 남아 있다.

Phase 33.5C에서 취소와 이미 존재하는 destination의 사전 거부는 report/audit를 만들거나 바꾸지 않는 동작으로 구체화했다. 시작 gate run 40174710982는 통과했지만 그 다음에 추가한 Linux-only smoke와 benchmark step은 새 SHA CI에서 아직 실행되지 않아 Linux acceptance는 **NOT_TESTED**다. [33.5C 수용 기록](trusted_analyst_report_linux_acceptance_33_5c.md)에 자동 증거와 남은 항목을 구분해 둔다.

## 이 설계 변경의 검증 기록

- 변경 전 기준선: Phase 33.4C SHA `23c3ff4e782789d5a170dc8ea7d7c3eaf5cb449a`, 전체 pytest **2667 passed, 2 warnings**. Ubuntu CI run 40170482306도 같은 결과였다.
- test-first: 새 문서 계약 테스트를 먼저 실행했다. 설계 파일과 README/docs index/33.4C 최종 GO 문구가 아직 없어 **3 failed**로 의도한 실패를 확인한 다음 문서를 작성했다.
- 최종 로컬 검증: 전체 pytest **2670 passed, 2 warnings**; 설계·33.4C·privacy/API/report/guidance focused **118 passed, 2 warnings**; Node/Chromium/axe **14 states, 0 violations, external_requests=0**.
- 기존 규칙 기반 합성 평가: 79/79, Linux process 21/21, risk 70/70, case 70/70.
- `npm ci --ignore-scripts --no-audit --no-fund`, `uv sync --locked --dev`, `uv lock --check`, Python/Node syntax, `git diff --check` 통과. Dependency와 lockfile은 변경하지 않았다.
- 이번 단계에서 실제 분석 자료나 report를 생성하지 않았으며 production code/API/SSE/UI를 변경하지 않았다.
