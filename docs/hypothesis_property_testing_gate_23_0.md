# Phase 23.0 — Hypothesis property-based testing 도입 gate

판정: **CONDITIONAL GO (Phase 23.1의 제한된 개발용 pilot만)**. 이 단계는 문서 감사이며 Hypothesis 설치, 실행, production/API/분석 의미·의존성·lockfile 변경은 없다. GO의 근거는 테스트 개수가 아니라 독립적인 상태 모델로 queue 조합을 탐색하고 최소 반례를 얻을 수 있는 가능성이다. 실제 결함 발견이나 CI 비용 합격은 아직 입증하지 않았다. Phase 23.1 의존성 추가는 별도 승인 후에만 한다.

## 시작 기준과 공급망

2026-10-16 기준 `main`/`origin/main`은 `2d61ba226bf5da2f80e613a69986ee8afba94637`로 일치했고 working tree는 clean이었다. [해당 SHA의 GitHub Actions run](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38865560994)은 completed/success다. 변경 전 `uv run pytest -q`는 **2,249 passed, 기존 deprecation warning 2개**였다. 공개 `v0.2.0` annotated tag의 peeled commit은 `2520e317475f96d48b4bfeef8f7ee04d63720308`이고 공개 Release도 그 target을 유지했다.

| 항목 | 읽기 전용 확인 결과 | Phase 23.1 조건 |
| --- | --- | --- |
| 공식 소스·버전 | [HypothesisWorks/hypothesis v6.170.0](https://github.com/HypothesisWorks/hypothesis/releases/tag/v6.170.0), source commit `7572cd07bbb9d845c40f71c95ba3853fb7467403`; [PyPI hypothesis 6.170.0](https://pypi.org/project/hypothesis/)은 조사 시점 최신 안정판 | exact version으로 고정하고 새 게시가 있으면 metadata 재확인 |
| Python·license | [공식 package metadata](https://github.com/HypothesisWorks/hypothesis/blob/v6.170.0/hypothesis/pyproject.toml): Python `>=3.11`, MPL-2.0. 현재 Python 3.12와 호환 후보 | MIT 저장소에 개발 전용 의존성으로 쓰는 것은 명백한 충돌로 보이지 않지만 재배포 시 라이선스 고지 의무를 별도 확인; 법률 보증 아님 |
| dependency | 기본 직접 의존성 `sortedcontainers>=2.1.0,<3.0.0` 하나. [sortedcontainers 2.4.0](https://pypi.org/project/sortedcontainers/)은 Apache-2.0이고 조사한 wheel metadata에 추가 `Requires-Dist`가 없다. Hypothesis extras는 요청하지 않음 | `uv add --dev hypothesis==6.170.0` 제안만 하고 실행하지 않음. lock resolution 결과를 승인 후 검토 |
| 배포·설치 | PyPI에는 CPython 3.12 macOS ARM64/Linux wheel이 있다. v6.170.0 [build backend](https://github.com/HypothesisWorks/hypothesis/blob/v6.170.0/hypothesis/pyproject.toml)는 `maturin`이므로 최신 wheel은 플랫폼별 native code를 포함하는 배포물이다. macOS ARM64 cp312 wheel의 게시 SHA-256은 `0e8fc166ab2c10dbd8c798d0cf0e7fe3125df36e6993db25cf45104f6915bf41`이다. | 이번 단계에서 tarball/wheel을 다운로드·설치하거나 native payload를 검사하지 않았다. 승인 후 wheel hash·파일 목록·Linux wheel·wheel metadata를 확인하고 sdist fallback/build를 무심코 허용하지 않음. 설치 script/native code가 없다고 주장하지 않음 |

Wheel 설치는 npm lifecycle script와 같은 계약이 아니지만, sdist fallback은 PEP 517 build hook과 Rust toolchain을 실행할 수 있다. 현재 source-checkout 설치 방식은 바꾸지 않는다. Hypothesis와 sortedcontainers는 production runtime dependency나 사용자 기능으로 추가하지 않는다.

## 기존 테스트가 이미 보장하는 것과 새로운 가치

| 계층 | 현재 고정 테스트 | 추가할 조합 탐색 |
| --- | --- | --- |
| parser·tail | `test_live_parser_adapter.py`, `test_live_tail_reader.py`, parser parity: PARSED/IGNORED/REJECTED, UTF-8·CRLF·partial·2048 byte 줄 경계, FROM_END, 교체·축소 오류 | 문법을 지키는 세 role별 bounded 생성 줄과 chunk 분할·빈 줄·무효 byte·시각 경계를 조합. typed rejection은 허용하고 hang/예상 밖 오류를 거부. 같은 source bytes·timezone은 같은 normalized 의미를 내야 함 |
| queue·lease | `test_live_record_lease.py`, `test_live_record_ownership.py`: 한 active lease, stale/foreign 거부, FIFO release, ack, 32 items/16 KiB | append→poll→lease→release/ack→close의 다양한 짧은 순서에서 **독립 reference deque**와 resident=available+leased, sequence·byte·ack 집계를 매 단계 대조; 최소 실패 trace 축소 |
| worker·checkpoint | Phase 16.2/22.4 fault injection, `test_live_checkpoint.py`: ack 전/후 분리, bounded replay·semantic parity·private write, fail closed | fixture가 놓친 완성 LF byte offset·partial/chunk·replay anchor 조합. 단, I/O 비용과 재시작 oracle이 크므로 첫 pilot에는 포함하지 않음 |
| publication·privacy | `test_live_publication_buffer.py`, `test_live_analysis_publication.py`, privacy canary: batch 원자성, event ID/revision/replay gap, safe DTO | 다양한 category/change 조합에서 event ID·revision 단조성, replay가 정확한 suffix 아니면 명시적 gap, projection 문자열 canary 비노출. 이를 parser/queue보다 뒤 pilot으로 배치 |

기존 60초 경계·microseconds·nearest success·동률·순서 역전·중복, UTC/KST 및 반복 결정성은 이미 회귀에 있다. 보안 분석 의미를 새로운 임의 oracle로 재정의하지 않는다. Property는 기존 batch 계산 또는 **독립 reference model**과 비교하고, 동일 production 함수를 양쪽에서 호출하는 tautology를 피한다.

## Phase 23.1 최소 pilot의 세 property

1. **Parser property 하나.** `application`·`ssh`·`access`별 실제 문법의 작은 합성 template에서 정상·무시·거부 완성 줄을 만들고, 줄 길이 0/1/2048/2049 byte, LF/CRLF, strict UTF-8 오류, partial LF, chunk 경계, timezone 및 microseconds/60초 경계를 교차시킨다. 각 record의 예상 outcome class는 template에서 독립 지정한다. 동일 입력을 재실행한 normalized safe 의미는 동일해야 하며, `REJECTED`와 고정 typed 오류를 성공으로 바꾸지 않는다. 입력은 해당 `LiveTailRecord` 계약 이하이며 원본 임의 `st.binary()`만 반복하지 않는다.
2. **Lease/queue `RuleBasedStateMachine` 하나.** `tmp_path`의 합성 regular file 하나와 독립 `deque` 모델을 사용한다. rule은 append, poll, lease, release, acknowledge, parser 실패 주입, close. [공식 stateful API](https://hypothesis.readthedocs.io/en/latest/stateful.html)의 축소된 operation trace를 사용한다. 각 rule 뒤 active lease ≤1, resident=available+leased, 32 items/16 KiB 상한, FIFO/sequence, ack된 record만 제거, settlement 후 stale lease 거부, close 후 변화 거부, expected overflow 명시, 안전 snapshot raw payload 비노출을 확인한다. Poll/append는 명시적 bounded step만 수행하고 실제 사용자 파일·기본 config·홈을 열지 않는다.
3. **Privacy-safe projection property 하나.** 합성 account/IP/query/path/raw line/내부 예외에 서로 다른 **비실제 ASCII canary**를 넣고 typed input/유효한 change 조합만 생성한다. public DTO, error `str/repr`, snapshot과 직렬화된 JSON/SSE allowlist에서 원문 canary가 없는지 검사한다. Trusted event/queue payload와 private checkpoint metadata는 public 검사의 대상이 아니며, 이 한 property가 모든 개인정보 비노출을 증명한다고 주장하지 않는다. Public schema와 분석 의미는 수정하지 않는다.

후속 후보는 (a) checkpoint committed offset이 완성 LF 다음 **byte**인지, (b) 1/16/64/128/256 parsed prefix의 bounded batch 의미와 replay parity, (c) publication event ID·revision 단조성 및 suffix-or-gap exclusivity다. 파일 identity 교체·symlink·rotation/copytruncate는 무작위 파일 탐색이 아니라 별도 임시 파일 상태 기계에서 fail-closed만 검증한다. 256 event/256 KiB replay, 4096 byte/16 record poll, 2048 byte line, 32 item/16 KiB queue, 32 item/16 KiB publication과 128 KiB analysis snapshot을 각각 다른 한계로 취급한다.

## 재현성·CI·실패 산출물

실패는 Hypothesis의 shrinking으로 최소 **합성** 사례/operation trace를 얻고, 확인된 회귀는 고정 `@example` 또는 현재 fixture로 승격한다. Seed 하나에 의존하지 않는다. [공식 재현 문서](https://hypothesis.readthedocs.io/en/latest/tutorial/replaying-failures.html)의 로컬 `.hypothesis` example database는 pilot에서는 기본 사용을 피하고 CI profile은 `database=None`으로 명시할 계획이다. `.hypothesis/`는 추적하지 않도록 무시 규칙을 추가할 수 있지만 현재는 생성하지 않았다. `@reproduce_failure`는 버전 결합 임시 진단이지 영구 fixture가 아니다. CI output/pytest failure에 실제 로그·경로·credential을 넣지 않으며, 합성 canary도 실제처럼 보이는 secret 문자열을 쓰지 않는다.

변경 전 전체 pytest는 macOS 개발 환경에서 약 **82초**(2,249 tests, 기존 경고 2개). Phase 23.1은 parser/property와 짧은 state machine을 별도 파일/marker로 분리하고 **추가 시간 +10% 내외(약 8초)**를 PR CI의 *임시 후보 budget*으로 측정한다. 이는 측정 전 의사결정 기준이지 보장이나 운영 SLA가 아니다. warm-up, example 수, stateful steps, deadline은 실제 macOS·Ubuntu 24.04/Python 3.12 반복 측정 후 정한다. 첫 pilot의 checkpoint I/O-heavy·최대 prefix 조합은 nightly/수동 opt-in 후보이며 PR 필수 CI로 바로 넣지 않는다. Flaky failure를 재실행만으로 숨기지 않는다. UTC와 Asia/Seoul에서 동일해야 하는 것은 명시적 timezone 입력의 normalized UTC 의미와 safe projection이며, 로컬 시각 표시 자체가 같아야 한다는 property는 금지한다.

## Go/no-go와 보류 범위

**CONDITIONAL GO**: 위 세 pilot이 (1) 독립 모델에서 실제 반례를 축소하거나 (2) 기존 수작업 조합 수를 줄이면서 queue/개인정보 invariant를 더 넓게 검증하고, (3) supply-chain 검사와 CI 비용 gate를 통과하면 장기 유지한다. 단순 랜덤 반복이나 테스트 수 증가만 있으면 NO-GO. 설치 전에 사용자 승인이 필요하다. Native wheel 내용/설치 경계가 불명확하거나 sdist build가 강제되면 중단한다.

이번 단계에서 REA 실행형 pilot은 계속 **NO-GO**다. 자동 rotation/copytruncate handoff·두 세대 private checkpoint metadata 확대도 **NO-GO**. SSH checkpoint, access live analysis, cross-source 분석, exactly-once/무유실은 이번 test gate가 구현하거나 검증 완료로 바꾸지 않는다. 실제 운영 로그와 개인정보는 생성 strategy나 실패 example database에 넣지 않는다.
