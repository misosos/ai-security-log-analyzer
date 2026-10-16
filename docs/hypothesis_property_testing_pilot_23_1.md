# Phase 23.1 — bounded Hypothesis 개발용 pilot

판정: **CONDITIONAL GO**. 합성 parser·queue·개인정보 projection의 새로운 조합을 기본 CI가 수집하는 테스트 파일 하나에 추가했다. macOS arm64/Python 3.12.7에서 안정적으로 실행됐고 새 production 버그는 발견하지 못했다. Ubuntu 24.04 x86_64의 정확한 wheel을 정적으로 검사했지만 이 커밋의 원격 CI 실행은 push 전이라 아직 검증되지 않았다. Hypothesis가 운영 탐지율, 개인정보 완전성, 무유실, exactly-once를 증명하지 않는다.

## 설치 전 공급망 gate와 개발 의존성

2026-10-16 기준 [공식 Hypothesis v6.170.0 release](https://github.com/HypothesisWorks/hypothesis/releases/tag/v6.170.0)의 source commit은 `7572cd07bbb9d845c40f71c95ba3853fb7467403`이다. [PyPI 6.170.0 metadata](https://pypi.org/project/hypothesis/6.170.0/)는 Python `>=3.11`, MPL-2.0, 기본 직접 의존성 `sortedcontainers>=2.1.0,<3.0.0`을 명시한다. Extras는 요청하지 않았다. [sortedcontainers 2.4.0 metadata](https://pypi.org/project/sortedcontainers/2.4.0/)는 Apache-2.0이며 추가 runtime dependency가 없다. MIT 저장소에서 개발 전용으로 사용하는 데 명백한 라이선스 충돌은 확인되지 않았으나 법률 보증은 아니다.

설치 전에 전용 OS 임시 디렉터리에 **wheel만** 내려받아 게시 SHA-256과 실제 값을 대조하고 ZIP 파일 목록·권한·METADATA/entry points를 읽었다. Sdist는 다운로드·빌드하지 않았다.

| 대상 artifact | tag / byte | 게시 SHA-256 = 실제 SHA-256 | 정적 내용 |
| --- | ---: | --- | --- |
| `hypothesis-6.170.0-cp312-cp312-macosx_11_0_arm64.whl` | CPython 3.12, macOS arm64 / 790,115 | `0e8fc166ab2c10dbd8c798d0cf0e7fe3125df36e6993db25cf45104f6915bf41` | 실행권한 파일은 예상된 `hypothesis/_native.cpython-312-darwin.so` 하나 |
| `hypothesis-6.170.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | CPython 3.12, Ubuntu CI x86_64 호환 / 1,162,826 | `13be368fd3aa29bd199c79dc459e18b1d6b4cb0687419bcd751f22a2e1b773a9` | 실행권한 파일은 예상된 `hypothesis/_native.cpython-312-x86_64-linux-gnu.so` 하나 |
| `sortedcontainers-2.4.0-py2.py3-none-any.whl` | universal / 29,575 | `a163dcaede0f1c021485e957a39245190e74249897e2ae4b2aa38595db237ee0` | native binary·별도 실행권한 파일 없음 |

Hypothesis wheel에는 console/pytest entry point가 있으나 `.data/scripts`, 별도 installer 실행 파일, 추가 native addon은 없었다. Wheel 설치에는 npm식 lifecycle script가 없지만 **native code 자체는 존재**한다. Sdist의 [공식 빌드 backend](https://github.com/HypothesisWorks/hypothesis/blob/v6.170.0/hypothesis/pyproject.toml)는 `maturin`이고 빌드 실행 경계가 다르다. 따라서 `uv add --dev 'hypothesis==6.170.0' --no-build`로 설치했으며 CI 기존 locked install 단계에 두 새 package의 `--no-build-package` gate를 더했다. 플랫폼에 wheel이 없으면 조용히 sdist로 넘어가는 대신 실패한다. 배포물의 서명·provenance나 native binary의 소스 재현 빌드는 **독립 검증하지 않았다**.

Mac의 설치된 WHEEL tag는 `cp312-cp312-macosx_11_0_arm64`, `_native`는 Mach-O arm64로 확인했다. Ubuntu CI는 `ubuntu-24.04`, Python 3.12.7이며 위 manylinux wheel이 후보이나 실제 CI 선택/실행 결과는 해당 commit push 후 별도 확인해야 한다. `pyproject.toml`에서 Hypothesis는 `dependency-groups.dev`에만 있고 프로젝트 runtime `dependencies`와 application import graph에는 없다. `uv.lock`의 변경은 Hypothesis·sortedcontainers와 dev metadata에 한정됐다. Source-checkout 설치 방식과 공개 schema는 유지했다.

## 세 pilot과 oracle

`tests/test_live_property_pilot_23_1.py`만 Hypothesis를 import한다. 각 test에 `database=None`, `derandomize=False`, 기본 deadline을 사용했고 seed 고정·health-check suppression·flaky retry는 없다. 최종 `max_examples`는 parser 60+tail 35, state machine 35(각 24 step), privacy 25로 측정 후 유지했다.

| Pilot | 생성 전략·검증 | 보장하지 않는 것 |
| --- | --- | --- |
| A parser/tail | application·SSH·access별 합성 valid/optional/blank/malformed/fractional timestamp, 작은 Unicode token, 초 00/01/05/59. 고정 문법에서 기대한 PARSED/IGNORED/REJECTED, 같은 입력의 반복 결과, UTC·microsecond=0. 별도 임시 regular file에서 길이 0/1/1023/2047/2048/2049 byte, LF/CRLF/partial, invalid UTF-8, 원본 byte offset·FROM_END를 검증 | 모든 임의 byte 문자열의 의미, 미지원 fractional timestamp의 자동 수용, batch와 live adapter의 동일 control flow, 운영 log 형식 완전성 |
| B queue/lease | `RuleBasedStateMachine`의 짧은 줄·512/700 byte 넓은 줄 append, poll/lease/release/ack/close와 foreign·stale/중복 settlement. Production queue를 복제하지 않는 독립 `deque`의 byte/sequence/FIFO reference model과 매 step 비교. 32 item·16 KiB를 별도로 탐색하고 resident=available+leased, overflow 고정 실패, close 후 거부 | 무제한 동시 프로세스, OS 파일 교체/rotation, worker의 모든 ack 후 crash window. 생성 실행이 매번 각 overflow 경로를 방문한다고 주장하지 않음 |
| C privacy | 합성 account/IP/path/query/raw marker/filename/내부 예외 조합으로 실제 application worker commit 후 safe snapshot·change event·serialized SSE·`repr`·`asdict`·JSON·stdout/stderr, 예상 밖 poll 오류를 검사. 원문/긴 부분 문자열/SHA-256 hex 비노출 | 임의 신종 PII 검출, 모든 API/DOM 경계의 완전 증명; trusted detection history에는 원문이 의도적으로 남음 |

두 검사 실패는 **pilot oracle 오류**였다. 첫 실행에서 CRLF의 `\r` 한 byte를 최대 줄 길이에 포함하지 않아 Hypothesis가 `width=2047, ending=CRLF, invalid UTF-8` 최소 반례를 축소했다. 실제 tail은 2049 byte를 `LINE_TOO_LONG`으로 거부하는 올바른 기존 계약이었다. 또한 `capsys`는 생성 example마다 초기화되지 않는 함수 fixture여서 Hypothesis health check가 거부했다. 길이 oracle을 고치고 example-local `StringIO`로 바꾼 뒤 통과했다. Production 결함으로 기록하거나 억지로 코드 의미를 변경하지 않았다. 따라서 수정 전 **deterministic production 실패 회귀**나 production 수정은 없다.

## 실행 시간·CI 비용

측정 환경은 macOS arm64, Python 3.12.7, 동일 source checkout/uv env다. 각 명령을 독립 Python process에서 3회 실행했고 Hypothesis example database는 껐다. OS cache를 지운 cold 측정은 아니므로 첫 실행은 *process cold/cache warm 가능*, 뒤 2개는 warm 비교다. `tracemalloc`은 사용하지 않았다. 단위는 pytest 보고값 초다.

| 대상 | 각 3회 측정 | 범위 | 입력 상한 |
| --- | --- | --- | --- |
| Parser+tail A | 1.00 / 1.07 / 1.03 | 1.00–1.07 | 60+35 examples, 줄 ≤2049 byte |
| Queue B | 1.45 / 1.43 / 1.50 | 1.43–1.50 | 35 traces × 최대 24 step |
| Privacy C | 1.01 / 1.02 / 0.99 | 0.99–1.02 | 25 worker runs, 합성 6줄씩 |
| 전체 property 파일 | 1.94 / 1.94 / 1.82 | 1.82–1.94 | 위 세 pilot |

각 pilot의 독립 실행 시간 합계를 전체 파일 비용으로 계산하지 않는다(공통 pytest/uv 시작 비용이 겹친다). 변경 전 전체 회귀는 **2,252 passed / 77.88초 / 기존 경고 2개**였다. 변경 후 전체 회귀 두 표본은 **2,258 passed / 81.58초**와 **2,258 passed / 82.42초**, 모두 같은 경고 2개였다. 동일 환경 관측 차이는 **+3.70~4.54초**이나 baseline 1회·변경 후 2회뿐이므로 plugin 비용이나 CI 최악 시간을 이 수치로 확정하지 않는다. 목표 +8초는 Phase 23.0의 개발용 gate 후보이지 운영 SLA나 hard timeout이 아니다. CI는 별도 property 반복 job을 만들지 않고 기존 full pytest가 파일을 한 번 수집한다. Checkpoint 대규모 I/O property는 별도 장시간 후보로 보류한다.

## 개인정보·artifact·최종 경계

입력은 RFC 5737 예시 IP와 생성 token·임시 synthetic file뿐이다. 사용자 홈/기본 monitor config/실제 로그/credential은 읽지 않는다. Hypothesis가 축소한 실패 출력도 합성 값만 포함하도록 strategy를 제한했다. `database=None`은 **실패 example database**를 끄지만 Hypothesis 자체의 `.hypothesis/constants`·Unicode cache는 생성될 수 있으므로 저장소 루트 `.gitignore`에 `.hypothesis/`를 명시했다. Cache나 raw 실패 output을 commit하지 않는다. Confirmed regression만 고정된 비민감 pytest fixture로 승격한다. 앞선 두 oracle 수정은 production 결함이 아니다.

REA 실행형 pilot, 자동 rotation/copytruncate handoff와 두 세대 private checkpoint metadata는 계속 NO-GO. SSH checkpoint, access live analysis, cross-source, exactly-once는 이번 테스트 추가로 지원되는 기능이 아니다. 이 pilot은 기존 parser·detection·correlation·risk·case 의미 또는 API/SSE/UI schema를 바꾸지 않았다.
