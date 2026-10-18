# Phase 23.5 — bounded OpenAPI property pilot

판정: **CONDITIONAL GO**. macOS arm64의 wheel-only 임시 설치, 네트워크 차단 in-process ASGI, 합성 실패 출력 검사, 세 endpoint의 최소 property가 통과했다. Ubuntu x86_64용 정확한 wheel은 다운로드·hash 검증했지만 **실제 Ubuntu 실행/CI는 이 로컬 커밋을 push하기 전에는 NOT_TESTED**다. 요청 생성의 빈틈과 실패 출력의 원문 재현 위험도 남는다. Schemathesis는 dev group에만 있으며 production runtime/API schema/분석 의미는 변경하지 않았다. Semgrep은 계속 SUPPLY_CHAIN_BLOCKED다.

## 시작 상태와 resolver

시작 `main`/`origin/main` SHA는 `6d295e036a1422ebbcda68a908aebbc2a4cab144`, clean/behind 0/ahead 0이었다. [동일 SHA의 CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38915888353)는 completed/success, Ubuntu locked install과 전체 **2,267 passed, 기존 경고 2개, 새 경고 0개**였다. 로컬 변경 전도 **2,267 passed, 동일한 경고 2개**였다. 공개 v0.2.0 tag/Release target은 `2520e317475f96d48b4bfeef8f7ee04d63720308`으로 불변이었다.

공식 [Schemathesis 4.31.1 PyPI](https://pypi.org/project/schemathesis/4.31.1/)·[source tag](https://github.com/schemathesis/schemathesis/tree/v4.31.1)·[설계 gate](schemathesis_api_fuzzing_gate_23_4.md)를 재확인했다. `uv pip compile`/`uv pip install --dry-run`을 Python 3.12의 `aarch64-apple-darwin`과 `x86_64-manylinux_2_35`에서 `--only-binary :all:`로 해석해 **양 플랫폼 각각 27 package**, 합집합 **32 wheel**, sdist 0을 확인했다. `hypothesis==6.170.0`과 `pytest==9.1.1`을 함께 고정해 실제 resolver 충돌이 없었다. 정확한 27개 버전은 아래 wheel filename에 전부 나타난다. 다운로드는 `files.pythonhosted.org`에서만 수행했고 각 파일의 size와 SHA-256을 PyPI metadata와 재계산해 비교했다. 패키지 배포 출처는 PyPI; source repository는 Schemathesis의 공식 `schemathesis/schemathesis` 및 metadata의 Project-URL이 확인된 일부에만 직접 연결했다. 모든 전이 패키지의 source commit/provenance까지 확인했다는 뜻은 아니다.

wheel 내부 경로·`.data/scripts`·entry point·native/shared library를 정적으로 열거했다. `.data/scripts`는 0개였다. Schemathesis 본체에는 native library가 없고 `schemathesis`/`st` CLI 및 pytest plugin entry point가 있다. **jsonschema-rs 0.58.6**은 `jsonschema_rs/jsonschema_rs.abi3.so` 하나를 포함하며 macOS 파일은 arm64+x86_64 Mach-O universal, Linux 파일은 x86-64 ELF다. 이 native binary는 실행 경로의 별도 공급망 위험이며 source-to-binary reproducible build나 서명/provenance는 독립 검증하지 못했다. 다른 native extension은 이미 프로젝트 dev에서 쓰는 Hypothesis와 `charset-normalizer`, `MarkupSafe`, `PyYAML`에 있었다. `certifi/tests/test_certify.py`에는 실행 권한 bit가 있으나 wheel install script나 자동 실행 entry point가 아닌 테스트 파일로 분류했다. 추가 다운로더·wheel lifecycle script는 발견하지 않았지만 패키지의 모든 runtime branch에 네트워크 기능이 없다고 증명하지는 않는다. PyPI license metadata는 주로 MIT/BSD/Apache/MPL/PSF였고 비어 있던 markdown-it-py/mdurl은 wheel LICENSE를 직접 확인했다. 설치 전 전체 wheel 목록·license/source metadata 결과는 임시 감사 자료로만 보관했고 raw 결과를 commit하지 않는다.

### 검증한 정확한 wheel manifest

아래는 두 플랫폼의 **합집합 32개**다. 플랫폼 suffix가 없는 wheel은 양쪽 공통이고, macOS/Linux suffix가 있는 행은 각 플랫폼 선택이다. 단위는 byte다. 이는 다운로드한 파일의 SHA-256과 PyPI metadata가 일치한다는 뜻이며, publisher identity나 native reproducibility 증명은 아니다.

| Wheel filename | Bytes | SHA-256 |
| --- | ---: | --- |
| anyio-4.15.1-py3-none-any.whl | 132079 | `6152fdbbf9a77fdec97731721bebf7c4c44f7c29b424b0065826173efc7ed101` |
| certifi-2026.7.22-py3-none-any.whl | 136983 | `62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775` |
| charset_normalizer-3.5.2-cp312-cp312-macosx_10_13_universal2.whl | 367780 | `ed2a239c0ea213acc1908150a3037257083c7c083128f1a4cec2ec4b97dca491` |
| charset_normalizer-3.5.2-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl | 257601 | `3d31298449090ab8d47b7b1b2a555ff73cac7ed438a08b7ac160980c7ebed649` |
| click-8.5.0-py3-none-any.whl | 125251 | `255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360` |
| graphql_core-3.2.13-py3-none-any.whl | 268191 | `b0eb04f2c31556b2310a77c8fb53c74e8b56570f8fea594d89c6ef7827dbb497` |
| harfile-0.5.0-py3-none-any.whl | 7172 | `ab8a01d0d21d3b7f5ad57e7dc56b8b829f6a8855c1fa143aad464e7e8169f5e3` |
| hypothesis-6.170.0-cp312-cp312-macosx_11_0_arm64.whl | 790115 | `0e8fc166ab2c10dbd8c798d0cf0e7fe3125df36e6993db25cf45104f6915bf41` |
| hypothesis-6.170.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl | 1162826 | `13be368fd3aa29bd199c79dc459e18b1d6b4cb0687419bcd751f22a2e1b773a9` |
| hypothesis_graphql-0.13.2-py3-none-any.whl | 22870 | `fafcc07b901f04d64ac9c6c2e0c48a66817f04bd330766bd8b91bf76dc341a6a` |
| idna-3.20-py3-none-any.whl | 69583 | `ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c` |
| iniconfig-2.3.1-py3-none-any.whl | 7552 | `9121e2c1fdb355232495be3194c8dfe87ccc2d5dee45947b78e68f499790d7a7` |
| jsonschema_rs-0.58.6-cp310-abi3-macosx_10_12_x86_64.macosx_11_0_arm64.macosx_10_12_universal2.whl | 11058691 | `9df8a54ee953197307875a725161033e9ce9a979da33ce0bd2c0740daaa0444a` |
| jsonschema_rs-0.58.6-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl | 5929272 | `0e56428f4803dfbe6dee4f1d07e1710b5af377ed769275df256b81c1eb4178ea` |
| markdown_it_py-4.2.0-py3-none-any.whl | 91687 | `9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a` |
| markupsafe-3.0.4-cp312-cp312-macosx_11_0_arm64.whl | 12050 | `0930db9bdc62d22944e10b066448bb65dc9abe9112880c7cab8da54db4284d5f` |
| markupsafe-3.0.4-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl | 22985 | `8e124f974786f831d6043728e38296969d3579db8896fe004682f5758e613581` |
| mdurl-0.1.2-py3-none-any.whl | 9979 | `84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8` |
| packaging-26.3-py3-none-any.whl | 129956 | `d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c` |
| pluggy-1.7.0-py3-none-any.whl | 27082 | `7dd7b0d8832ba3cb632c306926ded123429211b83641b35dc5c41ad2d34f9bec` |
| pygments-2.21.0-py3-none-any.whl | 1250147 | `2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9` |
| pyrate_limiter-4.5.0-py3-none-any.whl | 57188 | `e7320a715adf404cb7b2f399e05ceb59cae165275b21f7708eb1b9fd9608e91c` |
| pytest-9.1.1-py3-none-any.whl | 386536 | `37a86b45efb9a47a61a36449063e8e18d0cab3161329fc099eb21783169c4f0c` |
| pyyaml-6.0.3-cp312-cp312-macosx_11_0_arm64.whl | 173973 | `fc09d0aa354569bc501d4e787133afc08552722d3ab34836a80547331bb5d4a0` |
| pyyaml-6.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl | 807870 | `ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc` |
| requests-2.34.2-py3-none-any.whl | 73075 | `2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0` |
| rich-15.0.0-py3-none-any.whl | 310654 | `33bd4ef74232fb73fe9279a257718407f169c09b78a87ad3d296f548e27de0bb` |
| schemathesis-4.31.1-py3-none-any.whl | 1122419 | `157529ed712cce00ead84a17e9e4a8f6a07e460c0b6e4901d037d9e313db99d1` |
| sortedcontainers-2.4.0-py2.py3-none-any.whl | 29575 | `a163dcaede0f1c021485e957a39245190e74249897e2ae4b2aa38595db237ee0` |
| typing_extensions-4.16.0-py3-none-any.whl | 45571 | `481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8` |
| urllib3-2.8.0-py3-none-any.whl | 135717 | `0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3` |
| werkzeug-3.1.9-py3-none-any.whl | 228700 | `6392e50c78460ba618e5b21f08a71f59c99ce99cdc6cf6e3dd7e6ccca8754fab` |

## 격리 실행·출력 개인정보

전용 임시 wheelhouse에서 `uv pip install --no-index --find-links ... --only-binary :all:`로 별도 venv에만 설치했다. `HOME`/`TMPDIR`을 임시 값으로 교체하고 credential 환경변수 없이 실행했다. 임시 ASGI `/ping`에 대한 `schemathesis.openapi.from_asgi` import·version·request·schema validation이 성공했고 `socket.connect`/`connect_ex`/`create_connection`과 audit hook의 외부 연결 시도는 **0회** (`NETWORK_DENIED` harness)였다. 임시 HOME에는 생성 파일이 없고 default report directory도 생성되지 않았다. 이는 실제 OS firewall 검증이나 모든 Schemathesis CLI branch의 네트워크 0 보증은 아니다.

별도의 **의도적 실패 synthetic ASGI app**은 account/IP/path-query/filename/raw line/exception/fake absolute path를 서로 다른 canary로 사용했다. pytest 실패 출력에는 **모든 canary, 응답 본문과 재현 `curl` 요청 body**가 나타났고, `str(exception)`·`repr(exception)`에도 canary가 있었다. 그러므로 실패 출력은 안전 DTO가 아니며 실제 로그·기본 monitor config·checkpoint·credential을 생성 case에 사용하지 않는다. HAR/VCR/cassette/SARIF, Schemathesis report, raw 요청·응답을 저장하거나 GitHub artifact/Cloud로 업로드하지 않는다. 합성 최소 반례만 로컬 출력에 허용한다. 실패 출력에 host의 임시 실행 경로가 traceback으로 나올 수 있어 문서·snapshot으로 복사하지 않는다.

## Pilot의 정확한 coverage

`tests/test_schemathesis_api_pilot_23_5.py`는 `database=None`, 고정 seed·derandomize·health-check suppress 없이 실행한다. sample/status는 `max_examples=6`, legacy 생성 missing-field는 `max_examples=4`다. 기본 200ms deadline은 cold schema/ASGI 경로에서 **251~769ms 관측 후 flaky DeadlineExceeded**를 냈다. 전체 회귀 중 legacy case도 **229ms**로 초과했다. 재시도로 숨기지 않고 세 property 모두 **2초 deadline**으로 조정했다; 이는 운영 latency 기준이 아니다. 각 status case는 임시 regular file·fresh worker/service/app를 만들고 종료 시 close한다. Schemathesis ASGI client의 peer는 기본 `testclient`라 실제 local guard에서 403이 된다. test-only wrapper가 peer를 `127.0.0.1`로 표시하고 Host를 loopback으로 고정한다; non-loopback·Origin·forwarded 거부는 기존 `tests/test_live_http.py`가 별도 확인한다. client가 네트워크 socket을 쓰면 즉시 테스트가 실패한다.

| 대상 | Schemathesis COVERED | deterministic 보완 및 NOT_COVERED |
| --- | --- | --- |
| POST /api/v1/investigations/sample | OpenAPI-generated no-body case의 200, JSON response schema/content type, schema_version, 합성 label, 5xx·canary 비노출 | OpenAPI에 body/query 없음: unknown query/body/form/multipart/content-type 거부는 별도 hand-written negative. analyze/case adapter exact call count·LLM/Linux 격리는 기존 `tests/test_sample_investigation_api.py`에서 유지. 자동 malformed-input generation은 NOT_COVERED |
| GET /api/v1/live/status | 활성 app의 closed response model·200, revision/집계, no-store/nosniff, fresh service/FD close | 비활성 app 404, query 400, method 405, GET body의 기존 읽기 전용 200은 별도 deterministic 검사. Schemathesis의 testclient peer는 실제 loopback security 증거가 아님. SSE/Last-Event-ID는 NOT_COVERED |
| POST /api/analyze | OpenAPI-generated multipart operation을 작은 missing-file body로 제한해 422 schema/error, deprecated OpenAPI 표시 | 정상 synthetic 3파일 성공, `Deprecation: true`, nested safe projection·temp cleanup은 explicit fixture. Arbitrary generated multipart를 안전한 크기/형식으로 제어하지 못해 valid/unknown/repeated field 자동 fuzz는 NOT_COVERED; 기존 FastAPI/legacy tests가 담당 |

모든 새 생성 case는 예상 밖 5xx, traceback, safe response의 account/IP/path/query/filename/raw-line/exception canary, 외부 network를 거부한다. legacy malformed 로그의 **고정** `LEGACY_ANALYSIS_FAILED` 500은 기존 실패 의미이므로 Schemathesis 생성 정상 case의 성공으로 분류하지 않는다. 실제 로그 파일·기본 config·checkpoint·홈 자료는 사용하지 않았다. OpenAPI는 수동 multipart/stream guard를 완전히 기술하지 않으므로 API 완전성 증명이 아니다. 탐지·상관분석·risk·case 의미나 운영 탐지율·보안 무결성·무유실 증명도 아니다.

## dependency, CI 비용과 다음 gate

`uv add --dev --no-build --no-sync schemathesis==4.31.1` 후 `uv sync --locked --dev --no-build`가 성공했다. `pyproject.toml` runtime dependencies는 불변이고 `uv.lock` 변경은 새 dev transitive package 추가뿐이며 `hypothesis==6.170.0`은 유지됐다. 별도 임시 production environment에 `uv sync --locked --no-dev --no-build`를 실행한 결과 `schemathesis`/`jsonschema_rs` import spec이 없었고 `app/`·`frontend/` runtime import도 0건이었다. Ubuntu workflow의 기존 install을 `--no-build` wheel-only로 강화하고 **pilot focused step 하나만** 추가했다; 전체 회귀 step은 기존 하나를 유지한다. 실제 Ubuntu CI 성공은 push 이후 별도 확인 전까지 NOT_TESTED다.

| 측정 조건 | 표본 | wall time 관찰 | 해석 |
| --- | ---: | --- | --- |
| Schemathesis import/startup, 동일 macOS host | 3 | 0.033~0.077초 | process startup 포함, cold/warm OS cache 혼재 |
| sample property, `max_examples=6` | 3 | 1.14~1.30초 | 초기 측정, deadline 조정 전 성공 run |
| live status property, `max_examples=6` | 3 | 1.11~1.16초 | test-only loopback scope 포함 |
| legacy property/fixture, `max_examples=4` | 3 | 4.83~5.54초의 **실패 run** | 동시 첫 200ms deadline 초과의 전체 process 비용 영향; 정상 비용으로 사용 금지 |
| 전체 pilot, 초기 실패 run | 3 | 6.16~7.63초 | flaky를 발견한 비용, 합격값 아님 |
| 전체 pilot, 최종 6-test 연속 PASS | 3 | 4.91, 4.96, 5.10초 (median 4.96, 표본 p95 5.10, max 5.10) | 별도 process wall time, cold/warm OS cache 혼재 |

비교 baseline은 같은 macOS에서 변경 전 전체 pytest **29.80초**, Ubuntu CI **47.20초**이나 서로 다른 host와 냉/온 cache를 직접 비교하지 않는다. 최종 전체 suite 3회는 첫 DeadlineExceeded 실패 **97.59초**, 수정 후 **86.11/86.56초**였다. Schemathesis pytest plugin을 꺼도 **86.62초**여서 plugin 자체만으로 이 차이를 설명할 수 없다. 느린 항목은 기존 setup/runtime 프로세스 smoke 7.54/7.42/4.11초 등이었고, 추가 pilot 단독 wall time은 약 5초다. 따라서 baseline과의 큰 차이를 새 pilot의 순수 비용으로 주장하지 않는다. +10초는 기본 CI 후보 gate일 뿐 보장값이 아니다. 이 단계의 판정은 **CONDITIONAL GO**: local pilot은 유효하지만 Ubuntu 실제 locked wheel-only install/독립 suite 결과와 실패 출력 정책을 CI에서 재확인해야 한다. schema/runtime gap과 multipart·SSE는 별도 Phase의 판단을 기다린다.

## 최종 검증 기록

관련 API·Hypothesis·live focused는 **51 passed, 기존 경고 2개**, 전체 documentation은 **188 passed**, Node를 포함한 UI focused는 **53 passed**였다. 전체 회귀는 **2,276 passed, 기존 경고 2개, 새 경고 0개**로 최종 2회 통과했다. 합성 평가는 인증·웹 **79/79**, Linux **21/21**, risk/case **70/70**을 유지했다. UTC와 Asia/Seoul의 새 pilot·기존 property는 각각 10 passed였다. `uv sync --locked --dev --no-build`, `uv lock --check`, 변경 test의 `py_compile`, frontend 세 JS `node --check`, Linux/live Node behavior, `git diff --check`가 통과했다. web UI Node behavior는 JSON stdin이 필요한 harness라 직접 무입력 호출은 실패했으며 JSON을 제공하는 기존 pytest 경로에서 통과했다. Linux CI는 후속 원격 실행 전까지 NOT_TESTED다. 전용 임시 wheelhouse/venv/cache/raw failure probe는 내용을 확인하고 삭제했으나 secure erase는 주장하지 않는다. no report upload 경계는 유지한다.
