# Phase 23.2 — local static security analysis gate

판정: **CONDITIONAL GO**, 설계만 승인. 이번 단계는 **no installation**, no Semgrep execution, no CI scan, no production/dependency/lockfile change이다. Phase 23.3에서 고정된 배포물과 오프라인 실행, 실제 규칙의 양·음성 fixture, 두 플랫폼 비용을 검증해야 한다. 규칙 후보 네 개가 pytest의 결과 중심 검사와 다른 *새 코드 작성 시점의 구조적 예방* 가치를 가질 수 있으나 아직 실제 scan 성공이나 finding baseline을 주장할 근거는 없다.

## 시작 상태와 Phase 23.1 판정

2026-10-16, `main`과 `origin/main`은 `f8bf1d00f32bc289ac210929af30e4faa8041323`에서 일치하고 시작 작업 트리는 clean이었다. [해당 SHA의 Ubuntu CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38911161229)는 completed/success였다. Ubuntu 24.04/Python 3.12.7의 `uv sync --dev --locked --no-build-package hypothesis --no-build-package sortedcontainers`와 전체 `uv run pytest -q` 단계가 각각 성공했고, 후자는 **2,258 passed, 기존 경고 2개, 새 경고 0개, 44.74초**였다. `tests/test_live_property_pilot_23_1.py`는 전체 pytest에 포함된다. 전용 property CI job은 없으므로 독립 job 성공으로 표현하지 않는다. 같은 commit의 변경 전 로컬 baseline은 **2,258 passed, 기존 경고 2개, 84.60초**였다. 따라서 Phase 23.1은 Ubuntu locked wheel gate까지 **GO**로 닫는다. 경고는 Starlette TestClient/httpx와 AnyIO 별칭의 기존 deprecation 두 건이다. 공개 `v0.2.0` annotated tag는 `2520e317475f96d48b4bfeef8f7ee04d63720308`을 가리키며 Release도 그대로 공개 상태였다.

## 공식 배포와 공급망: 조사 사실, 미검증 사실

조사일 기준 [공식 `semgrep/semgrep` tag v1.181.0](https://github.com/semgrep/semgrep/tree/v1.181.0)의 annotated tag object `77a9477dbb1d7e8780d6113adc7c8204dac83150`은 source commit `72d3525fe7e02f486428386078f192f8c4756804`를 가리킨다. [PyPI `semgrep` 1.181.0](https://pypi.org/project/semgrep/1.181.0/)은 2026-10-14 게시된 조사 시점 최신 안정 버전으로, Python `>=3.10`(3.12 포함), license expression `LGPL-2.1-or-later`다. 이는 프로젝트 MIT source의 개발용 도구 사용과 명백히 충돌하지 않지만 법률 보증은 아니다. [공식 저장소](https://github.com/semgrep/semgrep)의 Semgrep CE CLI/엔진과 Semgrep Registry의 규칙 라이선스, 로그인 기반 Pro/Cloud는 구분한다. 이번 후보는 **OSS CLI + 저장소에 추적된 자체 local rule**뿐이다.

PyPI metadata의 직접 기본 `Requires-Dist`에는 `attrs`, `boltons`, `click-option-group`, `click`, `colorama`, `exceptiongroup`, `glom`, `jsonschema`, **`mcp==1.29.0`**, `opentelemetry-api/sdk/exporter-otlp-proto-http/instrumentation-requests/instrumentation-threading`, `packaging`, `peewee`, `pyjwt[crypto]`, `requests`, `rich`, `ruamel.yaml`, `ruamel.yaml.clib`, `semantic-version`, `tomli`, `typing-extensions`, `urllib3`, `wcmatch`와 Windows 조건부 `pywin32`가 있다. PyPI의 이 `Requires-Dist` 목록에는 optional extra로 분리된 직접 의존성이 보이지 않는다. 하지만 **전이 dependency, wheel 내부 binary, setup/build hook, installer network behavior, 정확한 lock resolution은 이번 단계에서 검사하지 않았다**. 특히 `mcp`, OTel exporter, `pyjwt[crypto]`, YAML C extension은 좁은 정적 검사 목적에 비해 큰 공급망/관찰성 경계다. 필수 스캔 경로에서 로드되지 않음을 확인하기 전에는 도입하지 않는다.

PyPI 게시 wheel 후보는 **macOS arm64** `semgrep-1.181.0-...-macosx_11_0_arm64.whl` 49,776,451 byte, SHA-256 `05d79ad777fae86f6d914a67bedec1b9e2c3e637f61d49a4ef557e2bf69fed01`; **Ubuntu x86_64** glibc 2.34+ `semgrep-1.181.0-...-manylinux_2_34_x86_64.whl` 70,540,779 byte, SHA-256 `c142ec04a2ed144970cb0a92f6877651dd3c088505eec737bb7f4db7ae5f0ffa`이다. 둘 다 platform wheel이고 프로젝트의 Python 3.12 후보와 호환되지만 **다운로드·hash 재계산·native binary 목록 검사·provenance/서명 독립 검증은 하지 않았다**. sdist fallback은 빌드 코드 실행 경계이므로 pilot에서는 금지 후보. 설치 시점 network는 PyPI/index와 전이 wheel 취득에 제한되어야 하고 scan 시점 network는 차단해야 한다. Semgrep CE가 native engine을 포함하는 큰 wheel이라는 점도 Phase 23.3의 실행 격리·성능 gate다.

## 로컬/오프라인 실행 경계

[공식 CLI reference](https://docs.semgrep.dev/cli-reference)는 `semgrep scan`이 로그인 없는 로컬 scan이며, `--config auto`는 Registry 접근과 project URL 사용을 동반한다고 명시한다. `semgrep ci`, `login`, `--config auto`, `p/...`, URL config, Pro, MCP, Secrets/Supply Chain 기능은 이번 후보에서 금지한다. `--config ./tracked-rules.yml`, `--metrics=off`, `--disable-version-check`, `--oss-only`, `--error`를 결합하고 **network deny**를 별도로 적용해야 local-only를 강제할 수 있다. 플래그만으로 모든 plugin/의존성/실패 경로의 egress 부재가 실측 증명되는 것은 아니다. [metrics 문서](https://docs.semgrep.dev/metrics)는 로컬 rule만 쓸 때 기본 metrics가 없다고 하되 로그인/Registry 사용 시 `auto`가 전송되므로 명시적 off가 필요하다. Registry rule을 내려받거나 자동 update하지 않는다. 표준 출력은 finding의 **source snippet**과 상대/절대 path를 포함할 수 있으며 `--json`/SARIF 파일은 더 오래 남는다. CI artifact upload와 결과의 외부 POST/URL output은 기본 NO, debug/trace도 NO. 실제로는 제한된 offline container 또는 CI의 OS egress 차단 아래에서 synthetic canary를 넣고 네트워크 요청 0건을 검증해야 한다. 이것이 확인되지 않으면 NO-GO다.

## 기존 테스트의 보장과 정적 규칙의 차이

| 경계 | 현재 증거 | 정적 규칙 후보 판정 |
| --- | --- | --- |
| trusted analysis/correlation/risk dict의 범용 직렬화 | `tests/test_live_analysis_publication.py::test_analysis_serializer_rejects_raw_inputs`, `tests/test_public_privacy_phase62.py`의 API canary; `app/analyzer/llm.py`에는 **의도된 내부** `asdict` 후 safe projection이 있어 문자열 일괄 금지는 오탐 | 타입·dataflow가 필요해 일반 규칙 NO-GO; 특정 public 함수/반환문은 별도 검토 |
| raw Event/Evidence `repr`, account/IP/path/query/filename/argv/raw line의 공개 DTO | `tests/test_live_monitor_privacy.py`, `tests/test_live_record_lease_privacy.py`, `tests/test_live_processing_worker_privacy.py`, `tests/test_local_investigation_api.py`, `tests/test_public_privacy_phase62.py`의 canary | 다단계 alias와 projection의 의미가 필요해 pytest 우선; 직접 logger payload는 범위 축소 후보 |
| exception 원문 HTTP 오류 | `tests/test_live_monitor_privacy.py`, `tests/test_linux_audit_api_security.py`, `app/api.py`의 고정 detail | HTTP exception 구조 패턴은 제한적 GO 후보. wrapper/alias는 false negative |
| `UploadFile.filename` 로깅 | `app/api.py`는 확장자 검증에만 filename 사용, `tests/test_local_investigation_api.py`에서 filename 비노출 | 직접 `logger.*(file.filename)`만 좁게 가능; source-wide filename 금지는 NO-GO |
| frontend HTML sink와 browser storage | `tests/test_web_ui.py`, `tests/test_live_monitoring_ui.py`, `tests/test_linux_audit_web_ui.py`는 금지 문자열 검사와 Node 동작 테스트 | JS AST로 호출/할당을 잡으면 문자열·주석 오탐을 줄이고 신규 파일에도 적용 가능 |
| `shell=True` 또는 사용자 입력 subprocess | production `app/`의 직접 사용은 현재 source audit에서 0건; setup/live 격리 테스트 | 구조적 `subprocess.*(..., shell=True)`는 GO 후보, 동적 인자/alias는 미검출 |
| unsafe temp permission, path TOCTOU/symlink | `tests/test_local_investigation_api.py`, `tests/test_web_ui.py`, checkpoint/setup tests가 실제 FS 상태 검사 | 단순 호출 패턴으로 안전성을 증명 못 하므로 pytest/fault test 우선 |
| unrestricted CORS/debug/traceback | API/웹 보안 회귀와 OpenAPI/CSP 테스트 | 고정 `allow_origins=['*']`, `debug=True` 등 좁은 별도 후속 후보; 일반 금지는 오탐 |
| raw analysis를 LLM에 전달 | `tests/test_public_privacy_phase62.py::test_cli_and_llm_input_do_not_copy_private_fields`, `app/analyzer/llm.py` safe projection | 전체 구조를 봐야 해 의미 검사 유지 |

현재 `rg`로 `app/**/*.py`와 `frontend/**/*.js`에서 직접 `shell=True`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `localStorage`, `sessionStorage`, `indexedDB` production 사용은 0건이었다. 이것은 **not a Semgrep baseline**이며 간접 호출·alias·생성 코드까지 안전함을 증명하지 않는다. 실제 도구 finding baseline, false-positive rate와 false-negative rate는 미측정이다.

## Phase 23.3의 네 가지 최소 구조 규칙 후보

각 rule은 `app/**/*.py` 또는 `frontend/**/*.js` production 파일로 한정하고 `tests/`, `docs/`, `.venv/`, `.git/`, vendor/cache/generated, sample logs 및 사용자 config를 제외한다. 정책은 심각한 sink *사용 형태*에 대한 것이다. 단순 단어 검색이 아니며 허용된 safe wrapper가 필요하면 정확한 호출 지점 allowlist와 제거 조건을 문서화한다. 아래 코드는 **설계 fixture**이고 Semgrep에서 실행되지 않았다.

| ID·scope·분류 | should-match 합성 예 | should-not-match 합성 예 | 한계 및 false positive/false negative |
| --- | --- | --- | --- |
| R1 DOM HTML sink, `frontend/**/*.js`, 높은 신뢰도 | `panel.innerHTML = userText; panel.insertAdjacentHTML('beforeend', userText);` (또한 `outerHTML` assignment) | `panel.textContent = userText; panel.append(document.createTextNode(userText));` | 프로젝트 정책은 raw HTML sink 금지. 문서 문자열은 JS AST라 무시; alias/computed property `panel['innerHTML']`과 framework wrapper는 false negative 후보. 의도된 정적 HTML도 이 프로젝트에서는 리뷰 대상이지 자동 safe 예외 아님. |
| R2 browser storage, `frontend/**/*.js`, 높은 신뢰도 | `localStorage.setItem('analysis', state); sessionStorage.setItem('x', value); indexedDB.open('x');` | `const state = new Map(); state.set(id, value);` | 프로젝트 live 결과의 client persistence 금지. 식별자 문자열·주석은 제외; `window['localStorage']`와 alias는 false negative 후보. 타 기능에서 승인된 저장소가 생기면 파일/함수 범위를 재설계. |
| R3 shell=True, `app/**/*.py`, 높은 신뢰도 | `subprocess.run(args, shell=True)` 또는 `subprocess.Popen(cmd, shell=True)` | `subprocess.run(['git', 'status'], shell=False)` | `from subprocess import run as r`와 `**kwargs` 간접 전달은 false negative. 안전 wrapper가 필요해도 `shell=True` 자체는 승인 gate로 처리. 테스트의 의도된 injection fixture는 scan 제외. |
| R4 HTTP exception detail, `app/api.py`, `app/web_ui.py`, `app/**/http.py`, 제한적 신뢰도 | `raise HTTPException(400, detail=str(exc))`, `raise HTTPException(500, detail=repr(exc))`, `JSONResponse(content={'error': traceback.format_exc()})` | `raise HTTPException(400, detail='고정 오류')`, `JSONResponse(content=SafeError(code='INVALID').model_dump())` | exception 변수의 다른 이름, f-string, helper 반환, alias/전달식은 false negative. 고정 문자열과 public DTO는 제외. 실제 dataflow 전체 안전성은 canary pytest가 담당; 넓은 `str(...)` 금지는 false positive 과다. |

R4는 Phase 23.3 fixture에서 alias·f-string을 측정하고 false negative가 크면 제외한다. 그 경우 직접 `logger.warning(record.payload)`/`print(event.raw_line)`의 좁은 `app/live_monitoring/**` 규칙을 **후보**로 검토하되 현재 trusted 내부 debug와 공개 log를 혼동하면 NO-GO다. R1~R3도 실제 양성·음성 fixture에서 해당 AST가 예상대로 매치되지 않으면 도입하지 않는다. 최소 **검증된 고신뢰 규칙 3개**가 GO 조건이지 이 문서의 후보 수가 통과를 뜻하지 않는다.

## CI·오탐·개인정보 gate

Phase 23.3은 고정 CLI version과 검증된 wheel/transitive lock만, project runtime과 분리된 dev tool/독립 container를 제안한다. 로컬 rule 파일만 추적하고 `scan --error`로 새 finding을 fail closed한다. 기존 finding의 무기한 baseline/`nosem` 허용은 금지하며, 예외는 정확한 파일·행·이유·만료 조건을 리뷰한다. Rules에는 **should-match/should-not-match** fixture를 각각 2개 이상 두고 원래 source의 positive와 safe negative를 독립 확인한다. Missing scan target, parse error, oversized skip, timeout, network attempt는 `0 findings` 성공으로 취급하지 않는다. 기본 PR에서는 전체 tracked production `app/`+`frontend/`를 스캔해 변경 파일 scan의 새 위치만 보는 누락을 피하고, 변경 파일 scan은 개발자 빠른 피드백 후보로만 사용한다. `semgrep ci`가 아니라 `semgrep scan`을 사용한다. Semgrep 자체 시간은 설치/실행 금지로 **미측정**; 현 baseline은 macOS full pytest 84.60초, Ubuntu CI pytest 44.74초다. PR 추가 시간 후보 **+10초 이내**는 측정용 목표이지 보장값이 아니다. macOS arm64와 Ubuntu x86_64에서 process cold/warm 각 3회, full/changed scan, memory와 skipped count를 기록한 후 결정한다.

합성 fixture에만 비밀이 아닌 canary를 사용한다. 현 저장소 source라도 future real path/config/log가 실수로 포함될 수 있으므로 `.gitignore`에만 의존하지 않고 scan target을 production allowlist로 제한한다. stdout/stderr와 JSON/SARIF는 source snippet, rule message, 경로를 포함할 수 있어 developer-local private 자료로 취급한다. CI artifact 업로드, PR comment, Semgrep Cloud, Registry, login/token, LLM 전송은 기본 금지다. 필요하면 비민감 rule ID/건수만 별도 안전 projection하고 원문 finding은 저장하지 않는다. Semgrep의 [공식 metrics 설명](https://docs.semgrep.dev/metrics)에 “source code never sent”라는 정책이 있어도 network deny 실측 없이 프로젝트 개인정보 경계를 충족했다고 단정하지 않는다. 호스트 절대 경로와 실제 로그는 문서·테스트 실패 출력에 남기지 않는다.

## 대안과 결정

[Ruff 공식 FAQ](https://docs.astral.sh/ruff/faq/)는 프로젝트 전용 custom lint plugin을 지원하지 않는다고 하므로 R1/R2 같은 JS+Python 구조 규칙의 대체가 아니다. [Bandit 공식 문서](https://bandit.readthedocs.io/)는 Python 보안 패턴, 특히 subprocess/shell 검사의 대안이나 JS DOM/storage 정책을 함께 다루지 못한다. [CodeQL CLI 공식 문서](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli)는 local DB/query 실행도 가능하지만 DB와 SARIF 출력, 별도 배포/CI 비용을 요구하며 GitHub upload는 별도 단계다. 이번 작은 정책 gate에는 과하다. 이 대안들도 현재 설치·실행하지 않았다.

**CONDITIONAL GO → Phase 23.3 pilot 조건:** (1) 정확한 Semgrep·전이 artifact SHA-256/라이선스/native/install hook 조사와 wheel-only locked install; (2) offline/network-denied scan에서 egress 0건; (3) local rule 3개 이상이 양·음성 fixture와 repository scan에서 허용 가능한 오탐·미검출; (4) skipped/parse-error fail closed; (5) macOS/Ubuntu CI 비용·privacy output 확인. 하나라도 실패하면 Semgrep 도입 NO-GO, pytest와 기존 property tests만 유지한다. 별도 승인이 있기 전까지 Semgrep 설치, `pyproject.toml`/`uv.lock` 변경, CI stage 추가는 금지다. 정적 규칙은 실제 API/SSE/LLM canary·TOCTOU·checkpoint 재생·분석 의미 테스트를 대체하지 않는다.
