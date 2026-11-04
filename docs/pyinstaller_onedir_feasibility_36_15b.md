# Phase 36.15B — PyInstaller onedir feasibility

## Executive Summary

An unsigned PyInstaller `onedir` prototype was built and exercised on the current host: macOS 15.7.7, arm64, CPython 3.12.7. The copied bundle ran from an external directory with a non-ASCII path, without Python, uv, Git, Node, or the source checkout on its runtime path. Synthetic sample, text-analysis, local retrieval, UI navigation, health, and fixed-asset checks passed. The tested listener remained on `127.0.0.1`; the isolated browser and proxy observed zero external requests.

This is host-specific feasibility evidence only. It is not a signed release, a security certification, or a production/organizational-use approval. Windows and Linux bundles require separate builds and remain untested here.

## 시작 SHA/CI Gate

- Baseline: `ca14b6400b4a5c11aef2949f7c2287c1677fe1a8`.
- Exact GitHub Actions run: [41775612153](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41775612153), `push`, `completed / success`, exact head SHA.
- The required full pytest, Linux TCP Syslog, JSONL acceptance, Restricted Report, Chromium/axe, and tracked-file steps ran and succeeded. Artifact count: 0.
- `v0.4.0` remains at `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`; no tag or Release was changed.
- Local branch started clean on `main`, with local and remote main equal and ahead/behind `0/0`.

The local pre-change full pytest was also attempted alongside the evaluation CLI: one monitor setup subprocess test failed to become ready while those process-heavy commands overlapped; the same test passed immediately when run alone (`1 passed`). The evaluation completed successfully. A final sequential full-suite run is the completion gate for this commit; the overlap result is retained here rather than hidden.

## Production Dependency Closure

The existing `app.local_web` is reused through a thin frozen entry point. Its listener contract remains owned by the production launcher: fixed `127.0.0.1`, one worker, reload off, proxy headers off, and no host override. `--no-browser` was used. The entry point calls `multiprocessing.freeze_support()` before importing the application, as required by PyInstaller's frozen multiprocessing guidance; this was necessary for the existing text analysis API, which uses spawned workers. No production `app/` logic was changed.

The archive inspection found the reachable FastAPI/Uvicorn application, Pydantic core, Python runtime, and native libraries. It did not contain Google GenAI, pandas, NumPy, pytest, Hypothesis, or Schemathesis modules. The baseline lockfile was used to provision the isolated build environment; no project dependency or lockfile was changed. Runtime does not invoke Node/npm.

The pre-change full pytest command had one concurrent-process failure as noted above. Evaluation results were: synthetic boundary 79/79, Linux process synthetic evaluator 21/21, risk 70/70, case 70/70; parser corpus totals 195/200 parsed, 2 ignored, 3 rejected, with no unexpected outcomes. Focused and final full regression results are recorded below after sequential completion.

## PyInstaller 빌드 방식

PyInstaller `6.22.3` was pinned in a temporary isolated CPython 3.12.7 environment, not added to `pyproject.toml` or `uv.lock`. The environment was provisioned from the locked production dependency export; PyInstaller and its hook dependencies were build-only. The executable spec uses `EXE(... exclude_binaries=True)` plus `COLLECT`, so output is onedir and not onefile. Build output is ignored and is not committed or uploaded.

Official PyInstaller documentation identifies the supported resource approach: resources adjacent to a bundled module can be located relative to `__file__`; onedir's internal directory layout is accounted for by PyInstaller. This matched the application's existing `__file__`-relative frontend, metadata, and retrieval corpus paths, so a production path rewrite was unnecessary. The actual copied-bundle tests confirmed those resources loaded.

PyInstaller 6.22.3's PyPI metadata states Python 3.8–3.15 support; the host's Python 3.12 and macOS arm64 are supported. PyInstaller documents that builds are OS-specific rather than cross-compilers. Its GPLv2-or-later license includes a special exception for distributing applications under other terms. The installed `pyinstaller-hooks-contrib` license file distinguishes standard community hooks (GPL-2.0-or-later) from runtime hooks (Apache-2.0); its package metadata also lists Apache and GPL classifiers. Build transitive tools included `altgraph` and `macholib` (MIT), `packaging` (Apache-2.0/BSD), and `setuptools` (license files are present; notice inventory still required). PyPI did not expose Trusted Publishing/provenance evidence for the selected PyInstaller release in the checked metadata. These are supply-chain limitations, not proof of malicious content.

Build and inventory details:

- Command: isolated Python 3.12 `python scripts/build_standalone.py --clean`.
- Spec: `packaging/ai-security-log-analyzer.spec`.
- Build script resolves the repository from its own file, uses a fixed allowlist, and only cleans the exact owned `dist/ai-security-log-analyzer` directory after checking a repository-specific marker and rejecting symlinks or redirected paths.
- A failed/unsafe path check stops without broad deletion. The manifest is adjacent to, not inside, the bundle, avoiding self-hash recursion.
- The inventory is path-sorted and records relative path, type, size, and SHA-256. For a symlink, the size and digest describe its relative target text; absolute, dangling, and escaping links are rejected. Manifest generation is deterministic for the observed tree; byte-for-byte 재현성을 검증하지 않음.

## 정적 리소스 및 Native Library

The runtime allowlist contains only:

- `frontend/index.html`, `style.css`, `app.js`, and the six fixed production frontend JavaScript modules.
- `data/account_metadata.json`.
- `app/knowledge_corpus_33_1/corpus.json` and `manifest.json` for explicit local guidance retrieval.
- Three existing hash-checked synthetic samples: `sample_logs/brute_force.log`, `ssh_auth.log`, and `web_shell.log`.

The bundle excludes `.git`, `.github`, `.env`, credentials, tests and fixtures, screenshots, benchmarks, caches, coverage, arbitrary documentation, Node/npm content, user logs, config/checkpoint/report output, and all other sample-log files. It has no browser executable or runtime write location. The copied app directory was read-only during execution and its manifest did not change.

Native contents include the macOS Python framework and bundled system/runtime libraries such as OpenSSL and Pydantic's compiled extension. The exact per-file list and digest are in the generated local manifest; the manifest and binary are intentionally not committed.

## Bundle 실행 E2E

`tests/standalone_bundle_smoke_36_15b.mjs` copied the actual executable and bundle outside the repository into a path containing spaces and Korean characters. The test ran with that location as cwd, `PYTHONPATH` absent, empty `PATH`, isolated HOME/TMP, no source checkout argument, and a separate Chromium profile. It preserved bundle symlinks and made the copied runtime tree read-only.

Observed results:

- `--no-browser` startup and `/api/health`: success.
- Root HTML, CSS, JS, and the three review/input-quality/workflow modules: success.
- Existing synthetic sample-analysis route: success; explicit checklist POST count remained zero.
- Synthetic text analysis for application, SSH, and access source: HTTP 200; input scope and the complete input-quality projection matched a separately running source-checkout server for each source.
- Invalid synthetic source: bundle and source server matched the existing HTTP 422 / `UNKNOWN_SOURCE` contract.
- Explicit local retrieval corpus request: one expected guidance POST and citation response; no checklist POST.
- Dashboard-to-detail navigation and axe scan: passed, zero axe violations in the tested dashboard state.
- Same-port collision: a benign sentinel server received zero requests; the bundle exited instead of attaching to it.
- SIGINT shutdown: exit code 0 within the bounded timeout; copied bundle manifest unchanged; isolated browser, temporary workspace, and server were cleaned.

The smoke harness records only request method/path/count categories and fixed stage categories on failure; it does not print synthetic input. No actual user logs were used.

The separate process benchmark used five cold launches (no deliberate warm-up), then one discarded warm-up and 20 warm launches. Cold/warm median, p95, max milliseconds were: readiness `916/1065/1065` and `711/726/918`; root response `2/5/5` and `2/3/3`; synthetic sample analysis `23/47/47` and `21/23/35`; shutdown `271/330/330` and `226/248/251`. These are single-host synthetic observations, not an SLA; filesystem cache and host scheduling were not controlled.

## Loopback 및 개인정보 보안 검증

The existing launcher binds to `127.0.0.1`; the bundle has no host override. Smoke requests used loopback only. A local blocking proxy and Playwright request interception observed `external_requests=0`; no remote LLM or AI route was called. The browser was Chromium in a test-owned temporary profile, not a user profile.

Manifest and output checks found no source checkout absolute path, temporary build path, personal HOME path, `.env`, `.git`, test directory, or world-writable file. All four observed macOS framework symlinks were relative and remained inside the bundle. The runtime copy was read-only; no config, checkpoint, report, or other state appeared in it. The smoke did not prove malware absence or cover every optional application feature.

Port 8000 was occupied before smoke and was not contacted or stopped. The test used the launcher's existing `--port` option with an OS-selected free loopback port, then separately verified fail-closed behavior on a controlled collision. No new public bind option was added.

## Artifact Manifest·크기·라이선스

Host manifest: `darwin / arm64`, CPython `3.12.7`, PyInstaller `6.22.3`; 102 file entries, including four internal framework symlinks and 60 executable-mode regular files. Sum of regular-file bytes: **31,672,744 bytes**; symlink-target text contributes another 90 bytes to the manifest. `du -sk` reported **31,148 KiB allocated**. The main executable is **6,922,448 bytes**. The largest contents include the executable, Python framework, `libcrypto`, Pydantic core, Python standard-library archive, and `libssl`.

The top 20 files by manifest size were inventoried during the build; the largest six are listed above. Production frontend assets total 397,681 bytes in the existing accessibility harness measurement; the added launcher and builder do not change frontend assets.

No standardized application SBOM was generated. A locked, hash-bearing production dependency export was used for environment provisioning; archive imports and native files were inspected. A release candidate must produce a machine-readable SBOM and complete license notices, including transitive build tooling, before packaging approval. No fixed size ceiling is claimed from this single prototype.

The PyInstaller warning file listed 92 unresolved/optional import entries. They include platform-specific Windows modules and optional/runtime alternatives. Tested macOS routes ran, but warning entries are not universally dismissed: live-monitoring and other optional features need separate packaged tests, and Windows/Linux need native builds.

## OS별 미검증 사항

| Target | Status |
|---|---|
| macOS 15.7.7 arm64, CPython 3.12.7 | Built and tested as an unsigned local prototype |
| Ubuntu/Linux | `NOT_TESTED` in this phase; requires a native Linux build and Linux smoke |
| Windows | `NOT_TESTED`; Windows 지원 선언 아님 |
| macOS Intel / universal2 | `NOT_TESTED` |
| Signing, notarization, installer, updater | `NOT_TESTED` / out of scope |
| User-facing release or GitHub Release artifact | Release artifact 미제공 |

## 문제점과 수정 내용

The first bundle E2E exposed a real frozen-process issue: text analysis returned a fixed failure because PyInstaller child invocations re-entered the entry point without multiprocessing's frozen dispatch. The standalone adapter now calls `multiprocessing.freeze_support()` before importing `app.local_web`; the production launcher and analysis behavior remain unchanged. The rebuilt bundle then passed the text API checks.

The first inventory implementation also surfaced framework symlinks. It now records safe relative symlink targets and rejects links escaping the bundle. No broad asset glob or source-tree runtime fallback was introduced.

TDD evidence: initial package-contract tests failed because the spec/build entry point did not exist; they now exercise the allowlist, onedir shape, launcher delegation, manifest rules, and safe-clean boundary. Documentation-contract tests initially failed while the report/index entry was absent and must pass after this record is added.

## 후속 36.15C 진입 조건

Proceed only with a separate gate and scope. Required first steps:

1. Native Linux and Windows feasibility builds, each with platform-specific package closure and isolated end-to-end tests.
2. Resolve dependency provenance and license-notice/SBOM generation for both application and build tools.
3. Test live monitoring, checkpoint lifecycle, restricted report, temporary cleanup, and resource permissions in each bundle environment.
4. Define signing/notarization, archive integrity, upgrade/rollback, uninstall, and user-data deletion contracts before a release artifact exists.
5. Keep loopback binding fixed, external requests at zero by default, and deny user-data collection or automatic response.

Rollback is limited to removing the standalone packaging spec/scripts/tests and their local ignored build outputs. The existing source-checkout launcher remains intact.

## 최종 판정

`PHASE_36_15B_PYINSTALLER_ONEDIR_FEASIBILITY_LOCAL_CONDITIONAL_GO` applies only after the final local regression passes and only to this unsigned macOS arm64 prototype. It does not authorize a release, production use, organizational logs, automatic response, Windows/Linux support, or signing claims. Actual user data, organizational operation, and automated response remain **NO_GO**.

### Official references checked 2026-11-04

- [PyInstaller runtime information](https://pyinstaller.org/en/stable/runtime-information.html)
- [PyInstaller spec files](https://pyinstaller.org/en/stable/spec-files.html)
- [PyInstaller common issues and pitfalls](https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html)
- [PyInstaller on PyPI](https://pypi.org/project/pyinstaller/)
- [pyinstaller-hooks-contrib on PyPI](https://pypi.org/project/pyinstaller-hooks-contrib/2026.9/)
