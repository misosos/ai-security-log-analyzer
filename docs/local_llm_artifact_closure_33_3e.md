# Phase 33.3E — local LLM artifact closure and storage gate

**Final verdict: `RESOURCE_NO_GO`.** The exact model files, Python wheel candidates, and llama.cpp source archive were pinned far enough to calculate a conservative planning scenario, but the scenario exceeds the available acquisition budget. Several license/install-hook and Ubuntu build-package details also remain unverified, so this record does not authorize acquisition. No model inference, runtime build, package installation, production integration, API/SSE/UI/dependency/lockfile/CI/version change occurred.

## Start gate

| Gate | Result | Evidence |
| --- | --- | --- |
| Branch, clean tree, local/remote equality | `PASS` | `main`; start SHA `4666bf17d794c6978ff0d10b1f9f3d5bc1093e72`; clean; ahead/behind `0/0` |
| Exact push CI | `PASS` | [Run 39982114651](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39982114651), completed/success, exact head SHA |
| Ubuntu locked setup and full regression | `PASS` | Locked install, compilation, Linux checkpoint/process tests, Phase 32 pair management/runtime/publication and full regression steps succeeded |
| Phase 33 contracts | `PASS` | Exact run’s Phase 33.1/33.2/33.3 contract steps succeeded |
| Node and axe | `PASS` | Pinned Node/browser setup and accessibility checks succeeded |
| Stored artifacts | `PASS` | Exact run artifact endpoint returned 0 |
| v0.4.0 tag and Release | `PASS` | Tag object `855a92827a605805b62c627ed719958620150ec4`, peeled target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`; Release target unchanged |

## Fixed model artifact manifest

The machine-readable allowlist is [the model manifest](artifacts/local_llm_model_manifest_33_3e.json). It lists the ten files at `Qwen/Qwen3-0.6B` revision `c1899de289a04d12100db370d81485cdf75e47ca`, including byte size, SHA-256, pinned Git blob SHA-1 where applicable, LFS flag, role, and a mandatory pre-acquisition byte recheck. The eight small non-LFS files were streamed from exact pinned `resolve` URLs; their sizes and SHA-256 values were computed and their Git blob SHA-1 values matched the pinned tree. The model weights and tokenizer LFS bytes were not fetched; their SHA-256 values are the pinned upstream LFS metadata and must be checked against bytes before any future acquisition.

The converter reads model config/tokenizer files and checks `README.md`; all ten repository entries are tracked in the manifest, while `.gitattributes` and `LICENSE` are metadata records rather than runtime mounts. Reject any unlisted path, symlink, executable, custom Python module, pickle, adapter, or LoRA file.

## Converter and wheel closure

The build manifest pins llama.cpp `v0.7.0` to commit `620d2225cc436ab0b001e3200e590e3b286ef9ab`. The exact source archive was streamed without retaining it: 38,195,486 bytes, SHA-256 `1d4a987d9bd048f6e93107e838026438df70fbde237fc0c69c63d600512b4bd9`. Converter, requirements, Qwen conversion, and GGUF package metadata source files have individual SHA-256 pins in the build manifest.

Static source inspection found `torch` is required: the pinned converter imports it unconditionally and enters `torch.inference_mode()`. The Qwen3 converter path is present. `--remote` invokes `huggingface_hub.snapshot_download`, so it is forbidden; only a verified local model directory is admissible. No `trust_remote_code` is required by the inspected path. Conversion output is a single unquantized F16 GGUF candidate; output size is modeled from 751,632,384 parameters × 2 bytes, before headers and padding.

The [wheel closure manifest](artifacts/local_llm_wheel_closure_33_3e.json) is a metadata resolution for Ubuntu 24.04 ARM64 / CPython 3.12. `uv pip compile` with `--only-binary :all:` resolved 28 wheels, total 197,071,951 bytes, with versions, target-compatible filenames, index, metadata SHA-256, size, license field and dependency annotations. No sdist was selected and no package was installed. The resolver output reported one transient 1,256,108-byte setuptools wheel download while resolving metadata; the isolated temporary uv cache inventory afterward contained 1,882 bytes and no retained wheel body. No project dependency or lockfile changed.

This is still **not a closed install supply chain**: the Python patch/build artifact was not fixed; wheel archives were not inspected for embedded installer scripts, native file inventory, or exact extracted sizes; PyPI metadata did not expose an unambiguous license for six packages (`fsspec`, `markupsafe`, `networkx`, `regex`, `sentencepiece`, `typing-extensions`); and apt package versions/hashes, compiler/CMake/Ninja versions, final build flags, linked libraries and `llama-cli` digest are unknown. The converter requirements include ranges, so the metadata resolution is a candidate lock, not proof of a tested offline installation. No OS package was installed.

## Disk peak gate

The user-provided VM figures are approximately 8.1 GiB free and a required 3 GiB reserve, leaving an approximate acquisition budget of 5.1 GiB. Those figures were not independently measured in this session.

The reproducible [disk calculator](../tests/local_llm_disk_peak_33_3e.py) combines all simultaneously present model files, the unquantized GGUF payload floor, the exact candidate wheelhouse and source archive with explicit planning caps for conversion staging, installed environment, extracted source, build directory and fixtures/output. It then adds 15% filesystem/safety overhead. This is deliberately more conservative than a simple source-plus-output sum. Planning caps are not measured upper bounds, so the tool separately reports that safe fit is unproven. Re-run with `uv run python tests/local_llm_disk_peak_33_3e.py --free-gib 8.1 --reserve-gib 3`.

| Component | Bytes |
| --- | ---: |
| Model weights, tokenizer and all pinned small model files | 1,519,209,243 |
| F16 GGUF payload floor | 1,503,264,768 |
| Wheelhouse | 197,071,951 |
| llama.cpp source archive | 38,195,486 |
| Conversion staging allowance | 1,503,300,328 |
| Installed converter environment allowance | 536,870,912 |
| Extracted runtime source allowance | 536,870,912 |
| Runtime build directory allowance | 536,870,912 |
| Bounded fixtures/output allowance | 67,108,864 |
| 15% filesystem/safety overhead | 965,814,507 |
| **Planning peak** | **7,404,577,883 bytes (about 6.90 GiB)** |

Planning peak exceeds the approximately 5.1 GiB usable budget by 1,928,494,581 bytes (about 1.80 GiB). Some allowances are not measured bounds; that uncertainty cannot justify treating the plan as fitting. Therefore the selected disposition is `RESOURCE_NO_GO`, independently of the remaining supply-chain closure work.

### Alternatives

| Option | Assessment |
| --- | --- |
| Add a dedicated pilot virtual disk | Best isolation/storage option to evaluate in a separate user-approved VM change. Do not create, format, mount, or remove it here. |
| Expand existing root disk | Not automatic; requires separate approval and a fresh VM/storage review. |
| Delete staged artifacts between conversion steps | Does not safely remove the simultaneous source, output, environment and conversion-space requirements; not accepted as a fit proof. |
| Select a smaller official model | Requires a new model/license/revision/converter/runtime gate, not a substitution in this phase. |

No unrelated user files or pre-existing images were removed. No VM, snapshot or virtual disk was modified.

## Revalidation tests

Focused Phase 33 tests: **64 passed**. Full pytest: **2,634 passed**, with two pre-existing Starlette deprecation warnings. The synthetic deterministic analyzer evaluations remained authentication/web **79/79**, Linux process **21/21**, risk **70/70**, and case **70/70**; they measure rule-based fixtures, not an LLM. The combined evaluation JSON was byte-identical under UTC and Asia/Seoul (SHA-256 `f15c3c6a0d937e3a49f19fcf7feb7b418fc99d4e3c776d160d01950eec0fe8c9`). Disk calculator output was also repeated under both zones with the same bytes and digest. `uv sync --locked --dev`, `uv lock --check`, Python and Node syntax checks, `git diff --check`, and the changed-file secret/private-path scan passed.

Focused tests check fixed model digests, missing/duplicate model entries, wheel tampering/duplicates, platform mismatch, missing build digest and the disk-budget result. The manifests bind metadata only; model/LFS bytes and all candidate wheels still require verification before any future acquisition. The phase decision does not authorize model or runtime download, installation, build, conversion or inference.

## Phase boundary

33.1 lexical retrieval remains the only retrieval baseline. 33.2B embedding production integration remains `NO_GO`. This phase did not acquire or execute Qwen or llama.cpp. Production API/SSE/UI, Gemini, and automatic fallback remain untouched. Any next attempt must first resolve license/install-hook/build-package closure and obtain user approval for a larger isolated VM storage plan; `READY_FOR_VM_ACQUISITION` was not reached.
