# Phase 33.3D — disposable Ubuntu VM structured local LLM pilot

**Final verdict: `SUPPLY_CHAIN_BLOCKED`.** This attempt stopped before artifact acquisition, conversion, build, or inference. The user supplied VM facts are recorded as user-reported evidence; this session did not operate the VM or independently verify those facts. The required complete converter/runtime dependency closure, including pinned wheel hashes and sizes, was not established. No model, tokenizer, runtime source/binary, wheel, GGUF, cache, or raw prompt/output was downloaded, installed, generated, or executed. No production code, dependency, lockfile, API/SSE/UI, CI, or version changed.

## Start gate

| Check | Result | Evidence |
| --- | --- | --- |
| Branch and working tree | `PASS` | `main`; clean before edits |
| Local and remote SHA | `PASS` | `8172be908c9a1c9478ad1dddd0e1b3354cb3907c`; equal; ahead/behind `0/0` |
| Exact-SHA push CI | `PASS` | [Run 39949787930](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39949787930), `completed/success`, exact head SHA |
| Ubuntu locked install and full regression | `PASS` | Locked setup and full regression job succeeded |
| Phase 33 contracts | `PASS` | Phase 33.1/33.2/33.3 contract tests passed in the exact run |
| Node and axe | `PASS` | Pinned Node/accessibility steps succeeded |
| Stored CI artifacts | `PASS` | Run artifact endpoint reported zero artifacts |
| v0.4.0 tag and Release | `PASS` | Existing tag object and peeled target remain `855a92827a605805b62c627ed719958620150ec4` → `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`; Release target unchanged |

## VM evidence and boundary

The user reported VMware Fusion, Ubuntu 24.04.5 LTS ARM64, Docker client/server 29.1.3, 2 CPUs, approximately 5.8 GiB RAM, approximately 4.7 GiB available memory, approximately 3.3 GiB swap, approximately 8.1 GiB free root space, snapshots named `clean-before-phase-31-2a` and `pre-phase-33-3d`, disabled Drag and Drop/Copy and Paste/Shared Folders, no `vmhgfs` mount, no running containers or volumes, only default bridge/host/none Docker networks plus one pinned BusyBox image, and listeners identified as systemd-resolved, Avahi, CUPS, SSH and containerd. The user described SSH as acquisition-only and planned to stop SSH and auxiliary services and disconnect the VMware adapter for inference.

These are **user-reported**, not session-verified. No guest command output or fresh VM inventory was received during this attempt. Current snapshot rollback, host integrations, credential/log absence, exact disk bytes, offline network-deny, and process/socket/file inventory remain `NOT_TESTED` by this session. No VM, snapshot, container, image, volume, or network was changed. No host-side model/runtime execution or Docker Desktop substitution occurred.

## Supply-chain preflight

The following is a static candidate allowlist assembled from the exact public repository metadata. It is **not an acquisition authorization**. The fixed model tree contains the ten listed paths; unexpected paths, symlinks, executables, Python source, pickle files, adapters, and LoRA files remain forbidden.

| Model file | Exact revision size | Repository digest | Fixed source |
| --- | ---: | --- | --- |
| `.gitattributes` | 1,570 | Git blob SHA-1 `52373fe24473b1aa44333d318f578ae6bf04b49b` | [Pinned Qwen revision](https://huggingface.co/Qwen/Qwen3-0.6B/tree/c1899de289a04d12100db370d81485cdf75e47ca) |
| `LICENSE` | 11,343 | Git blob SHA-1 `6634c8cc3133b3848ec74b9f275acaaa1ea618ab` | Same pinned revision; Apache-2.0 |
| `README.md` | 13,965 | Git blob SHA-1 `a50b19e76f5274f9ec99f5a5d99873dca5bff25e` | Same pinned revision |
| `config.json` | 726 | Git blob SHA-1 `f5c3703b78ae2a478ae15b247e9f855e0ce2107b` | Same pinned revision |
| `generation_config.json` | 239 | Git blob SHA-1 `20a8a9156fc8c3f25295ca067f61fdf120d517c5` | Same pinned revision |
| `merges.txt` | 1,671,853 | Git blob SHA-1 `31349551d90c7606f325fe0f11bbb8bd5fa0d7c7` | Same pinned revision |
| `model.safetensors` | 1,503,300,328 | LFS SHA-256 `f47f71177f32bcd101b7573ec9171e6a57f4f4d31148d38e382306f42996874b` | Same pinned revision |
| `tokenizer.json` | 11,422,654 | LFS SHA-256 `aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4` | Same pinned revision |
| `tokenizer_config.json` | 9,732 | Git blob SHA-1 `417d038a63fa3de29cfde265caedae14d1a58d92` | Same pinned revision |
| `vocab.json` | 2,778,833 | Git blob SHA-1 `4783fe10ac3adce15ac8f358ef5462739852c569` | Same pinned revision |

The repository/revision is `Qwen/Qwen3-0.6B` at `c1899de289a04d12100db370d81485cdf75e47ca`, Apache-2.0. SHA-256 values for the eight ordinary Git blobs were not recorded; their pinned Git blob IDs are SHA-1, not SHA-256. The two large LFS objects have the SHA-256 values shown. No file bytes were fetched or verified.

| Runtime/converter item | Static pin | Status |
| --- | --- | --- |
| llama.cpp source | `ggml-org/llama.cpp`, commit `620d2225cc436ab0b001e3200e590e3b286ef9ab`, tag `v0.7.0` | Commit identity checked from official source metadata; source/archive bytes and build output not obtained |
| HF converter | `convert_hf_to_gguf.py`, pinned Git blob SHA-1 `e09616b190cf124e818d8a740468d4e84086015c`, 13,012 bytes | SHA-256 not recorded; script not fetched or run |
| Converter requirements | `requirements-convert_hf_to_gguf.txt`, blob SHA-1 `b1f7c863e27e184e55408c9e5792158301c86547`, 200 bytes; legacy requirements blob SHA-1 `edc945c1cb677cf9275470c83b1a773572579998` | Pinned source shows torch `2.11.0`, transformers `4.57.6`, NumPy `~=2.2.6`, sentencepiece `<0.3`, gguf, and protobuf `<5`; exact transitive wheel set, byte sizes, SHA-256 hashes, and total installed/cache size not fixed |
| Runtime source archive | Exact commit above | Archive size/SHA-256 not established; no source fetched |
| Build output | `llama-cli` only; no HTTP server use | Compiler/CMake versions, flags, linked libraries, binary hash, and additional download behavior not measured |
| Conversion output | Safetensors through that exact converter; unquantized F16/BF16 only | Output GGUF size/hash, tensor inventory, and repeat-conversion equivalence do not exist |

Official static source references: [pinned Qwen tree](https://huggingface.co/Qwen/Qwen3-0.6B/tree/c1899de289a04d12100db370d81485cdf75e47ca), [pinned llama.cpp converter](https://github.com/ggml-org/llama.cpp/blob/620d2225cc436ab0b001e3200e590e3b286ef9ab/convert_hf_to_gguf.py), [pinned converter requirements](https://github.com/ggml-org/llama.cpp/blob/620d2225cc436ab0b001e3200e590e3b286ef9ab/requirements/requirements-convert_hf_to_gguf.txt), [pinned legacy requirements](https://github.com/ggml-org/llama.cpp/blob/620d2225cc436ab0b001e3200e590e3b286ef9ab/requirements/requirements-convert_legacy_llama.txt), [official PyTorch wheel index](https://download.pytorch.org/whl/torch/).

The Ubuntu package candidates for a source build would be `git`, `cmake`, `build-essential` (compiler, linker, make), and Python 3.12 venv/development tools. Installed package versions and package hashes were not checked; nothing was installed. Python wheel allowlist and hashes are incomplete. Therefore the required pre-download report cannot be considered complete and the explicit supply-chain stop condition applies.

### Disk budget

The user-reported free space of approximately 8.1 GiB leaves at most approximately 5.1 GiB of additional use while preserving the required 3 GiB floor. The pinned safetensors alone is 1.503 GB. An unquantized converted model must hold a comparable parameter payload, and the conversion needs both source and output concurrently. Runtime source/build, converter wheels and installed environment, package caches, and temporary conversion files are additional. Their verified upper bounds are unknown, so a safe peak cannot be demonstrated. No unrelated user file or pre-existing image was removed. This is a second unresolved gate; it is not represented as a measured disk failure.

### Planned temporary layout (not created)

If a future separately reviewed preflight passes, use a dedicated VM-only scratch root with `model-source/`, `llama-source/`, `converter-venv/`, `build/`, `model-output/`, and bounded `private-temp/`. Candidate cleanup is limited to these explicitly created paths and verified pilot artifacts. Keep only redacted aggregate metrics, verified digests, manifest, and test fixtures in the repository. Do not retain raw prompts/output, model bytes, GGUF, runtime binary, wheel cache, or private temp. No secure erase is claimed. Snapshot restore/deletion requires separate user approval.

## Execution and evaluation status

| Requirement | Result |
| --- | --- |
| Model/runtime/package download, install, build, conversion, inference | `NOT_TESTED` — stopped before acquisition |
| Safetensors-only, remote-code, tokenizer/template and GGUF checks | `NOT_TESTED` — no artifact bytes processed |
| Non-root container, network none, capability and resource limits | `NOT_TESTED` — no execution container/process created |
| Thinking suppression, grammar enforcement and output semantic validation against model output | `NOT_TESTED` |
| 24 synthetic scenarios × 3 runs × UTC/Asia-Seoul | `NOT_TESTED` — no model output |
| Schema/citation/unsupported claim/privacy/mutation/injection/tool/thinking/refusal/readability metrics | `NOT_TESTED` |
| Timeout, malformed/duplicate/oversized output, citation, crash/SIGTERM/OOM/write/network/temp faults | `NOT_TESTED` against an actual model subprocess |
| Load/first-token/latency/RSS/CPU/bytes/cleanup benchmark | `NOT_TESTED` |
| Before/after process/socket/container/temp/cache inventory | `NOT_TESTED` in the VM |
| Existing rule-based analysis | Unchanged; no model path invoked |

The user-reported resource figures and snapshot/service plan are not converted into VM PASS results. The 79/79, 21/21, risk 70/70 and case 70/70 synthetic evaluations remain rule-based regression results; they do not measure LLM explanation quality. The existing test-only input/output validators remain mechanical contract tests, not evidence of model behavior.

## Test-only preflight

`tests/local_llm_pilot_33_3d.py` implements pure checks for an exact closed artifact manifest with SHA-256 pins, a 3 GiB disk floor, and stop-verdict precedence. It does not inspect a filesystem, call a VM, download, or execute anything. Its success marker is `PREFLIGHT_COMPLETE_REQUIRES_REVIEW`, not permission to run inference. Missing isolation is `ISOLATION_BLOCKED`; missing artifact closure is `SUPPLY_CHAIN_BLOCKED`; insufficient disk margin is `RESOURCE_NO_GO`.

## Repository validation

| Check | Result |
| --- | --- |
| Before-change full suite | `uv run pytest`: 2,618 passed, 2 existing dependency deprecation warnings |
| Phase 33 focused set | 91 passed (33.3D preflight/docs, 33.3C/33.3B contracts, 33.3A docs, lexical retrieval and 33.2B regression) |
| Full suite after changes | `uv run pytest`: 2,624 passed, same 2 warnings |
| UTC lexical/envelope/preflight repeat | 59 passed |
| Asia/Seoul lexical/envelope/preflight repeat | 59 passed; same test outcomes |
| Existing synthetic rule evaluation | authentication/web 79/79; Linux process 21/21; risk 70/70; case 70/70 |
| `uv sync --locked --dev` / `uv lock --check` | Passed; 55 installed packages checked; lock unchanged |
| Python compile / Node syntax / `git diff --check` | Passed |
| Added-content privacy scan | No VM IP, hostname, username, VMX path, home path, credential or raw prompt/output recorded; generic loopback references remain product docs only |

These tests validate documentation, deterministic retrieval and pure preflight logic. They do not validate VM isolation, conversion, grammar, thinking suppression, actual output safety, model quality, or model resource use.

## Final disposition

**`SUPPLY_CHAIN_BLOCKED`**. Stop before download. Resume only after (1) user-provided guest-console output verifies current VM identity, snapshot/host integration state, disk bytes, and acquisition inventory; (2) every model auxiliary file has an accepted digest; (3) exact converter/runtime closure, all package/wheel hashes and sizes, build toolchain, and peak disk estimate are pinned; and (4) the 3 GiB free-space floor is demonstrated for the entire peak. Then report the complete acquisition manifest and wait for the next staged user-run command. Do not restore/delete/replace a snapshot without approval.

This is neither an LLM evaluation result nor production approval. Phase 33.4 remains unstarted. Embedding production `NO_GO`, lexical-only retrieval, no Gemini fallback, no production integration, and no actual user data remain unchanged.
