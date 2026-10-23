# Phase 33.3C — disposable Ubuntu VM local LLM pilot retry

**Final verdict: `ISOLATION_BLOCKED`.** This retry did not reach artifact acquisition or inference. The purpose was to remove the Phase 33.3B isolation blocker using an existing disposable Ubuntu 24.04 ARM64 VMware guest. The current session could not establish access to such a guest or verify its isolation boundary. No model/runtime artifact was downloaded, installed, converted, or executed. No VM, snapshot, container, image, volume, or network was created, deleted, restored, or modified.

## Start gate

| Check | Result | Evidence |
| --- | --- | --- |
| Branch and clean tree | `PASS` | `main`, clean before edits |
| Local and remote SHA | `PASS` | `4d8de514f84646a4d5e7277d36b22e4553cb298e`, equal; ahead/behind `0/0` |
| Exact-SHA CI | `PASS` | Push run [39947087923](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39947087923), completed/success, head SHA matched |
| Ubuntu locked install | `PASS` | Pinned uv/Python; lock verification and locked development install succeeded |
| Linux/Phase 33 regression | `PASS` | Checkpoint process restart, SSH checkpoint recovery, multi-source setup, OpenAPI pilot, full regression all succeeded |
| Node and accessibility | `PASS` | Pinned Node/dependencies, Chromium hash check, bounded axe pilot succeeded |
| Stored CI artifacts | `PASS` | Run artifact endpoint returned `total_count: 0` |
| v0.4.0 tag and Release | `PASS` | Tag object `855a92827a605805b62c627ed719958620150ec4`, peeled target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`; Release still targets that commit |

## VM isolation preflight

The host-side read-only `vmrun list` query exited with status 255. Its output did not provide usable guest identity or state; no path or account details are retained here. Prior Phase 33.3B records also state that VMware guest-information could not be obtained. This session did not receive an authenticated guest connection or independent VMware UI evidence for the claimed disposable Ubuntu VM. Therefore these required checks are **`NOT_TESTED`**:

- Ubuntu 24.04 ARM64 identity, clean snapshot and rollback readiness
- Docker client/daemon health inside the guest
- shared folders, clipboard, drag-and-drop, USB and other host integration disabled
- acquisition and offline-inference network phases, with OS-level deny verified before execution
- guest container/image/volume/network/process/listener inventory
- guest disk/RAM capacity and absence of real logs, repository credentials, SSH keys and cloud credentials
- non-root, capability removal, `no-new-privileges`, read-only mounts, resource limits, process/socket/file inventories and cleanup

No guest command was run. The local `vmrun` failure is not evidence that a guest is clean or isolated. Because the required snapshot, host-sharing boundary and network deny cannot be checked, the stop condition applies: **`ISOLATION_BLOCKED`**. No Docker Desktop, QEMU guest, host-side inference, or alternate isolation was substituted.

## Supply-chain and acquisition boundary

The only allowed candidate remains the one pinned in Phase 33.3A:

| Artifact | Fixed candidate | Status in this retry |
| --- | --- | --- |
| Model | `Qwen/Qwen3-0.6B`, revision `c1899de289a04d12100db370d81485cdf75e47ca`, Apache-2.0 | Metadata only from prior gate; actual bytes not fetched |
| `model.safetensors` | 1,503,300,328 bytes; SHA-256 `f47f71177f32bcd101b7573ec9171e6a57f4f4d31148d38e382306f42996874b` | Not downloaded or byte-verified |
| `tokenizer.json` | 11,422,654 bytes; SHA-256 `aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4` | Not downloaded or byte-verified |
| Runtime source | llama.cpp `v0.7.0`, commit `620d2225cc436ab0b001e3200e590e3b286ef9ab` | Source archive/binary not fetched or built |
| Prompt | `security-explainer-v1`, SHA-256 `0ee7cda9d3c3c7b025103c743b4088215575927e975b1fd48c8a7c0700a74ac8` | Existing fixture pin; no prompt instance rendered or saved |

No official GGUF was substituted. The official Q8 candidate lacks the required pinned source-to-converter binding and remains out of scope. A direct safetensors-to-GGUF converter commit, converter script digest, dependency/wheel hashes, exact allowlist for all small model files, and output GGUF digest are **not established**. Runtime source archive, build toolchain, CLI binary and provenance are **not established** either. Thus supply-chain readiness would require a separate verified gate after isolation; this attempt did not pass it. No URL was fetched for artifact bytes, no transfer directory was created, and no cleanup target was created.

### Intended acquisition manifest (not executed)

This is an incomplete planning allowlist, not authorization to fetch. The exact pinned model tree previously recorded in 33.3B includes only the following expected files; only the two large-file size/digest pairs below are currently pinned in this record. A later gate must obtain and verify size plus digest for **every** small file before acquisition. Any other path, executable, symlink, Python module, pickle, adapter, or LoRA is rejected.

| Allowlisted path | Pinned byte size / SHA-256 | Fixed source |
| --- | --- | --- |
| `model.safetensors` | 1,503,300,328 / `f47f71177f32bcd101b7573ec9171e6a57f4f4d31148d38e382306f42996874b` | [Exact model revision](https://huggingface.co/Qwen/Qwen3-0.6B/resolve/c1899de289a04d12100db370d81485cdf75e47ca/model.safetensors) |
| `tokenizer.json` | 11,422,654 / `aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4` | [Exact model revision](https://huggingface.co/Qwen/Qwen3-0.6B/resolve/c1899de289a04d12100db370d81485cdf75e47ca/tokenizer.json) |
| `.gitattributes`, `LICENSE`, `README.md`, `config.json`, `generation_config.json`, `merges.txt`, `tokenizer_config.json`, `vocab.json` | Size and SHA-256 not recorded here; acquisition blocked until fixed | Same pinned model revision, exact file path |
| llama.cpp source archive | Archive byte size/SHA-256 not recorded; expected commit `620d2225cc436ab0b001e3200e590e3b286ef9ab` | [Fixed source commit](https://github.com/ggml-org/llama.cpp/archive/620d2225cc436ab0b001e3200e590e3b286ef9ab.tar.gz) |
| converter script/environment and generated unquantized GGUF | No converter commit/script digest, wheel hashes, or output digest fixed | Not approved/not fetched; separate supply-chain evidence required |

If a later isolation gate passes, acquisition and inference must be separate phases. Candidate scratch is a dedicated guest-only directory such as `/var/tmp/local-llm-pilot-33-3c-acquire`, with an explicit inventory and cleanup list for only the verified artifacts, source archive, build tree, converter environment, model files, and bounded temp output. After hash verification, transfer to read-only model/runtime mounts; inference runs with external networking denied and synthetic DTO/citations only. Do not use host HOME or shared caches. No secure erase is claimed. This plan is incomplete and must be reviewed before any download.

## Input/output, evaluation and fault evidence

The existing test-only Phase 33.3B envelope/output validator and lexical-citation binding remain unchanged. It is a mechanical contract only and does not prove semantic entailment or model behavior. A new pure test-only preflight helper accepts only literal boolean attestations and fails closed when any required assertion is absent. Even a complete set returns `PREFLIGHT_ATTESTATIONS_COMPLETE_REQUIRES_REVIEW`; it explicitly does not verify a VM.

| Check | Result |
| --- | --- |
| 24 synthetic scenarios, at least 3 runs each, UTC and Asia/Seoul | `NOT_TESTED` — no model executed |
| Schema/citation/unsupported-claim/privacy/mutation/injection/tool/thinking/refusal metrics | `NOT_TESTED` — no raw model output exists |
| Korean readability and repeated output stability | `NOT_TESTED` |
| Timeout, malformed/duplicate/oversized output, invalid citation, crash/signal/OOM/write/network/cleanup faults | `NOT_TESTED` |
| Model load, first token, latency, RSS, CPU, output size, cleanup benchmark | `NOT_TESTED` |
| Before/after process, socket, file, cache, temp, core, container and VM inventory | `NOT_TESTED` — guest unavailable |

No result is counted as a pass for the 24 scenarios. No test expectation was weakened. The deterministic analysis remains authoritative; no AI path was invoked, so no fallback was used. Production integration is not approved.

## Cleanup and remaining state

No pilot VM was accessed and no VM/snapshot restore was attempted. No model, GGUF, tokenizer, runtime, converter environment, cache, prompt instance, raw output, temporary inference file, process, listener, container, volume, or network was created by this attempt. Consequently there is no pilot artifact cleanup to report. Existing host software and any shared image/layer caches were not modified or deleted; no secure erase is claimed.

## Repository verification

The existing deterministic non-LLM synthetic evaluation returned authentication/web **79/79**, Linux Audit **21/21**, risk **70/70**, and case **70/70**. These are existing rule-based fixture results, not model quality or production performance.

| Check | Result |
| --- | --- |
| Before-change baseline | `uv run pytest`: 2,612 passed, 2 existing deprecation warnings |
| Phase 33/32 focused after changes | 124 passed, 2 existing deprecation warnings |
| Full suite after changes | `uv run pytest`: 2,618 passed, 2 existing deprecation warnings |
| Lexical retrieval and preflight contract under UTC | 42 passed |
| Same focused set under Asia/Seoul | 42 passed |
| `uv sync --locked --dev` | Passed; 55 packages checked |
| `uv lock --check` | Passed |
| Python compileall, Node `--check`, `git diff --check` | Passed |
| Added-content privacy scan | No personal paths or credential patterns; one generic loopback literal inherited in the README line |

The timezone runs exercise deterministic retrieval and pure preflight tests only. They do not stand in for LLM repeatability; no LLM output was generated.

## Test-only preflight gate

Re-run the preflight contract tests with:

```bash
uv run pytest tests/test_local_llm_pilot_33_3c.py tests/test_local_llm_pilot_33_3b.py tests/test_local_llm_pilot_33_3b_documentation.py
```

The helper tests fail-closed behavior for each missing attestation and demonstrate that even fully supplied booleans are not treated as verified isolation. It is not a guest probe, model harness, or substitute for a human-verified VM inventory.

## Final disposition

**`ISOLATION_BLOCKED`** — exact result of this attempt. The later [Phase 33.3D retry](local_llm_pilot_33_3d.md) recorded user-provided VM facts but stopped before artifact transfer because the converter/runtime wheel closure and disk peak were not fully pinned. Resume only after guest isolation evidence and the exact artifact supply-chain/3 GiB disk-floor gate both pass. Do not restore/delete snapshots without explicit approval. Phase 33.4 and production use remain unstarted.

### Scope not tested

Model/runtime supply-chain bytes, converter reproducibility, thinking suppression, grammar behavior, all model metrics, all injected faults, native Ubuntu inference, process/socket/file/network inventory, resource bounds and cleanup are `NOT_TESTED`. No actual user data was used. Embedding/vector/hybrid retrieval, Gemini fallback, production dependencies, API/SSE/UI, `uv.lock`, CI and version remain untouched.
