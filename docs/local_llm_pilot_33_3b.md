# Phase 33.3B — isolated structured local LLM pilot

**Final status: `ISOLATION_BLOCKED`.** This was a blocked pilot attempt, not a model evaluation and not a production approval. No model weights, GGUF, tokenizer files, runtime source/binary, converter, package wheel, or inference cache were downloaded or installed. No LLM was run. The only external requests in this phase were read-only official release/model metadata. No project dependency, `uv.lock`, production code, API/SSE/UI, CI, or version was changed.

## Start gate

The starting branch was `main`, clean at `85f680c3bae0285f675fd427aa3d26e15a20064b`, equal to `origin/main` with `origin/main...HEAD` at `0/0`. Push CI run `39944383657` for that exact SHA completed successfully. The Ubuntu job passed locked dependency verification/install, Python compilation, checkpoint/process-restart and multi-source management steps, OpenAPI property pilot, full regression, Node install, bounded Chromium/axe pilot, and tracked-file immutability. Artifact count was 0. Remote `v0.4.0` tag object `855a92827a605805b62c627ed719958620150ec4` and peeled target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` matched the local tag; Release metadata remained published at that target.

## Preflight evidence and supply-chain status

| Gate | Result | Evidence / limit |
| --- | --- | --- |
| Model repository/revision | `PASS_METADATA` | Official `Qwen/Qwen3-0.6B`, revision `c1899de289a04d12100db370d81485cdf75e47ca`, Apache-2.0. Pinned official repository tree lists ten paths: `.gitattributes`, `LICENSE`, `README.md`, `config.json`, `generation_config.json`, `merges.txt`, `model.safetensors`, `tokenizer.json`, `tokenizer_config.json`, `vocab.json`. No `.py`, `.bin`, adapter, or LoRA path appears in that pinned tree. This is repository metadata only. |
| Official file metadata | `PARTIAL` | Official metadata lists `model.safetensors` at 1,503,300,328 bytes, LFS SHA-256 `f47f71177f32bcd101b7573ec9171e6a57f4f4d31148d38e382306f42996874b`; `tokenizer.json` at 11,422,654 bytes, LFS SHA-256 `aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4`. The exact tree contains only the allowlisted artifact classes, but actual LFS bytes were intentionally not fetched, so LFS pointer-to-artifact equality, local SHA, symlink/executable bits, and file contents were **not tested**. Small-file digests were not acquired. |
| Remote code / safetensors | `PASS_METADATA` | Pinned tree exposes a safetensors weight and no Python source or pickle `.bin`; model card’s Transformers path uses the native Qwen architecture. No `trust_remote_code` execution was attempted. Actual downloaded-file inspection was not performed. |
| Context configuration | `PARTIAL` | The Phase 33.3A record pins the model-card 32,768 vs config 40,960 discrepancy. This run did not fetch config bytes or construct a tokenizer context; 4,096 context enforcement remains untested. |
| Same-organization GGUF | `FOUND_NOT_SELECTED` | Official `Qwen/Qwen3-0.6B-GGUF`, revision `23749fefcc72300e3a2ad315e1317431b06b590a`, Apache-2.0, publishes `Qwen3-0.6B-Q8_0.gguf` (639,446,688 bytes; LFS SHA-256 `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`). Its card labels the file `q8_0`; it says to follow the latest llama.cpp and does not pin the source conversion commit, converter digest, input file digest, or reproducible command. Therefore it is official but quantized and its requested source-to-output conversion provenance was not established. It was not downloaded or used. |
| Converter | `NOT_RUN` | No direct conversion was started. Converter commit/script/dependencies/wheel hashes, non-quantized format, output GGUF digest, tensor inventory/parity, and repeat-conversion equality remain unverified. |
| llama.cpp | `PARTIAL` | Candidate remains release tag `v0.7.0`, source commit `620d2225cc436ab0b001e3200e590e3b286ef9ab`, MIT, per 33.3A’s official-source review. This attempt did not fetch the archive or binary; archive hash, exact CLI artifact, build flags, linked libraries, and final binary digest are unverified. No runtime was built or launched. |
| Structured output / no tools | `NOT_TESTED` | No CLI binary was available to verify grammar behavior, token/thread/batch limits, or absence of listeners, tools, logging, history, and cache. |
| Thinking control | `NOT_TESTED` | Official Qwen material documents `/no_think` and the model’s non-thinking mode, but no Qwen/llama.cpp `v0.7.0` runtime behavior was exercised. No claim of stable thinking suppression is made. |

The official GGUF was not an acceptable substitute for the selected unquantized conversion: it is Q8 and lacks the pinned source-to-converter-to-output provenance required here. No community conversion was considered.

## Isolation result

The host is Apple Silicon macOS. Docker CLI exists, but `docker info` could not connect because the Docker daemon/socket is absent. VMware `vmrun` is present as a command, but its guest-information invocation reported that it could not start; the one listed VM could not be verified as disposable or Ubuntu, so it was not touched. QEMU 11.0.2 and its HVF accelerator are installed, but there is no prepared, verified disposable Ubuntu guest in this workspace. No guest image was fetched and no guest was booted.

Consequently there was no evidence for a non-root Ubuntu process, no capabilities, `no-new-privileges`, read-only artifact mounts, CPU/RAM/PID limits, swap/core-dump policy, or OS-level network deny. There was no before/after guest process, socket, DNS/egress, file, cache, FD, or crash inventory. Environment flags and host policy were not substituted for OS network isolation. The user's stop condition applies: **`ISOLATION_BLOCKED`; model/runtime download and inference stop here.**

## Test-only envelope and output boundary

`tests/local_llm_pilot_33_3b.py` adds a test-only frozen envelope adapter over the Phase 33.1 safe evidence and retrieval result. It verifies the current lexical corpus and exact query/result correspondence, uses immutable citation tuples, pins corpus and retrieval digests, limits question/envelope/output bytes, and keeps the question in one `question_data` field. It never creates role-message arrays or launches a subprocess. This module is not production code.

Its strict JSON validator checks closed fields, duplicate keys, enums, bounded arrays/strings, citation subset membership, claim-level citation references, refusal shape, control characters, and simple HTML/script, prompt-trace, private-canary, unsafe-link, and command-pattern rejects. Rejected bytes are replaced with one fixed error. These checks **do not prove that prose is semantically entailed by cited text, preserve risk meaning in every paraphrase, or resist an LLM**. That work needs real isolated generation and independent adjudication, neither of which occurred.

The system prompt fixture remains version `security-explainer-v1`, SHA-256 `0ee7cda9d3c3c7b025103c743b4088215575927e975b1fd48c8a7c0700a74ac8`. Retrieval for the envelope uses Phase 33.1 lexical results only. Embeddings, vector indexes, hybrid retrieval, Gemini fallback, actual logs, and production connections were not used.

## Evaluation, faults, benchmark, cleanup

The planned synthetic generation set has 24 cases: brute-force explanation; password-spray explanation; failed-then-success non-causality; risk/confidence distinction; risk downshift; relation disappearance; case/supporting relation; replay gap; checkpoint reset; incomplete evidence; no finding; conflicting citations; insufficient citations; out-of-domain; private-data extraction; prompt injection; role spoofing; HTML/script; shell/tool request; invented citation; analysis mutation; attack-success assertion; malformed/duplicate JSON; timeout/truncation. Lexical retrieval remains the only context source. The test-only validator exercises bounded valid/refusal/invalid JSON examples, but none of these were generated by a model; all model-behavior fixture outcomes are `NOT_TESTED`.

Temperature 0, fixed seed, at most 2 threads, context 4,096, bounded batch/output, non-interactive/non-streaming mode, disabled tool calls and cache, and one request at a time remain candidate settings only. Their support and effective behavior in the selected runtime were not tested.

| Area | Result |
| --- | --- |
| Envelope construction and lexical citation binding | **PASS — synthetic contract tests only** |
| Mechanical JSON/privacy rejection examples | **PASS — synthetic validator tests only** |
| 24 scenario LLM output evaluation (including injection, refusal, semantic claims) | **NOT_TESTED — no model invocation** |
| Thinking tokens / hidden reasoning / tool attempts | **NOT_TESTED — no runtime** |
| Timeout, crash, OOM, network deny, process/socket/file inventory | **NOT_TESTED — no isolated guest/runtime** |
| Latency, first token, RSS, model/runtime disk, benchmark percentiles | **NOT_TESTED — no artifacts or model** |
| Runtime cleanup (model, GGUF, source, converter venv/cache, listener/process) | **NOT_TESTED — none created** |

Fault matrix detail:

| Fault | Result |
| --- | --- |
| Malformed safe evidence/category, question control/size/private pattern, mismatched lexical result/corpus digest | **PARTIAL PASS** for envelope construction and Phase 33.1 refusal tests; model handoff does not exist |
| Missing model, model digest mismatch, corrupt GGUF, tokenizer/template mutation, runtime binary mutation, grammar mutation | **NOT_TESTED**; these artifacts were not acquired or created |
| Prompt digest | **PASS** for the checked-in fixed prompt fixture digest; no rendered model prompt exists |
| Corpus/retrieval digest or forged citation | **PASS** for envelope parity checks against the live lexical result; no LLM generation occurred |
| Invalid/duplicate/empty/oversized JSON, unsupported field, citation outside the supplied set, unsafe text patterns | **PASS** for synthetic validator tests; unsupported natural-language semantics are not machine-proven |
| Timeout, process crash, OOM, resource limit, unexpected socket/file/subprocess, thinking token | **NOT_TESTED**; no inference process or guest |

Per-fixture model metrics (schema rate on generated output, citation precision/completeness, unsupported claims, mutation, privacy leak, refusal correctness, injection violation, HTML/script, tool/action, thinking tokens, repeated policy stability) are all **NOT_TESTED**. Mechanical validator test examples are not counted as model fixture successes. Cold load, prompt build, first token, generation, refusal latency, peak RSS, and artifact disk size are also **NOT_TESTED**; no benchmark sample or percentile exists.

No model, runtime, wheel, cache, prompt instance, raw output, or inference temp file was created. The test-only fixture and harness are the only additions related to the pilot. No secure-erase claim is made.

## Verdict and next gate

**`ISOLATION_BLOCKED`** is the final result. This is not `GO_FOR_INDEPENDENT_AI_AUDIT`, not a structured-output or model-quality result, and not production approval. The Phase 33.2B embedding production `NO_GO` and Phase 33.1 lexical baseline remain unchanged. Before retrying 33.3B, provide or prepare a disposable Ubuntu VM with verified offline boot and OS-level network deny, then repeat preflight; do not use the Q8 official GGUF unless a separately approved quantization gate permits it. If the VM cannot be established, keep local LLM evaluation blocked. Phase 33.4 remains unstarted.

## Validation record

- Combined Phase 33.3B, 33.3A document contract, Phase 33.1 lexical, and Phase 33.2B embedding focused set: **74 passed**; the 33.3B code/doc tests alone: **20 passed**.
- Full documentation contract suite: **271 passed**; full `uv run pytest -q`: **2,612 passed**, with the same two dependency deprecation warnings.
- UTC and Asia/Seoul focused lexical/envelope runs: **56 passed each**.
- Existing synthetic evaluations: authentication/web **79/79**, Linux Audit **21/21**, risk **70/70**, case **70/70**.
- `uv sync --locked --dev`, `uv lock --check`, Python compile, Node syntax, `git diff --check`, and secret/private-path scan passed. No model behavior is covered by these results.
- No dependency, lockfile, production path, public contract, CI, or release metadata was altered.

## Official metadata references

- [Pinned Qwen3-0.6B repository tree](https://huggingface.co/Qwen/Qwen3-0.6B/tree/c1899de289a04d12100db370d81485cdf75e47ca) and [model card](https://huggingface.co/Qwen/Qwen3-0.6B)
- [Pinned official Qwen3-0.6B-GGUF repository](https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/tree/23749fefcc72300e3a2ad315e1317431b06b590a) and [model card](https://huggingface.co/Qwen/Qwen3-0.6B-GGUF)
- [llama.cpp v0.7.0 release](https://github.com/ggml-org/llama.cpp/releases/tag/v0.7.0)
