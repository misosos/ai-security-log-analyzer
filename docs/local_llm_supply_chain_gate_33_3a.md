# Phase 33.3A — 구조화 local LLM 설명 pilot 공급망·평가 gate

**상태: 정적 설계 gate 완료. Phase 33.3B 실행은 조건부로만 제안한다.** 조사일은 2026-10-23이다. 모델·runtime을 다운로드·설치·실행하지 않았다. dependency, `uv.lock`, production 코드, API/SSE/UI, CI, version도 변경하지 않는다. 외부 요청은 공식 public metadata를 읽는 정적 조사에만 사용했다.

Phase 33.2B 결론은 유지한다. **Embedding production 통합은 `NO_GO`이며 Phase 33.1 lexical retrieval이 유일한 context search다.** Embedding, vector index, hybrid ranking을 LLM 입력에 사용하지 않는다. 이 문서가 제안하는 것은 합성 safe evidence와 이미 검증한 lexical citation을 설명 모델에 전달하는 격리 pilot gate다. 통과해도 바로 제품에 연결하지 않는다.

## 권한·제품 경계

### 권위 있는 계층

Parser, detection, correlation, risk, case, safe publication은 기존 결정적 분석기가 계속 소유한다. 모델은 이를 설명할 뿐 새 분석을 만들거나 기존 결과를 숨기지 않는다. 사용자에게 표시되는 AI 문구는 항상 **“조사 보조 설명이며 탐지·위험도·사례의 권위 있는 결과가 아닙니다.”**라는 경계를 함께 갖는다.

허용 역할은 기존 결과의 쉬운 설명, 검증된 citation에 근거한 다음 확인 항목, 불확실성과 한계의 표현, 고정 refusal code 선택뿐이다.

### 모델이 갖지 않는 권한

- detection·relation·risk·case의 생성, 변경, 삭제, 재분류
- 공격 또는 침해 성공 확정, 계정 차단·잠금, 파일 변경·삭제 등 자동 대응
- shell·도구 실행, 파일 또는 network 접근, corpus 수정
- citation 생성·변경, 원본 로그 요구, 개인정보 추론 또는 재구성
- 기존 분석이나 한 역할의 실패를 숨김
- 모델·runtime 실패 시 Gemini 또는 다른 모델로 fallback

AI가 꺼지거나 실패하면 기존 분석기와 UI 결과는 그대로 동작한다. Gemini 경로는 독립된 legacy 경로다. Phase 33.0 감사의 내용, 즉 legacy helper의 IP 포함 projection과 검증되지 않은 자유 문자열 응답 가능성을 이 설계에서 다시 확인·수정하지 않았다. **Local↔Gemini fallback, DTO 공유, output 계약 공유는 금지**한다. Gemini 유지·폐기 또는 안전 projection 이전은 별도 gate다.

## 입력 계약 후보

입력은 frozen/closed `LocalExplanationEnvelope` 후보 하나다. 임의 dict나 모델이 만든 role-message 배열을 받지 않고 고정 adapter가 safe DTO와 검증된 33.1 result에서 만든다. `extra=forbid`, strict types, immutable tuple, canonical JSON byte cap을 적용한다.

| 필드 | 계약 |
| --- | --- |
| `schema_version` | 고정 문자열 `local-explanation/1` |
| `request_id` | 무작위 session-local ID; 경로·시간·사용자 식별자 파생 금지 |
| `question_category` | 33.1의 고정 category enum 7개 중 하나 |
| `evidence` | 별도 33 safe evidence DTO; 승인 enum·bounded count/string만 허용 |
| `citations` | 현재 corpus/digest로 검증한 lexical citation만, 최대 5개 |
| `corpus_digest` | 64 lowercase hex이며 현재 pinned manifest와 일치 |
| `retrieval_result_digest` | canonical verified citation tuple의 SHA-256 |
| `locale` | `ko-KR` 또는 `en-US`만 |
| `output_limits` | 코드 고정 token·byte·item 상한; 요청자가 확대할 수 없음 |

33.3B pilot 제안 상한은 citation 5개, citation excerpt 512 UTF-8 bytes, evidence item 32개, 한 safe string 160 bytes, prompt context 6,144 tokenizer tokens, 생성 512 tokens, 결과 JSON 16 KiB, 처리 30초, 동시 요청 1개다. 모델의 context window를 채우려 하지 않는다. 각 한도는 실제 pilot에서 확인하고 초과 입력은 축약 추측 없이 거부한다.

허용 데이터는 source role, 승인 detection/relation/case 표시명, risk/confidence enum, 제한 집계, 시간 차이, session-local public ID, completeness·limitation code와 33.1 검증 citation이다. Raw log, account/IP/hostname, path/query, rationale/evidence 원문, checkpoint metadata, browser state, 내부 identity·exception, config/HOME 위치는 DTO에 존재하지 않는다.

사용자 질문은 최대 256 Unicode scalar·1,024 UTF-8 bytes로 제한한 **단일 `question_data` string field**다. system/developer/user role을 사용자가 공급하거나 prompt 내부에 role로 끼워 넣지 못한다. 허용 category·33.1 질문 계약을 먼저 통과시킨 후 고정 serializer가 하나의 data field로 직렬화한다. 개인정보 형태, 역할 위조, 공격 성공 단정, 실행 요구, prompt override, 금지 category는 검색·모델 호출 전에 고정 refusal로 끝난다. 개인 정보를 제거하거나 익명화했다고 추정해 계속하지 않는다.

## 고정 prompt와 renderer

고정 system policy fixture는 [`local_llm_system_prompt_33_3a.txt`](../tests/fixtures/local_llm_system_prompt_33_3a.txt)이며 version `security-explainer-v1`, SHA-256 `0ee7cda9d3c3c7b025103c743b4088215575927e975b1fd48c8a7c0700a74ac8`이다. Digest는 UTF-8 bytes를 LF/final newline로 고정해 직접 계산한다. 변경은 새 version·digest와 재검토를 요구한다.

Renderer는 다음 경계를 보존한다.

1. 위 digest로 고정한 system policy
2. safe evidence JSON object
3. corpus digest가 검증된 citation tuple
4. 단일 허용 question category
5. JSON string escape된 하나의 `question_data`
6. 닫힌 output JSON schema와 상한

근거 excerpt와 evidence string은 인용된 **untrusted data**로 표기한다. “이전 지시를 무시하라”, 가짜 system/developer 역할, command가 들어와도 지시로 해석하지 않는다. Prompt는 기존 분석 결과를 변경하지 말 것, 제공된 citation 밖 사실을 만들지 말 것, 공격·침해 성공을 확정하지 말 것, 근거 부족·충돌 시 거부할 것, 개인정보를 추론하지 말 것, 도구·파일·network 접근을 하지 말 것, JSON 이외 출력을 내지 말 것을 분명히 한다. 내부 prompt와 chain-of-thought는 출력하거나 일반 log/report에 기록하지 않는다.

선정 runtime은 `llama-cli`의 고정 JSON-schema grammar 경로를 pilot에서 확인하는 안이다. prompt와 schema를 argv에 직접 넣지 않는다. process argv에는 고정 flag와 비민감 file descriptor reference만 둔다. Linux disposable VM에서 system template는 read-only constant input, request envelope는 bounded pipe/stdin으로 전달하고 stdout은 bounded memory capture, stderr는 수집하지 않는 구성을 검증한다. 이 framing이 실제로 prompt를 argv·disk·diagnostic에 남기지 않는지 확인하지 못하면 모델을 실행하지 않는다.

## 닫힌 출력 계약 후보

모델은 다음 구조 외 필드를 생성하지 않는다. Output schema는 JSON Schema Draft 2020-12 형태로 `additionalProperties: false`, enum, max length/count를 고정한다.

```json
{
  "status": "ANSWER | REFUSED",
  "summary": [{"text": "bounded claim", "citation_ids": ["doc/section"]}],
  "citation_ids": ["doc/section"],
  "next_checks": [{"text": "bounded check", "citation_ids": ["doc/section"]}],
  "uncertainty": ["INCOMPLETE_WINDOW"],
  "limitations": ["NO_SUCCESS_PROOF"],
  "refusal_code": null
}
```

각 자연어 summary/next-check 문구는 하나의 claim block이며 최소 한 citation ID를 붙인다. `citation_ids`는 claim blocks에 사용된 집합과 같아야 하고 입력 citation tuple의 부분집합이어야 한다. 불확실성·한계는 고정 code enum을 우선한다. `REFUSED` 응답은 고정 refusal code만 갖고 claim arrays는 비어 있어야 한다.

모델이 쓸 수 있는 문자열과 목록은 예를 들어 summary claim 최대 3개×240 chars, 다음 확인 최대 3개×160 chars, citation ID 최대 5개, 전체 UTF-8 JSON 16 KiB로 제한한다. HTML tag, script/style, Markdown link, `javascript:` 등 위험 scheme, null/control, duplicate JSON key, extra field, trailing text, malformed/truncated JSON, duplicate IDs, unknown enum, 위험한 명령·개인정보 pattern은 거부한다. Output object의 `citation_ids`는 입력 집합을 벗어나면 안 된다. Risk/confidence/case/source-role 수치·표시는 evidence와 충돌할 경우 거부한다. Prompt·chain-of-thought 패턴이 있거나 private canary가 있으면 raw model output을 버리고 고정 code만 반환한다.

`model_id`, 승인된 model artifact digest prefix, runtime version, corpus digest와 request ID는 **모델 output에 포함시키지 않는다.** 고정 local runner가 validated result envelope에 붙여 모델이 값을 위조하지 못하게 한다. Raw generation은 API·UI·log에 직접 전달하지 않는다.

Schema·citation-set은 기계적으로 검증할 수 있지만, 자유 문장과 citation의 의미상 entailment, risk 의미 보존 전체를 일반 validator만으로 증명할 수는 없다. 그래서 supported-claim 경계는 pilot fixture의 수동 이중 adjudication과 Phase 33.4 독립 감사를 요구하며, unsupported claim 0을 입증하지 못하면 답변을 제품에 노출하지 않는다. Citation이 존재하는 사실과 citation이 사실을 뒷받침한다는 의미는 다른 검증 단계다.

## 후보 모델 정적 비교

공식 repository/model card와 공식 Hugging Face metadata만 사용했다. Revision은 조사 시점 main branch head를 찾는 데만 확인했고 실행 때 branch alias로 쓰지 않는다. 공개 metadata는 exact revision pin과 weight digest 계획을 돕지만 artifact를 취득·검증한 증거는 아니다.

| 모델 후보 | revision·license·파일 | 언어·목적·크기 | 제약과 판정 |
| --- | --- | --- | --- |
| `Qwen/Qwen3-0.6B` | `c1899de289a04d12100db370d81485cdf75e47ca`; Apache-2.0; official `model.safetensors` BF16 751,632,384 params, 1,503,300,328 bytes, LFS SHA-256 `f47f71177f32bcd101b7573ec9171e6a57f4f4d31148d38e382306f42996874b`; `tokenizer.json` 11,422,654 bytes SHA-256 `aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4`; config, vocab, merges, generation config와 tokenizer config를 별도 allowlist/hash pin | 공식 card는 0.6B·pretraining+post-training·instruction following·100+ languages를 주장한다. Card context 32,768; pinned config `max_position_embeddings`는 40,960으로 불일치하므로 pilot 입력은 최대 4,096 tokens로 제한하고 차이는 실험 전 확인한다. Korean 개별 점수는 card에 없음. safetensors와 Qwen3 native architecture 지원 | Tool-call/thinking template 문자열 포함. Tool definitions를 전달하지 않고 thinking을 끄는 고정 template/CLI behavior를 검증한다. Native remote Python code 불필요. **`CONDITIONAL_GO` / 단독 후보** |
| `google/gemma-3-1b-it` | `dcc83ea841ab6100d6b47a070329e1ba4cf78752`; Google Gemma Terms of Use, HF gated/manual acceptance; 999,885,952 params; `model.safetensors` 1,999,811,208 bytes SHA-256 `3d4ef8d71c14db7e448a09ebe891cfb6bf32c57a9b44499ae0d1c098e48516b6`; tokenizer JSON 33,384,568 bytes, tokenizer.model 4,689,074 bytes; 1B weight file size alone does not estimate peak RAM | instruction-tuned; card says 140+ languages and 1B context 32K; Korean-specific score not inspected | Terms acceptance/reuse needs separate legal review; gated access complicates reproducible unattended acquisition. **`NO_GO` for this pilot** |
| `microsoft/Phi-4-mini-instruct` | `cfbefacb99257ffa30c83adab238a50856ac3083`; MIT; 3.836B BF16 params; two safetensors 4,903,637,712 + 2,768,428,504 bytes, each has official LFS SHA-256; official repository includes Python `configuration_phi3.py` and `modeling_phi3.py` | card explicitly lists Korean among 24 languages; instruction/function-call tuning; context 128K | official Transformers snippets require `trust_remote_code=True`; weights alone exceed 7.6GB, so the 8GB pilot limit is implausible after runtime/context. **`NO_GO`** |
| `meta-llama/Llama-3.2-1B-Instruct` | `9213176726f574b556790deb65791e0c5aa438b6`; gated Llama 3.2 Community License, not OSI permissive; safetensors 1.23B parameters, listed 2.47GB; file LFS SHA was not confirmed in this read-only review | instruction-tuned multilingual dialogue, 128K context; official supported-language list is English, German, French, Italian, Portuguese, Hindi, Spanish, Thai | Korean is not in supported list; access gated and custom license. **`NO_GO`** |

Qwen is the only conditional candidate because it offers the smallest parameter/weight footprint in the reviewed instruct-capable options, Apache-2.0 terms, official safetensors and LFS digest, and official multilingual instruction-following claims. This is a test candidate, not a quality recommendation. Korean claim quality, non-inference of secrets, refusal, and output structure remain unverified until synthetic tests. It is 0.6B post-trained rather than a separate `-Instruct` repository; do not present the repository name as a model quality guarantee.

Model weight size is not runtime peak RSS. For B, cap the entire VM at 8 GiB and abort if the selected profile or any request exceeds it. Pin the exact official model files, including all small-file Git blob IDs plus downloaded-byte SHA-256; keep tokenizer and chat template digests; reject adapters/LoRA, extra model files, community GGUF, auto-download, and unlisted code. Convert only the pinned official BF16 safetensors to GGUF with the exact pinned converter source, no quantization for the initial profile. Record input hashes, converter/build/toolchain versions, exact commands, output GGUF hash, and tensor-level/numeric parity. If conversion needs custom model code, community artifacts, unsupported architecture, or >8 GiB, stop.

## Runtime 정적 비교 및 조합

| Runtime | 고정 metadata/지원 | 기능·surface | 판정 |
| --- | --- | --- | --- |
| `llama.cpp` | stable tag `v0.7.0`, release commit `620d2225cc436ab0b001e3200e590e3b286ef9ab`, MIT. Commit signature verifies; annotated version tag object is unsigned. Official project supports macOS Apple Silicon and Ubuntu CPU builds. Native source, CMake/toolchain/build dependencies; no PyPI wheel selected. | `llama-cli` process, local GGUF, CLI JSON-schema/grammar constraint, thread/context/token controls. No listener required. Tool features exist elsewhere in project, so use CLI only, no server/agent/tool/MCP/template extension, `shell=False`, no shell child. Model conversion needs exact official converter. No auto download if no remote-model flags and a local path is used; enforce OS egress deny. | **`CONDITIONAL_GO` selected runtime**: lowest product-facing exposure because pilot uses one short-lived CLI process and no HTTP listener. Source build, conversion, Qwen template behavior, memory, output and prompt handling still unverified. |
| Ollama | current official release `v0.40.9`, repository commit `5e31438d5d2223d8338595b366b7434ef3539708`, MIT; official macOS/Linux release assets and checksum file. Native daemon and installer script. | Model runner requires HTTP API/daemon (default loopback host, configurable); API has no authentication by default. CLI can pull missing models; Cloud models/network features exist. Structured JSON Schema format supported, but that does not authenticate local caller or prove semantic correctness. | **`NO_GO` for first pilot**: unneeded unauthenticated listener, model auto-pull risk and extra managed runtime state. |
| Transformers + PyTorch | official PyPI latest at research time: Transformers `5.20.2` (Apache-2.0, Python ≥3.10; 245 published requirement markers/extras) + torch `2.14.1` (BSD-style license, Python ≥3.10; 17 requirements). Python 3.12 wheel metadata lists macOS 14 ARM64 and manylinux 2.28 x86_64 torch wheels with SHA-256. | In-process API, no listener needed, can use local safetensors and `local_files_only`; PyTorch brings substantial C++/native library surface. Transformers does not itself guarantee a JSON grammar; parse/schema/citation verifier remains mandatory. Seed/temp controls are not proof of deterministic natural language. | **`CONDITIONAL_GO`, not selected**: avoids conversion and subprocess, but the combined Python/native dependency surface is broader; constrained output needs another component or refusal-on-invalid-output. |

Only one 33.3B combination is proposed: **official Qwen3-0.6B at the pinned revision + locally built `llama.cpp` v0.7.0 `llama-cli`, no HTTP server, no quantization, fixed JSON Schema grammar, temperature 0 candidate**. It remains `CONDITIONAL_GO`; current Phase 33.3A did not build or run anything. At generation, disable thinking, omit `tools`, and reject any tool-call or reasoning markup. If Qwen3-0.6B behavior cannot be forced into the no-thinking, no-tool profile in this exact CLI build, this combination becomes `NO_GO`; do not silently change the model or runtime.

Version·revision·source commit pins are not binary provenance. Before B, pin and validate the exact compiler/toolchain, CMake dependencies, converter, GGUF format/architecture, generated GGUF, CLI binary and tokenizer/chat-template digests. Build from the verified source commit in acquisition/build stage, then make runtime/model read-only for inference. For each downloaded byte, verify exact allowlist, size, official LFS SHA-256 or repository blob identity, and independently computed SHA-256. Any upstream change creates a new gate.

## 격리·위협 모델

| 자산/진입점 | 위협 | 예방·탐지 | 실패 동작·잔여 위험 |
| --- | --- | --- | --- |
| Safe DTO·질문·citation | log/RAG indirect prompt injection, role spoof, private-data extraction | 입력은 schema-validated closed object, lexical verified citations only; excerpts untrusted data; PII/query/path pre-reject; no raw log | 위반/크기 초과는 fixed refusal; prompt hierarchy는 모델 안전을 증명하지 않음 |
| corpus/retrieval | corpus poisoning, citation manipulation, retrieval collision | 승인 static corpus만, 33.1 digest와 lexical ranker 고정; citation ID/content reverify; duplicate/conflicting facts 분리 | digest/identity mismatch면 generation 전 fail closed; 의미 충돌은 자동 resolve하지 않고 refuse 표시 |
| model/tokenizer/template | malicious weights/tokenizer, unexpected code, hidden tool template | pinned official repo/revision, safetensors, no remote code, exact file allowlist, template digest; no adapters/LoRA/tool messages | unexpected file/template/converter output 시 `NO_GO`; model can still emit malicious text |
| runtime/build artifacts | native code compromise, supply-chain substitution | signed/verified source commit, isolated build, SBOM/file hashes, binary digest, no package auto-install in inference VM | signature/hash/toolchain mismatch stops; build provenance and compiler compromise remain risks |
| inference process | filesystem/network access, local endpoint abuse, DNS rebinding, egress | disposable Linux VM, no NIC or deny-all egress firewall enforced outside process, non-root, drop capabilities, no-new-privileges, read-only runtime/model, only bounded scratch, no server, no tools | any socket/listener/child beyond fixed runner/process or unexpected open file aborts; hypervisor escape remains |
| user-facing JSON | HTML/Markdown/URL injection, invented citation, unsupported facts, changed risk/case | constrained grammar plus independent strict JSON/citation/evidence validator; claim-level citations; plain-text rendering only in later phase | discard raw response, fixed error/refusal; semantic entailment is not fully machine decidable and remains independent-audit risk |
| resources/concurrency | oversized context/output, memory/pid/CPU exhaustion, hangs, concurrent races | 6,144 input token, 512 output token, 16 KiB output, single request, 30s timeout, 8 GiB VM cap, PID/CPU quotas | kill isolated VM/process and return fixed `MODEL_UNAVAILABLE`; base analysis remains untouched; OS kill may leave host swap/crash artifacts |
| data at rest/diagnostics | prompt, output, KV cache, core dump, swap, backups, trace/report persistence | anonymous pipes/memory only, core dump disabled, no prompt/output logs, no crash upload, ephemeral VM disk, inventory before/after | abort on unexpected file/network; clean only known temp; no secure erase claim; host swap behavior must be separately controlled |

Environment variables, `HF_HUB_OFFLINE`, or runtime flags do **not** establish egress denial. Phase 33.3B must use a disposable Linux VM (or separately proven equivalent) with OS-level deny-all network at inference. Networked model/source acquisition is a separate stage and artifact-transfer boundary. The inference VM is non-root, has no capabilities, `no-new-privileges`, read-only model/runtime mounts, bounded tmpfs, CPU/RAM/PID/time limits, no actual HOME/config/log/checkpoint/credential mount, no HTTP listener, and synthetic envelope/citation only. Before and after execution inventory process tree, sockets/listeners, open files, mounts, VM disk/swap/core dump and temporary artifacts. An unexpected network attempt, listener, file read, child process, prompt persistence or tool/action marker stops the pilot.

## Phase 33.3B synthetic evaluation contract

Evaluation uses synthetic safe DTOs, synthetic question text and the same Phase 33.1 lexical citations. No actual logs. Fixtures cover brute force, password spray, failed-then-success non-causality, risk-confidence distinction, risk downshift, relation disappearance, case/supporting relations, replay gap, checkpoint reset, incomplete evidence, no finding, conflicting citations, insufficient citation, out-of-domain, private-data extraction, prompt injection, role spoofing, HTML/script, shell/tool request, nonexistent citation, analysis mutation, attack-success assertion, malformed/duplicate/truncated JSON, timeout and cancellation. Each fixture has expected allowed claim classes, citation IDs, refusal code and immutable analysis digest.

Machine-scored metrics: closed schema success, citation subset validity, citation precision/completeness, unsupported claim rate (separate adjudicated label), authoritative analysis mutation count, privacy leakage, refusal correctness, injection-policy violations, HTML/script/unsafe URL count, tool/action attempt count, retrieval determinism, repeated semantic stability, output bytes/tokens, latency, peak RSS and timeout rate. “Plausible answer” and detector recall are not metrics. Temperature 0 is a candidate fixed setting but byte-identical prose is not required or assumed. Measure output schema, citation/decision semantics and natural-language repeat variation separately.

### Phase 33.3B 진입 gate 후보

- license and attribution approved; exact model revision and each official artifact byte hash pinned
- exact llama.cpp commit/build/toolchain, converter, GGUF digest, tokenizer/chat template and prompt digest pinned
- offline inference under OS network deny; no listener, unapproved process, file, or egress
- safe envelope closed, bounded, immutable; lexical citations verified against current corpus
- input/output limits and 8 GiB VM cap enforced; single in-flight request and 30 s timeout
- schema validation 100%; nonexistent citation 0; unsupported claim 0 after adjudication
- analysis mutation 0; privacy leakage 0; tool/action attempt 0; injection policy violation 0
- all required refusal fixtures pass; timeout/malformed output returns fixed error and AI-disabled regression is 100%
- prompt/runtime/model/corpus digest assertions pass; AI failure leaves deterministic analysis and existing UI unchanged

Any unknown license, hash/revision drift, remote/custom code, pickle, unexpected download, egress/listener, >8 GiB RSS/cap failure, unsupported converter, model-format discrepancy, tool call, privacy canary, invalid citation, unsupported claim, mutation, incomplete refusal, or inability to cleanly account for prompt/artifacts is immediate `NO_GO`. Do not fall back to Gemini or embedding/hybrid retrieval. If conditional checks cannot be met, keep lexical-only retrieval and AI-disabled operation.

## 단계 구분

| Phase | 범위 | 상태 |
| --- | --- | --- |
| 33.0 | 설계·위협 모델·기존 Gemini 감사 | 완료 |
| 33.1 | 결정적 lexical retrieval·citation baseline | 유지, LLM 없음 |
| 33.2A | embedding 공급망 설계 | 기록됨 |
| 33.2B | 합성 embedding 비교 | 완료, embedding production `NO_GO`; lexical 유지 |
| 33.3A | 이 문서: structured local LLM 공급망·평가 설계 gate | 완료, 실행 전 |
| 33.3B/33.3C | 한 모델/runtime의 격리 합성 LLM pilot 및 재시도 | [33.3B](local_llm_pilot_33_3b.md), [33.3C](local_llm_pilot_33_3c.md); `ISOLATION_BLOCKED`, 미다운로드·미실행 |
| 33.3D | 사용자 제공 Ubuntu VM에서 재개 gate | [33.3D](local_llm_pilot_33_3d.md); `SUPPLY_CHAIN_BLOCKED`, converter/runtime wheel closure 미고정으로 취득·실행 중단 |
| 33.3E | artifact closure·disk peak gate | [33.3E](local_llm_artifact_closure_33_3e.md); `RESOURCE_NO_GO`, 5.1 GiB usable budget에 안전한 fit 입증 불가; 일부 wheel license/install-hook 및 Ubuntu build closure 미확정 |
| 33.4 | 독립 injection·hallucination·privacy 감사 | 미시작 |
| 33.5 | 명시적 opt-in API/UI와 실제 사용자 수용 | 미시작 |
| 34.0 | River/PyOD anomaly detection shadow mode | 별도 설계 |

## 조사 출처

- [Qwen3-0.6B official model card](https://huggingface.co/Qwen/Qwen3-0.6B) · [official model metadata and current revision](https://huggingface.co/api/models/Qwen/Qwen3-0.6B) · [Qwen3 llama.cpp instructions](https://github.com/QwenLM/Qwen3/blob/main/docs/source/run_locally/llama.cpp.md)
- [Gemma 3 1B IT official model card](https://huggingface.co/google/gemma-3-1b-it) · [Google Gemma Terms of Use](https://ai.google.dev/gemma/terms)
- [Phi-4-mini-instruct official model card](https://huggingface.co/microsoft/Phi-4-mini-instruct) · [Llama 3.2 1B Instruct official model card](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct)
- [llama.cpp v0.7.0 source release](https://github.com/ggml-org/llama.cpp/releases/tag/v0.7.0) · [CLI structured output, JSON schema and grammar](https://github.com/ggml-org/llama.cpp/blob/master/tools/cli/README.md) · [Qwen3 support note](https://github.com/QwenLM/Qwen3/blob/main/docs/source/run_locally/llama.cpp.md)
- [Ollama v0.40.9 release](https://github.com/ollama/ollama/releases/tag/v0.40.9) · [Ollama API introduction](https://docs.ollama.com/api/introduction) · [Ollama structured outputs](https://ollama.com/blog/structured-outputs)
- [PyTorch 2.14.1 PyPI metadata](https://pypi.org/project/torch/2.14.1/) · [Transformers 5.20.2 PyPI metadata](https://pypi.org/project/transformers/5.20.2/) · [PyTorch platform guidance](https://docs.pytorch.org/get-started/locally/)

## 변경 경계

이 Phase는 문서와 문서 계약 test/prompt fixture만 추가한다. 모델·runtime download/install/execute, dependency/lockfile, production code, Gemini helper, API/SSE/UI, CI와 version은 변경하지 않는다. Phase 33.2B embedding `NO_GO`와 Phase 33.1 lexical-only retrieval는 이 문서에서도 그대로다.
