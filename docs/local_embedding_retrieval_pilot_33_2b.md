# Phase 33.2B — isolated multilingual E5 retrieval pilot

**상태: 합성 자료로 격리 retrieval 비교 완료. Production 통합은 `NO_GO`다.** 이 기록은 실제 사용자 로그나 config를 사용하지 않았다. LLM 설명을 생성하지 않았고 Gemini 경로, production 분석, API/SSE/UI, project dependency와 `uv.lock`을 변경하지 않았다. 모델·wheel·cache는 검증한 `/private/tmp/phase-33-2b` 아래에만 두었고 inventory 확인 후 정리했다. Secure erase는 주장하지 않는다. 이 실험은 운영 SLA나 탐지 성능 평가가 아니다.

## Phase 33.2A gate와 고정 기준선

Phase 33.2A의 E5-small 후보는 조건부였다. 이번 실행은 revision, MIT 표시, 정확한 allowlist, 크기와 SHA-256을 검증한 뒤 계속했다. pinned revision은 `614241f622f53c4eeff9890bdc4f31cfecc418b3`이고 model repository는 `intfloat/multilingual-e5-small`이다. 다섯 파일은 총 487,725,595 bytes다. 모델 외 파일을 자동 다운로드하지 않았다.

| 파일 | Bytes | SHA-256 |
| --- | ---: | --- |
| `model.safetensors` | 470,641,600 | `1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477` |
| `config.json` | 655 | `69137736cab8b8903a07fe8afaafdda25aac55415a12a55d1bffa9f581abf959` |
| `tokenizer.json` | 17,082,730 | `0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39` |
| `tokenizer_config.json` | 443 | `a1d6bc8734a6f635dc158508bef000f8e2e5a759c7d92f984b2c86e5ff53425b` |
| `special_tokens_map.json` | 167 | `d05497f1da52c5e09554c0cd874037a083e1dc1b9cfd48034d1c717f1afc07a7` |

세 작은 JSON 파일의 Git blob SHA-1도 Phase 33.2A pin과 모두 일치했다. test-only manifest는 [모델 pin fixture](../tests/fixtures/multilingual_e5_small_33_2b_manifest.json)에 있다. `trust_remote_code=False`, `use_safetensors=True`, local path, `local_files_only=True`를 강제했다. `.bin`, `.pt`, `modules.json`, SentenceTransformers 설정과 모델 저장소의 나머지 파일은 거부한다.

Phase 33.1 lexical 기준은 바꾸지 않았다. 기준 corpus는 18 section, digest `fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6`이다. Tokenizer contract digest는 `fe698fbf34c16eee5c41f906c3633753682c34db2544e8a3fc77cd8f47069dcd`, stopword digest는 `91d498b9f40152dba3767371296a93f2fee682eb6bfc8742fd41859e6bf45115`다. Tokenizer digest는 tokenize 함수 source, token regex, stopword digest, Unicode database version `15.0.0`, NFKC/casefold와 Hangul bigram 정책을 UTF-8 canonical JSON(sorted keys, compact separators)으로 인코딩한 SHA-256이다. BM25는 `k1=1.2`, `b=0.75`, threshold `2.2`, top-k 5다. 기존 17개 합성 fixture는 expected citation 11/11, precision 0.941, completeness 1.0, 잘못된 citation 0, privacy leak 0, schema 100%였다. 알려진 과잉 인용은 `failed success relation causation` 질문에 `relation-gone` 문서가 함께 나온 한 건이다. lexicon·ranker를 이 모델 결과에 맞춰 조정하지 않았다.

## Runtime 공급망과 임시 격리

실행은 Apple Silicon macOS에서 Python 3.12.7로 했다. direct runtime은 PyTorch 2.14.1, Transformers 5.20.2이며, 복사한 33.1 citation verifier 실행을 위해 Pydantic 2.13.5를 같은 임시 venv에 넣었다. Sentence-Transformers는 설치하지 않았다. `pip download --require-hashes --only-binary=:all:`로 38개 wheel을 받고, PyPI hash로 확인한 뒤 `--no-index --find-links --require-hashes`로만 설치했다. wheelhouse 총량은 169,489,300 bytes이고 정확한 파일·크기·SHA-256 목록은 [runtime wheel manifest](../tests/fixtures/local_embedding_runtime_33_2b_manifest.json)에 있다. 생성한 temporary lock digest는 `7b59917cd43816618271752bc32f4aacfbbfa8b6fb58fa972096948a382f7388`다. 프로젝트 `uv.lock`에는 손대지 않았다.

주요 wheel 확인값은 PyPI metadata와 일치한다. torch macOS ARM64 wheel은 127,307,099 bytes, SHA-256 `420dbf314c180ee4b86e9bc00aee5746a7d6e5bacdd7df925af671ed393f0b2e`이고 Transformers universal wheel은 12,844,921 bytes, SHA-256 `7ae75dbc1fb3922aff1b6c97b9e5479d6cf26fd86a8866bfb71324190479f807`이다. PyPI는 torch wheel에 build provenance attestation을 제공하지 않았다. 이 SHA 검증은 파일 무결성을 pin할 뿐 빌드 출처나 악성 여부를 증명하지 않는다. [PyTorch 2.14.1 PyPI metadata](https://pypi.org/project/torch/2.14.1/) · [Transformers 5.20.2 PyPI metadata](https://pypi.org/project/transformers/5.20.2/).

Runtime venv, wheelhouse, model, cache, `HOME`, `HF_HOME`, corpus와 source 복사본은 모두 전용 임시 경로 아래에 있었다. model 파일은 read-only mode였고 model directory의 파일 집합은 위 5개와 정확히 일치했다. source 복사본에는 `local_retrieval_33_1.py`, 승인 corpus 2개, test-only harness와 합성 fixture만 있었다. 실제 monitor config, 원본 로그, checkpoint, credential, 사용자 HOME 자료는 staging에 넣지 않았다. fixture에는 합성 거부 canary만 있다.

실행은 network-restricted tool sandbox 안에서 했고 Python socket audit guard도 적용했다. `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, local-only model load를 강제했다. 실행 중 socket connect/bind 시도는 관측되지 않았고 process child나 listener도 만들지 않았다. 이는 별도의 packet capture나 dedicated VM 검증은 아니다. Docker daemon은 사용할 수 없었고 macOS `sandbox-exec` 호출도 상위 sandbox에서 허용되지 않았다. Tool sandbox는 repository read 권한이 별도 OS 계정/VM보다 넓을 수 있으므로 악성 native runtime 전체를 격리했다는 증거로 과장하지 않는다.

PyTorch CPU thread는 intra/inter-op 각각 1, query batch 1, passage batch 8, 최대 512 token, CPU 시간 상한 600초로 제한했다. macOS는 이미 점유된 virtual address space 때문에 4 GiB `RLIMIT_AS` 상한을 적용하지 못했다. 따라서 peak RSS는 측정값이지 hard memory cap이 아니다. 이 resource gate는 **PARTIAL**이다. 한 번의 초기 실행은 resource-limit 설정에서 모델 load 전에 거부되어 재현·수정했고, 이후 유효 실행 세 번은 통과했다.

## Retrieval·citation 계약

동일한 safe evidence DTO와 질문 category/refusal 검사를 모든 방법에 적용했다. 실제 허용 query와 corpus는 전부 합성·승인 자료다. E5는 `query: ` / `passage: ` prefix, fast tokenizer, 512-token truncation, attention-mask mean pooling, L2 normalization, CPU deterministic mode를 썼다. embedding vector는 process memory에만 있었고 API·DB·checkpoint·log·report로 저장하지 않았다. 18 section vector matrix는 27,648 bytes였다.

Cosine threshold는 평가 query와 문구가 겹치지 않도록 분리한 4개 합성 calibration 질문으로 결정했고 그 실행값은 `0.862624`였다. 점수는 6자리로 고정한 뒤 내림차순, 동점은 document ID·section ID 오름차순이다. Hybrid는 고정 RRF `1/(60+rank)`와 constant 60을 썼다. 세 방법은 동일한 승인 corpus, top-k 5, 31개 evaluation fixture 및 citation identity/content verifier를 썼다. Phase 33.1 `validate_result`는 BM25 점수 threshold·순서에 결합되어 있어 embedding cosine을 그 BM25 score로 위장하지 않았다. test-only candidate verifier가 같은 corpus ID, approved section, exact title/source/excerpt/digest, duplicate, top-k, finite score 조건을 검증했다.

31개는 기존 Phase 33.1의 17개 fixture와 한국어/영어/혼합 표현, password spray 구분, risk/confidence, 관계 소멸, replay/checkpoint, no finding, 개인정보, injection, 위조 citation, oversized/out-of-domain 질문 등 14개 합성 추가 사례다. 정답 관련 문서 집합은 fixture에 고정했다.

### 결과

| 방법 | 기존 17개 expected hit | 31개 expected hit | 31개 precision | completeness | MRR / nDCG@5 | non-gold citation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| lexical only | 11/11 | 18/19 eligible | 0.727 | 0.960 | 0.947 / 0.947 | 9 |
| embedding only | 10/11 | 15/19 eligible | 1.000 | 0.680 | 0.789 / 0.721 | 0 |
| hybrid RRF | 11/11 | 18/19 eligible | 0.727 | 0.960 | 0.947 / 0.947 | 9 |

31개 전체에서 각 방법은 거부 fixture 12/12를 올바르게 거부했고, citation invalid 0, schema validation 100%, privacy leak 0, 권위 있는 분석 mutation 0, injection execution 0이었다. 같은 macOS ARM64 host에서 repeat 및 UTC·Asia/Seoul 결과는 byte-identical이었다. 모델 similarity가 근거의 의미적 지지를 증명하지 않으며 평가 gold set의 관련성도 사람 검토를 대체하지 않는다.

이 결과는 embedding-only가 precision을 높이는 대신 citation completeness를 크게 낮췄음을 보인다. Hybrid는 lexical과 같은 결과여서 작은 corpus에서 lexical baseline의 효과를 넘지 못했다. 따라서 **모델 retrieval을 제품에 연결하지 않고 Phase 33.1 lexical을 기준선으로 유지한다.** 이를 탐지율이나 설명 답변 품질로 해석하지 않는다.

## 실행 측정과 자원

세 번의 성공 실행에서 model load 표본은 3회였다(첫 cold load 포함). passage encoding도 각 실행 1회였다. Query/model/rank latency는 두 최종 실행 각각 19개 eligible query 표본이며, citation construction은 실행별 방법마다 57 표본이다. corpus load와 lexical index build는 최종 실행 1표본이라 분포 추정치로 보지 않는다.

| Operation | 표본 | Median | p95 | Max |
| --- | ---: | ---: | ---: | ---: |
| model load (cold 포함, 세 실행 합산) | 3 | 22,934.6 ms | 42,872.6 ms | 42,872.6 ms |
| 18 passage embedding (세 실행 합산) | 3 | 901.3 ms | 917.1 ms | 917.1 ms |
| model query + rank (두 실행; 실행별 p95를 합산하지 않음) | 19 × 2 | 실행 median 32.5–34.5 ms | 실행 p95 37.4–41.7 ms | 최대 41.7 ms |
| citation construction, lexical (두 실행) | 57 × 2 | 실행 median 0.038–0.039 ms | 실행 p95 0.060 ms | 최대 0.073 ms |
| citation construction, embedding (두 실행) | 57 × 2 | 실행 median 0.020 ms | 실행 p95 0.037 ms | 최대 0.055 ms |
| citation construction, hybrid (두 실행) | 57 × 2 | 실행 median 0.026 ms | 실행 p95 0.045 ms | 최대 0.053 ms |
| corpus load/verify (최종 실행) | 1 | 7.744 ms | 단일 표본 | 7.744 ms |
| lexical index build (최종 실행) | 1 | 3.158 ms | 단일 표본 | 3.158 ms |

세 실행의 peak RSS는 약 1.12 GB 범위였다(1,119,797,248–1,126,154,240 bytes). 단일 개발 Mac과 작은 합성 corpus에서 나온 표본이다. 운영 SLA, 최악 지연 또는 다른 hardware 성능을 보장하지 않는다.

## 재현 절차

1. 별도의 임시 디렉터리와 `HOME`을 만들고 위의 정확한 Hugging Face revision에서 다섯 allowlist 파일만 다운로드한다. manifest의 size·SHA-256이 모두 맞지 않으면 중단한다.
2. runtime wheel hash manifest에서 temporary hash-only requirements를 만든다.

   ```bash
   PYTHONPATH=tests:. uv run python tests/prepare_local_embedding_pilot_33_2b.py \
     --mode pins \
     --manifest tests/fixtures/local_embedding_runtime_33_2b_manifest.json \
     --wheelhouse /private/tmp/phase-33-2b/wheelhouse \
     --output /private/tmp/phase-33-2b/runtime.pins.txt
   ```

3. Python 3.12 native macOS ARM64에서 네트워크 허용 staging 단계로 `pip download --require-hashes --only-binary=:all: --dest <temp-wheelhouse> --requirement <runtime.pins.txt>`를 실행한다. 이후 다음 명령이 정확한 파일 집합과 hash를 검사해야 한다.

   ```bash
   PYTHONPATH=tests:. uv run python tests/prepare_local_embedding_pilot_33_2b.py \
     --mode verify \
     --manifest tests/fixtures/local_embedding_runtime_33_2b_manifest.json \
     --wheelhouse /private/tmp/phase-33-2b/wheelhouse
   ```

4. 별도 임시 venv에 `uv pip sync --python <temp-venv>/bin/python --no-index --find-links <temp-wheelhouse> --require-hashes <runtime.pins.txt>`로 설치하고, 위와 같이 corpus/source/fixture만 임시 staging에 복사한다.
5. `HOME`, `HF_HOME`, `XDG_CACHE_HOME`은 임시 HOME으로, `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, `TOKENIZERS_PARALLELISM=false`, `PYTHONNOUSERSITE=1`을 설정하고 [runner](../tests/run_local_embedding_pilot_33_2b.py)를 실행한다. 보고서에는 query, excerpt, embedding vector나 절대 경로를 저장하지 않는다.
6. 끝난 뒤 temp process/cache/file inventory를 확인한다. 생성 사실이 확인된 이 pilot 임시 자료만 정리한다. secure erase는 주장하지 않는다.

이는 개발자가 재실행할 수 있는 test-only 비교다. CI 성능 gate가 아니며 모델 artifact나 wheel을 저장소에 포함하지 않는다.

## 상태와 다음 단계

| Gate | 결과 | 근거/제한 |
| --- | --- | --- |
| exact model files/revision/license | PASS | 5개 파일 hash·크기 고정, MIT 표기, `safetensors`만 사용 |
| exact native Mac runtime wheel set | PASS | 38 wheel hash·size 검증, offline hash-only 설치 확인 |
| runtime build provenance | PARTIAL | PyTorch 공식 PyPI artifact에 provenance attestation 없음 |
| offline/local loading | PASS | local path, `local_files_only`, no remote code, run에서 socket 시도 0 |
| network isolation | PASS WITH LIMIT | tool sandbox와 Python audit guard; packet capture 또는 독립 VM 증거 없음 |
| filesystem isolation | PARTIAL | 실제 HOME/cache/log/config 미복사; tool sandbox의 workspace read 권한은 전용 OS 계정보다 넓음 |
| hard memory limit | PARTIAL | macOS `RLIMIT_AS` 불가; peak RSS만 계측 |
| retrieval/citation/privacy/determinism | PASS | 합성 평가와 닫힌 verifier |
| production adoption | **NO_GO** | hybrid가 lexical을 개선하지 않고 hard memory/process isolation 조건이 완전하지 않음 |

### Roadmap

- **33.0:** 설계·위협 모델·현재 Gemini 감사.
- **33.1:** 결정적 lexical retrieval/citation baseline. 유지한다.
- **33.2A:** 정적 model/runtime 공급망 gate 설계.
- **33.2B:** 이번 합성 전용 embedding 비교. 제품에 연결하지 않는다.
- **33.3A:** [구조화 local LLM 설계 gate](local_llm_supply_chain_gate_33_3a.md); lexical citation만 허용하고 모델/runtime 실행은 없다.
- **33.3B:** 추가 gate 통과 때만 합성 DTO·lexical citation의 단일 local LLM pilot. Embedding, vector index, hybrid는 계속 금지다.
- **33.4:** injection/hallucination/privacy 독립 감사.
- **33.5:** UI opt-in·사용자 수용.
- **34.0:** River/PyOD anomaly detection shadow-mode 설계.

## 변경 경계

변경 파일은 test-only harness, 합성 fixture/runtime hash manifest, 문서와 문서 계약 테스트다. Production detector/correlation/risk/case, Gemini, dependencies, project lockfile, API/SSE/UI, CI와 version은 변경하지 않았다. Phase 33.2A에서 기록한 corpus digest/tokenizer/BM25 수치와 과잉 인용 한계를 그대로 보존했다.
