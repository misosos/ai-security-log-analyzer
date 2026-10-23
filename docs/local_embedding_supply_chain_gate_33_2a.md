# Phase 33.2A — 로컬 embedding 공급망·평가 설계 gate

**상태:** Phase 33.2A 정적 설계 gate 기록. 당시에는 모델 weight·tokenizer·runtime wheel을 받거나 실행하지 않았다. 후속 Phase 33.2B 합성 pilot은 별도 [검증 기록](local_embedding_retrieval_pilot_33_2b.md)에 있다. 이 문서의 이후 시제 표현은 Phase 33.2A 당시의 상태를 뜻한다.

조사일은 2026-10-23이다. Hugging Face `main` revision은 이 날짜에 API metadata로 조회한 뒤 문서의 40자리 commit으로 고정했다. `main`은 조사 시점의 head를 찾는 용도로만 썼으며 실행 시 branch 참조로 사용하지 않는다. 저장소가 이후 바뀌면 이 기록은 새 상태를 뜻하지 않는다.

## Phase 33.1 기준선 고정

Phase 33.1 구현과 기준선은 그대로 유지한다. 검색 결과는 자연어 답변이 아닌 승인된 section의 citation 후보이며 기존 lexical 결과가 비교 기준이다.

| 기준 | 고정값 |
| --- | --- |
| corpus | 18개 section, 14,833 bytes |
| corpus digest | `fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6` |
| tokenizer | NFKC + casefold, Unicode letter/number run, 한글 원 token과 `ko2:` bigram |
| stopword digest | `91d498b9f40152dba3767371296a93f2fee682eb6bfc8742fd41859e6bf45115` |
| BM25 | `k1=1.2`, `b=0.75`, threshold `2.2`, top-k 최대 5 |
| 합성 retrieval | 17개 fixture, expected citation hit 11/11 |
| citation 품질 | precision `0.941` (17개 중 관련 16개), completeness `1.0` |
| 안전 계약 | 잘못된 citation 0, privacy leak 0, schema validation 100% |
| 결정성 | UTC·Asia/Seoul 및 반복 실행 결과 JSON byte 동일 |
| 한계 | 과잉 인용 1건 |

과잉 인용 사례는 개인정보 없는 `failed success relation causation` 질문이다. 기대 문서는 `failed-success`이고 실제 결과에는 `failed-success`와 `relation-gone`이 들어왔다. `relation-gone` 문서는 관계가 사라진 사실을 해결로 해석할 수 없다는 일반 한계를 다룬다. 이 문서도 관계 lifecycle 개념으로는 가까우나 해당 fixture의 실패 뒤 성공 관계 질문에 기대된 근거는 아니므로 precision 계산에서는 과잉 인용이다. Phase 33.2 비교는 이 known lexical error를 같은 fixture와 같은 citation verifier로 측정한다. 이 기준선을 맞추려고 production lexical ranking을 바꾸지 않는다.

## 정적 모델 후보 비교

공식 Hugging Face API의 pinned revision/tree metadata와 model card를 조사했다. 공개 metadata의 size와 digest는 조사 시점 기준이며 파일을 검증했다고 뜻하지 않는다. 모든 후보는 33.2B에서 다시 조회해 pinned revision이 유지되고 파일별 hash가 일치하는지 검사해야 한다.

| 후보 | Revision / license | 규모·목적 | 파일·무결성·실행 조건 | 판정 |
| --- | --- | --- | --- | --- |
| `intfloat/multilingual-e5-small` | `614241f622f53c4eeff9890bdc4f31cfecc418b3`; MIT | 약 0.1B parameter, 384-d, 최대 512 token, multilingual asymmetric retrieval. query는 `query: `, section은 `passage: ` prefix; attention-mask mean pooling 후 L2 normalization | 43개 파일, 전체 약 2.28 GB. safetensors 470,641,600 bytes, LFS SHA-256 `1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477`. Python custom model/tokenizer 코드 없음. 같은 revision에 pickle `.bin` 대안도 있으나 allowlist에서 거부해야 함. | **CONDITIONAL_GO** — 33.2B 비교 후보 하나. 아래 해시·runtime·격리 gate 완료 전에는 실행하지 않음 |
| `intfloat/multilingual-e5-base` | `d128750597153bb5987e10b1c3493a34e5a4502a`; MIT | 약 0.3B parameter, 768-d, 최대 512 token. E5 query/passage prefix·mean pooling·normalization 계약 | 23개 파일, 전체 약 5.32 GB. safetensors 1,112,201,288 bytes, SHA-256 `a18a44fad1d0b46ded15928144138cff1135d5cc8233bdd90be5f18822de09a7`. pickle `.bin`도 있어 명시 allowlist 필수. | **NO_GO** 첫 pilot — small보다 2배 이상 큰 차원/weight이며 18-section corpus에서 품질 이득을 뒷받침하는 프로젝트 평가가 없음 |
| `BAAI/bge-m3` | `5617a9f61b028005a4858fdac845db406aefb181`; MIT | 약 0.57B parameter (공식 `config.json`의 24 layers·1,024 hidden·250,002 vocab에서 구조상 추정; model card는 이 수를 직접 선언하지 않음), 1,024-d, 최대 8,192 token, 100개 이상 언어를 model card가 주장. dense·sparse·multi-vector 기능. query prefix 불필요 | 30개 파일, 전체 약 4.59 GB. pinned main tree에 `model.safetensors`가 없고 2,271,145,830-byte `pytorch_model.bin`, `.pt` 파일들이 있음. 공식 ONNX 파일도 있지만 allowlist는 safetensors 출발만 허용. | **NO_GO** — safetensors 요구 위반. 더 큰 multi-vector 기능은 corpus에 과함 |
| `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` | `e8f8c211226b894fcb81acc59f3b34ba3efd5f42`; Apache-2.0 | 약 0.1B parameter (model page의 rounded model size), 384-d, 최대 128 token, 50개 이상 언어. sentence similarity/paraphrase 목적, mean pooling; E5처럼 query/passage retrieval prefix 계약 없음 | 28개 파일, 전체 약 4.62 GB. safetensors 470,641,600 bytes, SHA-256 `eaa086f0ffee582aeb45b36e34cdd1fe2d6de2bef61f8a559a1bbc9bd955917b`. 추가 `.bin`, `.pt`/TensorFlow·ONNX 아티팩트는 모두 거부. custom Python 코드 없음. | **NO_GO** 첫 retrieval pilot — 용도와 128-token 한계가 E5보다 불리하고 같은 크기 범위; E5보다 유리한 결과가 입증되지 않음 |

model card의 언어 범위와 benchmark 주장은 공급자 설명이지 이 앱의 보안 문서 검색 성능 증거가 아니다. 특히 low-resource language 성능 저하, 보안 어휘의 의미 차이, 좁은 18-section corpus에 대한 embedding 적합도는 합성 평가에서 따로 측정한다. BGE-M3는 현재 main tree만 검사했다. PR branch, community 재배포본, 다른 repository의 변환 모델로 대체하지 않는다.

공급자 card의 학습 provenance 요약은 다음과 같다. E5-small은 Microsoft Multilingual-MiniLM-L12-H384 초기화 후 multilingual weakly-supervised contrastive 학습과 supervised pair fine-tuning을 설명하며 mC4, CC News, NLLB, Wikipedia, Reddit, S2ORC, StackExchange, xP3 등 데이터 출처를 열거한다. E5-base는 XLM-RoBERTa base 초기화와 같은 다국어 학습 설명을 쓴다. BGE-M3는 bge-m3-unsupervised 기반의 multilingual dense/sparse/ColBERT 통합 fine-tuning이라고 설명한다. MiniLM v2는 영어 paraphrase MiniLM teacher와 multilingual MiniLM student의 증류 계열로 설명된다. 조사한 repository head commit subject는 각각 E5-small/base evaluation metadata 추가, BGE-M3 MIRACL 평가 결과 갱신, MiniLM의 Transformers v5용 tokenizer class 설정이다. 따라서 조회된 최신 head가 weight 학습 revision을 뜻한다고 보지 않고, pinned tree의 실제 model file size/hash를 별도로 고정한다. 이 설명은 dataset snapshot·권리·수집 pipeline·학습 weight를 재현하거나 독립 검증하지 않는다. 선택 후보의 provenance 출처는 [pinned E5-small model card/README](https://huggingface.co/intfloat/multilingual-e5-small/tree/614241f622f53c4eeff9890bdc4f31cfecc418b3)와 [Multilingual E5 technical report](https://arxiv.org/abs/2402.05672)다.

### 33.2B의 E5-small 파일 allowlist 초안

정확한 repository와 revision 아래 이 다섯 파일만 가져오는 방안을 조건부로 선정했다. `model.safetensors` 외에는 model repository의 어떤 weight, image, evaluation file, Python 파일, `.bin`, `.pt`, `.h5`, ONNX 또는 OpenVINO 파일도 허용하지 않는다. direct `AutoModel` + fast tokenizer를 사용하고 SentenceTransformer metadata에 의존하지 않는 설계 후보라 `modules.json`과 `1_Pooling/config.json`은 제외한다.

| 정확한 경로 | 기대 bytes | 공식 metadata digest |
| --- | ---: | --- |
| `model.safetensors` | 470,641,600 | SHA-256 `1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477` |
| `config.json` | 655 | Git blob `60a2a84020f1d74cc53ea9e8c4e91cf4af6c2b68` (SHA-1; SHA-256은 공식 API에서 확인되지 않아 33.2B 취득 단계에서 계산·별도 승인 pin 필요) |
| `tokenizer.json` | 17,082,730 | SHA-256 `0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39` |
| `tokenizer_config.json` | 443 | Git blob `059214673d9d6d2ee319411e2ffec8c024b816d5` (SHA-1; 33.2B에서 SHA-256 pin 필요) |
| `special_tokens_map.json` | 167 | Git blob `e0b1d18ecd0ae4ff1d47bd297d910c0cf83e504b` (SHA-1; 33.2B에서 SHA-256 pin 필요) |

allowlist 예상 합계는 487,725,595 bytes다. API metadata가 LFS SHA-256을 제공한 큰 파일은 위에 기록했다. 작은 git 파일의 SHA-256을 알아내기 위해 이 단계에서 tokenizer/config 파일을 받아오지 않았다. 고정 commit의 Git blob ID는 파일 식별 값이지만 SHA-256 요구를 대신 충족한다고 간주하지 않는다. 33.2B는 이 작은 파일들의 SHA-256을 고정 revision에서 내려받은 bytes로 계산하고, 같은 pinned git blob ID와 크기까지 검증한 뒤 manifest를 검토·고정해야 한다. 값이 고정되지 않으면 실행을 중단한다.

모델 저장소의 Git history는 원본 제공자 `intfloat`의 upstream E5 설명·기술 보고서와 기존 config/tokenizer/weight 파일 이력을 따른다. 다만 모델 weight의 전체 학습 data provenance가 파일 hash만으로 증명되는 것은 아니다. model card와 arXiv 기술 보고서의 training 설명을 provenance 설명으로 보되, 재현 가능한 학습 이력 또는 독립적인 weight attestation으로 확대 해석하지 않는다.

## Runtime 후보 비교

모델 아티팩트와 실행 runtime은 별도로 평가한다. 정적 PyPI metadata 조사일은 2026-10-23이며 여기 적힌 최신 안정 버전은 Phase 33.2B의 최종 고정 버전이 아니다.

| Runtime | 현재 안정 버전·플랫폼 | 설치·공급망 표면 | offline·자원 통제 | 판정 |
| --- | --- | --- | --- | --- |
| PyTorch + Transformers (SentenceTransformers 없이 direct API) | PyTorch `2.14.1`, Transformers `5.20.2`; Python 3.12 macOS ARM64·Linux x86_64 wheel 존재. PyTorch BSD-3-Clause, Transformers Apache-2.0 | PyPI의 macOS arm64 torch wheel 127,307,099 bytes, SHA-256 `420dbf314c180ee4b86e9bc00aee5746a7d6e5bacdd7df925af671ed393f0b2e`; Linux x86_64 wheel 554,618,695 bytes, SHA-256 `23011fe29a99b591eabb3a31a25080c62e2c2f0690a3c798744e5489dae50451`. Transformers universal wheel 12,844,921 bytes, SHA-256 `7ae75dbc1fb3922aff1b6c97b9e5479d6cf26fd86a8866bfb71324190479f807`. Transformers의 기본 요구는 9개 package이며 `tokenizers` native extension 포함. PyTorch PyPI metadata는 17개의 직접 requirement를 열거하고 Linux에 CUDA/toolkit, cuDNN, NCCL, Triton 계열 marker 요구가 나타난다. 네이티브 대형 wheel과 BLAS/OpenMP 등 전이 표면이 크다. PyPI 이 파일들의 provenance attestation은 발견되지 않았다. 설치는 package installer로만 하며 source `setup.py`/임의 설치 script는 실행하지 않는다. | `HF_HUB_OFFLINE=1`, `local_files_only=True`, commit 고정 로컬 경로, `use_safetensors=True`, `trust_remote_code=False`; 전용 `HF_HOME`을 기본 HOME 밖에 두고 model을 별도 로컬 디렉터리에서 읽는다. tokenizer parallelism off, CPU threads 1, batch 1/8, sequence ≤512 계획. 별도 OS network deny 검증. | **CONDITIONAL_GO** — safetensors 직접 읽기 가장 단순하지만 설치·native/resource 표면이 큼. pinned CPU-only Linux dependency closure와 각 wheel hash 검토 전 cross-platform 실행 금지 |
| ONNX Runtime CPU | `onnxruntime 1.31.0`; Python 3.12 macOS ARM64·Linux x86_64 wheel 제공, MIT | macOS wheel 20,882,054 bytes / SHA-256 `aaab9b3af536b06ca27ab5e35e3d429c97457ce76cf298af103f687e8b9975c0`; Linux x86_64 wheel 23,760,984 bytes / SHA-256 `5e129d6c56abd53e659cb70f00a108d6824086470ff99c2e47a82e5786563db3`. PyPI metadata상 직접 runtime 요구는 flatbuffers, numpy, packaging, protobuf이며 native wheel 포함. 이 버전 파일의 PyPI provenance attestation은 없음. | CPU provider 명시, intra/inter-op thread 제한, 로컬 세션, OS network deny가 가능하다. E5 safetensors를 ONNX로 내보내는 별도 converter와 변환 artifact/hash 필요. 변환 stack 공급망이 추가된다. | **NOT_VERIFIED** — runtime은 작지만 safetensors → ONNX 변환기·변환 품질·고정 hash를 이 조사에서 검증하지 않았음 |
| Sentence-Transformers | `6.2.0`; Python 3.12 지원, 순수 Python wheel | direct required metadata에 Transformers, tokenizers, Hugging Face Hub, torch, numpy, scikit-learn, scipy, typing_extensions, tqdm가 포함된다. pip wheel 게시 provenance 확인 불가. 편의 loader가 cache/network behavior를 더 숨길 수 있어 direct API보다 넓음. | Offline과 자원 제어는 아래 Transformers·PyTorch 경계에 종속. 단일 `SentenceTransformer(...)`로 자동 로드하지 말고 매개변수를 명시할 필요가 큼. | **NO_GO** — 첫 pilot에는 불필요한 추상화와 dependency surface |
| llama.cpp embedding mode | release `v0.7.0` (2026-10-15); 조사 시 `master` `f5027fb21307eb264aed483242603d68c87b0fe3`; C/C++ native build | Python wheel이 아니라 CMake/native source build. source compiler/toolchain, BLAS/Metal 선택, converter/quantizer와 generated GGUF 공급망을 별도로 고정해야 한다. 공식 문서는 GGUF 입력 및 embedding endpoint/CLI를 지원하고 모델 변환·정확도 대조를 요구함. | local file + `--host 127.0.0.1`, no-network 실행 가능. 단, server를 쓰지 않아도 native binary와 변환된 GGUF를 검증해야 함. 실행 파일/native parser의 공격면이 커짐. | **NO_GO** 첫 pilot — 현재 safetensors 직접 로딩과 거리가 있고, conversion/build 표면이 작지 않으며 local server는 불필요 |

`transformers`와 SentenceTransformers가 Hugging Face cache/network를 사용할 수 있으므로 environment flag만으로 네트워크 격리를 증명하지 않는다. 실행 단계에서는 OS/container network namespace가 외부 연결을 막는지 별도 확인해야 한다. Model loading은 local path로만 하고 `local_files_only=True`, `HF_HUB_OFFLINE=1`, `trust_remote_code=False`, `use_safetensors=True`를 함께 강제한다. 기본 HOME/cache는 사용하지 않고 전용 임시 디렉터리를 지정한다. tokenizer parallelism을 끄고 CPU thread, batch, sequence length를 hard cap 한다.

## 조건부 선정과 Phase 33.2B 계획

**선정 후보 하나:** `intfloat/multilingual-e5-small@614241f622f53c4eeff9890bdc4f31cfecc418b3` + direct PyTorch/Transformers CPU inference. 상태는 **`CONDITIONAL_GO`**다. 다른 후보는 이번 pilot에 선정하지 않는다.

이 선택은 유행이나 공급자 benchmark 순위 때문이 아니다. 18개의 짧은 승인 section을 대상으로 하는 작업에는 384차원·약 118M parameter 모델이 충분히 작은 출발점이고, 한국어/영어 지원과 asymmetric passage retrieval 목적이 겹친다. MIT license와 safetensors/LFS SHA-256은 metadata로 확인된다. E5 base는 같은 계열에서 weight·RAM·disk가 크게 늘고, BGE-M3는 safetensors 부재, MiniLM은 짧은 sentence similarity 목적이다. 다만 lexical보다 낫다는 증거는 없으며 33.2B가 같은 fixtures로 판단한다.

조건부 선정은 33.2B 실행 승인이 아니다. 아래 항목이 모두 완료되기 전에는 모델·runtime 취득·설치·실행하지 않는다.

1. 이 문서의 exact commit, license, allowlist 파일명·size·digest를 새 날짜에 공식 metadata에서 재확인한다. 모델 revision을 바꾸려면 새 gate다.
2. 취득은 network가 허용된 별도 disposable staging step에서만 수행한다. HTTPS host를 Hugging Face 공식 repository와 PyPI로 제한하고 exact revision/파일 allowlist 이외 요청은 차단한다. `main`, `latest`, community mirror는 금지한다.
3. PyPI wheelhouse를 별도 allowlist로 고정하고 dependency resolver를 실행 환경에서 사용하지 않는다. Python 3.12 macOS arm64/Ubuntu x86_64용 wheel, direct/transitive package 버전, filename, size, SHA-256, publisher/provenance 결과를 모두 manifest화한다. 설치 source/wheel index를 확인하고 hash/출처를 승인하지 못하면 중단한다.
4. E5-small은 모델 디렉터리를 Git revision에 매핑되는 로컬 저장소에만 받는다. 허용 파일만 일반 파일로 복사하고 symlink·hardlink·extra file·case-fold duplicate·크기 mismatch를 거부한다. 대형 파일은 upstream LFS SHA-256을 검증한다. 작은 config 파일의 SHA-256과 Git blob ID를 모두 기록한다. directory inventory와 manifest digest가 승인된 뒤 읽기 전용 mount한다.
5. 네트워크가 필요한 취득/설치 단계를 끝낸 뒤 이미지나 VM snapshot을 고정하고 네트워크를 끈다. 실행에서는 **host-level egress deny**를 적용하고 packet/socket capture와 감사 log로 DNS·HTTP·기타 연결 시도를 검사한다. `HF_HUB_OFFLINE=1`과 `local_files_only=True`는 추가 방어다.
6. 실제 HOME, 사용자 monitor config, 원본 로그, checkpoint, SSH key, credential, browser profile을 mount하거나 복사하지 않는다. 합성 corpus·query와 Phase 33.1 safe evidence fixtures만 staging한다. 입력은 account/IP/hostname/path/raw-line 차단기를 통과한 합성 값만 쓴다.
7. 실행은 전용 임시 HOME/cache, 임시 working directory, 비-root account, Linux capability 제거, `no-new-privileges`, seccomp/AppArmor, read-only root/model mount, writable temp 제한, `pids`·CPU·RAM 제한을 적용한다. 제안 상한은 2 CPU, 4 GiB RAM, 64 processes, query batch 1, passage batch 8, 512 token 이하이며 모델과 상위 torch/transformers wheel 파일만 약 628 MB(압축 wheel·전이 dependency 제외)다. 이는 runtime peak RAM 측정이 아닌 개발 실험 상한이며 운영 용량 약속이 아니다. macOS host의 동등한 sandbox/resource enforcement가 확인되지 않으면 Linux VM에서만 실행한다.
8. 실행 전후에 파일 tree·hash·permissions, process tree, 열린 socket/listener, runtime-owned FD, cache/temp inventory를 비교한다. 임의 추가 파일, outbound attempt, unexpected process/listener, limit 초과, raw output/embedding spill이 있으면 pilot 중단한다.
9. raw query, safe evidence, embedding vector, model output, trace, crash dump를 저장소·CI artifact·report·upload·일반 로그에 남기지 않는다. 결과는 citation ID/rank/metric만 합성 report에 남긴다. Cleanup은 이번 실행에서 생성됐다고 확인된 임시 경로만 삭제하며 secure erase를 주장하지 않는다.
10. Docker Desktop 테스트와 Ubuntu VM 테스트를 별도 기록한다. Docker Desktop은 격리된 Linux VM에서의 확인일 뿐 macOS native runtime 검증이 아니다. Ubuntu VM도 native Ubuntu host 검증을 대체하지 않는다. Phase 33.2B 종료 전 macOS ARM64와 Ubuntu 중 최소 한 곳의 실제 native 환경에서 tokenizer/model/runtime를 확인한다.

Acquire 단계 성공 후에도 offline inference에 필요한 wheel과 모델 파일만 보존한다. 임시 source tree, 다운로드 cache, builder image, exporter/intermediate file은 inventory한 뒤 폐기한다. 다른 단계가 재사용하는 사용자 cache를 삭제하지 않는다.

## Embedding privacy·공급망 위협 모델

| 자산 / 진입점 | 공격·오류 | 예방·탐지 | 실패 동작 | 잔여 위험 |
| --- | --- | --- | --- | --- |
| 합성/승인 corpus와 vector index | embedding inversion·membership inference, similarity 기반 민감정보 추론 | 입력 allowlist; 18개 승인 corpus만 인덱싱; vector는 confidential derived data; process memory only; API/SSE/UI/log/report 금지 | index/입력 경계 실패 시 pilot 종료, vector 폐기 | 비공개 corpus embedding도 원문 의미를 일부 드러낼 수 있음 |
| corpus 및 tokenizer | corpus poisoning, 악성 tokenizer/tokenizer metadata, Unicode normalization 차이 | pinned commit, file allowlist/hash, `trust_remote_code=False`, normalizer/tokenizer versions 고정, NFKC fixture, corpus manifest 검증 | unexpected code/file/hash/tokenization mismatch면 fail closed | 악성/오류 tokenizer는 허용 입력의 의미와 nearest neighbor를 바꿀 수 있음 |
| 검색 ranker | adversarial nearest neighbor·retrieval manipulation | 동일 corpus와 top-k/verifier, cosine·normalization·score quantization 고정, deterministic ID tiebreak, no finding threshold | threshold 미달·NaN·Inf·tie inconsistency면 refusal/no result | 유사도는 근거의 사실성이나 인용의 의미적 support를 증명하지 않음 |
| 질문/DTO | oversized input, 혼동 Unicode, 같은 질문 fingerprinting | 기존 closed DTO/category; synthetic-only benchmark; bytes/token/batch cap; process-local no persistence | oversized/privacy input은 검색 전에 고정 refusal | 타이밍·리소스 관찰로 요청 추론 가능 |
| 모델/runtime/artifact | dependency·weight 공급망, malicious weight, pickle execution, package installer script | immutable commit, safetensors only, hashes, wheel provenance, isolated wheelhouse, no source installer, no remote code | 어떤 hash/provenance mismatch든 설치/실행 중지 | hash는 게시자 신원·학습 데이터·모델 안전성을 증명하지 않음 |
| local process/endpoint | local endpoint 노출, DNS rebinding, browser access, unexpected egress | embedding은 in-process API only, HTTP listener 없음, network namespace deny, no external URL, firewall/socket audit | 연결/listener 시 즉시 종료·격리 조사 | host compromise 또는 sandbox escape |
| host memory/filesystem | cache·swap·crash dump·backup 잔존, raw vector 로그/report | 전용 tmp/cache, swap/core dump 정책 검토, no request logging, file/FD inventory | 남은 자료 발견 시 pass 보류, 확인된 임시 자료만 정리 | OS snapshot/SSD remanence; secure erase 보장 불가 |
| test/review artifacts | prompt/query/vector/report trace의 재노출 | 합성 fixtures; result는 ID/rank/metric만; report scrub; artifact upload 금지 | PII/canary 흔적 1건이면 전체 gate fail | 개발자가 수동 복사하거나 외부 도구가 별도 로그를 남길 수 있음 |

Embedding vector도 안전한 공개 정보가 아니다. 어떤 embedding도 status/API/SSE/UI, database, checkpoint, persistent cache 또는 일반 log에 넣지 않는다. 결과가 필요하면 과정 안에서만 similarity rank를 계산하고 session 종료 시 vector reference와 temporary arrays를 버린다. Python allocator/OS memory를 secure wipe로 표현하지 않는다.

Fail-closed: revision·license·size/hash 불일치, 추가 파일, pickle/custom code, network egress/listener, unsupported platform/runtime, resource limit 초과, 개인정보 canary, nondeterministic top-k mismatch, citation verifier 실패, 낮은 점수, timeout/crash 중 하나면 embedding result를 사용하지 않고 Phase 33.1 lexical baseline으로 자동 fallback하지 않는다. 비교 harness에서 실패 후보는 해당 fixture의 refusal/error로 기록하고 lexical-only 행은 독립 결과로 유지한다. 기존 detection/risk/case나 결과 가시성은 바뀌지 않는다.

## 동일 조건의 비교 평가 계약

Phase 33.1의 동일한 17개 합성 fixture를 보존하고 세트 digest를 기록한다. 합성 보강 fixture는 한국어 질문, 영어 질문, 한국어+영어 보안용어 혼합, 동의어, 같은 뜻의 다른 표현, brute force/password spray 구분, risk/confidence 구분, relation disappearance/resolution 구분, replay gap/checkpoint reset 구분, no finding, 충돌 문서, 개인정보 요청, prompt injection, 존재하지 않는 citation 유도, out-of-domain 질문을 포함한다. 실제 사용자 자료는 쓰지 않는다.

각 candidate에 같은 corpus digest, safe evidence DTO, query bytes/token cap, top-k 최대 5, refusal category, citation verifier와 expected citation gold set을 쓴다. corpus/fixture를 candidate마다 수정하지 않는다. 동일한 top-k citation validator로 lexical, embedding, hybrid를 각각 별도 측정한다.

| 비교 경로 | 33.2B 정의 |
| --- | --- |
| lexical only | Phase 33.1 코드/기준값 그대로: BM25 `k1=1.2`, `b=0.75`, threshold `2.2`, stopword/tokenizer digest 고정 |
| embedding only | E5 query/passage prefix, fixed tokenizer/model/revision, attention-mask mean pooling + L2 normalization, cosine score. score는 finite/non-negative 확인 뒤 6 decimal places로 quantize; tie는 document ID/section ID 오름차순. 별도 held synthetic calibration split에서 threshold를 정하고 평가 set을 threshold 튜닝에 재사용하지 않음 |
| deterministic hybrid candidate | BM25 rank와 embedding rank를 합치는 fixed reciprocal-rank fusion `1/(60+rank)` 두 항의 합; 최대 top-k 5, 동점 ID 정렬. weight/constant를 평가 결과에 맞춰 사후 조정하지 않음 |

질문 category refusal와 개인정보 차단은 모든 ranker보다 먼저 실행하고 모든 경로에 동일하게 적용한다. embedding 높은 score가 권한 밖 요청을 허용하지 않는다. 문서 충돌은 ranker 선택으로 해소하지 않고 충돌 문서 집합으로 표시한다. Inference는 eval mode + CPU deterministic settings, `torch.use_deterministic_algorithms(True)`, thread 1을 고정한다. score의 6자리 양자화 후 동점 tie-break를 적용한다. 같은 host/version에서 byte 동일성을 요구하고, 서로 다른 CPU architecture의 raw floating-point vector byte가 같다고 요구하지 않는다. timezone/locale은 tokenizer/ranker에서 읽지 않는다.

| 지표 | 정의/통과 경계 후보 |
| --- | --- |
| expected citation hit | 정답 section이 결과 top-k 안에 있는 fixture 비율; lexical 11/11을 고정해 같이 출력 |
| precision / completeness | top-k citation 중 gold relevant 비율 / gold section 중 반환된 비율 |
| MRR / nDCG@5 | 사전 정의 relevance grade를 사용하는 ranking 순위 지표 |
| wrong/unsupported citation | gold set에 없는 section 수와 존재하지 않는 ID 수를 분리; 존재하지 않는 ID는 0이어야 함 |
| refusal correctness | 개인정보, injection, unsupported, out-of-domain, low-score fixture의 올바른 고정 refusal 비율 |
| privacy leakage | input/output/log/report/vector artifact에서 synthetic canary count; 0이어야 함 |
| determinism | 동일 환경 반복 byte-identical; TZ UTC/Asia-Seoul, locale 변경에서 동일한 rank/IDs |
| 자원 | model/index disk bytes, index build latency, query p50/p95/max, peak RSS, inference batch/sequence cap |

이 측정은 retrieval 품질만 다루며 detector recall/precision, analyst effectiveness, 실운영 탐지율 또는 LLM 답변 품질이 아니다. “그럴듯함”은 metric에 포함하지 않는다. 모델의 cosine 값을 lexical BM25 threshold와 직접 비교하지 않는다.

## Gate 결정

33.2B 진입 조건: license와 attribution 확인; exact commit 고정; 모든 allowlist 파일의 size와 SHA-256 pin; safetensors weight; no remote code; local-only load; wheel closure와 hashes/provenance 검토; network deny 증거; resource/cache cleanup plan; 실제 로그·개인정보가 없는 eval; Phase 33.1 citation verifier 재사용; 최소 한 native 환경 실행 계획을 모두 만족해야 한다.

즉시 NO-GO: pickle 필요, `trust_remote_code=True` 필요, license/hash 불명, 다운로드 자동 추가, 외부 API/telemetry 의존, unexpected egress, 실제 사용자 자료 필요, 격리 또는 cleanup 검증 불가, citation verifier 우회, lexical baseline 결과를 덮거나 숨김, review 전 production 연결.

따라서 **33.2A 설계 결과는 E5-small candidate `CONDITIONAL_GO`; 33.2B 준비 상태는 BLOCKED/PRECONDITION_PENDING**이다. blocker는 (a) macOS/Ubuntu 전이 wheel closure 및 PyTorch CPU 설치 provenance/hash 고정, (b) small config 파일의 SHA-256 pins, (c) isolated native/offline/egress/cleanup 실증이다. blocker 해결 전 모델은 다운로드·설치·실행하지 않는다. 후보가 조건부 선정되었으므로 이번 단계 변경은 문서와 문서 계약 테스트뿐이다.

## 33.2B 진행 전 체크리스트

- [ ] isolated workspace와 새 OS account/VM 생성; user HOME·로그·config/checkpoint mount 없음.
- [ ] pinned model commit/tree/license를 다시 확인하고 허용 파일 manifest를 승인.
- [ ] file SHA-256 및 exact byte count 검증. Git blob ID로만 확인 가능한 작은 파일은 다운로드 후 두 digest를 모두 pin하고 승인.
- [ ] wheel source, wheel filename/size/SHA-256, dependency closure, native libraries, installation script를 수동 검토.
- [ ] 네트워크 단계는 model/PyPI allowlist에만 제한; 이후 offline snapshot/network namespace deny.
- [ ] non-root/capability drop/read-only mounts/resource caps 적용; listener/process/socket 검사 준비.
- [ ] 합성 corpus/query만 복사하고 17 fixture + multilingual/adversarial extension digest 고정.
- [ ] 시작 전/후 file·process·FD·listener·cache inventory 저장. inventory에는 경로와 데이터 내용 대신 redacted counts/hash만 남김.
- [ ] cleanup은 확인된 disposable artifacts에만 수행하고 결과 기록. Secure erase는 주장하지 않음.
- [ ] actual native macOS ARM64 또는 Ubuntu 환경 하나 이상에서 검증; Docker Desktop/VM은 별도 보조 증거.

## Phase 경계

- **33.0:** 설계·위협 모델·legacy Gemini 경로 감사.
- **33.1:** safe evidence, static approved corpus, lexical retrieval와 citation verifier. 현행 고정 baseline.
- **33.2A:** 모델/runtime 공급망 후보를 정적으로 조사하고 격리·평가 gate를 설계. 이 문서.
- **33.2B:** 한 후보의 합성 전용 retrieval 비교는 [별도 기록](local_embedding_retrieval_pilot_33_2b.md)에 완료되었다. macOS memory hard cap 및 전용 OS isolation 증거가 부족하고 hybrid가 lexical을 개선하지 않아 production 통합은 NO_GO다.
- **33.3A:** [구조화 local LLM 설계 gate](local_llm_supply_chain_gate_33_3a.md); 모델/runtime 미다운로드·미실행.
- **33.3B:** 33.3A의 조건부 Qwen+llama.cpp 조합만 별도 승인 후 합성 pilot 후보. Phase 33.2B embedding `NO_GO`와 lexical 기준선은 유지한다.

Phase 33.2A 작성 당시에는 LLM·embedding·Ollama·llama.cpp·vector DB를 다운로드, 설치, 실행하지 않았다. 후속 Phase 33.2B에서는 pinned E5-small만 별도 temp 환경에서 실행했으며 그 한계와 측정은 연결된 기록에 있다. 기존 Gemini 경로는 변경하지 않았고 retrieval은 production API/SSE/UI 또는 분석 pipeline에 연결하지 않았다. Lexical baseline은 계속 기준선이다.

## 조사 출처

### 공식 model repository와 runtime metadata

- [E5-small pinned model card](https://huggingface.co/intfloat/multilingual-e5-small/tree/614241f622f53c4eeff9890bdc4f31cfecc418b3) · [E5-small pinned README](https://huggingface.co/intfloat/multilingual-e5-small/blob/614241f622f53c4eeff9890bdc4f31cfecc418b3/README.md)
- [E5-base pinned model card](https://huggingface.co/intfloat/multilingual-e5-base/tree/d128750597153bb5987e10b1c3493a34e5a4502a) · [E5-base pinned README](https://huggingface.co/intfloat/multilingual-e5-base/blob/d128750597153bb5987e10b1c3493a34e5a4502a/README.md)
- [BGE-M3 pinned model card](https://huggingface.co/BAAI/bge-m3/tree/5617a9f61b028005a4858fdac845db406aefb181)
- [MiniLM pinned model card](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/tree/e8f8c211226b894fcb81acc59f3b34ba3efd5f42) · [Sentence-Transformers model overview](https://github.com/huggingface/sentence-transformers/blob/main/docs/_static/html/models_en_sentence_embeddings.html)
- [PyTorch 2.14.1 release metadata](https://pypi.org/project/torch/2.14.1/) · [Transformers 5.20.2](https://pypi.org/project/transformers/5.20.2/) · [ONNX Runtime 1.31.0](https://pypi.org/project/onnxruntime/1.31.0/) · [Sentence-Transformers 6.2.0](https://pypi.org/project/sentence-transformers/6.2.0/)
- [Transformers offline loading](https://huggingface.co/docs/transformers/installation#offline-mode) · [Hugging Face offline environment variable](https://huggingface.co/docs/huggingface_hub/en/package_reference/environment_variables#hfhuboffline)
- [ONNX Runtime installation and compatibility](https://onnxruntime.ai/docs/install/) · [ONNX Runtime Python session thread controls](https://onnxruntime.ai/docs/api/python/api_summary.html)
- [llama.cpp v0.7.0 release](https://github.com/ggml-org/llama.cpp/releases/tag/v0.7.0) · [embedding model conversion guide](https://github.com/ggml-org/llama.cpp/blob/master/examples/model-conversion/README.md)

### 적용 해석과 한계

공급자 card의 학습 언어·parameter·sequence length는 모델 설명에 한정한다. PyPI wheel filename/hash/size는 release metadata이지 악성코드 부재 증명이 아니다. source code의 offline flag는 자체적으로 OS egress 차단을 보장하지 않으므로 B 단계는 OS 네트워크 격리를 함께 검증한다. 다운로드 전 정적 비교는 native 실행 동작, 실제 peak RAM/latency, 모델 성능, wheel runtime egress, tokenizer equivalence를 검증할 수 없다. 그 결과를 보완하기 위한 실행·측정은 다음 Phase gate의 범위다.
