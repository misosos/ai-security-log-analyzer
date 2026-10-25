# Phase 33.3F — local LLM isolated storage and residual closure

**Final disposition: `STORAGE_SETUP_BLOCKED`.** The 20 GiB disk scenario fits the current conservative planning model, and all 28 pinned wheel archives now have a recorded license/content audit. The physical disk has not been added or inventoried, and the target VM's apt/build closure is not frozen. No disk was formatted or mounted; no model, runtime source archive, package, or project dependency was installed; no model conversion or inference occurred.

## Start gate

| Gate | Result | Evidence |
| --- | --- | --- |
| `main`, clean tree, local and remote SHA | `PASS` | Start SHA `ad226412e2440fceb7cc458b1976f40780c32d62`; `main`; clean; `origin/main...HEAD` 0/0 |
| Exact push CI | `PASS` | [Run 40148946929](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40148946929), push event, exact head SHA, completed/success |
| Locked install and lock verification | `PASS` | Exact run's locked development environment install and dependency lock steps succeeded |
| Ubuntu regression and Phase 33 | `PASS` | Exact run's full regression and Phase 33 contract steps succeeded |
| Node and accessibility | `PASS` | Pinned Node/browser setup and bounded Chromium accessibility step succeeded |
| Stored CI artifacts | `PASS` | GitHub run artifact endpoint reported 0 |
| v0.4.0 tag and Release target | `PASS` | Tag object `855a92827a605805b62c627ed719958620150ec4`, peeled target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`; release target unchanged |

## Storage plan and physical acceptance

The new [machine-readable storage plan](artifacts/local_llm_storage_plan_33_3f.json) and [calculator](../tests/local_llm_storage_33_3f.py) use a 20 GiB disk scenario, at least 5 GiB reserved on that disk, at least 3 GiB retained on the existing root filesystem, and 15% filesystem/safety overhead. The calculation includes all ten model repository entries, the model and tokenizer bytes, the 28-wheel compressed wheelhouse, a 1 GiB installed converter environment cap, a 1 GiB apt package archive cache cap, the pinned llama.cpp archive, 512 MiB each for extracted source and build output, conversion staging, the F16 GGUF payload floor, and bounded fixtures/output.

| Component | Planned bytes |
| --- | ---: |
| Ten model allowlist files | 1,519,209,243 |
| 28 pinned wheel archives | 197,071,951 |
| Installed converter environment cap | 1,073,741,824 |
| Staged apt package archive cache cap | 1,073,741,824 |
| llama.cpp source archive | 38,195,486 |
| Extracted runtime source cap | 536,870,912 |
| Runtime build directory cap | 536,870,912 |
| Conversion staging cap | 1,503,300,328 |
| F16 GGUF payload floor | 1,503,264,768 |
| Fixture/private output cap | 67,108,864 |
| Subtotal | 8,049,376,112 |
| 15% filesystem/safety overhead | 1,207,406,417 |
| **Peak planning estimate** | **9,256,782,529 (~8.62 GiB)** |

The 20 GiB scenario leaves 12,218,053,951 bytes, above the 5 GiB reserve. The 1 GiB environment cap is above the measured 744,996,145-byte uncompressed total of the wheel archives, with room for interpreter files and install metadata. The apt archives can be staged on the dedicated disk, while installed OS packages still consume root filesystem space; acquisition must measure root free space after package installation and stop if less than 3 GiB remains. These are planning caps, not measurements of a VM install or hard bounds on conversion/build behavior. This is a capacity calculation, not proof that a disk exists or that the workflow fits under all conditions.

Only a private VM mount below a pilot-owned directory is allowed for apt cache, model cache, temporary files, source, build, model, corpus, prompt, and output. These locations must remain beneath that mount, use no symlinks, and leave root `/tmp` free of large temporary files. The proposed filesystem is ext4 with a pilot label, mountpoint mode `0700`, non-root ownership, `nosuid,nodev`; `noexec` must be decided for any executable location. No persistent `/etc/fstab` entry is planned. A disk-full fault can be tested inside a disposable, size-capped filesystem image stored on the pilot disk; the pilot filesystem itself must not be filled.

The prior Ubuntu/VM facts in Phase 33.3D were supplied by the user and were not independently checked by this agent. They did not identify a new pilot disk. I requested the specified `lsblk -b -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL,UUID` inventory before and after adding a new disk; both inventories are still pending. No VM connection or storage command was run in this phase. Consequently, root filesystem immutability, snapshot state, disk identity, filesystem state, mount, free space, ownership, network, and shared-feature state remain `NOT_TESTED`. No format approval was requested or received, and `mkfs`, mount, partitioning, root resize, and snapshot changes were not performed.

The acceptance record intentionally stores only pending/verified status fields. It does not store a device path, UUID, serial, user, IP, host name, or VM path. A new device must be the sole added top-level disk near 20 GiB with no filesystem and no mountpoint, and must be distinct from the root disk. Only after that evidence can the exact target, size, empty state, and root distinction be shown for a separate explicit formatting approval. This phase does not authorize formatting.

## Pinned wheel and license audit

The [wheel-license manifest](artifacts/local_llm_wheel_licenses_33_3f.json) covers all 28 pinned candidates for CPython 3.12 / ARM64, including exact filenames, tags, compressed sizes, SHA-256, source index, license expression, license-file path and digest, native-file count, install-hook review, and resolved `required_by` edges. The wheelhouse totals 197,071,951 bytes; the inspected archive payload totals 744,996,145 bytes. All candidate wheel bytes were rechecked against their pinned SHA-256 and size in a mode-0700 temporary audit directory; no wheel was installed and no sdist was used. The audit directory was removed after inspection.

For `tokenizers` and `sentencepiece`, the wheel had no license text, so the manifest pins the official upstream release-tag license path and SHA-256. Setuptools is a torch dependency and was also fetched by the earlier resolver while collecting metadata. Its wheel contains 17 vendored license texts and `distutils-precedence.pth`; that startup file conditionally imports `_distutils_hack` and adds its distutils shim. This hook was inspected but not executed because the wheel was not installed. The setuptools archive's vendored license files are listed separately in the manifest.

This closes the license-file evidence for the candidate wheel set, not a tested Python install. A future acquisition must still use the exact wheel allowlist and hash checks, install only in the isolated VM, and check the resulting environment and startup behavior. The [PyPI metadata documentation](https://docs.pypi.org/project_metadata/) explains that PyPI reports project-declared licensing and does not independently validate that the declared license matches the project; this audit therefore records wheel/source license text and digests as well as metadata.

## Ubuntu/llama.cpp build closure

The [build manifest](artifacts/local_llm_build_closure_33_3f.json) carries forward the exact llama.cpp commit and archive digest and the converter source file digests from 33.3E. It also records official Noble ARM64 package references for `build-essential`, `cmake`, `ninja-build`, GCC/G++, `make`, and CPython 3.12 components. The references are not the user's current apt candidate set. Official package pages show, for example, [build-essential 12.10ubuntu1](https://packages.ubuntu.com/noble/arm64/build-essential), [CMake 3.28.3-1build7](https://packages.ubuntu.com/noble/arm64/cmake), [Ninja 1.11.1-2](https://packages.ubuntu.com/noble/arm64/ninja-build), and [Python 3.12 development package details](https://packages.ubuntu.com/noble-updates/arm64/python3.12-dev).

The VM's exact installed/candidate apt versions, apt index Release digest, transitive `.deb` hashes, compiler/CMake/Ninja version output, Python patch build, and linked libc/libstdc++ versions are not available. Build flags and option names have not been revalidated against the pinned source archive, and no network-denied configure/build was performed. The intended target remains `llama-cli` only, with the HTTP server and curl/network support excluded, generic ARM64 CPU selection, and no runtime download path. Exact flags, FetchContent behavior, target inventory, shared-library linkage, and the final binary digest remain `NOT_TESTED`. Therefore the Ubuntu build closure is still partial and does not authorize source acquisition/build.

## Verification

Before editing, `uv run pytest -q` passed **2,634 tests** with two existing deprecation warnings. The test-first storage/license tests initially failed because the 33.3F manifests and acceptance status were missing. After adding them, the focused storage, license, and adjacent 33.3E contract suite passed **18 tests**. Final full regression passed **2,649 tests** with the same two deprecation warnings. The test-only calculator reports the peak and 5 GiB reserve above; it does not inspect VM hardware. CI evidence is independent from the macOS-host repository tests and from any user-side VM operation.

The `STORAGE_SETUP_BLOCKED` disposition is caused by the missing before/after inventory and separate format approval. The build manifest also records unresolved target-VM package/build evidence. No model, llama.cpp source archive, converter environment, or runtime was acquired in this phase; no build, conversion, or inference was run.
