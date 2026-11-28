# RE-002 · Source build of the x86-64 unsigned 128-bit remainder routine

Node #115's published-library census identified a 197-byte function also emitted under the public symbol `__umodti3`. Can a fresh compilation of the licensed Rust sources reproduce those bytes? Two separate Rust 1.95.0 builds each reproduced the full interval byte for byte. With the same target and release profile, Rust 1.94.1 emitted a function of the same length with 45 different bytes.

## Inputs and comparison

| Input | Identity |
| --- | --- |
| Target | Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| Reviewed extent | Linked ELF virtual addresses `[0x63efd70, 0x63efe35)`; file offset `0x63eed70` |
| Existing identification | [RE-002 standard-library census](../RE-002-node115-std-census/README.md), including an identical-source alias for `__umodti3` |
| Positive source | [Rust 1.95.0](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/compiler-builtins/compiler-builtins/src/int/udiv.rs#L169-L178) |
| Control source | [Rust 1.94.1](https://github.com/rust-lang/rust/blob/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/compiler-builtins/compiler-builtins/src/int/udiv.rs#L169-L178) |
| Source target | `x86_64-unknown-linux-gnu`; builds were cross-compiled on Apple Silicon macOS |
| Component | Public `compiler-builtins` dependency, under RE-002 build provenance |

The build selects the defined ELF function symbol from the freshly compiled archive, retaining its complete body. The two `.bin` files contain the outputs of the respective **source builds**. Their [upstream licensing terms](compiler-builtins-LICENSE.txt) accompany them (MIT AND Apache-2.0 WITH LLVM-exception). The verifier opens the captured ELF as data, authenticates the whole file, maps its executable section, and compares the unmodified bytes. It also cross-checks the previous published-library census. Building the symbol requires only the public toolchain and source inputs.

| Rust release | Body length | Body SHA-256 | Raw matches against node #115 |
| --- | ---: | --- | ---: |
| 1.95.0, two clean builds | 197 | `9dd5017012d72e6a6fdc6640c992611ac84dcfbb807abfcad9f0bd4cc3ba15e7` | 197/197 each |
| 1.94.1, control build | 197 | `12f5828bd833666b6023e761036da32c29aeb7d1e7eedbb93d734f730f391e26` | 152/197 |

Within the recorded run both 1.95.0 builds also gave identical archive and object digests. A new invocation in another source-extraction path can change outer archive/member identities while preserving the function bytes. The selected object sections have zero relocations. The comparison uses no masks or normalization. The source releases both identify the crate as version 0.1.160. Changing the release changes multiple build inputs, so the control does not isolate a single compiler change.

## Reproduce

From this packet directory inside the checkout, run `python3 verify.py` to compare the retained bodies against the authenticated ELF and the previous census. The repository's full byte catalogue is checked from the checkout root with `make catalogue-check`.

To regenerate the bodies, install Python 3.12+, GNU binutils, and the two pinned Rust toolchains (`rustup toolchain install 1.95.0 1.94.1 --profile minimal`). Run the following from this directory. Provisioning fetches the pinned Rust source archives and Cargo dependencies. The three compilations then use Cargo offline in fresh directories.

```sh
lab=$(mktemp -d)
python3 build.py provision --cache "$lab/cache"
python3 build.py run --cache "$lab/cache" --output "$lab/result"
python3 verify.py "$lab/result"
```

The script accepts `--binutils-dir` for a non-default GNU installation. It rebuilds `core,compiler_builtins` with Cargo's build-std option using the extracted release library, opt-level 3, 256 codegen units, and incremental compilation disabled. A small no-std library drives the cross-build. The compiler is pinned by release and commit. The extractor verifies the x86-64 relocatable ELF, public function symbol, size, section extent and absence of relocation fields. [Raw build results](build-results.json) retain per-build tool versions, archive/member identities and function hashes. The captured executable is never launched.

## Scope

The recorded compiler flags are one sufficient recipe for this function. The result upgrades the provenance of a previously counted dependency window. It adds no unique covered target bytes, first-party implementation bytes, or component gates. It establishes neither the historical node build invocation nor equivalence of the entire library or node. A bounded follow-up would test whether the same recipe reproduces a different previously identified arithmetic routine.

## Which optimization levels reproduce this function?

The [build plan](../RE-002-node115-build-plan/README.md) leaves the optimization level open and calls for comparison with a known function. Its fixed-source, fixed-compiler control for this leaf gives the following results. All six builds used the recipe above and fresh target directories. The builder verifies the optimization level Cargo actually reports for the freshly compiled `compiler_builtins` artifact.

| Cargo opt-level | Source body bytes | Relocation fields | Whole-body match |
| --- | ---: | ---: | --- |
| 0 | 12 | 1 | No |
| 1 | 171 | 0 | No |
| 2 | 192 | 0 | No |
| 3 | 197 | 0 | Yes |
| s | 42 | 1 | No |
| z | 5 | 1 | No |

Only level 3 reproduced the 197-byte linked function under these fixed inputs. Each alternative had a different whole-symbol length, including the three bodies with relocations. The result narrows the recipe for this library function. Cargo supports profile overrides per package, and changes to other compiler inputs could change the comparison.

Using the provisioned cache from the preceding section, replay the matrix from this directory. The JSON records the full source-body digest and exact target for each comparison.

```sh
python3 -B opt_profiles.py --cache "$workdir/cache" > "$workdir/profiles.json"
diff -u opt-profiles.json "$workdir/profiles.json"
```
