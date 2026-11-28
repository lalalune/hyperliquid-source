# RE-002 · What node #115 tells us about Rust panics

**The linked node contains a Rust exception-raising runtime. The retained build artifacts do not identify the root crate's `-C panic` flag.** The previous provenance reader inferred `unwind` whenever the total ELF exception-table size exceeded 1,000,000 bytes. It counted every linked input together. On #115, we can inspect the owners of the metadata and test that inference against two ordinary builds.

Target is Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Task is RE-002, component `foundation`. This packet refines compiler-profile inputs for the [deterministic build plan](../RE-002-node115-build-plan/build-plan.json). It requests no component gate or implementation-byte credit.

## Who handles exception frames in #115?

The earlier [CIE census](../RE-001-node115-ehframe-cie-census/README.md) identified three unwind-record groups and left the destinations of two indirect personality pointers open. A personality routine interprets a frame's language-specific exception data (LSDA) during unwinding. Resolving the pointers' dynamic relocations gives the following groups. Counts describe recorded call-site ranges, rather than runtime events.

| Personality | Frame descriptions | Distinct LSDAs | No landing pad | Cleanup only | Nonzero action |
| --- | ---: | ---: | ---: | ---: | ---: |
| None | 82,631 | 0 | 0 | 0 | 0 |
| Local Rust-associated personality | 48,005 | 48,005 | 125,436 | 191,477 | 63,344 |
| Imported C++ personality | 4,677 | 4,677 | 5,078 | 14,604 | 904 |

- At slot `0x64efa28`, an ELF `R_X86_64_RELATIVE` relocation resolves to `0x5cad7b0`. Its 1,439-byte FDE and body digest agree with the [published Rust object attribution](../RE-002-node115-std-census/census.json) for `rust_eh_personality`. The [independent routine study](../RE-012-unwind-personality-inputs-115/README.md) confirms its use of the unwind library. Published-object attribution does not establish complete recompilation or identify the crate that emitted each protected frame.
- At slot `0x64fee68`, an ELF `R_X86_64_64` relocation resolves against dynamic symbol 235, `__gxx_personality_v0`.
- The [Rust exception wrapper](../RE-012-panic-exception-payload-115/README.md) constructs the Rust-specific exception class and transfers to the imported `_Unwind_RaiseException`. The verifier rechecks its complete FDE digest, class bytes and import slot. The official [Rust 1.95.0 panic runtime](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/panic_unwind/src/gcc.rs#L58-L75) uses this mechanism.

The static reader follows all 52,682 distinct LSDA pointers in the 2,900,276-byte `.gcc_except_table`. It bounds each call-site table by the next distinct LSDA or the section end, then checks the declared length, ordering, covered ranges and landing-pad offsets against its owning FDE. All 400,843 call-site rows passed. A nonzero landing pad with action zero counts as cleanup only. The count for nonzero action does not interpret the action or type tables. The earlier [single-function LSDA reader](../RE-001-node115-lsda-call-site/README.md) provides the byte decoder. [Full census](census.json)

## Two root strategies, one dependency

The control compiles [a Rust dependency](component.rs) once with `-Cpanic=unwind`, then links the same archive into two Linux x86-64 executables. A [separate root crate](root.rs) invokes the dependency and performs its own analogous operation. Both functions retain a guard across a callback. The sole compiler-profile difference between the two roots is `-Cpanic=abort` versus `-Cpanic=unwind`. The Rust reference permits a target binary with an abort strategy to include inputs compiled for unwind. [Rust 1.95.0 codegen options](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/src/doc/rustc/src/codegen-options/index.md#L490-L502)

| Root flag | Selected runtime in linker map | Exception-table bytes | FDEs with LSDA | Dependency operation LSDA | Root operation LSDA | Imports `_Unwind_RaiseException` |
| --- | --- | ---: | ---: | --- | --- | --- |
| `abort` | `panic_abort` | 10,892 | 108 | Present | Absent | No |
| `unwind` | `panic_unwind` | 10,968 | 115 | Present | Present | Yes |

The exception tables and the dependency's own cleanup survive in both builds. In this fixture the linker-selected runtime and the root-owned operation distinguish them. On #115 the Rust exception wrapper supports starting a candidate build with `panic=unwind`. An archived compiler invocation or equivalent build metadata would settle the historical root flag. Other inputs, including C++ code and precompiled Rust dependencies, contribute exception metadata. [Fixture results, input hashes and complete ELF hashes](control.json)

## Reproduce

Run from the repository root with the materialized #115 Git LFS artifact and Python 3.9+. The first command authenticates and statically parses the capture. The second checks both root-profile and call-site corruption regressions.

```sh
packet=research/work-items/RE-002-node115-panic-strategy
python3 "$packet/census.py"
python3 -m unittest discover -s tests -p 'test_node115_panic_strategy.py'
python3 -m unittest discover -s tests -p 'test_build_provenance.py'
python3 tools/build_provenance.py --check
```

To rebuild both control executables, use rustup's Rust 1.95.0 with its x86-64 Linux target, the bundled linker and GNU binutils (`ar` and `readelf`). On macOS, pass the GNU `ar` executable with `--ar`. On Ubuntu x86-64 the default library directory is `/usr/lib/x86_64-linux-gnu`. It must contain `libc6`, `libc6-dev` and `libgcc-s1` inputs. To cross-link on another host, give `--lib-dir` a directory with the eight Linux files named in `native_inputs_sha256` in the retained JSON. The recorded Apple Silicon run used the authenticated Ubuntu Noble base-release files and the Rust-bundled LLD 22.1.2. The runner builds in a temporary directory, verifies that both links consume the same unmodified rlib and checks each ELF and linker map. The result records the archive's compiled object hash, excluding variable Rust metadata. Neither the node nor the control binaries are executed. The flags, library selection and SHA-256 values are recorded independently of the node.

```sh
rustup toolchain install 1.95.0 --profile minimal
rustup target add --toolchain 1.95.0 x86_64-unknown-linux-gnu
python3 "$packet/profile_control.py" --output /tmp/re002-panic-control.json
```

A different sysroot or host can change the full ELF hashes and frame counts. The control checks the root, dependency, panic runtime and raise import directly. Repeating the recorded native-input configuration reproduced the committed JSON.
