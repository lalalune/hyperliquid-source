# RE-002 · Public Rust source for the #115 decimal display digit worker

Two published versions of `rust_decimal` reproduce the 1,541-byte size and all 1,461 bytes outside relocation fields of the #115 decimal digit worker. Both also reproduce the data used by six literal references and the file suffixes and coordinates of nine source Locations. The evidence qualifies a public implementation of this function. Its instructions and these Locations cannot distinguish versions 1.36.0 and 1.39.0.

The target is the Linux x86-64 #115 capture, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The inspected repository base is `2da45cb0a761cff6b478e40421699857d87a94df`. Prior work already established sign-clear scalar preparation and the selected positive decimal formatting path inside the TWAP encoder. Existing rust_decimal byte-window evidence covers nearby parsing functions. This experiment measures the source identity of the display worker those callers reach. [Preparation #966](https://github.com/lalalune/hyperliquid-source/pull/966) · [Rust implementation #1323](https://github.com/lalalune/hyperliquid-source/pull/1323) · [TWAP wire #4383](https://github.com/lalalune/hyperliquid-source/pull/4383) · [Decimal parsing bindings](../RE-002-node115-rust-decimal-parse-bindings/README.md)

## Function and data comparison

The caller at VA `0x41c5aeb` selects the display wrapper through a relative relocation. The wrapper's direct call at `0x5c449ef` enters the measured digit worker at `0x5c43040`. The verifier reads both calls, the binding and both FDE endpoints from the pinned ELF. It locates the two source definitions by full Rust symbol pattern, ELF symbol type, section index, symbol size and section size. The source objects identify rustc 1.95.0 in their own `.comment` sections.

| Public source and release profile | Digit worker | Display wrapper |
| --- | --- | --- |
| 1.36.0, overflow checks on, two fresh builds | 1,541 bytes, identical source bodies | 397 bytes |
| 1.39.0, overflow checks on | Identical to both 1.36.0 bodies | 397 bytes |
| 1.36.0, overflow checks off | 1,482 bytes | 397 bytes |
| Node #115 FDE | `0x5c43040..0x5c43645`, 1,541 bytes | `0x5c449c0..0x5c44b3f`, 383 bytes |

The unmodified checked source body matches 1,475 of 1,541 target bytes. The source object's relocation table contains 16 `R_X86_64_PC32` and four `R_X86_64_GOTPCREL` entries, each four bytes wide with addend −4. Their fields cover 80 distinct bytes. All 1,461 remaining bytes agree. The comparison resolves the target address of each operand from its linked displacement. [Measured fields and digests](results.json)

| Reference class | Count | Observation |
| --- | ---: | --- |
| Literal loads and one diagnostic string | 6 | All five SIMD/scalar loads agree at their actual widths, as do all 43 message bytes. |
| Source Locations | 9 | Eight point to `rust_decimal/src/str.rs` and one to `arrayvec/src/array_string.rs`. All nine line/column pairs agree. The reference and target source-root prefixes differ. The arrayvec Location is resolved through a second object in the same rlib. |
| Formatter vtable | 1 | The first three words agree at `[0, 4, 4]`. The method bodies and their equivalence remain open. |
| Helper imports in the source object | 4 | The source symbols and the four target relative-addend destinations are recorded. Independent helper body identities remain open. |

The source crate licenses the implementation under MIT. The public package archives are authenticated by the checksums in the included Cargo lockfiles. The repository revisions below are recorded in the published crates' `.cargo_vcs_info.json`. [1.36.0 digit source](https://github.com/paupino/rust-decimal/blob/38ab8254ad77e0a612f8eef8f12a2f7febee3ff8/src/str.rs) · [1.39.0 digit source](https://github.com/paupino/rust-decimal/blob/a028cf43fe1c383cc6927ed2dbd4b6aac443e99c/src/str.rs)

## Reproduce

The measured host was macOS arm64, Python 3.14.3, pyelftools 0.33 and rustc 1.95.0 (`59807616e`). Run from the repository root with its materialized #115 LFS object. Set `AR_TOOL` to GNU ar or LLVM ar. On macOS with Homebrew binutils, `$(brew --prefix binutils)/bin/ar` supplies GNU ar.

```sh
packet=research/work-items/RE-002-node115-rust-decimal-display-source
rustup toolchain install 1.95.0 --profile minimal
rustup target add --toolchain 1.95.0 x86_64-unknown-linux-gnu
python3 -m venv /tmp/decimal-display-venv
/tmp/decimal-display-venv/bin/pip install pyelftools==0.33
AR_TOOL=ar
/tmp/decimal-display-venv/bin/python "$packet/replay.py" --ar "$AR_TOOL" --fetch
```

Once dependencies are available, omit `--fetch` for a fully offline replay. The four clean builds use Cargo's locked/frozen release profile at optimisation level 3 with default features disabled. The runner explicitly selects the rustc and rustdoc executables using rustup. Source comparison reads the Linux objects without executing them. Two native builds run only the small public reference against the 2,540 frozen raw scalars and compare every output line with Python's exact decimal arithmetic. Both versions produce the same TSV SHA-256, `3888af0f29ebc87a14f51ee6de8fcdd6473b69f01667e4d0389247ffea59581c`. Temporary build trees are removed on exit. [Original scalar corpus](../../../src/node115-quantity-preparation/target-vectors.tsv)

```sh
/tmp/decimal-display-venv/bin/python "$packet/replay.py" --ar "$AR_TOOL"
python3 -m unittest discover -s tests -p test_node115_decimal_display_source.py
```

The stdlib-only tests reread both target FDEs, the incoming calls and all 20 captured destinations. The compiler replay performs the independent source comparisons. The checked/unchecked control measures sensitivity in this particular build. Local controls leave the node's workspace-wide compiler flags, precise dependency version, wrapper source match, helper bodies and full assets/ELF acceptance gates open.
