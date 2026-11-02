# Post-delegate JSON-related tail admission: bounded independent Rust implementation

- Task/component: RE-012 / foundation HTTP response boundary.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline: `e5c9b6436876b2a4a39daef813171f9879317699`. Reference pin stays `999556f6e0a474b8312db96ec3149e1c44e97c23`; inferred unlicensed code was not copied or used as implementation authority.
- Before: the maintained [RE-001-json-trailing-admission-94](../RE-001-json-trailing-admission-94/README.md) packet established this selected policy, but no corresponding independent Rust implementation existed in `src/`. After: buildable safe Rust, an external comparison harness and reproducible target-bound validation. No new discovery credit or progress gate is requested.

## Evidence and implementation scope

The 440-byte owner at ELF VA `[0x15ba010,0x15ba1c8)` delegates first, then scans forward from the returned cursor. This module implements only that established post-delegate policy. It does not parse a response or trim before parsing.

`finish_tail(output_word, input, cursor)` bypasses scanning for raw word `0x8000000000000001`. Otherwise it admits exactly bytes 09/0a/0d/20, increments the cursor only for admitted bytes, and reports local code 0x16 at the first other byte. A cursor at or beyond length follows the observed no-scan exit; this is not proof that an oversized cursor is reachable. Form feed 0x0c, vertical tab and high bytes are excluded. The unsigned byte bound before the target BT instruction prevents high-byte aliases.

The new `TailResult` is a safe abstract interface, not the original 104-byte result layout. Delegate semantics, error construction, cleanup/allocation helpers, full caller behavior and reachable cursor states remain unresolved.

`verify.py` authenticates the complete input before calling the existing maintained static analyzer. Fresh records must equal `evidence.json`. Those checks bind the original code/data operands, FDE ranges, branches and relevant supporting records. Existing retained native disassembly remains the review source; this contribution neither copies it into machine-code output nor claims new decoding or helper closure. All addresses are original ELF VAs, not guessed runtime addresses.

## Reproduce

With pinned captures materialized, from the repository root:

```sh
python3 -B research/work-items/RE-012-json-tail-rust-94/verify.py --rustc /path/to/rustc-1.94.1 --output work/node94-json-tail-new --controls
```

The output directory must not exist. The production source is `src/node94-json-tail/lib.rs`. Builds invoke rustc 1.94.1 (`e408947bf`, LLVM 21.1.8) directly with edition 2021, `-D warnings`, `-C overflow-checks=on` and optimization levels 0/3. No Cargo.lock is needed because no Cargo project or external dependencies are introduced. Host: macOS arm64, Python 3.11.15. Host ARM code is not compared to the original x86-64 ELF.

The separate harness receives input words/bytes only. Python retains the expected stream and checks all output lines. This is data-flow separation, not OS sandbox isolation. All 256 one-byte and all 65,536 two-byte suffixes, supplied-cursor offsets, the raw sentinel and its adjacent word, empty input, ignored prefixes and `usize::MAX` cursors are covered. Expectations use an independently enumerated byte set and are cross-checked against the maintained mask model. The corpus does not assume any example prefix was accepted by the original delegate.

## Observed results

- 65,915 cases per debug, optimized and repeated optimized runner: zero mismatches.
- Both own optimized `.rlib` builds are byte-identical, proving repeatability of this host library only.
- Own Rust unit tests pass; full output is `unit-tests.txt`.
- All 6 independently compiled semantic mutants are detected. The runner changes production code only, leaves test source intact and compares the external output. Results include each mismatch count, compiler identity and source/corpus/output digests.
- Existing static checks and required repository checks are recorded in VALIDATION.md when complete. No broader pass is inferred from the focused results.

## Limits and next work

This is a selected policy implementation over raw scalars/valid byte slices, not a complete recovered subsystem, original ABI or runtime-equivalence claim. Existing decoded semantics remain the proof boundary, and finite examples do not establish whole-node correctness. No actual parser, network client or captured code is run. Original imports, captures, tools, reference pins and all component gates remain unchanged.

Next recover and validate the excluded producer/helper/caller contracts before joining this policy into a full node path.
