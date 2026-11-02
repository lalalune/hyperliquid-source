# Raw RPC-context code classification: bounded independent Rust implementation

- Task/component: RE-012 / foundation HTTP response boundary.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline: `e5c9b6436876b2a4a39daef813171f9879317699`. Reference pin stays `999556f6e0a474b8312db96ec3149e1c44e97c23`; inferred unlicensed code was not copied or used as implementation authority.
- Before: the maintained [RE-001-rpc-code-classifier-94](../RE-001-rpc-code-classifier-94/README.md) packet established this selected policy, but no corresponding independent Rust implementation existed in `src/`. After: buildable safe Rust, an external comparison harness and reproducible target-bound validation. No new discovery credit or progress gate is requested.

## Evidence and implementation scope

The 533-byte owner at ELF VA `[0x15bb930,0x15bbb45)` classifies the raw ESI word and stores its kind at output +0x30 and original raw code at +0x34. This module implements only those selected numeric results, using a newly chosen `Classification` interface.

The mapping is -32700→0, -32007→1, -32600→2, -32601→3, -32602→5, -32603→6, otherwise 7, interpreted as raw u32 two's-complement words. No kind 4 is emitted by this selected path. The original raw u32 is retained unchanged. No named enum or original output layout is assigned.

The captured wrapping addition by 32603 is a bijection on u32. Indexes 0..3 therefore have exactly four preimages, distinct from the two explicit singleton comparisons; all other words take the default. This finite partition argument is not exhaustive native execution. Upstream JSON number admission/narrowing, optional-data serialization, allocation, 24-byte copies and full error-constructor/caller closure remain excluded.

`verify.py` authenticates the complete input before calling the existing maintained static analyzer. Fresh records must equal `evidence.json`. Those checks bind the original code/data operands, FDE ranges, branches and relevant supporting records. Existing retained native disassembly remains the review source; this contribution neither copies it into machine-code output nor claims new decoding or helper closure. All addresses are original ELF VAs, not guessed runtime addresses.

## Reproduce

With pinned captures materialized, from the repository root:

```sh
python3 -B research/work-items/RE-012-rpc-code-rust-94/verify.py --rustc /path/to/rustc-1.94.1 --output work/node94-rpc-code-new --controls
```

The output directory must not exist. The production source is `src/node94-rpc-code/lib.rs`. Builds invoke rustc 1.94.1 (`e408947bf`, LLVM 21.1.8) directly with edition 2021, `-D warnings`, `-C overflow-checks=on` and optimization levels 0/3. No Cargo.lock is needed because no Cargo project or external dependencies are introduced. Host: macOS arm64, Python 3.11.15. Host ARM code is not compared to the original x86-64 ELF.

The separate harness receives input words/bytes only. Python retains the expected stream and checks all output lines. This is data-flow separation, not OS sandbox isolation. The signed interval -65,536..65,535, full-width boundary words and 4,096 seeded raw samples are deduplicated and compared. An independent numeric dictionary is checked against the target-bound wrapping-index/table model. The harness returns both kind and original code; it receives no expected answers. Input is u32, so no wider-wire aliasing behavior is invented.

## Observed results

- 135,171 cases per debug, optimized and repeated optimized runner: zero mismatches.
- Both own optimized `.rlib` builds are byte-identical, proving repeatability of this host library only.
- Own Rust unit tests pass; full output is `unit-tests.txt`.
- All 5 independently compiled semantic mutants are detected. The runner changes production code only, leaves test source intact and compares the external output. Results include each mismatch count, compiler identity and source/corpus/output digests.
- Existing static checks and required repository checks are recorded in VALIDATION.md when complete. No broader pass is inferred from the focused results.

## Limits and next work

This is a selected policy implementation over raw scalars/valid byte slices, not a complete recovered subsystem, original ABI or runtime-equivalence claim. Existing decoded semantics remain the proof boundary, and finite examples do not establish whole-node correctness. No JSON number parser or captured code is run. Original imports, captures, tools, reference pins and all component gates remain unchanged.

Next recover and validate the excluded producer/helper/caller contracts before joining this policy into a full node path.
