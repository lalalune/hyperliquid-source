# RE-008: distinct key collections in the Node115 stake/count caller

- Component: consensus; partial RE-008 quorum-math work, not its full transition acceptance.
- Target: Linux x86-64 node #115, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Source/reference base: 05bc2de303c05525b71e7e257426e741bc66a390.
- Coordinates: original linked ELF virtual addresses, half-open ranges; raw exports also include file offsets and FDE records.
- Question: which inputs feed the two tests at caller 0x28aa050, and does the count test reuse the stake keys?
- Result: the caller projects two different map fields, at +0 and +0x20. After the first key collection passes the saturating stake predicate, it builds the second collection for a strict count/fraction test. The second test is not a cryptographic verifier.
- Claim: target-bound static observations and a conditional logical Rust reconstruction. No original ABI, native execution, machine-code equality or acceptance gate is claimed.

## Prior work and the gap

The existing RE-001-node115-validator-stake-saturation packet establishes the selected/all saturating reductions and strict wide comparison. It explicitly leaves caller collection provenance open. The integration packet RE-003-pr-integration-20261103 already censuses this caller's 798 bytes; merely decoding them is not new coverage.

PR #2750 reconstructs the flat-map stake predicate, including ring lookups and repeated supplied key occurrences. That implementation and its test corpus are not copied here. This contribution instead follows the enclosing caller's distinct source fields and subsequent count gate. Shared predicate owners, lookup #2033 and iterator #2308 are credited, not claimed as newly recovered bytes. The other predicate caller at 0x595bc40 belongs to RE-008-tc-parallel-abort-115 and is not included in this implementation.

## Observed dataflow

The full 0x28aa050..0x28aa36e unwind extent contains 798 bytes / 215 instructions. FDE extents are unwind metadata, not proof of whole semantic function ownership.

| Original coordinates | Observation |
| --- | --- |
| 0x28aa05e..0x28aa067 | Preserve original RCX in RBX, RDX in R14, RSI in R12, RDI in R15. |
| 0x28aa06a; 0x28aa136 | Read first map header at original RDI+0; construct descriptor and call key collector 0x22bdfa0. Flat rows have 96-byte stride; sentinel 2^63 selects the tree-shaped path. |
| 0x28aa13b..0x28aa147 | Forward original RSI and first collection to relocation slot 0x64e6a98 -> 0x4d3e1a0; retain Boolean result. |
| 0x28aa149..0x28aa1c6 | Destroy the first temporary, then test retained result. Failure returns false at 0x28aa1ff without collecting the second map. |
| 0x28aa1c8; 0x28aa2a3 | Load a different map header at original RDI+0x20; construct descriptor and invoke the same collector. |
| 0x28aa2a8..0x28aa2b1 | Forward original RDX as fraction pointer, original RCX as member-set reference and the second collection to 0x2738a80. |
| 0x28aa2b6..0x28aa333 | Destroy second temporary and return its saved Boolean. EH cleanup/unwind edges are retained but not reconstructed. |

The collector reads each projected key as 16+4 bytes, collects a 20-byte-stride vector, selects sort paths for lengths 2..20 versus >=21, initializes a 232-byte node and calls builder 0x1cdcdb0. The builder compares complete 20-byte keys, skips equal adjacent keys and increments output length once per emitted key. Empty output has null root and length zero; inactive height is not initialized. The Rust API consumes logical key projections, not these memory descriptors.

The count guard at 0x2738a80..0x2738c7f (511 bytes / 124 instructions) loads q from its first argument. An ordered comparison to zero returns true for either sign of zero before iteration. Otherwise it iterates the supplied second collection, searches the member tree with the actual imported memcmp (symbol 12, slot 0x64dfb50), and checked-adds one for each match. Key width is 20 bytes. It converts matches and member length from u64 to binary64 using the retained vector constants, multiplies q*length, then UCOMISD/SETA returns strict ordered matches > product. NaN therefore returns false. It does not impose a positive/finite-q guard.

## Logical implementation and domain

src/node115-stake-count-gate is independently authored MIT Rust with only the standard library and its own lockfile. Its safe API takes two distinct key projections, immutable weights and immutable members. It deduplicates projections into sets, computes selected B and total S with saturating u64 additions, compares 2*S < 3*B in u128, destroys the first temporary, then applies the count guard to the second set. Keeping both sums separate matters at overflow; reusing one collection for both stages changes normal results.

This is conditional on canonical stable source maps, key collection yielding their unique complete keys, preserving sort/comparison helpers, valid finite allocation and normal return. Full tree traversal, both sort implementations, allocator/drop behavior, original types, concurrency, native struct parsing and unwind semantics remain unclosed. Safe sets are not a recovered physical map implementation. In particular this does not reproduce #2750's malformed/ring-duplicate domain or assert that protocol inputs admit duplicate keys. The original higher-level policy and signature/message transition remain unknown.

## Reproduce and controls

From repository root, with Python, Capstone 5 and GNU objdump:

    python3 research/work-items/RE-008-node115-stake-count-gate/check.py
    python3 research/work-items/RE-008-node115-stake-count-gate/check.py --export <output-directory> --objdump <GNU-objdump>
    python3 -O research/work-items/RE-008-node115-stake-count-gate/check.py
    cargo test --offline --locked --manifest-path src/node115-stake-count-gate/Cargo.toml
    cargo test --offline --locked --release --manifest-path src/node115-stake-count-gate/Cargo.toml

bindings.json pins nine complete FDE byte ranges, 32 instruction boundaries, the predicate/sort relocations, memcmp symbol and u64 conversion constants. The checker exports full GNU/Capstone partitions and checks equality without masking. Five byte-corruption controls bypass file/body digests intentionally to exercise named instruction pins. These are static integrity controls, not behavioral execution or exhaustive semantic proof.

predictions.tsv contains 18 manual expectations frozen before Rust authorship (SHA-256 fae80b665bb4b46bed0c99673f6c04f8ab3c9783fe4ebbe93ff5858b8a86d5a5). They cover distinct-key sources, empty/missing keys, strict ties, saturation, both zero signs, nonfinite fractions and negative fractions. They are native-derived predictions, not captured outputs or blind independent authorship. The Rust integration test evaluates every row. Separate compiled wrong programs challenge swapped sources, wrapping sums, inclusive count comparison and missing zero shortcut.

Actual focused validation: both offline locked Rust profiles pass all18 frozen rows. All four wrong programs compile successfully, then fail the behavioral test (exit101). The complete native export passes for all9 FDE ranges /7,149 bytes and all5 named corruption controls. See validation/rust.json and validation/static.json with logs. The public reproduce_rust.py was actually run successfully, the static checker also passed with Python -O, and make catalogue passed (validation/portable.json). Disassembler labels are nearest exported-symbol offsets, not recovered function names. These focused results do not establish repository-wide success. Mandatory repository checks are pending the foreign shared-validation lock; their actual final status is recorded separately before submission.

## Limits and next question

No source-built native ABI, Linux node build, container/network compatibility, instruction execution, original/Rust binary comparison or gate completion is established. The consensus component map records the logical implementation path; make catalogue regenerated its tables. All 92 full-scope gates remain false; no byte-window registration or imported evidence is changed. The next question is to close collection sorting/traversal invariants and establish the caller's original higher-level message/state identity before integrating it into consensus.
