# RE-001: byte-class selection across every u32 input

Component: foundation. Target node94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Main base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink `999556f6e0a474b8312db96ec3149e1c44e97c23`, unchanged and unread. Author: 신준.

The predecessor `foundation-byte-range-select-94` corrected an earlier scout's reversed selection rule, but left Rust unimplemented and confirmed only three of its 113 direct call candidates as instruction boundaries. This packet reconstructs the complete leaf `[0x359be70,0x359bebe)` (78 bytes/26 instructions), proves its complete raw RAX relation for all u32 pairs, and confirms every direct caller boundary. New source: `src/node94-byte-class-selector/`.

## Relation and domain

The first argument's low byte selects the complete first u32 for values 192..223. Other classes return the second u32 unchanged or rewrite only its low byte: first byte 1..143 uses low four bits plus 128, byte 144 uses low four bits plus 144, and byte 160 uses low five bits plus 160. The second value's upper 24 bits survive every second-derived path; all first bits survive first-derived paths. Every native return writes EAX and therefore zero-extends full RAX. Incoming argument bits32..63 cannot affect this value.

`PROOF.md` derives the disjoint/exhaustive class partition, exact range direction, zero case, signed-compare domain and high-field separation. It proves all 2^64 pairs of u32 inputs without pretending to enumerate all upper 24-bit combinations. No source identity, UTF/text interpretation or meaning of the numeric classes is inferred.

The safe `no_std` function accepts every u32 pair without a data-validity premise. It returns the complete u64 RAX projection. The native leaf has no input-memory read/store; no pointer, alias, alignment or allocation premise is needed. Scratch registers, flags, timing, instruction/control faults and native ABI are excluded. This is a value reconstruction, not a callable machine-code replacement.

## Complete static evidence

Full target authentication precedes section mapping and all 121,299 FDE/3 CIE decoding. The leaf and 104 complete caller FDEs have exactly their bound overlaps and exact used FDE/CIE bytes. The callers total 84,739 bytes/20,643 instructions. GNU and Apple LLVM agree on every byte and instruction partition, retained in combined complete caller exports. All 113 E8 candidates are verified instruction boundaries. Two trailing INT3 bytes are separately bound.

The complete 80,300-entry RELA scan finds no entry-naming addend or relocation overlapping protected code. The selected leaf has no call, external branch or RIP-relative data dependency. Its broader callers and indirect/computed references remain outside the claim. Static records and complete exports are under `static/`.

The packet-local verifier uses complete prefix-maximum interval indexes to avoid repeating exhaustive window scans for each corruption. An audit checks all 105 bound FDE queries, all 80,300 relocation destinations and 735 additional boundaries against exhaustive predicates. A new control moves an otherwise unselected FDE onto the leaf. The indexes alter lookup cost, not the bound inventory or overlap rule. All 252 static controls passed, reaching instruction/caller/FDE/CIE/padding/call-census/relocation checks below the full-target gate, except the separate full-target corruption itself.

## Independent pre-Rust expectations

Before the Rust source directory existed, the independent oracle built an explicitly disjoint/exhaustive low-byte classification table and evaluated outputs by base-256 quotient/remainder arithmetic. Rust uses range matching and bit masks. No target instruction emulator, captured execution, copied inferred implementation or Rust result supplied expectations.

All 77,412 cases were frozen before Rust: every 65,536 low-byte pair plus 11,876 high-bit/full-u32 witnesses. The latter exercise each bit 8..31 in both argument roles, mixed prefixes, boundaries and seeded random inputs. Input SHA-256 `20cb0f52c3242a6890ef5f0a82154e11a31a5e714f468b2e0dacf4de74c31281`; expected SHA-256 `6132e2a631833055333aec01d0bdab72afb54607aab8f8502eb73629a4e83377`. Oracle/source/fixtures remained unchanged during qualification.

The first two attempts were interrupted during static corruption checking before any native build or execution. Logs and checker versions are retained in `initial/` and `logs/`; `COMMANDS.md` explains the indexing adjustment. Control review also identified a mask 0x0f→0x1f change under OR 0x90 as equivalent, verified all 256 low-byte cases, and replaced that uncompiled candidate with mask 0x3f. The equivalent candidate is not counted. No source or oracle fix, post-Rust fixture supplement, failed compiler build or failing correct native result occurred.

## Native qualification and validation

The fresh complete run passed all 77,412 cases at opt0 and opt3, twice each: 309,648 exact full-RAX comparisons. Library/client hashes repeated at each optimization. All 22 actual compiled mutants exited normally and differed from frozen expectations; the smallest mismatch count is 358. Four comparator controls and two archive controls were rejected. Inputs only enter the standalone client; expected outputs never do. No masks apply.

`native/result.json` records exact source/artifact/compiler/platform hashes and per-mutant witnesses/counts; `native/commands.json` records compilation. Source SHA-256 `8710b0c8779ba32ea0a5d842e880c19f706f46964929772e4ee02cb5deb98921`. A deterministic lossless shared-line archive retains all 26 exact stdout streams and verifies their hashes/lengths. This is host Rust versus target-derived mathematical expectations, not captured-native differential execution or compiled-target-byte equivalence.

Focused predecessor checker/10 tests, Cargo offline check, rustfmt, doctor, verify, catalogue-check and reproduce passed. Global exits are retained in `logs/global-results.json`. Exact reproduction, initial interruptions and archive checks are documented in `COMMANDS.md`. No full test sweep or hosted CI outcome is claimed on this head. Imported evidence, pins, global config, progress and catalogue are unchanged.

Live initial/final scope inventories and source searches are retained in `overlap/`; no selected-address/semantic overlap was found. No whole-node build/equivalence, source identity or progress gate is claimed. The callers' higher-level roles and meaning of these numeric classes remain unresolved.
