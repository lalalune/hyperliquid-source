# RE-001: close the byte selector and its equality wrapper

Component: foundation. Target node94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Base main: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; pinned reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference code was not read or copied. Author: 신준.

The predecessor `foundation-helper-low-byte-equality-94` proved the 49-byte wrapper's AL comparison while explicitly leaving its 104-byte callee unknown. This packet reconstructs that complete selector and closes the actual call. All selector return paths zero-extend RAX, so the wrapper's full register result is exactly 0/1. The historical arbitrary-callee examples remain historical conditional observations; no prior evidence is modified.

New independent Rust: `src/node94-bounded-byte-selector/`. Complete observed bodies: selector `[0x4ff8ac0,0x4ff8b28)` (104 bytes, 32 instructions); wrapper `[0x5004e70,0x5004ea1)` (49 bytes, 13 instructions). ELF VAs and section-resolved file offsets are retained. The descriptive names are inferred; original names, types and wider algorithms are unresolved.

## Relation and safe scope

`select_byte` preserves flag-zero return without reads; cached-byte sentinel and signed wrapping field-minus-one comparison; full64 empty-span comparison and default byte; index-zero shortcut; and the positive part of the signed low32 minimum of relative index and span-minus-one. No positive length or valid-array assumption is imposed. The data address addition wraps at 64 bits. `matches_stored` preserves eager inner-bound loading, argument forwarding and final stored-byte comparison.

Both APIs read an immutable image addressed by abstract u64 values. Required ranges alone must fit; fixed field formation/image extents must not wrap. A selected byte may fit while the low pointer itself is outside the image. Missing required ranges return `Unavailable`. The full return value is preserved; data memory is never written. Native control storage must be disjoint, ordinary and valid. Fault timing, permissions, concurrent/MMIO behavior, stack/control/data aliases, fixed-field wrap, unobserved registers and native pointer ABI are excluded. The implementation is `no_std`, forbids unsafe code and has no dependencies. `PROOF.md` establishes every path, width transition and access premise.

## Static closure

Full-target authentication precedes section and unwind parsing. All 121,299 FDEs/3 CIEs are decoded; each selected body/caller has exactly its bound overlap and exact FDE/CIE bytes. GNU and Apple LLVM independently agree on every decoded byte/instruction partition. The eight complete external caller FDEs total 40,618 bytes and 8,449 instructions. Nine selector calls (including the wrapper's call) and one wrapper call are confirmed instruction boundaries; all `.text` E8 patterns reaching either entry are accounted for. The wrapper's single call is closed. Selector has no calls; all branches stay inside their respective bodies. Neither body has a RIP-relative static-data dependency.

All 80,300 RELA entries are scanned: no entry addend names either function and no relocation overlaps protected code. Eight selector alignment bytes and fifteen wrapper alignment bytes are separately bound. Seven larger caller FDEs are shared context with the distinct gated-block-copy body at 0x4ff8b30; their algorithms are not claimed. E8/addend scans do not establish a complete indirect-reference census.

`static/records.json`, dual decoder exports and `static/frames.txt` retain this evidence. Seventy-six corruptions test body instructions, incoming calls, FDE ranges, both CIEs, padding, added call patterns, naming relocations and code relocations. These local checks run below the whole-file hash gate; a separate full-target corruption tests that gate. No captured instructions are executed or emulated.

## Independent expectations and native qualification

The mathematical Python oracle was fixed before Rust existed, using a piecewise address/value relation and arbitrary-precision residues. Final pre-Rust freeze: 4,716 cases, `fixtures/freeze.json`; input SHA-256 `1ac30a4fb5025958b8a6221d333a92464398a6961652a5a720cc05f285db1e5f`, expected SHA-256 `154f11d3c871cecf7cec400eac69bb4ff7796091f8f4b9b82d816e18eaa07997`. It covers all byte values, signed boundaries, low32 truncation versus full64 equality, exact lengths, unused/unavailable fields, invalid mappings and wrapper argument/ordering cases, plus seeded synthetic images. The pre-Rust review expansion is recorded separately.

The initial run passed all four correct builds and 25 compiled controls, but the checked-address-add control survived. Its failure and all 30 exact streams are retained. The original oracle, corpus and Rust remain unchanged. A clearly separated post-Rust supplement adds 24 cases using the direct equation `(2^64-missing+step) mod 2^64 = step-missing` when nonnegative, cross-checked against the original oracle. Fifteen of these witness valid wrapping reads and reject checked-add substitution. Its timestamp and source hashes are in `fixtures/supplement.json`; it is not represented as pre-Rust evidence.

The fresh full qualification passed 4,740 cases (4,716 pre-Rust + 24 post-Rust) in each of four native executions: optimization 0 twice and 3 twice, 18,960 exact status/full-RAX comparisons. Every build at a given optimization reproduced both rlib and client hashes. All 33 actual compiled mutants exited normally and produced observable differences. Four comparator corruptions and two archive corruptions were rejected. The client receives only inputs and never expected outputs; no output masks apply. `native/result.json` records per-mutant counts/witnesses, exact source/artifact hashes and tool versions; `native/commands.json` records compilation. Final source SHA-256: `3ba2af51c1ec29ae5d516fd76351ab0e419ea2ad2cd1e35908f08245f255d46b`.

The two deterministic gzip archives retain 30 initial and 37 final exact stdout streams using lossless shared-line dictionaries. `audit_archives.py` reconstructs and checks every stream. The initial surviving mutant, failed qualification log and compiler commands remain inspectable. This is host execution of new Rust against target-derived mathematical expectations, not a native target differential or machine-code identity test.

## Checks, overlap and limits

`COMMANDS.md` gives exact reproduction and chronology. Focused predecessor static checker and all 15 tests passed. Cargo offline check, rustfmt, doctor, verify, catalogue check and reproduce passed. Doctor's first attempt selected Apple objdump from PATH and failed; that log is retained, followed by the successful GNU-binutils PATH invocation. No installation, shared configuration, imported evidence, pins, catalogue or progress files changed. The full test sweep was not repeated and is not claimed here.

Read-only scope inventories retained 119 initial and 122 final open PRs (including drafts/reviewed work), 30 recent merges at each check and zero open issues. No selected-address/semantic match or prior Rust implementation was found. The static predecessor's explicit callee gap is the bounded question answered; nearby or shared-caller work is distinguished in `overlap/summary.json`.

No whole-node build/equivalence, source identity, original runtime mapping, hosted CI result or progress gate is claimed. The outer callers' roles and the meaning of their stored byte/pointer fields remain unresolved.
