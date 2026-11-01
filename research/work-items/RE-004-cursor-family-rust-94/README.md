# RE-004: four cursor leaves with exact register and image effects

Target node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`;
reference gitlink `999556f6e0a474b8312db96ec3149e1c44e97c23` unchanged.
Task/component: bounded RE-004/foundation additional research. No component,
coverage or progress gate is advanced. Node115 and visor are not targets.

## Result

The new safe no_std library `src/node94-cursor-family` reconstructs complete
entries at 0x52c6e50,0x52c6e70,0x52c6e80 and 0x52c6ea0 (100 body bytes,
30 instructions). These compute a bounds difference plus 40, dereference the
cursor, advance unless equal to the terminal value, and retreat-or-wrap.
Full RAX/RDX and every final image byte are projected; Read preserves incoming
RDX, while the other members retain their loaded bounds pointer. Arithmetic
wraps without invented bounds ordering, alignment or source-container types.

The predecessor `foundation-cursor-retreat-or-wrap-94` qualified retreat
statically and warned against separate sibling-mining packets. This one
contribution groups the coherent family, including the intervening read leaf;
it does not claim an original component census. Only new source/evidence is
added. No inferred unlicensed source was read or copied.

PROOF.md derives the full relation from every instruction and covers reached
reads, arbitrary data aliases, no-op paths, exact store width, full-register
preservation, normal-return premises and new safe image refusals. A field need
not exist in the supplied image if its member/path never reads it. All reads
precede a possible store, so overlapping bounds/pointer/cursor bytes are handled
from the same entry image. No native pointer is created from a numeric address.

## Static closure and native qualification

`verify_static.py` binds all four actual FDE/CIE records, complete bodies and
12/4/5/7 padding bytes. GNU/LLVM/Capstone agree without masks on all boundaries.
Four raw-zero symbol-zero RELATIVE naming slots have unique full-width writers.
All 80,300 RELA records and complete .text E8/E9 candidate scans are checked;
no direct candidate, helper call or RIP-relative data dependency exists. These
scans are not a complete indirect-reference census. All 62 structural controls
are rejected independently of the initial whole-artifact digest check.

A dictionary-based immutable-image oracle was frozen before Rust existed.
All 22,300 cases per build matched at opt0/opt3 and repeats: 89,200 total,
including 56,100 admitted projections and 33,100 new API refusal checks. This
finite qualification complements the universal proof; it is not a full
memory-map enumeration. Every output byte is compared, including the unchanged
inactive image suffix. The input-only client receives no expected values.

All 25 compiled wrong implementations are detected, including eager unused
reads, equality replaced by ordering, altered stride/wrap arithmetic, premature
stores, register clobbers and wrong output widths. Same-option library/client/
output hashes repeat; three units per optimization and framing/comparator
corruption controls pass. No build/control failure occurred. All 196 final raw
stdout/stderr streams are retained losslessly with SHA-256 identity in the
content-addressed gzip archive (level1,mtime0). All 25 successful mutant metadata
compilation commands and generated sources are also archived.

The compiler is installed rustc 1.94.1,
commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`,
SHA-256 `b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Flags pin aarch64-apple-darwin, edition2024, denied warnings, overflow checks,
one codegen unit, panic abort for value builds and the actual system linker.
GNU2.47.20260726, AppleLLVM17 and Capstone5.0.7 provided static exports.
No captured binary/instruction emulator ran. Only newly authored native Rust
executed; original machine ABI, compiled-byte identity and whole-node behavior
remain unclaimed.

```sh
python3 -O -B research/work-items/RE-004-cursor-family-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-cursor-family-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/cursor-family-replay
```

Use a new output directory. Compiler location may differ; version and binary
hash remain checked. Exact commands, tool versions, source hashes, raw outputs,
mutants and first mismatch witnesses are retained in native-result/commands
and the archives. Static target instructions are evidence locks, never a Rust
implementation or executable transplantation.

## Repository verification limits

Doctor, verify, catalogue-check, reproduce, all 29 focused predecessor/FDE/GNU tests
and rustfmt all passed; exact results are retained in `repository-checks.json.gz`.
The separate shared baseline attempted 971 files/15,462 tests/69 skips. Original
exit2 was solely three disk-full errors, and all 20 affected tests passed isolated
retries. `shared-baseline-result.json` preserves that qualification and its log
hashes. This is not a successful full-sweep repeat, a per-head full suite,
skipped Linux execution or hosted CI success. Imported pins, generated progress
and acceptance gates remain unchanged.

## Independent review

A separate reviewer independently authenticated all 100 body bytes, four FDEs and four unique RELATIVE slots across all 80,300 records, then reran all 62 static controls. An interval reader, XOR action table and whole-image integer overlay matched all 22,300 frozen register/image results. Witnesses include 172 Read cases without bounds storage, 122 Span cases without cursor storage, 232 unequal Retreat cases without second-bound storage, 615 wrapped field formations and 1,031 aliased read/store roles. The corpus has no Advance case with an absent first bound; the complete instruction/source proof independently establishes that omission. This finite coverage limitation is preserved. The portable script, hashes and qualification record are retained; no peer native replay is implied.
