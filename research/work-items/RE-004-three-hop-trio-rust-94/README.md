# RE-004: three-hop field/store trio

Target node94: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23` unchanged.
This closes a bounded Rust gap; no component or progress gate advances.

The safe `no_std` library reconstructs the complete three-hop accessor family
at 0x514acc0, 0x514acf0 and 0x514ad20. Each reads O+0x788, follows P+0x8e8,
then reads Q+0xcd0/0xa70/0xa78, stores the raw qword, returns full RAX=1 and
preserves full RDX. All reads precede the sole write, so arbitrary output/input
aliases are supported. The selected three functions contain 102 bytes and
21 instructions; their 42 following INT3 bytes are bound separately.

PROOF.md covers the complete value/memory domain, independent wrapped field
formation, zero numeric pointer bases, exact read widths and unchanged bytes
outside the eight-byte output. Numeric addresses never become host pointers.
None is an unchanged-image refusal for missing spans or a wrapping image, not
original fault behavior. ABI, flags, MMIO, races, native mappings for synthetic
addresses and control-stack aliases are outside the projection.

## Evidence and independent expectations

All three unique FDEs/CIEs and full bodies agree across GNU, Apple LLVM and
Capstone. Full .text E8/E9 scanning finds no direct candidate; all 80,300 RELAs
contain no entry naming or body/padding writer. No helper, static table or
opaque dependency remains. These scans do not establish complete indirect
reachability. All 28 structural corruption controls are effective.

The historical static trio is PR#1286. PR#1287's neighboring two-hop reader
and PR#1296's call-sum pair mention this area but have different bodies and
remain excluded. Local source and live PR checks found no existing Rust
implementation of these three functions.

An immutable-address-map composition and output-overlay oracle froze 7,653
cases before Rust existed: 5,177 admitted results and 2,476 refusals. Coverage
includes 992 output aliases, 270 read-role aliases and 1,719 admitted wrapped
object fields. Dedicated fixtures admit zero object/first/second numeric bases.
The input-only client receives descriptors/data, never expected bytes. All
1,280 fixture bytes, status, full RAX and full RDX are compared. The library
itself has no 1,280-byte limit; that capacity belongs only to fixture framing.

The first control-generation attempt selected an ambiguous return-field anchor
that also matched a unit-test expectation. Its first-source mutation also left
an unused parameter, rejected by denied warnings in metadata/native compilation.
Because that initial command sequence continued after preflight failure, it
completed four correct native builds before stopping at the malformed control.
The original generator, validator, preflight records, 85 exact files and native
diagnostic are retained in initial-harness-failures.json.gz. The corrected full
return-object anchor and parameter-retaining wrong expression were preflighted
successfully for all 25 controls before a fresh native qualification. The base
Rust source, proof, original oracle and frozen corpus were unchanged. No
implementation-value mismatch or post-freeze fixture addition occurred.

Compiler: rustc 1.94.1, commit e408947bfd200af42db322daf0fadfe7e26d3bd1,
SHA-256 b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6.
Builds bind aarch64-apple-darwin, edition2024, denied warnings, overflow checks,
one codegen unit and the system linker. Static tools: GNU 2.47.20260726,
Apple LLVM 17 and Capstone 5.0.7. Only newly authored Rust executes; no captured
binary, instruction emulator, original compiled-byte identity or whole-node
behavior is claimed.

```sh
python3 -O -B research/work-items/RE-004-three-hop-trio-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-three-hop-trio-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/three-hop-trio-replay
```

Use a new output directory. The compiler location may differ while its identity
remains checked. Exact commands, source pins, outputs, mismatch witnesses and
failure records are retained; expectations are never rewritten from Rust output.

## Shared baseline limits

The separate baseline attempted 971 files / 15,462 tests / 69 skips. Original
exit2 was solely three disk-full errors; all 20 affected tests passed isolated
retries. shared-baseline-result.json retains that outcome and log hashes.
No successful full-sweep repeat, per-head full suite, skipped Linux run or
hosted-CI success is claimed. Imports, pins, catalogue and gates stay unchanged.

## Final qualification and second review

All 7,653 records match opt0/opt3 and repeat builds: 30,612 observations,
20,708 admitted results and 9,904 unchanged-image refusals. All three unit
tests pass per optimization and repeat artifacts have identical hashes. All
25 compiled controls are effective: 12 alter admitted values and 13 affect
admission only. The exact 196 streams / 98 commands occupy the lossless
175,585,536-byte native archive; verify_recorded.py independently checks its
payload hashes, full-image results and mismatch witnesses. The separate
36,590,917-byte initial-failure archive preserves the original harness errors.

A second reviewer independently rederived all 7,653 records with direct
interval reads and explicit entry-byte snapshots. Fresh GNU bytes, manual ELF
unwind/relocation scans and all structural controls agreed. The parent replay
exactly reproduced that report. Peer read-command path mistakes are retained
in peer/review.json; they did not affect computed expectations. Doctor, verify,
catalogue-check, reproduce, 29 focused predecessor/FDE/GNU tests and rustfmt pass.

The final live scan contains 204 open PRs, zero open issues and 100 recent
merges. Only the three historical static packets described above match; none
supplies the selected Rust reconstruction. The inventory and classification
are retained in final-overlap.json.gz.
