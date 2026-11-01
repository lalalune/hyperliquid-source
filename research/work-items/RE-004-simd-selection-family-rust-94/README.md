# RE-004: staged SIMD selection family

Node94: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` and reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23` remain unchanged.
This adds one bounded family reconstruction; no progress gate advances.

`src/node94-simd-selection-family` implements six complete leaves at
0x5657540, 0x56575a0, 0x5657620, 0x5657700, 0x5657880 and 0x56579a0.
They select 32/48/96/192/144/288 bytes using the low32 control bits, read both
sources, and advance all three numeric pointers by half the selected width.
Full entry RAX/RCX are preserved. The leaves load the next pair of16-byte
blocks before storing the previous block. Larger widths therefore observe
some earlier writes when source and destination overlap. Neither a whole-input
snapshot nor immediate block stores reproduce the entire admitted domain.

PROOF.md derives an acyclic byte-origin relation, exact GP outputs, all accesses
and arbitrary data aliases. The independent Python oracle uses that relation;
safe no_std Rust uses two16-byte buffers and the actual block schedule.
Both complete source spans remain required even when one is masked out.
Numeric addresses describe a nonwrapping finite image, never native pointers.
Missing spans cause a new atomic None refusal. Native ABI, SIMD output state,
flags, faults, MMIO, races and control-data aliases are outside the projection.

## Evidence

All1,581 bytes/360 instructions, six unique FDEs/shared CIE, and separate
8/10/28/26/8/3-byte NOP pads are authenticated. GNU, Apple LLVM and Capstone
agree on bytes and boundaries. An independent static operand walk validates
every block access and pointer bias. All84 E8 and2 E9 candidates lie in34
fully retained caller FDEs totaling19,221 bytes/4,852 instructions. Caller
algorithms are context only. All80,300 RELAs are checked; none names a selected
entry or writes the retained leaf bodies/padding. Indirect-reference completeness
is not claimed. All187 structural corruption controls are effective.

The pre-Rust freeze contains9,944 cases:8,519 admitted projections and1,425
refusals. Four native builds yield39,776 matching complete observations,
including the entire640-byte fixture image and five full registers. Of the
admitted cases,2,898 distinguish staged aliasing from a whole-input snapshot.
The input-only client never receives expectations. All26 compiled mutants are
effective, covering widths, selector interpretation, load/store order, aliasing,
pointer advances, preserved registers, missing unselected spans and image bounds.
Admission-only mutants qualify the new safe API domain, not original fault
behavior. Three units per optimization, malformed-input checks and comparator
controls passed. Same-option library/client/output hashes repeat exactly.

An initial rustfmt parse failure found two missing `fn` keywords in unit-test
declarations. The exact initial source/stdout/stderr are retained in
initial-rustfmt-failure.json.gz. The declarations were corrected before native
qualification; the original oracle/freeze were unchanged. All26 mutant sources
passed metadata compilation before the native run; the complete preflight is
retained. No native qualification failure occurred.

Native commands, all exact stdout/stderr, first mismatch witnesses and source
hashes are retained. The gzip archive is lossless, content addressed, level1
with mtime0. Only newly authored Rust executes. Captured binary execution,
instruction emulation, original compiled-byte identity and whole-node equivalence
are not claimed.

Compiler: rustc1.94.1, commit e408947bfd200af42db322daf0fadfe7e26d3bd1,
SHA-256 b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6.
Builds bind aarch64-apple-darwin, edition2024, denied warnings, overflow checks,
one codegen unit and system linker. Static tools: GNU2.47.20260726,
Apple LLVM17 and Capstone5.0.7.

```sh
python3 -O -B research/work-items/RE-004-simd-selection-family-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-simd-selection-family-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/simd-selection-family-replay
```

Use a new output directory; the compiler path may differ while its identity
remains checked. Captured bytes are static evidence only.

## Shared baseline

The separate baseline attempted971 files/15,462 tests/69 skips. Original exit2
was solely three disk-full errors; all20 affected tests passed isolated retries.
shared-baseline-result.json retains these outcomes and log hashes. No successful
full-sweep repeat, per-head full suite, skipped Linux run or hosted-CI success
is claimed. Imports, pins, catalogue and generated gates stay unchanged.

All repository checks (`doctor`, `verify`, `catalogue-check`, `reproduce`), 21 focused FDE/GNU tests and rustfmt passed; exact outcomes/streams are archived. The independent recorded audit rechecks all202 streams/101 commands and all39,776 native comparisons. Of26 mutants,22 alter successful values and four alter only safe admission: missing masked-out source A/B, strict endpoint and ignored image overflow. The retained native archive is103,825,044 bytes.

## Independent review

A separate reviewer read the complete source/proof, checked fresh disassembly of all six leaves, and derived all9,944 expected observations using timestamped A/B block snapshots and staged stores. This differs from the original byte-origin relation. Independent ELF/FDE/RELA parsing and full caller byte/boundary checks authenticated40 FDEs and all86 direct sites. All187 static controls also passed. The parent replay reproduced all computed results. A concurrent README check-summary addition triggered the reviewer hash guard; the reviewer reread it and retained both hashes. The parent report comparison initially also included that manual annotation, then confirmed exact computed-result equality after excluding only documentation metadata. Both diagnostics are retained; source, proof, oracle and static evidence were unchanged. No independent native replay is claimed.
