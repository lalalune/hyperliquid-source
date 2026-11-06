# RE-007: reconstruct node115 selected-row margin arithmetic

Component risk. Target Linux x86-64 node115,105896032 bytes, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Independent base05bc2de303c05525b71e7e257426e741bc66a390, unrebased ELF VAs.
This reconstructs established semantics under approvedScope and RE-007, not
new static discovery. Merged #2223 supplies credited source/row/relocation
context. Node94 #1257 is unrelated retired-target work, not implicitly migrated.
New material is independently authored MIT; no unlicensed inferred code read.

## Three independent point states, one arithmetic family

The complete containing bodies0x38b54b0..0x38b55f3 and0x38b5300..0x38b54a9
are323/425 bytes and82/105 instructions. All748 bytes/187 instructions are
exported with actual FDE/CIE bytes and agreeing GNU/Capstone boundaries. This
is STATIC CONTEXT. The interpreted selection is179 bytes/56 instructions in
the five spans retained in FREEZE.json; all56 selected starts are visited.

The API deliberately keeps three independent points separate:

- First at0x38b5592: fresh raw N in RBX, fresh selected row pointer RCX.
- Second at0x38b53e3: fresh raw N in RBX, fresh selected row pointer R14.
- Post-doubling point0x38b5475: independently fresh row pointer R14. Its first
  actual MOV sets RBX toUINT64_MAX; inactive N input must be canonical0.

Each row supplies c at-0x10 and byte b at-8. b is nonzero, enforced by the new
NonZeroU8 API. Native b0 division faults are outside this premise, not mapped
to an invented rejection. Fields remain stable during each call-free point;
no preservation or equality of b/c across an opaque diagnostic is assumed.
The third point accepts fresh fields and is NOT a callback return, a supplied
helper result or a composed trace of the second entry.

RSP names an already-existing body frame; return marker at+0x68 is the actual
epilogue slot implied by each preserved prologue. Saved registers/other flags
are unknown. Selected code may read only the16-byte row window and bounded
frame. Calls/writes/CFG escapes fail closed. Normal paths execute actual RET,
observe raw RAX and require final RSP+0x70 with input/stack bytes unchanged.
These are qualified point states, not a native function-entry ABI, recovered
struct definition, proof of caller reachability or exception implementation.

## Original arithmetic and boundaries

For the first entry, q=floor(N/(2*b)). If q<c, stop BEFORE0x38b55af (B).
Otherwise actual RET yields q-c. Narrow and wide DIV routes are included.

The second entry checks the high bit of N first. If set, stop BEFORE0x38b5466
(H); do not silently return a saturated result. Otherwise A=2*N, which fits.
The independently fresh post-doubling point instead sets A=UINT64_MAX by the
original MOV. Both then compute P=sat_u64(4*b*c). Actual MUL overflow selects
P=MAX without itself invoking the opaque diagnostic. If A<P, stop BEFORE
0x38b5406 (B). Otherwise actual RET yields floor((A-P)/(6*b)), including both
DIV widths. Equality produces0. B/H are PCs, not global native error variants.

The original parent describes whole-path saturation only conditionally on
normal diagnostic returns. This contribution does not replace that premise
with an unproved callback contract or claim that a borrow returns0. The direct
position dispatcher0x448b800, selected-row lookup0x3cd80d0, row ownership,
diagnostic side effects/nonreturn/unwind, units and full risk policy remain
unimplemented. No full-function/whole-position equivalence is asserted.

## Original-first expectations and corruption controls

Pre-Rust commit981911dc79c08650c12f72f0516c5e78a465cc47 seals5647 distinct
fixtures:2418 first-entry,2418 second-entry and811 fresh post-doubling.3572
actual RET observations,1739B and336H. All255 nonzero b bytes, high-bit N,
quotient/subtraction boundaries, product overflow and fresh point differences
are included. Stimulus equations choose input boundaries only; expected values
come solely from interpreting the authenticated original instructions.

FREEZE.json pins full input/output hashes;55 original smoke rows are retained.
Fifteen actual byte-COW controls alter row offsets, division operands, arithmetic,
guards, scales or saturation immediates and change observations. Original capture
SHA is checked before/after and never modified. No normalization mask or hidden
handler return is used. The unchanged MIT project instruction evaluator and
ELF View from RE-014-price-core-115 are credited reuse. Parent records, frames,
relocations and body exports are pinned supporting context.

All-state margin/Rust/row searches, open issues and active source inspection
found no competing node115 selected-row implementation within search indexing
and unpublished-work limits. Both bodies and the related fresh point are kept
in one PR. Branches, division widths and aliases do not earn separate outcomes.

## Reproduce and qualify

From the repository root with source ../hl-env.sh, Python3.12.14, Capstone5.0.6,
GNUobjdump2.47.20260726 and research rustc1.94.1/LLVM21.1.8:

    python3 research/work-items/RE-007-margin-row-115/native.py
    python3 research/work-items/RE-007-margin-row-115/build.py --rustc <rustc1.94.1> --output <new-directory>
    python3 -m unittest discover -s tests -p test_node115_margin_row.py -v

The historical freeze runs only at the pre-Rust seal checkout. Current native.py
and build.py reproduce frozen stream hashes. Clients receive inputs only,
without target expectations or alternate arithmetic. New no_std Rust uses no
external dependencies or invented recovered Cargo graph. Compilation on
macOSarm64/edition2021 is not an original Linux recipe or compiled body match.
Actual build/check records are retained only after observed completion.

No captured process/Unicorn, service, networking runtime, signing, chain or
wallet action runs. All92 gates remain false; no first-party byte or component
completion credit is requested. Next: close actual selected-row producers and
diagnostic effects before composing a complete risk path.

## Observed Rust comparison

Both rustc1.94.1 opt0/3 input-only clients match all5647 sealed original
observations exactly; optimized own-library repeat is identical. Two ordinary
tests pass per unmodified profile. Eleven compiled corruptions yield1162,1461,
997,2418,1009,230,676,1448,1199,1299,527 mismatches and each fails ordinary
tests with exit101. Complete build/control run153.387s PASS. Compiler,
source/driver/stream hashes and exact outcomes are in rust-results.json.

## Scoped repository checks

Six focused tests, formatting, Clippy, twelve packet-integrity tests, doctor,
artifact/import/packet verification, catalogue generation/check and actual
inventory reproduction pass. Complete scoped run395.259s; exact commands and
individual timings are retained. Only catalogue steps temporarily use the exact
already-submitted #2655 immutable-snapshot helper for its measured39.47GB
repeated-read blocker. validation-overlay.json pins both versions/scope; the
baseline helper is restored before reproduce/commit and absent from this diff.
These two steps are not unmodified-head catalogue validation. Earlier full
585/584-file upstream passes belong to other PRs; this PR's own full CI is
pending. No local full-suite or hosted-CI pass is substituted.
