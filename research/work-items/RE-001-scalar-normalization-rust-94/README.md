# RE-001: scalar-sum normalization with ordered input aliases

This contribution reconstructs the complete node94 leaf
`0x565eaa0..0x565ec0b`, previously mentioned only as FDE/context in nearby
research. It adds independent safe `no_std` Rust for its initial scalar stores,
two corrected scalar products, wrapped 320-bit sum, 31-bit extraction,
conditional magnitude, and full RAX/RDX/RCX observations.

Task RE-001, foundation; author 신준. Baseline
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23`, unchanged. Target is Linux x86-64
node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
New source/docs are independently authored MIT work. No unlicensed inferred
implementation was read or copied. Imported artifacts retain their existing
rights; prior evidence, pins, gates and generated coverage are untouched.

## Closed behavior and safe domain

The function stores scalar words x/y to destination+0/+8 before reading either
256-bit operand A/B. Those operands therefore come from the staged image,
including the new scalar bytes on aliases. For signed-u64 interpretation s,
its per-operand contribution is

`F(U,z) = s(z)*U - (abs(s(z))*2^256 if s(z)<0 and U=0 else 0)`.

The extra term is required: four-word conditional negation drops its carry,
while the separate negative top correction remains. Replacing this behavior
with ordinary signed multiplication changes negative-scalar/zero-input cases.
The [proof](PROOF.md) derives the term and both signed minima directly from the
complete native multiply/carry sequence.

Reduce `F(A,x)+F(B,y)` modulo `2^320`, then interpret that residue as signed320
Z. The 32 destination bytes become `abs(floor(Z/2^31)) mod 2^256`.
The sign is selected from the wrapped sum's bit 319, not the unbounded sum or
truncated output. RAX is one exactly when Z is negative; RDX and RCX are x/y
independently negated modulo `2^64` for that sign, otherwise unchanged.
A negative path may have a zero truncated output while retaining RAX=1.

[The image API](../../../src/node94-scalar-normalization/README.md) admits every
scalar and operand bit pattern and arbitrary partial/unaligned data aliases.
The complete 64-byte source and 32-byte destination must fit in one nonwrapping
image. Both spans are validated before any write, and refusal leaves the image
unchanged. This new refusal is separate from native fault/partial-write
behavior. Ordinary stable memory, valid disjoint code/control and the proof's
normal-return premises are required for correspondence. MMIO, concurrency,
other registers, flags, stack/RET effects and the original ABI are excluded.
No source type, number-system role, library identity or extern signature is
inferred.

## Complete static closure

The full target digest and all 121,299 FDEs/three CIEs are revalidated. The leaf
has exactly its actual 363-byte/109-instruction FDE overlap. The sole direct
caller is the complete `0x565df20..0x565e78b` FDE, 2,155 bytes/472 instructions.
Both bodies, actual FDE records and shared CIE are locked; GNU and LLVM agree
on every instruction byte partition.

The full 70,370,352-byte `.text` E8/E9 candidate scan finds 30 E8 sites in that
caller and zero E9 candidates targeting this entry. All 30 sites are verified
instruction boundaries. This does not exclude indirect callers. The caller's
other callees and overall algorithm remain context, outside the leaf claim.
The leaf itself has no outgoing calls, internal branches or RIP-relative data
references. All 80,300 RELA records are scanned: none names the entry or writes
either bound body.

Twenty-one padding bytes after each selected body are separately bound. The
next FDE `0x565ec20..0x565ecb2` is retained only as a boundary, not reconstructed.
The nearby `0x565e960..0x565ea92` helper is also excluded. Neither its shared
caller context nor the older subtraction packet's historical numeric mention
constitutes a duplicate implementation of this leaf.

## Pre-Rust oracle and actual native qualification

`oracle.py` uses staged byte replacement, two whole 256-bit integers,
zero-corrected signed products, whole 320-bit residue/sign selection and an
absolute floor quotient. It does not mirror the Rust word loops, execute
instructions, model flags or import implementation logic. Inputs, expectations,
their compressed bytes and the oracle file were hashed and frozen at
`2026-11-01T22:35:11.766302+00:00`, before the Rust directory existed. No
post-Rust supplement was needed.

The 4,652-case corpus contains 2,210 disjoint cases, 2,021 early-store aliases,
187 other aliases, 150 range refusals and 84 image-wrap refusals. Admitted
cases include 424 negative-zero x terms, 402 negative-zero y terms, 356 sums
outside signed320 before wrapping, 999 x=MIN cases, 738 y=MIN cases and 170
negative paths with zero truncated output. It also covers every one of the
512 source bit bases, all relative overlapping byte positions, scalar-bit and
31-bit quotient boundaries, exact map endpoints and deterministic random images.

The input-only Rust client sees only IDs/inputs and reports status, every
changed image byte and all three complete register values. The comparator
retains expectations independently and uses no masks. Recorded results:

- All 4,652 cases match at opt0 and opt3, each built twice: 18,608 native
  comparisons. Rlib/client hashes reproduce within each optimization level.
- All 36 compiled mutants return normally and differ on observable output.
  They include conventional negative-times-zero replacement, lost carries,
  saturated MIN, missing/swapped early stores, wrong input half/scalar,
  incorrect 320-bit sign/overflow handling, shifted-output sign selection,
  truncation toward zero, missing cross-word shift bits, coupled scalar carries,
  omitted final stores, overlap refusal and refusal side effects. No compiler
  failure is counted as a kill; all first witnesses and mismatch counts remain.
- All 151 static corruption controls reject: full digest, every leaf instruction
  boundary, all 30 caller sites, FDE/CIE/padding/adjacent boundary, an added
  overlapping FDE, call/jump census changes, naming and code relocations.
  Structural controls bypass only the full digest to exercise the relevant
  lower-level rejection.
- Five comparator controls and two archive controls reject changed registers,
  image bytes, IDs/count/order, invalid archive indices and wrong stream hashes.
  The deterministic shared-line archive retains all 40 exact stdout streams,
  with every reconstructed byte count and SHA-256 checked.

Only newly authored Rust ran on macOS arm64 with Rust 1.94.1. The evidence is
native qualification against a target-grounded mathematical relation, not
captured-target differential execution, target instruction emulation, Linux
ABI qualification or rebuilt-byte identity. The universal argument is in the
proof; finite cases are not a whole-node correctness claim.

## Reproduction, repository checks and overlap

From repository root with pinned artifacts materialized:

```sh
python3 research/work-items/RE-001-scalar-normalization-rust-94/oracle.py
python3 -O research/work-items/RE-001-scalar-normalization-rust-94/verify.py --out work/scalar-normalization-replay
python3 -O research/work-items/RE-001-scalar-normalization-rust-94/verify.py --check-archive
python3 -m unittest tests.test_fde_extents tests.test_elf_index -v
cargo +1.94.1 check --manifest-path src/node94-scalar-normalization/Cargo.toml --locked --offline
```

Use a fresh output directory. The validator uses standard-library Python,
existing ELF/FDE parsers, GNU/LLVM objdump and Rust 1.94.1. Override disassembler
paths via `GNU_OBJDUMP`/`LLVM_OBJDUMP`, or rustc with `--rustc`. Rust has no
third-party dependencies. Exact compiler arguments, versions, source hashes,
artifact hashes, raw outputs and controls are retained. Builds use warnings
as errors, overflow checks, abort panics and deterministic path remapping.

All 22 focused ELF/FDE tests, offline locked Cargo check, rustfmt, `make doctor`,
`make verify`, `make catalogue-check` and `make reproduce` passed. Exact command
exits and logs are under `checks/`. The check PATH prepended installed GNU
binutils and rustup; Cargo output stayed under ignored
`work/scalar-normalization/cargo-target`.

No full-suite sweep was duplicated. The shared baseline reported 971 files,
15,462 tests and 69 skips; its original exit 2 resulted solely from three
Errno28 disk failures, with all 20 affected tests passing isolated retry.
That is not a clean aggregate rerun on this head. Hosted CI, skipped Linux
checks and complete caller/node behavior are not claimed.

Initial live inspection covered 176 open PRs, zero issues and 50 recent merges;
final inspection covered 180 open PRs, zero issues and 50 recent merges.
The sole address match was PR #1400's historical correction of a false overlap
claim: that PR implements `0x565ee40..0x565ee9b` and `0x565eea0..0x565eeba`,
not this leaf. The distinction and complete inventories are retained under
`overlap/`. No source implementation overlap was found. Parent reservation
preceded substantial edits; adjacent helper scopes were explicitly excluded.

Only the new source and evidence directories change. From this packet directory,
`shasum -a 256 -c MANIFEST.sha256` checks all retained files, source, validators
and reused parsers/tests. Whole-node identity, original-source recovery and
acceptance-gate completion remain unclaimed.
