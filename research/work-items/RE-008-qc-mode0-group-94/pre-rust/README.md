# RE-008: full-word-zero four-integer group intake

Node94 target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base is published #1509 head
`fe1cfb11d40a6c119bc5695224749363f8fa1d97`. This ignored intake uses the existing
authenticated capture; no new capture copy, Rust source, build or public change
has been made. Coordinates are linked ELF VAs; ends are exclusive.

## New bounded question

For second QC-group call `0x4c7e422 ->0x466bf60`, what are the four accepted
integer values, cursor and first-short effects when **u64(D+0)==0**? Markers
0..FA, FB, FC and FD are included; charge C and limit L can be any u64.
Input bytes remain immutable. Decoder state, declared results and scratch
storage are valid and writable; their ranges and address arithmetic do not
wrap. Input/state/result ranges do not alias one another or a callee's own live
control/preservation machinery. Declared output temporaries in ancestor frames
are allowed: G is row-local RSP+0x28, and the scalar temporary is group-local
RSP+8. They are intentional writable argument slots, not forbidden stack
aliases. Ordinary returns/preserved registers and no external mutation are
premises. The first eight state bytes being zero is a byte-level premise, not
a recovered constructor or source enum.

This domain differs from #1509's admitted mode1 FD-only paths. Existing scalar
semantics are credited to #1365; new work is the mode-zero, variable-width
four-call composition and its actual QC caller/output route.

## Mode and charge facts

- `0x466bf74` compares only the mode DWORD to 1. Zero takes JNE `0x466bf77`
  to `0x466bfa8`, bypassing every reserve/limit load and charge store. The LEA
  at `0x466bfa8` computes D+0x20 without reading that word.
- Each scalar wrapper's DWORD comparison at `0x466bd11/14` likewise jumps to
  `0x466bd39`, bypassing all C/L operations.
- After the first three successful calls, the group tests **QWORD(D+0)** at
  `0x466bfdd`, `0x466c020`, `0x466c05f`. Zero takes the three JE edges past
  charge loads, underflow guards and refunds. Reader stores address D+0x10/+0x18
  only, so they cannot change that full-word-zero premise under the disjoint
  memory conditions.

Thus C/L are not loaded and C is never stored on the selected paths, including
first-short returns. C may exceed L or equal MAX. Merely asserting a zero low
DWORD is insufficient: the refund tests have a different width. Nonzero upper
words have no assigned native outcome here.

## Accepted markers and lengths

| Marker | Payload bytes | Total consumption on success | Value |
| --- | ---: | ---: | --- |
|0..FA|0|1|unsigned marker byte|
|FB|2|3|little-endian u16, zero-extended to u64|
|FC|4|5|little-endian u32, zero-extended to u64|
|FD|8|9|little-endian u64|

At `0x466bd3d/41`, remaining N>8 selects the fast arms; N<=8 passes D+0x10
and EDX=0 through `R_X86_64_RELATIVE` slot `0x57745e0 ->0x466d980`. The frozen
RELA is type 8/symbol 0; both dispatch tables and their signed-relative targets
are pinned. The wrapper and Reader agree on accepted successful values/cursors;
there is no minimal-encoding test on these arms. FD completion inside this
wrapper always takes the fast arm; its Reader completion arm is context only.

For example, `01 fb3412 fc78563412 02` consumes 10, produces
`[1,0x1234,0x12345678,2]` and visits fast/fast/Reader/Reader with remaining
`[10,9,6,1]`. C is unchanged. Four immediate bytes can instead visit the Reader
four times. FB/FC Reader endian selection and final zero-extension operations
are explicitly checked, not inferred from the fast arms alone.

A short marked field first consumes its marker and leaves all available
payload unread. Needed bytes are payload-width minus available payload:
FB needs 2-m, FC 4-m, FD 8-m. Empty input before the next marker consumes nothing
and needs 1. The group stops after that primitive, returns tag qword 1, kind
**byte** 0 and need qword at G+0/G+8/G+0x10. The already-qualified shared row
error corridor forwards these active fields and returns before recovery.
Other error bytes/padding/full 40-byte error images remain unspecified.

## Native identity and frozen data

Four complete bodies/FDEs are reauthenticated from node94:

| Body | FDE | Bytes | Body SHA-256 |
| --- | --- | ---: | --- |
|`0x466bf60..0x466c13f`|`0xef1f28`|479|`aa484554c9abb65bea26e5450e6cda287fc037cc7c53a47ed5e04e2069ab44a0`|
|`0x466bd10..0x466bdf5`|`0xef1eac`|229|`fca33a99b93d22ee7cde15b995c1faf05b6fc7f4967c1489ecaf77030d0f6f5e`|
|`0x466d980..0x466dabc`|`0xef2378`|316|`1f88da45c1b59f158544acc1df436cf698e6e4dcc10e960db50b102f8ae42f5b`|
|`0x4c7e340..0x4c7e60d`|`0xf443ac`|717|`691aada3f78a0a84acaa2b4e75ce3c58fe68b1e852aa29a98e464287e1ebf512`|

All use CIE `0xce1518`, have no LSDA and uniquely match the unwind index.
Two fresh GNU/LLVM generations have identical 130/69/95/168 instruction
partitions. Existing complete exports are dependency-hashed and checked against
the same target bytes. Complete body/context retention is not a new whole-body
recovery or target-byte equivalence claim.

`inputs.tsv` and separate `expected.tsv` freeze 96 target-derived cases before
new Rust: 36 asymmetric successes, 56 short FB/FC/FD cases across positions 1..4,
and 4 EOF cases. Each small-width family is placed at each position with exact
remaining 8/9, plus full-FD, nonminimal, unsigned maxima and mixed-order cases.
Inputs include C=MAX with L=0; no source budget policy may reject that domain.
No expected data will enter an input-only Rust driver.

Twelve frozen native controls cover charge bypass, all four fast widths,
coherent FB/FC Reader pointer/length widths, Reader FB sign-extension, a narrowed
Reader output store and each marked shortfall. The narrowed-store witness uses
a prior complete FD value to initialize the temporary high word; it does not
assume an arbitrary uninitialized stack value. These are static semantic
counterexamples, never executed patched binaries.

`API-EXCLUSIONS.json` contains only chosen future API rejections for wrong mode
word or FE/FF marker. It assigns **no native outcome** and is separate from the
96 target cases. `PRE-RUST-FREEZE.json` records full identity, data/CFG sites,
case roles, source dependencies and controls.

## Ownership and implementation boundary

Fresh scan: 238 open PRs/three pages. #1509 owns the existing group/caller
context. #1365 head `4d33431de9eb9c5c9c8d145d1e61b75a9634d57f` owns scalar
wrapper/Reader behavior. #1526 head `4978c066af5695dc59a8f62d2eae59645421df16`
composes different response helper `0x466c770..0x466c8ae`, not this group.
#1366 head `198ff2d031763ccf2e075ca91762abba70340a94` owns outer construction
at `0x4752890`, not these parser errors.

Rust follows independent frozen-evidence review. The genuine existing
`hl-bincode-varint` Reader can supply accepted scalar values/cursors; using a
proper path dependency would require a documented component lock/build and
exact dependency source closure in the selected-client verifiers. No dependency,
new crate or callback ABI has been invented here. Caller mode construction,
whole-QC reachability, original ABI/lifetimes, inactive errors, unwind and
cryptographic meaning remain open. All full component gates remain false.
