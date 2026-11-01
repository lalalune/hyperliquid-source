# RE-001: ordered two-scalar multiword combination

This packet reconstructs the complete node94 leaf at
`0x565e7a0..0x565e956` in independent safe `no_std` Rust. Before this work, only
unwind gap-table endpoints mentioned the entry/end; there was no semantic
packet or source implementation for it. The new implementation preserves the
literal fifth-word correction, both signed scalar minima, early-store aliases
into later input loads, every final destination byte, and complete RAX/RDX.

Task RE-001, foundation; author 신준. Baseline
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23`, unchanged. Target is Linux x86-64
node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
New code/docs are independently authored MIT work. No unlicensed inferred
implementation was read or copied; imported artifacts retain their rights.
No pins, prior packets, progress gates or byte-coverage registrations change.

## Established relation

Let `M=2^64`, `s(v)` be signed interpretation of a u64, and x/y be the two
scalar bit patterns. The target first snapshots five words A from source+0.
Conditionally negate A in 320 bits when x is negative, obtaining A'. Set
`mx=abs(s(x))`, `P=(A' mod M^4)*mx`, and `K=word4(A') & mx`.
It stores the first four product words into destination+0 **before** reading
eight later words B from source+40. B therefore includes any overlapping
bytes changed by those early stores.

The final 64 destination bytes encode

`(s(y)*B + P - K*M^4) mod M^8`.

The fifth-word operation really is AND; arbitrary fifth words are supported.
The product carry minus K always fits signed64 because `mx<=2^63`, giving a
universal signed-extension proof without an invented sign-limb invariant.
The final native multiply uses signed IMUL; its low product and signed high
half plus incoming carry are retained as full RAX/RDX. Later destination
addition does not change those registers.

The [complete proof](PROOF.md) derives each stage, multiplication/carry bounds,
exact auxiliary registers, MIN handling and the image-order theorem from the
full instruction body. Neither a number-system identity nor an original
source type or signature is inferred.

[The source](../../../src/node94-two-scalar-combination/README.md) takes a mutable
image, its numeric base, source/destination addresses and both scalar words.
The complete 104-byte source and 64-byte destination must fit in a nonwrapping
image. Partial, exact and unaligned aliases are admitted; all word/scalar bits
are unrestricted. Both fixed-address spans are validated before the first
write. Refusal leaves the whole image unchanged, while admitted later loads
still observe the earlier stores. This is an ordinary-memory value projection;
native faults, MMIO, concurrent changes, control-memory aliases, other register
state and the original ABI are excluded explicitly. The leaf clobbers registers
that a standard ABI might otherwise preserve, so no extern-function signature
is invented.

## Complete static evidence

`static_evidence.py` authenticates the full target, decodes all 121,299 FDEs and
three CIEs, and rejects any additional overlapping frame. The leaf's unique
actual FDE covers 438 bytes/130 instructions. The sole caller FDE
`0x565df20..0x565e78b` covers 2,155 bytes/472 instructions. Both bodies, exact
FDE records and shared CIE are locked; GNU and LLVM independently agree on all
instruction byte partitions.

All seven E8 candidates in the full 70,370,352-byte `.text` scan are actual
call instructions within that complete caller, at `0x565e43f`, `0x565e4b8`,
`0x565e531`, `0x565e5aa`, `0x565e623`, `0x565e69c` and `0x565e6c8`.
There are zero E9 candidates naming the entry. This does not exclude indirect
callers or references. The caller's other outgoing calls are retained as
byte context; its full algorithm is not reconstructed or added to this leaf's
semantic claim.

The leaf has no calls, RIP-relative data references or internal branches.
All 80,300 RELA records are scanned: none names the entry or writes either
bound code body. The 21 padding bytes after the caller and ten after the leaf
are separately locked. The adjacent FDE `0x565e960..0x565ea92` is checked only
as a boundary; its implementation is outside this contribution.

## Independent pre-Rust oracle and native evidence

`oracle.py` uses whole 320/256/512-bit integer arithmetic, one explicit early
32-byte image replacement, and a whole signed second product. The raw register
oracle independently uses the final signed two-operand product and a seven-word
prefix carry; Rust instead uses the unsigned full-product carry and signed
high-half correction. No instruction execution, flag simulation, captured
binary invocation or imported Rust logic is involved.

The oracle, 4,990 input cases and exact expected outputs were frozen at
`2026-11-01T22:24:09.086915+00:00`, before the Rust directory existed. Raw and
compressed fixture bytes and the oracle file have fixed SHA-256 values. No
post-Rust supplement was needed. The input-only Rust client receives IDs and
inputs on stdin, and reports status, all RAX/RDX bits and every changed image
byte; it never receives expected values.

Coverage comprises 1,479 disjoint cases, 1,813 early-store aliases into the later
snapshot, 1,462 other aliases, 158 range refusals and 78 image-wrap refusals.
Among admitted cases, 1,498 use x=MIN and 1,210 use y=MIN. Cases include every
one of the 832 source bit bases, every relative overlapping byte displacement,
scalar-bit boundaries, arbitrary fifth-word patterns, exact map endpoints and
deterministic synthetic random images.

Observed qualification, retained under `native/`:

- 4,990 cases at opt0 and opt3, each built twice: all 19,960 comparisons match
  without masks. The rlib/client hashes repeat within each optimization level.
- All 32 compiled mutants exit normally and differ on observable output.
  They cover endian changes, lost carries, sign mistakes and saturated MIN,
  fifth-word canonicalization/multiplication, missing early/final stores,
  wrong later-load offset, incomplete raw register handling, sign extension,
  refusal side effects, overstrict spans and rejected overlaps. Exact mismatch
  counts and first witnesses are retained; no compile failure counts as a kill.
- All 149 static corruption controls reject: every leaf instruction boundary,
  all seven caller sites, actual FDE/CIE records, padding and adjacent boundary,
  an extra overlapping FDE, call/jump census changes, naming and code relocations,
  and the full target digest. Structural controls bypass only the full digest
  to exercise their specific lower-level rejection.
- Five comparator controls and two archive controls reject altered register
  values, image deltas, IDs/count/order, invalid archive indices and wrong raw
  stream hashes. The deterministic shared-line archive retains all 36 exact
  stdout streams with reconstructable byte counts and SHA-256 values.

Only newly authored Rust ran on macOS arm64 using Rust 1.94.1. These are native
checks against a target-grounded mathematical relation, not captured-target
differential execution, Linux ABI qualification or rebuilt-byte identity.
Finite tests do not replace the universal proof or complete the caller/node.

## Reproduce and scope limits

From repository root with the pinned artifacts materialized:

```sh
python3 research/work-items/RE-001-two-scalar-combination-rust-94/oracle.py
python3 -O research/work-items/RE-001-two-scalar-combination-rust-94/verify.py --out work/two-scalar-combination-replay
python3 -O research/work-items/RE-001-two-scalar-combination-rust-94/verify.py --check-archive
python3 -m unittest tests.test_fde_extents tests.test_elf_index -v
cargo +1.94.1 check --manifest-path src/node94-two-scalar-combination/Cargo.toml --locked --offline
```

The validator requires standard-library Python plus the existing ELF/FDE
parsers, GNU/LLVM objdump and Rust 1.94.1. No third-party Rust dependency or root
workspace is introduced. Override disassembler paths using
`GNU_OBJDUMP`/`LLVM_OBJDUMP`, or rustc via `--rustc`. Use a fresh output directory.
Exact compiler arguments, native platform/version information, source hashes,
raw results and controls are retained. Builds enable overflow checks, warnings
as errors, abort panics and deterministic temporary-path remapping.

All 22 focused ELF/FDE tests, locked offline Cargo check, rustfmt, `make doctor`,
`make verify`, `make catalogue-check` and `make reproduce` passed. Exact exits
and logs are under `checks/`. The check PATH prepended installed GNU binutils
and rustup directories; Cargo output stayed under ignored
`work/two-scalar-combination/cargo-target`. No full-suite sweep was duplicated.
The shared baseline sweep reported 971 files/15,462 tests/69 skips; its original
exit 2 came solely from three Errno28 disk errors, and all 20 affected tests
passed isolated retry. This is not a clean aggregate rerun on this head, and
hosted CI or skipped Linux checks are not claimed.

Initial overlap inspection covered 169 open PRs, zero issues and 50 recent
merges; final inspection covered 173 open PRs, zero issues and 50 recent merges.
No matching range/source or semantic-name claim was found. Parent reservation
preceded substantial edits. Full public inventories and their hashes are
retained under `overlap/`.

Only the new source and evidence directories change. From this packet directory,
`shasum -a 256 -c MANIFEST.sha256` verifies all retained files, source and reused
static parsers/tests. Indirect consumers, the complete caller algorithm and
adjacent arithmetic helpers remain outside scope. No progress gate or whole
node equivalence is claimed.
