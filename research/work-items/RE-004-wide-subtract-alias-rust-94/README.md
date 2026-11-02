# RE-004: ordered wide-subtract memory aliases and exact RAX

The existing `src/node94-wide-subtract` implements a two-value numeric API and
explicitly excludes mutation/copy order, aliases and register return values.
This contribution adds `image::subtract_into_image` to that same library and
closes those exclusions for the complete node94 leaf `[0x32d8310,0x32d8361)`.
The original numeric function, client and 1,352 vectors are retained unchanged;
`lib.rs` gains only the documented module declaration.

Early minuend writes can alter later subtrahend loads, so entry-snapshot integer
subtraction is insufficient. The later 16/8/8 copy also reads its source in
stages. With difference words `(1,2,3,4)` and destination eight bytes above left,
the copied result is `(1,2,2,2)` and full RAX is 2. The last borrow-byte store
can alias operand bytes but cannot change the saved register. The new API
preserves every admitted byte overlap and observes the full resulting image.

Target node94: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink:
`999556f6e0a474b8312db96ec3149e1c44e97c23`. No inferred unlicensed source was
read or copied. New source/docs are independently authored under MIT; captured
bytes/disassembly retain the artifact's rights. Prior evidence, reference pins,
registries, catalogues and progress gates remain untouched.

## Complete target binding and proof

The [proof](PROOF.md) follows the complete subtract/borrow relation and every
read/write stage. It covers arbitrary u64 words, all unaligned overlaps, exact
RAX and checked-span safety. The independent arithmetic derivation uses whole
prefix integers and immutable byte overlays, rather than a decoded-instruction
interpreter or the Rust borrow loop. The two original numeric values are not
mistaken for the effective aliased operands.

Fresh GNU/LLVM/Capstone decodes agree on all 81 body bytes and 24 instructions.
The sole complete caller `[0x3299180,0x32996b6)` is retained; both sites
`0x32994ed` and `0x3299579` are instruction-aligned calls to the leaf. Exact
FDE/CIE records, 15 following INT3 bytes, straight-line body closure, all 80,300
RELA entries and the whole-text direct E8 scan are checked. Sixteen structural
corruption controls reject below the full-file identity gate. Complete raw
exports, tool/command hashes and structural records are retained without a
compiled-byte normalization mask. Indirect references and complete caller
semantics are not inferred from the bounded scan.

One ordinary stable memory image represents the accessed ranges. Left and
right each occupy 32 bytes; destination requires 33 bytes including the borrow
flag. No alignment or disjointness assumption is added. Correspondence requires
nonwrapping target effective addresses, valid read/write permissions, unchanged
code/control state and no concurrent or MMIO effects. The checked slice API
has no native pointer ABI. `Unavailable` is new atomic refusal policy; native
fault timing and partial fault writes are explicitly excluded.

## Frozen oracle and native qualification

Before the new image module existed, `oracle.py` froze 22,809 descriptors and
full-image/RAX expectations: 22,733 successes and 76 safe refusals. Existing
numeric source already existed and is acknowledged. The freeze guard checks
absence of the new image implementation, never pretends the entire library was
absent. Hashes and raw streams record local chronology rather than external
attestation. The new oracle does not import the numeric implementation or run
captured instructions.

Successful cases include 17,252 overlapping left/right regions, 17,435
output/left overlaps and 16 layouts with all bases equal. Every right/left
displacement -31..31 is combined with every output/left displacement -32..31
under four entry patterns. Bit perturbations span all eight alignments, and
additional arithmetic, seeded-image, exact-end and missing-span cases exercise
both word values and image admission. The 256-byte backing size is a harness
choice, not an API cap.

Each opt0/opt3 library/client pair is rebuilt and rerun, totaling 91,236 exact
native observations with zero mismatches. Each profile's repeated rlib,
executable and output hashes match. Five unit tests pass per optimization:
four new image behavior tests and the unchanged test of 1,352 numeric vectors.
Expected outputs are never provided to the native client, which emits status,
full RAX and all 256 backing bytes, including unchanged bytes beyond its slice.

All 15 wrong implementations compile, exit normally and mismatch. Fourteen
have admitted-value witnesses: snapshotting all subtrahend words changes
5,711 cases, snapshotting the whole copy changes 4,640, dropping borrow changes
8,646, combining borrow bits with AND changes 10,255, returning the third word
changes 12,351, and returning the destination changes 22,700. Rejecting exact
endpoints instead produces 89 false refusals; that is an admission control,
not a changed admitted-value witness. `native/result.json` separates these
counts and retains first inputs/results and source/artifact hashes. Two
comparator controls reject a changed record and a missing byte; malformed
partial native input is rejected before output. All 132 actual stdout/stderr
streams are archived losslessly with payload hashes.

Independent review recomputed all 22,809 cases using direct signed-integer limb
relations and explicit live snapshots, with zero mismatches. Target identity,
complete leaf/caller bytes and unwind records were independently checked. No
blocker or source change resulted; `peer-review.txt` binds the reviewed module.
All 8 focused legacy tests, new-module rustfmt, doctor, verify, catalogue-check
and reproduce passed. `repository-checks.json.gz` retains those command results
with path-only redaction. Current Rust/verifier hashes and all 132 native streams
were checked before commit. No unrelated existing source was reformatted.

## Reproduction and limits

From repository root with pinned artifact inputs materialized:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
export LLVM_OBJDUMP=/usr/bin/objdump
python3 -O -B research/work-items/RE-004-wide-subtract-alias-rust-94/oracle.py
python3 -O -B research/work-items/RE-004-wide-subtract-alias-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-wide-subtract-alias-rust-94/verify_rust.py \
  --out work/wide-subtract-image-review \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc
python3 -B -m unittest tests.test_foundation_wrapping_subtract_borrow_out -v
rustfmt +1.94.1 --check --edition 2024 src/node94-wide-subtract/image.rs src/node94-wide-subtract/image_driver.rs
make doctor verify catalogue-check reproduce
(cd research/work-items/RE-004-wide-subtract-alias-rust-94 && shasum -a256 -c MANIFEST.sha256)
```

Use a fresh `--out`. The qualified native host is macOS ARM64 and Python
3.14.3; rustc 1.94.1 commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM
21.1.8, actual executable SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The dependency-free rlib/client build uses explicit flags, warnings denied,
overflow checks enabled and the pinned native target. Exact tool/version pins
require separately labeled qualification on a different host. Static tools
are GNU binutils 2.47.20260726, Apple LLVM 17 and Capstone 5.0.7. Native validation
ran under Python `-O` with explicit evidence guards. No captured code or
instruction emulator ran, and no target compiled-byte identity is claimed.

The parent's shared full legacy sweep remains separate from this packet;
aggregate or hosted-CI success is not claimed. This completes a bounded memory
relation excluded by the existing value API. It does not recover original types,
caller intent, native compiler provenance or whole-component/node equivalence.
