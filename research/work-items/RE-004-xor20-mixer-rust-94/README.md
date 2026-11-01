# RE-004: node94 twenty-byte overlapping-load mixer in Rust

The existing `foundation-xor-mixer-94` packet established a static relation
but left its Rust implementation open. This adds a dependency-free `no_std`
value reconstruction of the complete `[0x4b27620,0x4b27669)` leaf: 73 bytes,
22 instructions, three unsigned full-width products and no branches/calls.
Target node94 is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` and reference gitlink is
`999556f6e0a474b8312db96ec3149e1c44e97c23`.

## Result

For `F(a,b)=low64(a*b) XOR high64(a*b)` and little-endian eight-byte reads
W at offsets 0, 4, 8 and 12 of a single twenty-byte array, the return is

```text
F(F(W(8)^S1, W(12)^S0) ^ F(W(0)^prefix, W(4)^S0) ^ 20, S0).
```

The [proof](PROOF.md) accounts for every multiply/high-half fold, overlapping
read, seed selection and tag, and proves the integer arithmetic for all
admitted input bits. The single-array API retains overlapping-byte correlations.
The public safe value function has no data-dependent error path. A prefix word
and two seed snapshots are explicit inputs; stable ordinary readable memory
is the original correspondence premise. The original pointer ABI, volatile or
concurrent reads, faults, flags, scratch RDX and seed initialization are outside
the returned-RAX claim.

The RIP-relative slot at `0x576e3e0` has a unique symbol-zero relative
relocation to `0x5788348`. The sixteen seed bytes lie in writable NOBITS `.bss`
and a writable PT_LOAD memory extent. Their runtime contents are unknown.
The slot's pre-relocation zero bytes are neither runtime seeds nor evidence
of a null pointer. The static checker handles the memory-backed NOBITS edge
explicitly instead of pretending that its addend has file bytes.

## Static evidence

`static.json` binds the complete leaf and caller bytes, file offsets and
hashes, CIE/FDE records, padding, decoded instruction rows and seed relocation.
All 121,299 FDEs are parsed and overlap-checked. The leaf body SHA-256 is
`299a5c9f54001c3f32800a37423ac3f12ed6cb41569889ef9c8b9f51695aa222`.
The complete caller `[0x4dd6ea0,0x4dd839e)` has 5,374 bytes and 1,034
instructions, SHA-256
`e4b2645c76cffe63617ef7ef27331aa7a453b7957f49d6d0a262df7ab8771c7a`.
The whole-text direct-E8 scan's single site `0x4dd768f` is confirmed at a
caller instruction boundary. This is not an indirect-call census or caller
reconstruction.

GNU objdump, Apple LLVM objdump and Capstone agree on every body byte and
instruction boundary. Exact raw GNU/LLVM exports are retained. Two caller
LOCK prefixes printed separately by LLVM are joined only after checking the
single F0 byte and contiguous addresses; no operand text is normalized into
evidence. The complete relocation scan checks the unique seed slot and
absence of relocation writes over protected code/seed-read regions. It does
not exclude ordinary runtime writes to `.bss`.

Ten intentional structural corruptions reach and fail body, padding, FDE,
CIE, caller, slot-word or seed-relocation checks after bypassing only whole-file
authentication. The unchanged original artifact is never executed or modified.
`overlap.json` records current public work checks and the local Rust gap;
prior static packets remain unchanged. No inferred reference implementation
was opened or copied. New Rust and prose use the repository MIT license;
captured bytes and disassembly retain the original artifact's rights.

## Independent native checks

The oracle was frozen before Rust source creation. It decodes bytes using
base-256 sums and computes products with four 32-by-32-bit multiplication
columns and explicit carries. The proof derives that relation independently
of Rust's u128 operation. It uses no decoded instruction or captured-state
evaluator. `frozen.json` binds the unchanged oracle and exact compressed input
and expectation streams.

There are 11,104 distinct input cases: boundary word/seed combinations,
every byte value at each of twenty positions, power-of-two neighbors and
4,096 deterministic varied inputs. In 192 cases seed0 is zero. This finite
corpus corroborates the all-input proof; it is not exhaustive enumeration.
An independent read-only reviewer regenerated all cases and checked them
against unbounded products plus 121 product-edge pairs, reviewed all source
and seed semantics, and reran the static verifier under Python `-O`.

The input-only native driver receives 44-byte records (prefix, twenty bytes,
two seeds) and emits only an eight-byte result. It cannot read expectations.
All 11,104 cases match at opt0 and opt3, each built and run twice: 44,416 row
comparisons. Repeated rlib, client and stdout hashes match within each level.
Two unit tests run per level; incomplete input is rejected before output.

Ten wrong variants actually compile, exit normally and differ from the same
frozen corpus: big-endian reads (10,113 rows), offset12→11 (10,149), offset4→0
(9,717), wrong first seed (10,389), ignored prefix (10,245), missing first
high half (10,417), missing second high half (10,357), missing final high
half (10,594), tag16 (10,533), and wrong final seed (10,912). Two comparator
controls detect one altered row and a missing output byte. No compilation
failure or crash is counted as a killed mutant.

`native/result.json` binds source, verification scripts, exact compiler and
linker binary hashes, artifacts, outputs and first mutant counterexamples.
`native/commands.json` records arguments, statuses and stream hashes.
`native/streams.json.gz` losslessly retains all 102 stdout/stderr streams
with deduplicated base64 payloads and SHA-256 values; the verifier checks the
archive against its raw streams before accepting the result. The recorded
host is macOS ARM64, rustc 1.94.1 commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8, Python 3.14.3.
The actual rustc binary SHA-256 is
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Cross-host reproducibility and target-byte matching are not measured.

## Reproduce

From the repository root with pinned artifacts materialized:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
export LLVM_OBJDUMP=/usr/bin/objdump
python3 -O -B research/work-items/RE-004-xor20-mixer-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-xor20-mixer-rust-94/verify_rust.py \
  --out work/xor20-review \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc
python3 -B -m unittest tests.test_foundation_xor_mixer -v
rustfmt +1.94.1 --check --edition 2024 src/node94-xor20-mixer/*.rs
make doctor verify catalogue-check reproduce
(cd research/work-items/RE-004-xor20-mixer-rust-94 && shasum -a 256 -c MANIFEST.sha256)
```

The native output directory must be fresh. Compiler binary pinning deliberately
requires the recorded macOS compiler; an alternative host requires a separately
labeled validation record. Static decoder export equality likewise uses the
recorded versions. `repository-checks.json.gz` retains raw check logs with hashes.
All eleven focused predecessor tests, rustfmt, and repository checks passed.
The shared full legacy sweep remains pending and is not claimed as this packet's
result. No hosted CI success, original binary execution, whole-node equivalence,
caller purpose, source identity, catalogue edit or component progress gate is
claimed. Only this packet and `src/node94-xor20-mixer/` change.
