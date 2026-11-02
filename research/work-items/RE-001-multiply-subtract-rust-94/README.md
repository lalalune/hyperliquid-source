# RE-001: reconstruct the node94 scalar-product subtraction pair

This adds safe Rust value implementations of two completely decoded leaves,
previously covered only by static packets. The pair is grouped by its actual
shared caller, operands and scratch state, not merely by adjacent addresses.
No component gate or byte-window registry changes.

- Component/task: `foundation`, bounded RE-001 arithmetic reconstruction.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, freshly fetched main.
  Reference gitlink remains `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No unlicensed inferred implementation was read or copied.
- Implemented windows: `[0x565ee40,0x565ee9b)`, 91 bytes/28 instructions;
  `[0x565eea0,0x565eeba)`, 26 bytes/8 instructions.
- Context window: caller `[0x564a900,0x564ab48)`, 584 bytes/130 instructions.
  Its whole bytes and FDE are revalidated, but its full behavior is not
  reconstructed. No caller-equivalence or source-identity claim is made.
- Changes are confined to `src/node94-multiply-subtract/` and this packet.

The established static predecessors are
[conditional reduction, packet #37](../foundation-conditional-reduction-94/README.md)
and [multiply-subtract](../foundation-multiply-subtract-94/README.md). Their
raw arithmetic observations are credited dependencies. This contribution
adds independently authored Rust, a complete selected-overlap audit, an
explicit snapshot relation and reproducible compiled validation.

## Corrected FDE overlap observation

The multiply-subtract predecessor says that FDE
`0x565eaa0..0x565ec0b` at `.eh_frame+0x2dc404` spans `0x565eea0`.
That interval comparison is false: its endpoint is `0x235` bytes before the
wide leaf and `0x295` bytes before the narrow leaf. The historical packet is
not edited; this new evidence explicitly supersedes that overlap statement.

`static_evidence.py` decodes the complete `.eh_frame` with the existing
`eh_frame_records` parser: three CIEs and 121,299 FDEs. For each selected
half-open interval, it retains every record satisfying
`record.start < selected.end && selected.start < record.end`. The complete
overlap lists are:

| Selected interval | All overlapping FDEs | FDE section offset |
| --- | --- | --- |
| `0x565ee40..0x565ee9b` | Only `0x565ee40..0x565ee9b` | `0x2dc468` |
| `0x565eea0..0x565eeba` | Only `0x565eea0..0x565eeba` | `0x2dc47c` |
| `0x564a900..0x564ab48` | Only `0x564a900..0x564ab48` | `0x2d9f88` |

This is a complete overlap test for these intervals, not a general claim that
the whole binary has no overlapping FDEs. The complete parsed inventory's
canonical SHA-256 is retained in `static/records.json`. GNU's fresh frame
dump independently confirms the three ranges and the falsely cited range.
A negative control expands the cited earlier FDE so it really does overlap;
the selected-overlap check rejects it.

The complete target SHA is checked before analysis. Each body has its own
byte witness, original bytes and file offset. All addresses are linked ELF
VAs; section mapping determines offsets. Both fresh GNU and Apple LLVM
exports decode every selected byte, agreeing on the instruction boundaries
without masks. The 5-byte and 6-byte NOP paddings after the leaves are locked
separately and excluded from their FDE body sizes. A scan of all 80,300 RELA
entries finds no addend naming either leaf. This does not establish an
exhaustive xref census or source provenance.

## Why this is a coherent pair

The complete caller bytes are retained in `static/caller-gnu.txt` and
`static/caller-llvm.txt`. Let S be its stack pointer after the fixed prologue.
Its earlier byte-load loop fills the four qwords at `S+0x20..S+0x40`.
The following straight-line sequence uses the two selected leaves:

| Preceding scalar-producing call | Selected leaf call | Destination passed to leaf | Operand passed to leaf |
| --- | --- | --- | --- |
| `0x564a99b → 0x565ede0` | `0x564a9ae → 0x565ee40` | `S+0x28`, 3 words | `0x9185f0`, 2 words |
| `0x564a9bc → 0x565ede0` | `0x564a9e3 → 0x565ee40` | `S+0x20`, 3 words | `0x9185f0`, 2 words |
| `0x564a9f0 → 0x565ede0` | `0x564a9fe → 0x565eea0` | `S+0x20`, 2 words | `0x9179c0`, 1 word |
| `0x564aa0b → 0x565ede0` | `0x564aa26 → 0x565eea0` | `S+0x30`, 2 words | `0x9179c0`, 1 word |

In every row the caller moves the preceding call's RAX into the leaf's RDX.
The destination ranges deliberately revisit the same four-word scratch
state. These are concrete call-site/dataflow observations under ordinary
System V callee-saved register preservation and normal returns, not a proof
of the intervening callee's transitive effects.

The pointer setup is visible at `0x564a96d` (RBP=S+0x30), `0x564a972`
(R15=S+0x28), and `0x564a9a6` (R13=S+0x20). RIP-relative LEAs at `0x564a991`
and `0x564a9d4` load the operand addresses into R12. The latter occurs after
the second wide call's RSI was already copied, so that call still uses
`0x9185f0`. The registers are then reused for the two narrow calls.

Fresh `.rodata` bytes show:

```
0x9185f0: [0x0000000100000000, 0xac45a4010001a402]
0x9179c0: [0xd201000000010000]
```

The first pair also appears as the RSI/RDX constants to the first two
`0x565ede0` calls; the final two calls use RSI=0 and the latter constant in
RDX. The LEAs, constants, exact direct-call bytes and instruction boundaries
are retained and checked. `0x565ede0` is identified only as the observed
scalar producer; its algorithm, its returned-value domain and whole caller
meaning remain unrecovered. The grouping claim is therefore the bounded
scalar-product subtraction pair used in this common preparation sequence,
not a recovered shared source routine or a proof of modular reduction.

## Complete arithmetic and memory relation

All words below are unsigned bit patterns, least significant first. Let
`R=2^64`, `O=o0+R*o1+R^2*o2`, `I=i0+R*i1`, and scalar `s`.

For the wide leaf, unsigned MUL instructions at `0x565ee4a` and `0x565ee56`
form `s*i0` and `s*i1`. The ADD/ADC at `0x565ee5a..0x565ee5d` forms all
three limbs of `P=s*I`, including carry from the middle limb. Since
`s<=R-1` and `I<=R^2-1`, P fits in 192 bits. Its top limb fits a u64 even
after adding that middle carry.

The SUB/SBB chain at `0x565ee6c..0x565ee72` computes O-P and final borrow
`b=1 iff O<P`. `sbb r8,r8` at `0x565ee75` turns that borrow into 0 or
all-ones. The high subtraction result is not stored. The mask both adjusts
the scalar and selects the two input words for the ADD/ADC add-back. The selected
stored words and RAX are:

```
low128 = (O - P + b*I) mod R^2
stored words = [low128 mod R, floor(low128/R), (s-b) mod R]
RAX = (s-b) mod R
```

The only store to destination+16 is the adjusted scalar at `0x565ee92`.
Carry out of the low-128 add-back is discarded; it must not increment that
stored top word. RAX is copied from the same adjusted scalar at `0x565ee96`.
The entry top word still controls the borrow comparison even though its
subtraction result is discarded.

Rust forms the product from two u128 products, then compares `(top, low128)`
tuples lexicographically for the exact unsigned 192-bit borrow. It uses
wrapping low-128 subtraction/addition and returns both the store words and
RAX value. The oracle instead computes O, I, P and the complete subtraction
with Python's unbounded integers, without reproducing those limb operations.

For the narrow leaf, `imul (%rsi),%rdx` at `0x565eea7` retains only the low
64-bit product. Signed and unsigned multiplication have the same residue
modulo R, so a wrapping u64 multiply is valid for every bit pattern without
asserting a signed source type. The complete output is:

```
stored words = [(out0 - s*input0) mod R, s]
RAX = s
```

It never reads the second destination word or a second input word. The saved
scalar remains in RAX from `0x565eea4` through the return.

Memory order matters. In the wide leaf, input qwords are read at
`0x565ee4a/0x565ee56`, output qwords at `0x565ee61/0x565ee64/0x565ee68`, and
input qwords reread at `0x565ee7e/0x565ee81`. All seven reads precede the
first store at `0x565ee8b`; stores then occur at +0, +8 and +16. In the
narrow leaf, the input read at `0x565eea7` and output read at `0x565eeab`
precede stores at `0x565eeb1/0x565eeb4`. Neither body calls a helper or has
a conditional control-flow branch; both terminate with `repz ret`.

The Rust APIs accept copied numeric snapshots, requiring valid nonwrapping
native ranges and stable ordinary memory for their native relation. If
source/destination overlap, including at byte offsets, consistent entry
snapshots still determine these arithmetic outputs because this body performs
no store before its last read. The returned values do not perform native
stores into shared aliases, and arbitrary independent snapshots need not
correspond to a given overlapping address layout. Concurrency, MMIO, faults,
volatile reread differences, unwinding and pointer/calling ABI behavior are
excluded. The returned structs are new projection types; the stripped
binary's original return type is unknown.

## Frozen tests, controls and build scope

`oracle.py` and separate input/expected files were frozen before writing Rust.
`fixtures/freeze.json` binds their SHA-256 values to the complete target and
both function ranges. The oracle reads neither Rust nor previous model
outputs and evaluates no captured instruction. Its static derivation remains
a shared premise: mathematical-model agreement is not target execution.

The 4,021 cases contain 3,040 wide and 981 narrow operations. They include
seven hand calculations, zero/sign-bit/all-ones and 32-bit boundaries,
wide O=P-1/P/P+1 and top-word-only changes, middle-product carry, borrow
chains, low add-back carry/overflow, discarded top differences, narrow
product truncation and wrapping subtraction, and 512 varied cases per width.
There are also 123 byte-offset overlap snapshots per width from three
synthetic buffers. These validate arithmetic for consistent snapshots, not
native alias writes. Irrelevant narrow-input protocol fields are deliberately
present but are not passed to the narrow value API.

The separately linked client receives inputs only on stdin. It prints every
stored output word and RAX independently; expectations are compared only by
the Python parent. Rust 1.94.1 opt0 and opt3 each pass all 4,021 cases in two
build directories: 16,084 checked case executions, zero mismatches. Repeated
rlib and Mach-O client hashes agree at each optimization level. This is
native-host build reproducibility, not captured x86-64 byte equality.

All 16 compiled source mutants return normally and are rejected by observed
output disagreement. They perturb product halves/carry, the borrow predicate,
each add-back word, add-back carry/overflow, stored top value, the wide RAX,
narrow high/low product choice, subtraction wrap, second store and narrow
RAX. Exact source substitutions, mismatch counts and first witnesses are
retained. In particular the product-top carry mutant changes 30 cases;
tests distinguish the carry even though it is rarer than low-limb arithmetic.

Forty-seven static corruption controls pass, including body/caller bytes,
selected FDE ranges, an actual injected overlapping FDE, constants, padding
and naming relocations. They run below the whole-file digest gate where
appropriate; body mutations are byte-witness rejections, not executions.
Four comparator controls reject changed values, dropped/duplicate/reordered
rows. The deterministic `native/raw-streams.json.gz` retains all 20 exact raw
output streams with labels, byte counts and SHA-256 values. Gzip timestamp is
zero. `verify.py --check-archive` checks every original stream hash.

## Reproduce and results

Observed tools: macOS arm64, Python 3.14.3, GNU binutils 2.47.20260726,
Apple LLVM objdump 17.0.0; Rust 1.94.1
`e408947bfd200af42db322daf0fadfe7e26d3bd1` / LLVM 21.1.8.
The crate has a real standalone Cargo manifest/lock with no third-party
dependencies. No root workspace or full node build is introduced.

From the repository root, using a fresh output directory:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
python3 research/work-items/RE-001-multiply-subtract-rust-94/oracle.py
python3 research/work-items/RE-001-multiply-subtract-rust-94/verify.py --check-archive
python3 research/work-items/RE-001-multiply-subtract-rust-94/verify.py --out work/subtract-review
cargo +1.94.1 build --offline --locked --manifest-path src/node94-multiply-subtract/Cargo.toml
rustfmt +1.94.1 --edition 2024 --check src/node94-multiply-subtract/lib.rs src/node94-multiply-subtract/client.rs
python3 -m unittest tests.test_foundation_conditional_reduction tests.test_foundation_multiply_subtract -v
make doctor verify catalogue-check reproduce
```

Fresh static exports are byte-identical to the retained exports. The native
checks, 18 prior focused tests, Cargo offline build, rustfmt, artifact/import
verification, catalogue consistency and reproduction pass; logs are retained.
Doctor reports analysis readiness, while exact whole-target rebuild readiness
remains false. Full repository tests are owned by the parent task and are not
rerun or claimed by this packet. No hosted CI or Docker result is claimed.

`native/commands.json` records compilation commands: edition 2024,
codegen-units=1, overflow-checks=yes, panic=abort, debuginfo=0, denied warnings
and source-path remapping. The input-only native client and deliberate source
mutants are the only programs executed for behavior checks. Captured node
execution, instruction emulation, live networking, keys and chain actions
are excluded. Compiler runtime/panic code is not identified with target code;
no machine-code equality or helper/whole-caller closure is claimed.

The remaining bounded question is the arithmetic and return contract of the
common scalar producer at `0x565ede0`, needed before composing these leaves
into a verified reconstruction of their caller's entire preparation sequence.
