# RE-001: reconstruct the shifted-threshold scalar producer

This closes the scalar-producer gap identified while reconstructing the
neighboring multiplication/subtraction leaves. The complete producer is
implemented for all pairs of 128-bit inputs, including zero and arbitrary
threshold low halves. Its exact behavior is weighted-cost inversion; ordinary
division is only a proved special case.

- Component/task: `foundation`, bounded RE-001 arithmetic reconstruction.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: freshly fetched main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`;
  unchanged reference gitlink `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No unlicensed inferred implementation was read or copied.
- Producer: `[0x565ede0,0x565ee3d)`, 93 bytes, 27 instructions.
- Supporting caller: `[0x564a900,0x564ab48)`, 584 bytes, 130 instructions.
  Its argument/result edges are inspected; its complete behavior is not claimed.
- New paths: `src/node94-shifted-divisor-scalar/` and this packet only.
  No progress gate, selected-byte registry, imported evidence or pin changes.

The earlier static packets for
[conditional reduction](../foundation-conditional-reduction-94/README.md) and
[multiply-subtract](../foundation-multiply-subtract-94/README.md) cover the
consumers. Their caller bytes are context, not new body recovery claimed here.
The separate Rust subtraction-pair contribution is not needed to build or
reproduce this packet. Reusable project-authored static/build scaffolding is
reused; the new arithmetic source and cost oracle are independently authored.

## Authenticated body and complete dataflow

`static_evidence.py` checks the full target digest and resolves every VA to
file offsets through ELF sections. The producer maps to file offset
`0x565dde0`, with SHA-256
`bab55289357afd9ee2be0618a4cef11b2a4d8dbd8e2a201bf64676e051b01abb`.
Its FDE is at VA `0xfbd96c` (`.eh_frame+0x2dc454`), CIE `0xce1518`.
The complete 121,299-FDE/three-CIE parse finds exactly this FDE overlapping
the producer range; the caller also has exactly its own overlapping FDE.
GNU's fresh frame dump agrees. This is selected-range qualification, not a
claim that unwind entries enumerate all functions.

Fresh GNU and Apple LLVM exports agree on every byte and instruction boundary
of both selected bodies, without normalization. The producer's three padding
bytes `90 66 90` are checked separately and excluded from its 93 bytes. All
80,300 RELA entries are scanned; none names the producer as an addend. This
does not establish a complete incoming-call census or source ownership.
Original bytes, frame records, calls and constants are in `static/`.

Let `R=2^64`. At native entry, `N=LE64([RDI])+R*LE64([RDI+8])` and
`D=RSI+R*RDX`. All comparisons are unsigned; no input bits are excluded.

| Instructions | Complete effect |
| --- | --- |
| `0x565ede0` | ENDBR64 landing instruction. |
| `0x565ede4..0x565ede7` | Load N's low/high words into R8/R9. These are the only memory reads. |
| `0x565edeb..0x565edee` | RAX=0; ECX=64. |
| `0x565edf3..0x565edfc` | Save both remainder words and subtract RSI/RDX with SUB/SBB, producing full 128-bit borrow. The intervening MOV preserves the low subtraction's flags. |
| `0x565edff..0x565ee04` | Form candidate `2*RAX+1` modulo R with LEA; copy threshold high half to RDI. Neither instruction changes the borrow flag. |
| `0x565ee07..0x565ee0f` | CMOVB restores both words on borrow; SBB subtracts that borrow from the candidate, appending 1 iff subtraction was accepted. |
| `0x565ee13..0x565ee1d` | Logically shift the combined RSI/RDX threshold right by one, including high-half bit 0 into low-half bit 63. |
| `0x565ee20..0x565ee23` | Decrement ECX and repeat at `0x565edf3` while nonzero: exactly 64 iterations. |
| `0x565ee25..0x565ee2a` | Form the final candidate in RCX; arithmetic-shift the old RAX by 63 into a zero/all-ones mask. |
| `0x565ee2e..0x565ee34` | Perform the 65th 128-bit subtract decision and subtract its borrow from RCX. The resulting remainder is unused. |
| `0x565ee38..0x565ee3b` | OR candidate with the mask and return in RAX. |

The body has no calls, no stores and one loop-back branch. The final physical
SUB/SBB changes scratch registers, but only its borrow is needed for the
selected return-value relation. The safe value implementation can compare at
that point without computing an unused remainder. Register clobber/flag
equivalence is not claimed.

## Derivation of all 65 decisions and saturation

Define `W_k=floor(D/2^k)`. Before decision k, let T be the current remainder.
The native SUB/SBB computes borrow iff `T<W_k`. Conditional moves restore T
on borrow, otherwise keep `T-W_k`. Thus the accepted digit is
`d_k=1 iff T>=W_k`, and every retained remainder remains nonnegative.
Zero weights always append 1 and leave T unchanged.

After the first 64 decisions (k=0..63), RAX contains precisely
`d_0 d_1 ... d_63`. Its sign bit is d_0, so SAR by 63 creates all ones iff
the original `N>=D`. The final candidate drops d_0 and appends d_64, while
the OR forces all ones if d_0 was set. Therefore:

```
if N >= D: return 2^64 - 1
otherwise: return greedy digits d_1..d_64 for weights D>>1 .. D>>64
```

There is no hidden restriction on D's low half or N's top bit. In particular,
zero D saturates even for zero N. A maximum result does not imply the first
bit was accepted: with N=0,D=1, the first bit is clear and all subsequent
weights are zero, yielding all ones. With N=0,D=2 the result is `2^63-1`.
With D=`2^64`, the result is `min(N,2^64-1)`. With N=`2^63`,D=`2^127`, only
the last of the 64 retained digits is accepted, so the result is 1.

## Independent weighted-cost oracle and proof

For a u64 q with bits `b_1..b_64` in descending significance, define

```
C_D(q) = sum(b_k * floor(D / 2^k), k=1..64).
```

The result for **all** N,D is the largest q in `[0,2^64-1]` with
`C_D(q)<=N`. This supplies a binary-search oracle that has no subtraction,
restore, shift-register or saturation loop corresponding to the native body.

First prove C is nondecreasing. When q increments, some zero bit k becomes
one and its less significant trailing ones become zero. The cost difference
is `W_k - sum(W_j,j=k+1..64)`. For `A=W_k`, later weights are
`floor(A/2), floor(A/4), ...`. If A>0 their finite sum is at most
`A-popcount(A)<=A-1`; if A=0 all are zero. The difference is therefore
nonnegative, including flat suffixes caused by zero weights. Binary search
for the last feasible q is valid on the entire u64 domain.

When N<D the initial native decision rejects D. For the remaining weights,
greedy selection chooses the numerically largest feasible bit prefix: if the
next weight fits, accepting it with later bits zero is already feasible and
beats every code with that bit clear; if it does not fit, no nonnegative
later costs can make that bit feasible. Induction yields the largest q with
C_D(q)<=N. When N>=D, all-ones q is feasible because
`C_D(2^64-1)=sum(D>>k,k=1..64)<=D` (strictly less for positive D).
It is the maximum possible q, agreeing with native saturation. D=0 also
satisfies this argument. Thus the oracle needs no special saturation branch.

`oracle.py` implements this cost and binary search with Python unbounded
integers. It reads neither Rust, earlier model outcomes nor decoded operand
objects. `verify.py` additionally checks the frozen answer's feasibility and
the next answer's infeasibility, unless already at u64 maximum. The argument
above is the target-grounding premise; model agreement is not target execution
or an independently machine-checked proof of the assembly semantics.

## Shared caller bindings and precise division special cases

The complete caller and these eight direct-call edges are retained. S denotes
its stack pointer after the fixed prologue. Normal return and ordinary System
V preservation of callee-saved registers are premises for reading its setup.

| Producer call | N pointer | D low/high | Immediate consumer of returned RAX |
| --- | --- | --- | --- |
| `0x564a99b` | `S+0x30` | `0x100000000`, `0xac45a4010001a402` | `0x564a9ae → 0x565ee40`, RDX receives RAX |
| `0x564a9bc` | `S+0x28` | same pair | `0x564a9e3 → 0x565ee40`, RDX receives RAX |
| `0x564a9f0` | `S+0x20` | `0`, `0xd201000000010000` | `0x564a9fe → 0x565eea0`, RDX receives RAX |
| `0x564aa0b` | `S+0x30` | same pair | `0x564aa26 → 0x565eea0`, RDX receives RAX |

Pointer setup is at `0x564a96d`, `0x564a972`, `0x564a9a6`; constants enter
RBX/R14 at `0x564a977/0x564a981` and R15 at `0x564a9c4`. Their matching
consumer `.rodata` words at `0x9185f0` and `0x9179c0` are independently read
and pinned. All call sites are decoder-confirmed boundaries and their rel32
targets are re-derived. This recovers a concrete producer/consumer interface,
not the entire caller or its algorithmic purpose.

For `D=A*R+B`, `0<=B<R`, expand the cost:

```
C_D(q) = A*q + sum(b_k * floor(B/2^k), k=1..64).
```

When B=0 and A>0, the result is exactly `min(floor(N/A),R-1)`. For the first
caller's B=`2^32`, its exact cost is `A*q + (q>>32)`, with
A=`0xac45a4010001a402`; the answer is the largest q whose cost fits N. For
example N=`A*2^32` yields `2^32-1`; ignoring B would incorrectly yield
`2^32`. The last pair uses B=0 and A=`0xd201000000010000`, so the division special case
applies. These are derived arithmetic facts, not library/source identities.
Replacing arbitrary B with zero changes behavior, and the general API does
not make that restriction. D's least significant bit alone is observationally
irrelevant to the weighted cost; merely toggling it would be an ineffective
negative control and is not counted as a killed mutant.

## API, validation and limits

`shifted_divisor_scalar(numerator: u128, threshold: u128) -> u64` is a safe
numeric projection. The original two input loads are little-endian and read
valid stable ordinary memory; the source takes their combined snapshot.
There are no writes or source/destination alias constraints. Native pointer
ABI, faults, torn/concurrent/MMIO reads, unwind behavior, register/flag
clobbers and timing identity remain outside the relation. No original source
function name, integer type or return signature is asserted.

Before Rust was written, `oracle.py`, inputs and expectations were frozen in
`fixtures/freeze.json` with hashes and the complete target identity. The
2,683 cases include 781 first-bit-saturated and 1,902 first-bit-clear cases;
2,140 have nonzero threshold low halves. They cover zero/one, all powers of
two through bit 127, odd values, all ones, quotient-cost neighbors, first-bit
saturation neighbors, last-bit decisions, both caller thresholds and 1,024
varied/bounded inputs. Eleven hand calculations anchor the model.

The input-only client never receives expected outputs. Opt0 and opt3 each
pass 2,683 cases in two build directories: 10,732 checked native case runs,
zero mismatches, identical repeated rlib/client hashes at each optimization
level. These are host build hashes, not target-code matches. Fifteen compiled
source mutants all return normally and produce detectable output differences:
iteration count, final decision, equality, saturation/sign bit, both threshold
halves, cross-limb shift, arithmetic versus logical shift, failed-subtract
restore, digit polarity, ceil shift and shifted starting weight. Omitting
saturation changes 489 cases, so the control is observably effective.

Thirty-nine static corruption controls and four output-comparator controls
pass. Static mutations exercise body/caller bytes, FDEs, constants, padding
and naming relocation checks below the full-file digest gate. They are static
witness rejections, not captured-instruction executions. All 19 exact native
output streams are stored in one deterministic `native/raw-streams.json.gz`
with zero gzip timestamp, labels, sizes and per-stream SHA-256 values.

Observed environment: macOS arm64, Python 3.14.3, GNU binutils 2.47.20260726,
Apple LLVM objdump 17.0.0, rustc 1.94.1
`e408947bfd200af42db322daf0fadfe7e26d3bd1` / LLVM 21.1.8. The standalone
Cargo manifest/lock has no third-party dependencies or root workspace.

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
python3 research/work-items/RE-001-shifted-divisor-scalar-rust-94/oracle.py
python3 research/work-items/RE-001-shifted-divisor-scalar-rust-94/verify.py --check-archive
python3 research/work-items/RE-001-shifted-divisor-scalar-rust-94/verify.py --out work/shifted-scalar-review
cargo +1.94.1 build --offline --locked --manifest-path src/node94-shifted-divisor-scalar/Cargo.toml
rustfmt +1.94.1 --edition 2024 --check src/node94-shifted-divisor-scalar/lib.rs src/node94-shifted-divisor-scalar/client.rs
python3 -m unittest tests.test_foundation_conditional_reduction tests.test_foundation_multiply_subtract -v
make doctor verify catalogue-check reproduce
```

Static regeneration, native checks, archive integrity, Cargo offline build,
rustfmt and the 18 existing consumer/context tests pass. `doctor`, artifact
and import verification, catalogue consistency and reproduction pass; logs
and exact compile commands are retained. Doctor's full-target rebuild
readiness remains false. The full repository suite belongs to the parent
task and is not rerun or claimed here. No hosted CI or Docker result is claimed.

Only newly authored Rust clients/libraries and their deliberate mutants ran
for behavior checks. No captured executable or instruction emulator ran;
no live node, chain, credentials or signing activity occurred. Compiler
runtime code is not identified with target code, and no compiled-byte or
whole-caller equivalence is claimed. The next bounded question is composition
of these scalars with the subtraction leaves across the shared four-word
scratch buffer, including the complete caller's data-preservation premises.
