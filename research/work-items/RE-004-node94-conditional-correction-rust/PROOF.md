# Complete four-entry conditional-correction family

Target node #94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Addresses are ELF virtual addresses before load bias. Four complete FDEs define
one coherent family; no neighboring function is included:

| Variant | Complete body | Bytes |
|---|---|---:|
| Add | `[0x565da40,0x565daba)` | 122 |
| Subtract | `[0x565dd00,0x565dd72)` | 114 |
| AddNonzero | `[0x565dde0,0x565de6e)` | 142 |
| SubtractNonzero | `[0x565de80,0x565df06)` | 134 |

Each body includes its two-byte `repz ret`. The 6/14/18/26 bytes of following
alignment context are separately locked and are not counted in the 512 body
bytes. Every body has no call or branch. The two Nonzero members extend their
respective arithmetic member with an OR reduction and a changed return value;
those extra instructions also change R8 and R10.

## Domain and memory correspondence

Let `B=2^64`, `N=B^4`, and encode each four-qword input in little-endian limb
order. Entry RSI identifies A, entry RDX identifies C, entry RCX identifies M,
and entry RDI identifies the 32-byte destination. A, C and M independently
range over every integer in `[0,N)`. M is called the correction operand,
without claiming it is a modulus or that the inputs are reduced. The resulting
operation is not asserted to compute a canonical remainder.

The source's byte-image API represents stable ordinary memory. All four
32-byte windows must lie within the image, with checked range addition. Any
such windows may overlap, including unaligned, partial and complete overlap.
The admitted target memory must also have successful reads/writes and valid
address formation. Its input/output windows must not overlap the target's
stack scratch, saved registers or return-control storage, and must not change
concurrently. This stack exclusion matters: the original prologue writes the
saved RBP/RBX before reading inputs, and the epilogue restores them after the
output stores. The safe image models data windows, not that stack or machine
ABI. Flags and faults are not reported.

`None` is solely the new API's refusal to model an out-of-image or overflowing
range. All ranges are checked before any image write, so refusal leaves the
image unchanged. It is not a recovered target return value or fault policy.

The complete memory order supports snapshot evaluation in all four members:

- Four initial MOVs load all A qwords.
- Add/ADC or SUB/SBB reads all C qwords; all M reads also occur before stores.
- Add members read M through four SUB/SBB memory operands.
- Subtract members read all four M qwords unconditionally through MOVs,
  interleaved with the C subtraction, before masking them by the borrow.
- Four destination MOVs follow all input reads. Register arithmetic may be
  interleaved with these stores, but it has no further data-window load.
- Only saved-register stack loads follow those destination writes.

Consequently every A/C/M byte is from the initial image. Destination stores
cannot affect any later input read. The four destination qwords do not overlap
one another, so their ordered writes equal one 32-byte immutable-image overlay.
Bytes outside that destination window remain unchanged. This establishes the
alias behavior without a captured instruction emulator.

## Add members, including overflow

Let `S=A+C`, `s=S mod N`, and `c=floor(S/N)`; c is zero or one. The four
ADD/ADC operations compute s and their final carry c. Before modifying the
sum, the body saves s0 in RAX and s1 in RSI; s2 and s3 are saved in RBX/RBP.
`SBB RDX,RDX` creates the mask `-c mod B`. The four SUB/SBB operations then
compute `t=(s-M) mod N` with final borrow `b=[s<M]`.

The final `SBB RDX,0` has result

```
RDX = (-c-b) mod B.
```

Its carry flag is one exactly when c=0 and b=1: subtracting b from zero
borrows iff b=1, whereas subtracting 0 or 1 from `B-1` cannot borrow.
The four CMOVB instructions restore s only on that condition. Otherwise t is
stored. Since M<N, `S>=M` is equivalent to `c=1 or b=0`. Hence the complete
stored integer is

```
V = (S-M if S>=M else S) mod N.
```

This is one conditional subtraction, even if S exceeds M by more than M.
M=0 is admitted, and adding values whose sum overflows 256 bits remains
well-defined. In particular, c=b=1 gives raw RDX=`B-2`; replacing RDX by a
boolean or a single borrow mask loses observable information.

For the plain Add member, RAX=s0 and RSI=s1 even when the stored result V
differs from s. They are not pointers and are not recomputed from V.

## Subtract members, including discarded final carry

The four SUB/SBB operations compute `d=(A-C) mod N`, with borrow
`b=[A<C]`. `SBB RDX,RDX` produces `-b mod B`. AND with that mask selects
all four correction words when b=1 and zeros otherwise. The subsequent
ADD/ADC chain stores

```
V = (A-C+b*M) mod N.
```

Carry out of the final addition is discarded. There is no extra high output
word and no further correction. The plain Subtract member leaves RAX=b*M0,
RSI=b*M1, and RDX=`-b mod B`. These are the selected correction words, not
the low result words or a destination address.

## Exact register projection

Let `v0..v3` be V's four words. All four members overwrite RAX, RDX, RSI,
R8, R9, R10 and R11 without restoring them. RDI and RCX retain their entry
pointers; R12..R15 are untouched. RBX/RBP are restored from the excluded
valid stack context. The final seven-register projection is:

| Variant | RAX | RDX | RSI | R8 | R9 | R10 | R11 |
|---|---|---|---|---|---|---|---|
| Add | s0 | `(-c-b) mod B` | s1 | v0 | v1 | v2 | v3 |
| Subtract | b*M0 | `-b mod B` | b*M1 | v0 | v1 | v2 | v3 |
| AddNonzero | `[V!=0]` | `(-c-b) mod B` | s1 | `v0\|v1\|v2\|v3` | v1 | `v2\|v3` | v3 |
| SubtractNonzero | `[V!=0]` | `-b mod B` | b*M1 | `v0\|v1\|v2\|v3` | v1 | `v2\|v3` | v3 |

The Nonzero members first OR v1 into R8, OR v3 into R10, then OR R10 into
R8. MOV sets the entire RAX to one, and CMOVE replaces it with the zero R8
only when that OR is zero. Thus full RAX is exactly zero or one. It is not
merely an AL observation. The ORs execute after all stores and do not change
the destination bytes.

## Source arithmetic bounds and independent oracle

The source uses four-limb carry and borrow helpers. Each addition is a u128
sum of two u64 words and a carry at most one, bounded by `2B-1`; shifting it
by 64 yields the next carry. Each subtraction uses two `overflowing_sub`
operations; the OR of their borrow bits is exactly the borrow of the combined
subtraction. Every lane index lies in 0..4. After `checked_add(32)` succeeds,
all subsequent offsets through 31 are representable and within the image.
The explicit wrapping operations for masks represent the target's modulo-B
register results. No Rust operation overflows unintentionally or shifts by an
invalid count.

The frozen Python oracle uses unrestricted 256-bit whole integers, comparisons,
and reduction modulo N. It reads the immutable initial image into whole
integers, derives V using the formulas above, extracts the seven register
observations by quotient/remainder, and creates a single immutable byte overlay.
It has no limb carry/borrow chain and no ordered instruction simulation. The
algebra above connects it to the separately structured Rust implementation.
Its source and expectations were frozen before the Rust directory existed.

## Static closure and remaining facts

The four full body hashes, exact FDE/CIE records and separately bounded padding
are rechecked against the full target digest. Complete Capstone and independent
GNU disassembly agree on the body extents. The static checker also verifies
that all input reads precede the first destination write, except the explicitly
excluded stack restores. There are no RIP-relative data operands, helper calls,
indirect transfers or embedded table dependencies in these four leaves.

A complete `.text` E8/E9/EB pattern scan has no incoming candidates for any of
the four entries. All 80,300 RELA records are checked: none names any entry,
and none overlaps the four code/padding windows. This does not establish that
the functions are unreachable or exhaust other address-formation mechanisms.
No caller, source symbol, mathematical operand meaning, neighboring helper,
node-wide ABI equivalence or acceptance gate is claimed.
