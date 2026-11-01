# Complete 384-bit single-correction addition family

Node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Coordinates are linked ELF virtual addresses. The full selected FDEs are
core `[5656980,5656a13)` (147 bytes), single wrapper `[5656940,565697c)`
(60 bytes), and ordered pair wrapper `[5656a20,5656a83)` (99 bytes).
The direct-call interior entry `565699b` is within the complete bound core;
it is not advertised as a separate FDE or independent complete function.
No original source/library/application identity is inferred.

## Independent interior entry and observations

Let B=2^64 and Q=B^6. All six-word unsigned A,Bop,C in [0,Q) are admitted;
the symbol Bop below is the right operand, distinct from the word radix B.
The full core loads A's six words from RSI before reaching `565699b`.
The actual interior entry instead receives arbitrary independently supplied
R8..R13 words. They need not have arisen from any known wrapper or arithmetic
operation, and no mapped RSI input span is required on this path.

At `565699b`, ADD [RDX],R8 overwrites incoming carry and the other arithmetic
flags. Every subsequent ADC uses only this new chain; arbitrary incoming CF
cannot affect the result. RSI, RAX, RBX, RBP, R14 and R15 are all overwritten
before their relevant use/observation. RDX independently supplies the right
operand pointer until its six reads finish; RCX independently supplies C, and
RDI supplies the destination. Initial values of every other overwritten register
are unrestricted. The unmodified RCX/RDI addresses are known caller metadata;
control state such as RSP/return storage must satisfy normal-return premises.
No wrapper consistency, canonical limb, reduced input or entry-carry constraint
is imposed on the interior-entry API.

The core writes six output qwords and returns all 13 written GP observations in
the `Core` projection: six result words in R8..R13, plus RAX,RDX,RSI,RBX,RBP,R14,R15.
Unchanged entry registers, flags, native ABI, control-stack effects and timing
are excluded. `combine` is the pure value relation; `apply_core` supplies its
actual data stores for either memory or register-snapshot input.

## Sum, subtraction, selection and exact RDX

The first six-word ADD/ADC chain forms the full 385-bit sum
`S=A+Bop`, `0<=S<=2Q-2`. Let `c=floor(S/Q)` and `W=S mod Q` with words w0..w5.
The target snapshots these low words in R14,R15,RAX,RBX,RBP,RSI respectively.
After the right reads complete, SBB RDX,RDX sets RDX=-c modulo B.

The six SUB/SBB instructions subtract C from W. If b=[W<C], their result is
`U=(W-C) mod Q`, and their final borrow is b. The usual wordwise invariant
`low_difference - borrow*B^k = low_W-low_C` at each k proves both facts for all
limb patterns. The Rust two-overflowing-subtraction OR is the same borrow:
first underflow means the wrapped intermediate is nonzero, so a simultaneous
second underflow cannot occur; otherwise the second underflow records the
incoming borrow subtracted from zero. Each u128 addition is at most 2B-1.

The target then computes SBB RDX,0, with arithmetic value `-c-b mod B`.
Its new CF is b when c=0, but zero when c=1: in the latter case the minuend
is B-1 and subtracting b in {0,1} cannot borrow. Therefore CMOVB restores W
only when c=0 and b=1. All other cases keep U. The complete table is

| c | b | full RDX | selected output |
| ---: | ---: | ---: | --- |
| 0 | 0 | 0 | U |
| 0 | 1 | B-1 | W |
| 1 | 0 | B-1 | U |
| 1 | 1 | B-2 | U |

When c=1, S>=Q>C; when c=0, b=0 is exactly S>=C. Thus the all-input result is

```
V = (S - C*[S>=C]) mod Q.
```

It subtracts C at most once. It is not general reduction modulo C; neither
A<C nor Bop<C is assumed. In particular C=0 is valid, and large unreduced
inputs may still exceed C after this operation. RDX is not simply a boolean
borrow mask or the selection flag: the two different middle rows above have
the same RDX but different selection behavior.

The MOV stores interleaved with the later CMOVB instructions do not alter flags,
so all six words use the same last SBB condition. All three input operands have
already been read before the first store. No instruction after selection changes
the saved sum-word observations. Consequently, with v0..v5 the words of V,

```
RAX=w2, RDX=(-c-b) mod B, RSI=w5,
RBX=w3, RBP=w4, R14=w0, R15=w1,
(R8,R9,R10,R11,R12,R13)=(v0,v1,v2,v3,v4,v5).
```

These are full 64-bit observations; no high-half mask or normalization is applied.

## Single wrapper and ordered two-block wrapper

Single saves RBX,RBP,R12..R15, calls the full core once and restores those saved
values. Its selected final tuple is

```
RAX=w2, RDX=(-c-b) mod B, RSI=w5, RCX=correction, RDI=destination,
R8=v0, R9=v1, R10=v2, R11=v3.
```

All six words are still stored even though R12/R13 are restored afterward.
The six restored entry-dependent register values are explicitly outside this
selected wrapper tuple; no assumed constant is returned for them.

Pair saves the two input addresses on its control stack, forms each +48 pointer
and destination+48, and calls the full core. It then reloads the original input
addresses, subtracts 48 from the unchanged destination register and calls the full
core again. RCX remains the same correction pointer through both calls. Finally
it restores the same six saved registers. Thus the exact sequence is:

1. Snapshot high48(A), high48(Bop) and current48(C); compute and write high48(D).
2. From that updated image snapshot low48(A), low48(Bop) and current48(C);
   compute and write low48(D).
3. Return the second call's selected tuple with original D/C addresses.

There is no carry linking the blocks: these are two six-word operations with a
shared correction pointer. There is also no whole-input snapshot across both
calls. The first stores may change later left, right or correction bytes under
arbitrary aliases. The implementation's two `stage` calls reproduce that order.
Reading C once for both calls, reversing block order, or returning first-call
auxiliary values changes admitted behavior and is tested by compiled controls.

## Safe image correspondence, aliases and refusal

The safe image represents one interval `[base,base+len)`, whose end is at most
2^64. Input/right/correction/output spans are ordinary stable readable/writable
memory as appropriate, with little-endian data and valid address formation.
Core/single require four 48-byte spans, except register-input core requires only
right/correction/output and arbitrary supplied six-word input registers. Pair
requires 96-byte left/right/output spans and one 48-byte correction span. These
explicit nonwrapping spans exclude arbitrary wrapped-pointer layouts rather than
silently treating their raw pointer ABI as a slice ABI. Byte alignment is not
required. The exclusive end may equal 2^64 when all accessed bytes are below it.

All data spans may overlap exactly, partially or at unaligned offsets. In one
core call there are no writes before all reads, so input snapshots preserve every
such alias. Pair's first stores are committed before the second snapshots; those
reads therefore see precisely the target's changed data. RCX and saved control
addresses cannot be changed by data stores under the stated separation premise.
The six stores in each block address distinct qwords. The final image outside
D's 48/96-byte span is unchanged.

Both wrappers push/save control state before data reads and restore it after
data stores. Data must be disjoint from saved-register/return/control storage,
and the original control accesses must be valid. The core likewise needs normal
return control. MMIO, volatile read effects, races, faults, native stack aliases,
CET/ABI state, flags and timing are outside this projection. Numerical pointer
fields in the wrapper result are metadata, not dereferenced executable addresses.

All safe spans are validated before any store. For pair, every later read/store
uses fixed offsets already within those checked spans; data writes cannot alter
addresses. Hence no validation remains that could fail after the high block has
been written. Invalid range, checked index arithmetic or wrapping global image
returns None without any mutation. This is an added safe-API refusal, not a
claim about the original invalid-pointer result or fault ordering.

## Static closure and independent qualification

All three complete bodies have unique exact FDEs in the complete 121,299-FDE /
3-CIE inventory, sharing CIE 0xce1518. GNU and LLVM independently decode every
selected instruction and all 41 external caller contexts from exact FDE starts.
The interior 565699b entry is explicitly confirmed at an instruction boundary
inside the bound full core. Three direct calls target that interior entry,
three target the full core, 51 target Single and 89 target Pair: 146 E8 sites.
One E9 site 564680a targets Pair. All 147 edges are checked at instruction starts;
all 44 bound windows total 32,780 bytes. Context callers are evidence for entry
boundaries only; their other code and algorithms are not reconstructed here.

The selected closure has no other outgoing helper or branch: Single calls core
once, Pair calls it twice, and core returns without calling anything. It has no
RIP-relative static data/table/import dependency. All operands are supplied
memory or registers. All 80,300 RELA records have no selected-entry naming record
and no writer overlapping bound code. Full target SHA, raw FDE/CIE records and
4/13/29-byte alignment gaps are bound. The following 5656aa0 FDE is boundary-only
and belongs to a separate previously reconstructed halving family. E8/E9/RELA
absence is not proof that computed indirect references cannot exist.

Before any Rust source, the independent oracle froze full integers A/Bop/C,
computing S and the single conditional whole-integer subtraction directly. It
extracts sum/output digits using division/remainder and computes RDX from two
mathematical comparisons, without a limb carry/borrow chain. Its image relation
makes high-then-low whole-integer updates to a copied byte image. This oracle is
independent of the Rust overflowing-subtract loop and mutable stage helper; it
is not an instruction emulator. Finite native comparisons and deliberate wrong
implementations qualify code and evidence, while the universal argument above
establishes the all-admitted-input relation. No captured executable runs, inferred
implementation copying, whole-node equivalence or completion gate is claimed.
