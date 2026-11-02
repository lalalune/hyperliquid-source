# Complete six-word classification pair

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Coordinates are linked ELF VAs. Single `[0x56573a0,0x5657402)` is 98 bytes /
28 instructions; Pair `[0x5657420,0x5657531)` is 273 bytes / 79 instructions.
Each complete body has one exact unique FDE. No library, cryptographic, original
source or application meaning is assigned to the two-bit classification.

## All-input doubled comparison

Let B=2^64, Q=B^6, and A,C be arbitrary unsigned values in [0,Q). There is no
reduced-input, odd-correction, canonical-limb or nonzero premise. Let

```
T = 2A, c = floor(T/Q), W = T mod Q,
b = [W<C], D = (W-C) mod Q = (2A-C) mod Q.
```

The six ADD/ADC instructions form all 385 bits of T, with c in {0,1}.
The first ADD erases incoming CF; the preceding XOR clears the extra word.
ADC extra,0 records the final carry. Each source u128 expression is at most
2B-1, so its cast/shift exactly preserves the low word and next carry.
The six SUB/SBB instructions form D and b. Inductively after k limbs,
`low_D - borrow*B^k = low_W - low_C`. Two overflowing subtractions with the OR
of their underflows implement one SBB: if the first underflows its wrapped
result is nonzero and cannot underflow from subtracting one; otherwise the
second underflow records precisely the incoming borrow against zero.

The last SBB extra,0 forms `h=(c-b) mod B`. NOT h followed by AND 2 gives

| c | b | h | (~h)&2 | 2A>=C |
| ---: | ---: | ---: | ---: | --- |
| 0 | 0 | 0 | 2 | true |
| 0 | 1 | B-1 | 0 | false |
| 1 | 0 | 1 | 2 | true |
| 1 | 1 | 0 | 2 | true |

For c=1, T>=Q>C regardless of the low-word subtraction borrow. Thus the second
bit is exactly `2*[2A>=C]`, including equality, carry-plus-borrow and C=0.
The low bit is the original input's parity. Define

```
tag(A,C) = (A mod 2) + 2*[2A>=C].
```

Because A is an integer, `[2A>=C]` is also `[A>=ceil(C/2)]`. The frozen oracle
uses that threshold formula, independently of the source's doubled limb and
borrow chains. The actual six difference limbs remain D even when the tag's
comparison bit is false; this routine does not conditionally restore A or W.

## Single: every selected register

The target loads all six A words before reading the six C words. It preserves
A's original low word in RDI before doubling, finally ANDs it with one, and ORs
it into the masked comparison. Let d0..d5 be D's little-endian words. Its complete
selected final tuple is

```
RAX=tag(A,C), RCX=d4, RDX=d5, RDI=A mod 2,
R8=d0, R9=d1, R10=d2, R11=d3.
```

All eight values are full u64 observations without comparison normalization.
RSI, the correction address, is untouched. RBX/RBP/R12..R15 are untouched.
Incoming values of the eight selected registers are overwritten before use as
output; RDI's and RSI's entry values instead identify the supplied input spans.
RSP/return storage, flags, SIMD state, CET/ABI and timing are not projected.
There are no target data stores or calls in this body.

## Pair: independent zero selections

Write its 96-byte input as low L followed by high H, each in [0,Q). Let
`u(X)=OR of X's six u64 words`, so `u(X)=0` exactly when X=0. Pair first loads H,
forms u(H), computes tag(H,C), and keeps that tag in RDI. It preserves u(H) in
its private stack scratch. It then loads all L words and forms u(L), retaining
L's original low word in RBP. It doubles L and subtracts the same C; these are
two independent six-word calculations with no carry linking the blocks.

Before the final two selections, RAX holds the complement of the low calculation's
extra word, RBP holds L's original low word, RBX holds u(H), and R8 holds u(L).
TEST R8,R8 / CMOVE RBP,RDI substitutes the high tag only when L=0. TEST RBX,RBX /
CMOVNE RAX,RDI substitutes the high tag only when H!=0. The final AND 1 on RBP
and AND 2 on RAX separate those two independent decisions. Therefore

```
first = L if L!=0 else H,
last  = H if H!=0 else L,
RAX = (first mod 2) + 2*[2*last>=C].
```

For example, both blocks zero and C=0 still returns 2; zero is not a general
sentinel classification. Using a single common selected block for both bits,
checking just the low limb for zero, treating a full OR union as a boolean
register result, or dropping the doubling carry changes admitted behavior.

Let e0..e5 be the words of `(2L-C) mod Q`. Pair's eight selected full GP values are

```
RAX = the selected two-bit result,
RCX=e4, RDX=e5, RDI=tag(H,C),
R8=u(L), R9=e1, R10=e2, R11=e3.
```

R8 is not e0. The low difference e0 was in RBX, which is restored from its saved
entry value before return. RBP is likewise restored. The source returns neither
a guessed RBX/RBP value nor an extra claimed difference register. RSI remains the
original correction address, R12..R15 are untouched, and all these unchanged or
restored entry-dependent values are outside the selected tuple. The two temporary
stack stores and final RSP restoration are control-state effects outside the
safe value projection; no data-output image is written.

## Snapshot and read-only image domain

`classify(A,C)` and `classify_pair(L,H,C)` are value APIs. Their supplied values
must correspond to the target's successful ordinary little-endian reads.
`read_single` and `read_pair` provide checked image adapters: one image covers
`[base,base+len)` with exclusive end at most 2^64. Single requires input48 and
correction48; Pair requires input96 and correction48. Every span is mandatory,
even for zero inputs or a classification whose final bit selects another block.
Address subtraction/index addition are checked; a span may end exactly at the
image's exclusive end. Byte alignment is unrestricted.

The target's input/correction data may alias at any byte offset. Single's loads
are input then correction. Pair's order is high input, correction, low input,
correction again. Pair writes only its separated control stack, so under stable
ordinary memory both correction reads observe the same bytes. Thus the source's
one correction snapshot and immutable image preserve all admitted data aliases.
There is no claim about intermediate control-memory aliases: pair's saved RBX,
RBP and scratch/return storage must be valid and disjoint from all supplied data.
Single also requires valid ordinary return control. Reads must not have MMIO or
volatile side effects; races, faults, concurrent memory changes and native pointer
ABI behavior are excluded. These are explicit normal-return correspondence
premises, not a claim about arbitrary wrapped layouts or invalid-pointer faults.

The source accepts immutable slices and has no unsafe code, so it cannot alter
the image. Invalid safe-image mapping or span returns None. That is a new checked
API refusal, not a target result; its validation order is not fault-order
emulation. Pure value APIs retain the complete arithmetic domain regardless of
where the original inputs could have been mapped.

## Static closure and qualification boundary

The full 121,299-FDE / 3-CIE inventory gives unique exact selected extents and
shared CIE 0xce1518. GNU and LLVM independently decode all 371 bytes into matching
107-instruction partitions. Full bodies have no calls or out-of-body branches,
no RIP-relative literal, table or import dependency, and only supplied data plus
private control-stack accesses. Thirty bytes after Single and fifteen after Pair
are separately bound padding. The following FDE at 0x5657540 belongs to the
separate SIMD selection family and is boundary evidence only.

Complete .text E8/E9 byte-pattern scans find no candidate targeting any byte of
either selected interval. All 80,300 RELA records have no naming addend in those
intervals and no writer overlapping selected code. No direct caller context
exists to decode for this scope. This establishes the stated census, not complete
indirect reachability, absence of computed callers, or execution frequency.
Neither selected full body has a second exact occurrence in .text; this is not
an exhaustive semantic-equivalence census of other code. Boundaries derive from
complete FDE records and complete code, not the synthetic objdump symbol label.

Before Rust, the independent oracle used threshold comparison, whole-integer
`(2X-C) mod Q`, quotient/remainder digit extraction, and bit-column existence to
compute the union. Its pair selection uses first/last nonzero values directly.
It does not use the source's limb arithmetic, flag table or union reduction and
is not a target instruction interpreter. Native correct builds and observable
compiled mutants qualify this source against those frozen expectations. The
universal argument above establishes the all-admitted-input relation; finite
fixtures alone are not a proof. No captured execution, byte transplantation,
whole-node equivalence, original source identity or completed node gate is claimed.
