# Same-flag copy pair: complete byte and register projection

Target node94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The scope is the full `[0x53b1120,0x53b114a)` and
`[0x53b1150,0x53b116e)` bodies: 42+30 bytes, 11+7 instructions.
They use the same flag field and move the same two external qwords in opposite
directions. This establishes neither an original type nor a whole-family census.

## Relation for every admitted image

Let N=2^64; all numeric effective-address additions reduce modulo N before
access. O and E are incoming RDI and RSI. A,D are incoming full RAX,RDX.
`q(X)` is a stable little-endian eight-byte load; `b(X)` is a byte load.
No alignment, canonical pointer, enum, object size or logical field meaning
is inferred. Zero is only a null gate where the original tests it.

For CopyOut at 0x53b1120, first load P=q(O+728). If P=0, no gate byte is
read, no stores occur, and (RAX,RDX)=(0,D). Otherwise read G=b(O+184).
If G=0, there are no further accesses and (RAX,RDX)=(P,D). For every other
byte G, read U=q(P+32), then V=q(P+96). Store U to E+16 and V to E+24, in
that order. The final full register pair is (V,U). Both source values are
loaded before the first store, even if their storage overlaps a destination.

For CopyIn at 0x53b1150, first read G=b(O+184). G=0 performs no other data
access and preserves (A,D). Every nonzero G reads q(E+16) and q(E+24), then
copies those sixteen bytes, in that order, to O+696. Full RAX and RDX remain
(A,D) on both paths. The vector instructions perform bit copies, not floating
arithmetic: all 128 source bits are admitted without NaN or numeric restrictions.
The API projects only RAX, RDX and memory; XMM0 state is not an output claim.

Every byte not selected for a store remains equal to the entry image. In
particular both functions preserve all memory on a closed gate. In the original
normally returning domain, each reached read and store must succeed; absent
unused fields impose no requirement.

## Exhaustive instruction argument

CopyOut begins with ENDBR64 and a full-width MOV of O+0x2d8 into RAX. TEST
RAX,RAX and JE partition all 64-bit P into zero and nonzero. The zero edge
lands directly on the final RET. The nonzero path compares the byte at O+0xb8
with zero; its JE has the same RET target. Thus 0x80 and 0xff enable the copy
just like 1. Both no-store paths leave RDX unchanged, while RAX holds P.

The remaining four MOVs load q(P+0x20) into RDX, load q(P+0x60) into RAX,
store RDX to E+0x10 and store RAX to E+0x18. In particular the second source
address uses the original P before that instruction overwrites RAX. All values
and both stores have width64, with neither boolean normalization nor extension
from a smaller width. The final RET changes only excluded control/stack state.

CopyIn has the same byte comparison followed by JE to its RET. On the enabled
path, MOVQ reads the first eight bytes into XMM0 low64 and clears its upper64;
MOVHPS reads the second eight into upper64 while keeping low64. MOVUPS stores
the whole128 bits at O+0x2b8. These are memory-to-register then register-to-memory
instructions, so overlapping or unaligned source and destination storage does
not change the snapshot rule. No GP output register is modified. No helper call,
RIP-relative operand, hidden loop or other path lies inside either complete FDE.

These partitions and width-preserving MOV operations prove the relation for
every normally returning stable-memory input, rather than extrapolating the
finite qualification vectors. Data races, concurrent observations of individual
stores, volatile/MMIO effects, exception/fault handlers, CET, flags, stack/control
aliases and native ABI integration are excluded. Data aliases among the object,
the followed pointer, gate, source bytes and destination bytes are all admitted.

## Safe finite-image correspondence

The new Rust selector is not an original argument. Slice byte i represents
numeric image_base+i in one nonwrapping interval. The interval end is calculated
in u128 and must not exceed N. Effective field addresses wrap in u64 first,
then checked subtraction/conversion and a checked span length establish that
every represented byte lies within the slice. O, E or P themselves need not
lie in the image if the reached fields do. Numeric addresses never become
native pointers. No unsafe code or allocation occurs in the library.

The safe API returns None when the finite map cannot supply a reached read or
destination. This is a new refusal, not an original return or fault behavior.
It leaves the entire image unchanged. CopyOut short-circuits the pointer-zero
test before the gate helper, and CopyIn never loads O+728. Closed paths never
validate otherwise unused sources or destinations. The whole-image nonwrap
rule is an explicit API domain restriction even on a path using only one byte.

For an enabled CopyOut, the Rust first and last values are local u64 snapshots.
Both destination spans are checked before either slice write. Their concrete
addresses and lengths match the original stores; any source/data-field alias
has already been consumed. Partial, unaligned aliases therefore need no special
case. On a failure before a store, the new refusal remains atomic. On a success,
ordered replacement of these exact byte spans is identical to the final original
memory. RAX/RDX depend on loaded U,V, not on their later memory representations.

For an enabled CopyIn, both source qwords are loaded before the 16-byte
destination check and write. Converting each with to_le_bytes preserves the
original memory bits, and concatenation puts the first qword in low64. This
matches MOVQ/MOVHPS/MOVUPS exactly for every bit pattern. A 16-byte destination
must be contiguous in the admitted interval; no SIMD alignment restriction is
added. Incoming RAX/RDX are returned unchanged regardless of data aliases.

## Static and reference closure

The full bodies, unique actual FDEs and their complete shared CIE are locked.
GNU, Apple LLVM and Capstone agree on all bytes and 18 boundaries without masks.
Six and two following INT3 bytes are separately bound as padding. All conditional
targets and RET locations are checked. Both leaves have no helper or static-data
dependency. Runtime object fields are supplied values; no unlicensed inferred
layout, source or function identity is used.

The raw-zero .data.rel.ro slots 0x57648b0 and 0x57648b8 each have exactly one
symbol-zero R_X86_64_RELATIVE writer naming the respective entry. All 80,300
RELA records are inspected for naming addends, full-width partial slot overlaps
and body/padding writes. Slot section/PT_LOAD mappings and exact records are
bound; unknown relocation widths and REL sections are rejected. Complete .text
E8/E9 candidate scans find no direct entry targets. This is not a complete
indirect reference census. The previous static packet covered only CopyOut and
explicitly excluded the adjacent same-flag member; this contribution closes
the pair together in Rust without altering that historical evidence.

## Independently frozen qualification

Before Rust existed, oracle.py formed an immutable numeric-address dictionary,
evaluated the two memory relations above, and produced final images by replacing
the selected destination bytes. It has no decoder or instruction-step state
machine and does not import Rust. The target/static record and oracle were
hashed with full input/expected streams before source creation.

There are 5,834 descriptors, each seven u64 fields followed by 800 synthetic
bytes. The active memory length varies from zero to800; expected output contains
status, full RAX/RDX and all800 bytes, including the inactive suffix. Per build,
4,460 admitted projections and1,374 explicit API refusals are checked. Structured
inputs include every gate byte, all incoming register bits, dense byte-shift
aliases, missing conditional fields, exact span endpoints, high image bases and
wrapped field formation. These are finite evidence, not exhaustive map coverage;
the preceding proof covers the entire admitted domain under its stated premises.

Only independently authored Rust is compiled/executed. Its input-only driver
receives no expected outputs or oracle. Full output bytes are compared without
masks, at opt0/opt3 and repeated builds. Neither captured code execution, an
instruction emulator, original x86 ABI behavior, original compiled-byte identity
nor whole-node reconstruction is claimed.
