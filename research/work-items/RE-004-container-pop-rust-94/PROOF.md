# Container pop/retreat: full-domain image proof

Target: node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The result concerns all 87 bytes in `[0x5178be0,0x5178c37)`, including
the internal NOP and both returns. Names such as "object", "top", "counter"
and "pop" describe local roles, not recovered library types or provenance.

## Static boundary and dependency closure

`verify_static.py` reads the complete captured ELF as data and checks its
91,774,280-byte size and full digest. The leaf SHA-256 is
`75452a99cb5494b32fa60fdadf25261f69374120431a4dbeaed1a02534c2d620`.
Its unique FDE at `0xf7ddd8` establishes the exact interval; the `zR` CIE at
`0xce1518` and raw unwind records are retained in `static.json`. The adjacent
FDEs end at `0x5178bd9` and start at `0x5178c40`; the intervening 7 and 9
bytes are INT3 padding. GNU, LLVM and Capstone agree on all 22 instruction
boundaries and bytes. The only branch is JE at `0x5178bec` to `0x5178c00`.
There are two RETs, no calls, no loop, and no RIP-relative constant loads.

The whole `.text` E8/E9 encoding census finds exactly one direct call
candidate, `0x508f33e`, and no direct jump candidate to this entry. Decoding
its full 1,261-byte, 283-instruction caller FDE `[0x508f300,0x508f7ed)`
confirms that instruction boundary and target. The preceding instruction is
`lea 0x228(%rdi),%rdi`; together those twelve bytes are independently pinned.
All 80,300 RELA records are checked for writes overlapping the retained
code and entry-naming addends; neither exists. The leaf has no data or
helper dependencies beyond caller-provided memory. This closes the leaf's
local behavior, not the caller's business purpose, exception handling or
other callees. Unseen indirect entry paths remain possible. The census is
explicitly not an exhaustive whole-program cross-reference proof.

## State and admitted memory

Let `M = 2^64`, and reduce every effective-address addition and every
qword arithmetic result modulo M. Let O be the incoming RDI value. A
little-endian qword load at address A is denoted `Q(A)`. The new Rust API
receives one mutable byte image, its numeric base B, and O. Image byte j
represents address B+j. The entire image must be nonwrapping; an image
whose final byte is at M−1 is valid. An empty image passes this first
check, then fails its required current-word admission.

The API computes `(O+k) mod M` before mapping each field. It does not
require O itself to point inside the image, does not impose alignment,
and does not interpret returned numeric values as Rust pointers. `span`
requires A≥B, converts A−B to usize without truncation, checks the end
with `checked_add`, and requires the whole interval inside the slice.
The preliminary image check therefore also proves that every admitted
multi-byte load/store has a nonwrapping address range.

The required access order for admission is current `[O+8,+16)`, comparison
`[O+16,+24)`, then, if equal, top `[O+32,+40)` and the selected popped
qword, then outputs. On the unequal path only the counter `[O+40,+48)`
needs further admission. On the equal path both the counter and the
16-byte pair `[O+16,+32)` are admitted. The offsets in these descriptions
are modular addresses, not host pointer arithmetic.

Errors `ImageRange`, `Current`, `Compare`, `Top`, `Popped`, and `Output`
are a new safe API policy in that priority order. Every necessary check
precedes every write. An error leaves all image bytes unchanged. In
particular, the original can store the new top and then fault while
loading an invalid popped address; the new API refuses without that
partial update. The correspondence claim is for normal returns with
valid stable memory, not original fault behavior.

## Unequal path

The first load sets RAX to `a = Q(O+8)`. The full 64-bit CMP tests
`a == Q(O+16)`, with no signed ordering or low-word truncation. If unequal,
SUB RAX,32 gives `r = (a−32) mod M`, SUBQ at O+40 writes
`(Q(O+40)−16) mod M`, and the final store writes r at O+8. RAX remains r
through RET. These two disjoint stores are the only memory effects.
Neither the top field nor its target is loaded on this path.

Rust performs precisely these wrapping subtractions and the same two
stores. Admission checks do not modify memory. The same formula covers
a<32 and counter<16: there is no saturation, trap or narrower-width
arithmetic. No condition restricts the other 64-bit field values.

## Equal path and alias order

Let `t = Q(O+32)` and `p = (t−8) mod M`. The instructions at
`0x5178c08` and `0x5178c0c` perform, in this order:

1. Store p at O+32.
2. Load v from address p using the old t retained in RAX.

Consequently v is read from the memory *after* the top store. For each
byte j of that qword, its value is the corresponding little-endian byte
of p if address p+j belongs to the top slot, and the initial image byte
otherwise. This handles all fifteen overlapping displacements −7..7,
including p=O+32, as well as disjoint memory. Rust first copies p into
`image[top]`, then loads the complete qword from `image[popped]`; both
ranges were computed from the original field values before mutation.

The next SUBQ decreases the counter by 16. Its original field bytes can
overlap the popped qword, so v must be saved before this write. The state
fields themselves are disjoint: their modular offsets occupy disjoint
subintervals of the 40-byte interval from O+8 through O+47. Translation
modulo M is injective on that interval, and each admitted field also has
a nonwrapping byte span. Thus the top write cannot alter the counter
field, and later state writes cannot invalidate earlier saved values.
Rust saves v, then reads and decreases the counter, in the same order.

The LEA computes `l = (v+512) mod M`. Each MOVQ places its source in the
low qword of its XMM destination. PUNPCKLQDQ combines the low qwords into
`[v,l]`, independent of all incoming SIMD bits. SUB RAX,32 gives
`r = (l−32) mod M = (v+480) mod M`. The final stores put r at O+8 and
the 16-byte little-endian concatenation `[v,l]` at O+16. RET returns the
full 64-bit r. Rust uses wrapping addition/subtraction and copies that
same 16-byte pair. There is no source-level tag, alignment or sign
interpretation. Both increments can wrap, including v near M−1.

These are all instructions with value effects in the leaf. ENDBR64,
the unreachable fallthrough NOP and RET do not change the projected
memory/RAX relation. Both branches terminate after finitely many
straight-line operations. No data-dependent iteration or hidden count
cap is introduced.

## Correspondence limits

The API projects final ordinary memory and numeric RAX on each normal
return, for every full-u64 input and byte pattern satisfying its memory
admission. Registers RDX/XMM0/XMM1, flags, stack/CET behavior, instruction
fault order, timing and intermediate external observations are not API
outputs. It is not a System V ABI replacement. All actual native memory
accesses must be valid and stable, with no concurrent mutation, MMIO,
code alias, return-stack alias or unwinding/control-state alias. A single
image covers arbitrary overlap among the data accesses described above;
it need not represent all possible discontiguous process memory maps.
Symbolic high and wrapped numeric addresses in fixtures do not assert
that those addresses are canonical or mapped on the captured host.

## Independent expectations and tests

`oracle.py`, `static.json`, compressed input/output bytes and `frozen.json`
were written before the Rust directory existed. The freeze stores that
fact plus their hashes. Expectations use Python unbounded integers,
an immutable per-byte overlay for the top store, and a closed final-byte
relation, rather than executing an instruction model or calling Rust.
The new library uses actual ordered slice reads/writes. Their independent
representations share the stated mathematical contract, not an executing
baseline implementation.

The 1,531 fixed cases include 824 admitted pops, 568 admitted retreats
and 139 refusals across all six error outcomes; all fifteen top/popped
overlap displacements; partial aliases with the other four state fields;
all eight object alignment phases; every single-bit position; arithmetic
wraps; exact final-byte boundaries; wrapped field and popped effective
addresses; unused invalid top values; and digest-derived inputs. The
native client receives only input bytes and emits the tag, RAX value and
entire final backing image, including bytes beyond the admitted prefix.
The finite corpus exercises the proof's boundaries; the proof above is
the full-domain argument. Host tests cannot establish original compiled
byte identity or whole-node equivalence.
