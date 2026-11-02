# Highest-bit selection over two words and a 128-entry table

The complete node94 `[0x55442e0,0x554431b)` body has 59 bytes and 17
instructions. Its full bytes, unique FDE/CIE, padding and caller are bound
to the target SHA-256 in `static.json`. This is a value reconstruction;
the source type and meaning of the returned table entries are unknown.

## Data layout and guarded BSR

Let H be the qword loaded at object+0x1490 and L the qword at object+0x1488.
The first load/test reads H. If H is nonzero, the body sets ESI=64 and
branches to BSR on H without reading L. Otherwise it loads L and clears
ESI. If L is also zero, MOV RSI,RAX returns full zero without reading a
table entry. If L is nonzero, BSR runs on L with bias zero.

Thus BSR never receives zero. Its otherwise undefined destination for a
zero source is irrelevant on every path in this body; no assumption about
a preserved destination register is needed. For a nonzero qword x, BSR
returns the unique j in 0..63 satisfying `2^j <= x < 2^(j+1)`.

Adding the bias in ECX yields an index in 0..127. The 32-bit addition and
subsequent MOV ECX,EDX cannot overflow and zero the high index bits.
The qword load at `object+0x1088+index*8` therefore selects one of exactly
128 slots. The largest start is object+0x1480 and the largest exclusive
end is object+0x1488. Consequently the complete table interval is adjacent
to, and disjoint from, the L/H fields. The qword moves to RSI and RAX
preserve all 64 bits; no boolean or low-word return interpretation applies.

## Combining the fields without changing priority

Define the mathematical u128 value `V = L + 2^64*H`.
If H is nonzero with highest position j, then

```text
2^(j+64) <= 2^64*H <= V < 2^(j+65).
```

For the upper bound, H<=2^(j+1)−1 and L<=2^64−1, so V is at most
`2^(j+65)−1`. Its highest bit is exactly j+64, independently of L.
If H=0 and L!=0, the highest bit of V is that of L. If both are zero,
V=0 and the original return is zero. Hence the complete relation is

```text
V = 0: return 0
V > 0: return table[floor(log2(V))].
```

This logarithm denotes the integer interval index, not a floating-point
operation. Rust's nonzero u128 has between zero and 127 leading zero bits,
so `127 - value.leading_zeros()` is exactly that index and cannot underflow.
The fixed 128-element array makes the resulting load valid. The zero branch
precedes subtraction and indexing. No unsafe code, unchecked index, shift
by a type width, arithmetic overflow or data-dependent panic is possible.

## Snapshot correspondence

The u128 API packs the L/H fields numerically; it does not claim the target
loads a u128 or that its object uses Rust layout. Table elements are decoded
little-endian qword values. Stable ordinary readable memory is required for
original accesses. The safe API requires valid snapshots of both fields and
all 128 table words, strengthening original availability: the target skips L
when H!=0 and skips the table when V=0. It can therefore have normal returns
on partially mapped objects that this safe snapshot API does not describe.

There are no stores. Concurrent/volatile changes, faults, pointer wrapping,
timing, original ABI, scratch registers and caller invariants are outside
the claim. The table's contents are runtime inputs, not recovered constants.
All u128 values and all 128-u64 arrays are admitted to the value relation.

## Independent native expectations

The pre-Rust oracle enumerates the 128 half-open power intervals and checks
that exactly one contains each nonzero V, and none contains zero. It uses
neither BSR, a leading-zero count nor a bit-length primitive. The interval
partition derives the expected index mathematically.

Compact fixture descriptors provide L,H,seed,step and one override. The
input-only host driver materializes a real 128-word array with
`table[i]=(seed+step*i) mod2^64`, then overwrites one selected slot and calls
the library. Expected values never reach the client. The oracle directly
evaluates the affine expression at the independently selected index, or uses
the override if that index matches. No target instruction evaluator or fake
sparse-load callback is involved.

All 128 selected indices and the zero case are covered. Power boundaries,
full low words combined with nonzero high words, full-width stored values,
constant tables, affine wrap and overrides at selected/unselected indices
exercise selection separately from table contents. The proof covers arbitrary
arrays; the finite affine/override corpus is not an exhaustive array census.
Mutants change priority, rank direction/off-by-one, the upper-word bias,
zero behavior, table-index width and returned-word width.

## Static closure and limits

The complete caller `[0x5522780,0x5522d66)` is decoded independently by
GNU, LLVM and Capstone. A whole-text direct-E8 scan finds `0x5522959`,
confirmed at a caller instruction boundary targeting this leaf. No caller
purpose or field invariant is inferred. Full FDE parsing proves the selected
body extents; five trailing INT3 bytes are separate padding. The leaf has
two internal conditional branches, two returns and no calls. Its only data
reads are the fields and selected table word described above. All 80,300
RELA records are scanned for entry naming and protected-code writes; none
is found. This is not a census of indirect references or a whole-node claim.
