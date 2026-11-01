# Full 20-byte mixer returned-value relation

This proof binds node94 ELF VA `[0x4b27620,0x4b27669)`: 73 bytes, 22
instructions, no branch or call, and one terminal return. The complete
body/FDE, relocated seed pointer and caller edge are checked statically.
The interpretation is a raw value relation, not a recovered hash algorithm,
source name or pointer ABI.

## Overlapping loads and explicit runtime seeds

Let `W(o)` decode the eight input bytes at offsets o..o+7 in little-endian
order. The selected offsets are exactly 0, 4, 8 and 12. Their union is the
20-byte input interval; neighboring loads overlap by four bytes. Independent
qword inputs would lose the correlations established by those shared bytes,
so the Rust API accepts one `[u8;20]` and performs the same four byte reads.
All offsets and lengths are fixed and within that array; the private conversion
from an eight-byte slice cannot fail for any public input.

Let P be the eight-byte value loaded through RDI. The pointer loaded from
RIP-relative slot `0x576e3e0` supplies seed values S0 at offset zero and S1
at offset eight. The slot has exactly one symbol-zero R_X86_64_RELATIVE record
with addend `0x5788348`. That address and the following 16 bytes belong to
writable allocated NOBITS `.bss` and a writable PT_LOAD memory extent. They
are not file-backed bytes. The file's zero slot word is pre-relocation data,
not a runtime seed or a runtime null pointer.

The API supplies P, S0 and S1 as explicit synthetic/runtime snapshots; it
infers no initialized seed values. Original reads require valid, stable,
ordinary memory. The leaf performs no writes, so overlap among those original
read-only regions is harmless under that stability premise; a physical alias
simply constrains the supplied snapshots to have consistent bytes. Volatile,
concurrent or torn reads and invalid-pointer faults are outside the relation.

## Three complete unsigned products

For unsigned u64 a and b define `F(a,b)=low64(a*b) XOR high64(a*b)`, where
the product has 128 bits. Its maximum `(2^64-1)^2` is below `2^128`, so the
Rust u128 multiplication is exact even with overflow checks enabled.
The casts select the low word, and shifting by 64 selects the high word.

The first MUL at `0x4b2763c` computes

```text
T1 = (W(8) XOR S1) * (W(12) XOR S0).
```

R8 preserves its low half and R9 preserves its high half. The second MUL at
`0x4b27652` computes

```text
T2 = (W(0) XOR P) * (W(4) XOR S0).
```

The following XORs combine both high halves and both low halves, followed by
the immediate 20. XOR is associative and commutative on fixed 64-bit words,
so the accumulator is exactly

```text
A = F(W(8) XOR S1, W(12) XOR S0)
    XOR F(W(0) XOR P, W(4) XOR S0)
    XOR 20.
```

The final MUL at `0x4b27662` multiplies A by S0, and the last XOR combines
its low and high halves. The selected return is therefore `F(A,S0)`. The
high half of T1 is not omitted, none of the three products is truncated before
its fold, and the final seed is S0 rather than S1. The implementation's helper
expresses this complete relation directly.

For S0=0 the final result is zero for every other input. With all input bytes
and P/S1 zero but S0=1, the result is 20. These are arithmetic consequences,
not assumptions restricting the admitted bit patterns. Every u64 prefix/seed
and every 20-byte array is accepted. There are no dynamic shifts, indexing
from input data, division or arithmetic error branches.

RDX also contains the last product's high word at RET. No caller use as an
additional return value is established here, and the API claims only RAX.
Register clobbers, flags, timing, original ABI and unwinding are unclaimed.

## Independent product-column oracle

The pre-Rust oracle decodes W using unbounded base-256 digit sums. Each product
fold is calculated from four 32-by-32-bit products rather than a native u128
multiply. With base B=2^32, write `a=a0+B*a1`, `b=b0+B*b1` and compute

```text
c0,w0 = divmod(a0*b0, B)
c1,w1 = divmod(a0*b1 + a1*b0 + c0, B)
high  = a1*b1 + c1
low   = w0 + B*w1.
```

Expanding the product shows `a*b = low+B^2*high`, with each w in `[0,B)` and
high in `[0,2^64)`. Hence `low XOR high` is precisely F. The oracle uses no
captured register/flag state, decoded operand evaluator or Rust execution.
It freezes its source and fixtures before Rust exists. A retained historical
sample is checked as an additional anchor, not used to generate expectations.

The proof covers all inputs. Finite native testing corroborates the new Rust
and host compiler path; it is not an exhaustive input enumeration or target
execution. Deliberate wrong implementations separately exercise overlapping
read offsets, endianness, seed selection, each omitted product high half and
the fold tag.

## Static and caller limits

The single direct E8 candidate at `0x4dd768f` is confirmed as an instruction
start in the complete caller FDE `[0x4dd6ea0,0x4dd839e)`. All bytes are decoded
and hashed. This does not establish the caller's full behavior or the seed
initialization path. A RELA scan binds the single seed slot and excludes
relocation writes over the selected code/seed-read region; runtime writes to
.bss by ordinary code remain possible and are not modeled as static constants.
The new value API does not resolve source provenance, input meaning, seed
ownership or whole-component behavior. No target binary or emulator executes.
