# Full byte-domain relation and captured-span bounds

The target is node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete leaf is `[0x14b4e20,0x14b4e48)`: 40 bytes, ten instructions,
one return, no calls or conditional branches. Addresses below are linked ELF
VAs. `L` denotes a numeric load bias and `N = 2^64`.

## Exact observed registers

Assume the original byte read at incoming RDI succeeds and returns `t`.
`MOVZX ECX, byte [RDI]` writes ECX, clearing the upper half of RCX; therefore
the entire RCX equals the unsigned integer `t`, with `0 <= t <= 255`.
`MOV RAX,RCX; XOR RAX,1` yields `u = t xor 1`. Toggling bit zero is a
permutation of the byte domain, so `0 <= u <= 255`.

`LEA RDX,[RAX+RAX*2]; ADD RDX,14` gives `3u+14`. Its maximum is 779,
well below `2^64`; neither operation overflows. The minimum is 14. Both are
64-bit destinations, so this is the complete RDX value, not its low byte or
low dword. The maximum occurs at `t=254`, whereas `t=255` gives 776.

The two RIP-relative LEAs have signed 32-bit displacements. Independently
adding each displacement to its next-instruction linked VA yields
`B=0x21bfa3` for RSI and `A=0x21bf92` for RAX. With a common load bias,
the numeric effective addresses are `(L+B) mod N` and `(L+A) mod N`.
LEA does not read the bytes at those addresses. The RSI assignment happens
unconditionally, including when `t=0`.

`TEST RCX,RCX; CMOVNE RAX,RSI` selects the entire RSI when `t != 0`.
The only return follows immediately. Thus all four written general registers
at normal return are:

| Register | Exact value |
| --- | --- |
| RAX | `(L + A) mod N` if `t=0`, otherwise `(L + B) mod N` |
| RDX | `3*(t xor 1)+14` |
| RCX | `t`, zero-extended to all 64 bits |
| RSI | `(L + B) mod N`, even when `t=0` |

There is no external call, unknown post-call register, partial-register final
write, implicit enum restriction, null-pointer test, or signed byte conversion.
Incoming RDI is unchanged by the body; its value is deliberately not an input
to the value API. No other general register is written except normal return
stack/control effects. Flags, stack state, faults, calling convention and
instruction timing are outside the API.

## Full data union, without a logical-name assumption

The original instructions do not dereference the selected pointer or validate
the returned extent. Considering the mechanical pair `(RAX,RDX)` at linked
coordinates, `t=0` selects `[A,A+17)=[A,B)`. Every other byte selects
`[B,B+3*(t xor 1)+14)`. All these intervals fit within `[A,B+779)`, and
`t=254` reaches its exact upper bound. The union is therefore exactly
`[0x21bf92,0x21c2ae)`, 796 bytes, not just the 62 bytes locked by the old
foundation packet.

The new static checker binds all 796 bytes to the actual artifact. It checks
the full `.rodata` section mapping, a file-backed read-only PT_LOAD and every
RELA record for an overlapping writer, including partial overlap at either
end. There are no such writers. The fixed file bytes describe a normal loader
mapping that remains unchanged; arbitrary runtime mutation is not assumed
away silently. If the original returned pointer is later dereferenced, its
validity is an additional premise about that later operation, not a condition
imposed by this leaf.

The first 17 bytes are `invalid character`, and the following 14 are
`invalid length`. Tags 0 and 1 select exactly those intervals. Higher tags
include subsequent captured bytes; those mechanical spans are not claimed to
be valid source enum values, error names, UTF-8 strings or null-terminated
strings. No source library/version or symbol identity is inferred.

## Safe Rust contract and arithmetic safety

`select(tag: u8, load_bias: u64)` projects the original successful byte read
and the four written register values. It accepts every input pair and never
dereferences a numeric address. Taking `u8` supplies the original read's result;
it does not reconstruct the caller's pointer, accessibility check, memory race
or read fault. The relation applies to the original when that byte read and
normal return succeed. Every numeric bias is supported by the algebra; this
is not a claim that every such bias is a feasible canonical executable mapping.

Rust widens before XOR/multiply/add. The bound `3*255+14=779` proves those
operations safe even with overflow checks enabled. The two address additions
use explicit `wrapping_add`, implementing arithmetic modulo `N` in both native
profiles. No signed shift, division, narrowing of the address, allocation,
dependency or unsafe operation occurs in the library.

`captured_bytes(tag, window: &[u8;796])` is a separate safe byte-view adapter.
It is not an extra load performed by the captured leaf. With the exact bound
captured window, it exposes all bytes of the mechanical linked interval.
With any other array it simply selects the same indices; target-data identity
is then not claimed. It uses a host slice independently of `load_bias`, not a
host pointer cast or a dereference of RAX. Its range is `0..17` for zero and
`17..17+length` otherwise, so the proof above excludes out-of-bounds access for
all 256 tags, including the exact 796 endpoint. `length <= 779` fits `usize`
on the qualified 64-bit host. Numeric addresses can wrap while these host
indices remain ordinary nonwrapping array indices.

## Static closure and remaining boundaries

GNU, LLVM and Capstone independently decode the complete 40-byte body with
identical byte boundaries. Full FDE/CIE records establish its extent; the four
preceding and eight following `INT3` bytes are excluded from it. Neighbor FDEs
are bound as boundary context, not claimed sibling reconstructions. The sole
entry-naming relocation is an exact `R_X86_64_RELATIVE` writer at `0x566de38`,
whose file qword is zero. The checker binds its entire record, raw slot and
section, proves its writer unique against all 80,300 RELA records, and also
rejects code/data relocation writers. No input tag restriction follows from
this pointer slot. The complete `.text` E8/E9 encoding scan finds no direct
candidate to the entry; this is not a complete indirect xref census.

The proof depends on observed instructions and ordinary integer/byte-array
relations. It neither executes nor emulates captured instructions. It does
not recover the indirect caller, source enum, original compiler, native ABI
adapter or original compiled-byte identity. Whole-component gates remain
unchanged.

## Independent expectations and finite qualification

Before the Rust source directory existed, `oracle.py` froze inputs, outputs
and hashes binding its own source, this target's static record and complete
captured data. Its length relation is `3*t+17` for even `t`, `3*t+11` for odd
`t`, derived from parity rather than the library's XOR expression. For even
`t`, toggling bit zero increases it by one; for odd `t`, it decreases it by
one. The two formulas therefore agree with the instruction relation for
every byte. The oracle computes addresses by unbounded integer addition and
division remainder, and enumerates every selected byte by interval indices.

The 6,885 frozen cases cover every byte across a common set of bias corners,
additional bit boundaries and deterministic random biases. They include 1,792
wrapped-address cases and 257 cases with a numeric zero in RAX or RSI. All
four registers and all selected bytes are compared; bytes are not replaced
by hash-only equality. The output padding is a host protocol detail.

These finite cases qualify actual newly authored host code and exercise wrong
implementations. The full-domain claim comes from the instruction and range
proof above, not from treating the corpus as exhaustive over 64-bit biases.
The original binary is never run or emulated.
