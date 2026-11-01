# Complete leaf value and memory proof

Coordinates are ELF virtual addresses in the pinned node #94. The complete
FDE is `[0x55716a0, 0x557170a)`; six `int3` bytes after it are padding.
The 30 decoded instructions contain no calls or external data reads except
the one byte through RDX. The two gap NOPs are inside the body. RDI is the
output address, RCX the unsigned 64-bit length, and RDX the payload address;
entry RSI is unused and becomes the payload index. These register facts do
not recover a source signature or format name.

## Exhaustive paths and width

`cmp rcx,31; ja` sends exactly `n >= 32` to the second comparison.
`cmp rcx,4095; jbe` sends exactly `32 <= n <= 4095` to the medium path.
The remaining path is exactly `n >= 4096`, including the entire upper half
of `u64`. Thus the three paths partition every possible input.

| Input n | Integer H | Header bytes stored w | Payload offset | EAX |
| --- | --- | --- | --- | --- |
| 0..31 | 8n+1 | 1 | 1 | 2 |
| 32..4095 | 16n+5 | 2 | 2 | 3 |
| 4096..2^64−1 | 16n+13 | 4 | 3 | 4 |

Let `h_i = floor(H / 256^i) mod 256` for `0 <= i < w`.
The observed little-endian stores write these digits. On the first path,
`8n+1 <= 249`, so the low-byte store loses nothing. On the medium path,
`16n+5 <= 65525`, so the low-word store loses nothing. On the last path,
ECX shift/add is modulo 2^32. For each `i < 4`, adding any multiple of
2^32 to H leaves `h_i` unchanged. Therefore using unbounded H in the
independent oracle is equivalent to the original 32-bit result for all
u64 n, including multiplication overflow and lengths above 2^32. The
header actually has period 2^28 within this last branch. This periodicity
does not authorize narrowing n before the branch comparisons.

The Rust header uses `n as u32`, `wrapping_mul`, and `wrapping_add`.
`(16(n mod 2^32)+13) mod 2^32 = (16n+13) mod 2^32`; the same relation
holds for the smaller paths. There is no data-dependent shift or integer
overflow trap. `to_le_bytes` defines byte order on every supported host.

## Memory substitution and alias order

Assume ordinary valid nonvolatile memory, no concurrent mutations, enough
writable output for the returned count, and a readable payload byte. Let M
be entry memory relative to the output address. The complete observable
store/load sequence is:

1. M' equals M, except `M'[i] = h_i` for `0 <= i < w`.
2. If the payload is at output-relative index j, read `p = M'[j]`.
   If it is disjoint, read its stable external byte p.
3. M'' equals M', except `M''[EAX−1] = p`. Return EAX.

This substitution accounts for every memory access in all three paths. In
the last path, step 3 overwrites `h_3`; when j=3 it writes that same `h_3`
back. Removing the fourth header store incorrectly reads the entry byte
instead. Treating the payload as an unconditional entry snapshot also
fails for any j inside the header. For example, with n=0x1000000 and
M[3]=0xc4, j=3 produces `0d 00 00 10`, while a stable disjoint 0xc4
produces `0d 00 00 c4`. With n=31 and j=0, the prefix is `f9 f9`.
With n=4095 and j=1, it is `f5 ff ff`.

Rust's copying of header bytes can use a different physical store sequence;
under the stated nonvolatile, nonconcurrent memory premises its completed
M' is identical before the payload read. The safe projection does not
claim atomicity, target instruction timing, faults or partial writes from
invalid target pointers.

## Safe API bounds

`total` is always in {2,3,4}; `w` is in {1,2,4} and `w <= total`.
The API first requires `output.len() >= total`. It then requires j within
the slice for `Payload::Output(j)`. Both checks precede every mutation.
On success all header indexing, the payload read, and index `total−1`
are in bounds. Every write is below total, so the suffix is unchanged.
The returned count converts exactly to u32. Rust's exclusive mutable slice
and explicit offset avoid creating aliased references; no unsafe code,
allocation, or pointer arithmetic is used in the library.

`OutputTooShort` takes precedence over `PayloadOutsideOutput` when both
safe premises fail. This precedence and the unchanged-buffer refusal are
new API choices. They make no claim about the original code on invalid
memory. The captured source's pointer type, container ownership and
possible broader aliases remain unresolved. External snapshots assume
disjoint stable storage; offsets model aliases anywhere in the supplied
slice, including bytes beyond the written prefix.

## Static closure and limit

The full body, its CIE/FDE, six padding bytes and complete 1,529-byte caller
FDE are bound to the target. Full linear decoding from the caller entry
places `0x5573e2b` at a real `call 0x55716a0` instruction. Immediately
before it, RSI comes from `[rsp+8]`, RDX=R10 and RDI=R12. No claim is made
about RCX's upstream meaning, the rest of the caller's behavior, or all
register-indirect references. The legacy full-section scan retains one
direct-e8 candidate and no relocation addend naming the leaf. All helper
and constant dependencies of this leaf are closed: there are no callees,
tables or relocated constants inside it. The header tags' purpose remains
unknown.

The proof is static and the numeric/memory tests run only new Rust. They
do not establish Linux ABI equivalence, captured execution equivalence,
machine-code matching, a full wire format, or a component progress gate.
