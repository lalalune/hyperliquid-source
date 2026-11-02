# Supplied-reader ABCI greeting: value and state contract

The operation is the complete ordinary-return value projection of node94
`0x4674820..0x4674b45`, including all six outer tags, all three nested tags,
all three map readers and their insertion/split/cleanup closure. The target is
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The selected caller projection is entry `0x471b880` with **EDX = 0** only.
Instrumentation-enabled paths remain context; no socket, startup, peer trust,
cryptographic validity, protocol-version or interoperability claim follows.

## Domain and premises

Input is a finite immutable byte span of length at most `2^63-1`, a cursor
within that span, a limit-enabled flag exactly 0 or 1, a u64 limit and a u64
charged count. The limit tag is the entire initialized u64 word 0 or 1, including
zero upper 32 bits: scalar wrappers test a DWORD, whereas group/map code tests
the QWORD. Merely providing a low-byte boolean with arbitrary upper bytes is
outside this contract. The supplied Reader has those initialized active fields at
`+0`, `+8`, `+0x10`, `+0x18`, `+0x20`; cursor and remaining identify the same
nonwrapping readable span. No requirement `charged <= limit` is imposed.
Disabled charging preserves the arbitrary initial charged count.

Reader, input, outputs, stack locals, allocator metadata and every live map
node/allocation are disjoint where their accesses require it. Ordinary SysV
register preservation, stable stack/Reader/input/outputs across opaque calls,
and absence of foreign mutation apply even after pointers have escaped.
Allocator calls return fresh, suitably aligned, nonaliasing live storage of
the requested size; the appropriate deallocator consumes exactly that owned
allocation, returns normally and preserves unrelated memory. No allocation
failure, panic, trap, unwind, allocator layout, callback timing, or Rust/native
allocation identity equivalence is claimed. These are premises, not conclusions
from symbols or from the existence of a normal return instruction.

Imported `memcpy` copies exactly its requested readable source bytes to a
valid disjoint destination and preserves all other live memory. For count zero,
the ordinary-call premise expressly permits the native nonnull sentinel
destination 1 and the empty source span without dereferencing either pointer;
the sentinel is not claimed to be an allocated object. `memmove`
has the same copy/frame effect with overlapping ranges allowed. `memcmp`
returns zero exactly for equal requested bytes and otherwise the sign of the
first differing **unsigned** byte, without changing those buffers. Imported
names are relocation-bound; implementation and frame behavior remain premises.
All map roots are created empty by this invocation; no arbitrary supplied
native tree is admitted. Their live tree invariants are proved inductively
from insertion, not assumed as an opaque map helper contract.

All exposed values omit native padding, inactive union bytes and allocation
pointers. A native map is projected to its finite key-to-value relation in
unsigned lexicographic key order; this ordering is a representation of the
proved relation, not an extra claim that this call invokes an iterator.

## Active error values

| Native kind | Exposed active fields |
| --- | --- |
| 0 | `needed: u64` |
| 1 | none (bulk byte-vector shortage) |
| 2 | none (charge multiply/add overflow or limit exceeded) |
| 3 | `expected: u8`, `found: u8` |
| 5 | `type_name`, inclusive permitted bounds, `found: u32` |

No semantic name is assigned to inactive copied bytes. Errors propagate the
active error and the Reader state at the first failing operation; there is no
rollback. Kind 5 is either `AbciStreamGreeting`, bounds 0..5, or `GreetingHash`,
bounds 0..2. Those names/bounds are bound literal data, not guessed type names.

## Scalar and fixed-width primitives

`charge(k)` does nothing when disabled. Otherwise, mathematical `charged+k`
above u64 MAX yields kind 2 **without storing**; a representable sum is stored
first, then kind 2 is returned if it exceeds the limit. No input is consumed
by a failed charge.

A u32/u64/usize scalar first charges 4/8/8 respectively. It then reads an
unsigned varint with marker 0..250 meaning that single-byte value; 251, 252,
253 mean little-endian payloads of 2, 4, 8 bytes when supported. Nonminimal
encodings are accepted. For u32, markers 253/254/255 are invalid with found
category 3/4/12; for u64 and usize, markers 254/255 are invalid with category
4/12. The expected category is 2 for u32, 5 for usize. **For u64 it is 2 on
the fast path and 3 on the slow path.** This difference is observable.

The fast path is selected iff remaining is strictly greater than 4 (u32) or
8 (u64/usize). It commits cursor/remaining only after a valid marker; enough
payload is guaranteed by that threshold. An invalid marker consumes nothing.
The slow path consumes an available marker immediately. Empty input yields
kind 0 needed 1 without consumption. A supported marker with insufficient
payload yields kind 0 needed `(1+payload_width)-old_remaining`, retaining only
the marker consumption. A supported complete payload commits the rest. An
invalid marker returns kind 3 after consuming the marker. Endianness supplied
to the Reader leaf is exactly zero at every wrapper call in this operation.

`fixed(n)` charges n, then if remaining<n returns kind 0 needed n-remaining
without consuming any fixed bytes; otherwise it consumes/copies exactly n.
The only widths are 20, 32 and 2048. A signature consists of two groups of four
u64 scalars followed by one arbitrary raw byte. Each group first charges 32,
then refunds 8 immediately before each scalar's own 8-byte charge. Thus an
accepted group reservation remains fully charged even if an early scalar
fails. The final byte charges 1 before EOF testing and accepts all 256 values.
There is no signature recovery/canonicality/verification claim.

A byte vector reads its length N using the u64 wrapper, charges N, then tests
remaining>=N. Shortage yields kind 1 with no consumption of the byte span.
Success allocates/copies N bytes (N=0 uses no allocation) and only then advances
the cursor by N. The passed `0x466bbb0` element-function address is not called:
full `0x4589a30` performs a bulk copy. N larger than isize MAX cannot pass the
remaining test in the admitted span domain.

## Full greeting grammar and logical values

An outer u32 tag is read first. Tags 2,3,4,5 have no further fields and return
logical `Empty2`, `Empty3`, `Empty4`, `Empty5` (native tags 4,5,6,7).
Outer tag 1 reads three u64 scalars in wire order a,b,c, returning `Triple(a,b,c)`
(native tag 3 stores b,c,a at offsets +8,+0x10,+0x18).

Outer tag 0 reads byte vector V, u64 scalar Q, then a nested u32 tag:

* Nested 0: fixed32 H, one signature map M; `Data0(V,Q,H,M)` (native tag 0).
* Nested 1: fixed32 H, signature map M1 followed by signature map M2;
  `Data1(V,Q,H,M1,M2)` (native tag 1).
* Nested 2: exactly three records R0,R1,R2; each is two usize scalars a,b then
  exactly 2048 raw bytes B; `Data2(V,Q,[(a,b,B);3])` (native tag 2).

Every map reads a u64 wire count N. Enabled charging reserves `96*N`, with
checked multiplication and then checked addition; representable addition is
stored before limit comparison. Each entry refunds 96 before decoding fixed20
key K and the signature value S. Entries are read in wire order. A repeated key
replaces the prior entire logical signature without increasing map length;
last occurrence wins. Successful maps have charged `8 + 85*N` beyond their
incoming charge (when enabled), despite the native reservation of 96 per row.
On failure, unprocessed reservations remain and the exact successful/failed
prefix charges are retained. No full-map refund is performed.

The group and map refund guards cannot fail within the domain: before each
unprocessed entry the remaining reservation includes at least 96, and before
each group scalar it includes at least 8. Accepted charge is representable
and never increases past the accepted map reservation during an entry because
its actual decoded charge is 85<96. A first failed map destroys its accumulated
native map before propagating its error. If the second map of nested 1 fails,
its own partial map and the already complete first map are destroyed. The
outer byte vector is destroyed on later scalar or nested failure. No partial
logical value is exposed on error. Those cleanup paths preserve the Reader
under the explicit frame premises.

## Selected caller projection

With EDX=0, `0x471b92b..0x471b967` constructs a fresh Reader from the supplied
pointer/length and dereferenced u64 limit: enabled=1, charged=0. On success it
returns the same logical value with `consumed=Some(original_length-remaining)`.
It does **not** require exhaustion of trailing bytes. On error it forwards the
active error with `consumed=None`; native +0x80 is inactive and need not be zero.
The internal Reader changes are not written back into the supplied three-word
caller input. A later safe interface may separately return the core Reader
state, but must not label that an existing caller ABI output.

## Source policy boundary

No source implementation exists at this pre-code stage. A later safe parser
may reject invalid host spans or report host allocation failure explicitly;
these are separate safe policies, not native error kinds or failure-atomicity
claims. It must preserve successful values, active errors and post-read state
on the admitted ordinary-return domain, including length-dependent scalar
errors, nonminimal encodings, duplicate keys and unconsumed trailing bytes.
The proposal does not require a native-layout tree, allocator or pointer ABI.
