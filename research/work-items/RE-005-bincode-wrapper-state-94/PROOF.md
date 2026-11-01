# Wrapper state relation and one caller composition

The native observations below bind only node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All coordinates are linked ELF virtual addresses; ends are exclusive.

## Preconditions and defined observations

Let D be entry RSI, O entry RDI, and w be 4 for `0x466bc10` or 8 for
`0x466bd10`. D contains a mode dword at +0, limit L at +8, input pointer P
at +0x10, length n at +0x18 and charge C at +0x20. These names describe
the observed operations; they do not recover a source type or constructor.

Assume valid readable input, nonwrapping pointer bounds, an ordinary stack and
callee-save convention, and disjoint input, output, state and stack regions.
The selected RELATIVE relocations must resolve as recorded. Output writes
cannot alias D, and external mutation cannot change the input/state during
the call. Native inactive result bytes are unspecified. Only the fields
written for the selected active status are part of the value relation.

All selected calls close within the six exported FDE bodies. The request has
three direct calls; the wrappers and Readers use slots `0x5775138 ->
0x466d850`, `0x57745e0 -> 0x466d980`, and `0x57745e8 -> 0x466dac0`.
Each binding has type 8 and symbol index 0. No allocator, formatter or external
callback remains on these selected normal paths. No selected FDE has an LSDA;
this does not establish whole-program exception safety.

## Fixed-width charge before all input outcomes

The two prefixes are identical apart from w:

| Operation | u32 VA | u64 VA |
| --- | --- | --- |
| Compare mode dword to 1; bypass if unequal | `0x466bc11` | `0x466bd11` |
| Load C; compare against M-w, M=2^64-1 | `0x466bc16..0x466bc1e` | `0x466bd16..0x466bd1e` |
| Load L; add w; store updated C | `0x466bc20..0x466bc28` | `0x466bd20..0x466bd28` |
| Unsigned updated-C <= L decision | `0x466bc2c..0x466bc2f` | `0x466bd2c..0x466bd2f` |
| Failure writes only status byte 2 | `0x466bc31` | `0x466bd31` |

If mode differs from 1, this prefix neither reads nor changes C/L. Otherwise:

1. C > M-w rejects before addition: C, P and n stay unchanged.
2. C <= M-w makes C'=C+w mathematically exact, without wrap. The store happens
   before the limit comparison. C'>L rejects with C' retained, P/n unchanged.
3. C'<=L reaches decoding with C'. No later path rolls the charge back.

Equality at both bounds is admitted. Thus an empty input can produce status2
before its would-be need-one result. Charge is w per attempted admitted prefix,
not encoded length: even a one-byte successful integer is charged 4 or 8.
On a non-overflow over-limit failure, another attempted call can charge again.

## Length, marker and cursor partition

After the charge prefix, `0x466bc3d/0x466bd3d` compare n to 4/8 and JBE chooses
the Reader. The slow branch passes D+0x10 and explicitly clears EDX, selecting
the existing Reader's little-endian relation. Fast loads are also little-endian.

| Input/tag after charge admission | Active result | Input consumed |
| --- | --- | ---: |
| n=0 | status0, qword O+8 = 1 needed | 0 |
| tag 0..250 | status18, value=tag | 1 |
| FB, complete payload | status18, little-endian u16 | 3 |
| FC, complete payload | status18, little-endian u32 | 5 |
| FD on u64, complete payload | status18, little-endian u64 | 9 |
| Accepted-width marker with short payload | status0, O+8 = total-width minus original n | 1 |
| FD on u32, FE or FF; n<=w | status3, expected/found bytes at O+1/+2 | 1 |
| FD on u32, FE or FF; n>w | status3, expected/found bytes at O+1/+2 | 0 |

Found codes are FD=3, FE=4 and FF=12. Expected code is 2 for both fast
wrappers and for the u32 Reader, and 3 for the u64 Reader. Successful u32
values occupy O+4 as a dword; u64 values occupy O+8 as a qword. RAX returns O.
No minimal-encoding check exists in these selected arms.

The bound is sufficient for every fast success load: n>w implies n>=w+1,
and each total load width is at most w+1. The table index is derived from an
unsigned loaded byte. Tag>=251 gives index0..4; CMP3 excludes index4 (FF)
before the four-entry table. All four destinations are bound to decoded arms.

Fast cursor writes occur only on success at `0x466bc8e..0x466bc98` or
`0x466bd97..0x466bda1`; error-builder branches do not update the cursor.
The Reader instead stores P+1/n-1 at `0x466d869/0x466d86c` or
`0x466d999/0x466d99c` before marker dispatch. A short payload therefore leaves
its available payload bytes unread. A successful payload replaces that initial
update with the complete P+total/n-total result. These Reader writes address
only D+0x10/+0x18 in the wrapper call, so they do not change the charge.
The error builder writes exactly status3 and the supplied two code bytes.

Concrete counterexamples to using the Reader at every length:

- u64 FE plus seven following bytes: expected/found 3:4, consumes1.
- u64 FE plus eight following bytes: expected/found 2:4, consumes0.
- u32 FD at lengths4 and5: both report2:3, but consume1 and0 respectively.

These are conditional static consequences, not executed target samples.

## Existing request caller, newly composed state

The already-mapped FDE `0x438b5c0..0x438b6d7` retains D in R14 and uses a
32-byte stack result. Call `0x438b5d2 -> 0x466bc10` reads the header. Only
status18 reaches its integer selector. Tag1/2 writes a unit value at output+8;
tag>2 writes status5 plus the offending tag and its existing type/range metadata.
Those routes do not call a u64 wrapper.

Tag0 calls `0x466bd10` at `0x438b646`. Only status18 permits the second call
at `0x438b65e`. Both use the same saved D. The first value is saved in R15;
on two successes, output+8/+0x10/+0x18 receive 0/first/second and status18.
The status checks are at `0x438b64f` and `0x438b667`. No transaction rollback
appears in this caller. The selected primitive effects therefore compose in
exact call order, stopping before later charges/reads on the first failure.

For example, `00 01 02` yields pair(1,2), consumes3 and adds20 to charge under
mode1 if each prefix is admitted. From C=0, limit19 fails the second u64
prefix with charge20 retained and `02` unread; limit20 permits all three reads.
An initially empty request still attempts the header's charge4 before need-one.

The caller copies inactive bytes together with active errors at
`0x438b5ff..0x438b62b` and `0x438b6a8..0x438b6c6`. This is not permission to
read uninitialized Rust values. Our composition adapter exposes only active
status/code/count/tag/value fields and the complete input suffix. Type metadata,
padding, original Rust layout and error ownership are not reconstructed.

## Why the safe implementation may reuse the Reader

For n<=w, the wrapper directly selects the little-endian Reader. For n>w,
the rejected marker cases above must be handled before any cursor update.
Every remaining tag is a successful native fast case with sufficient bytes;
its value and suffix equal the existing Reader relation. The Rust therefore
handles fast rejections first, then reuses the established Reader for remaining
cases. This is a value/state equivalence argument, not native call-trace identity.

The charge uses checked u64 addition, followed by the stored increment and
limit check. Safe borrows represent disjoint mutable state and immutable input.
The API's `from_state` supplies explicit research fields; no original
constructor, valid source enum, whole wire schema or compiler identity is inferred.

The Python fixture derivation is a separately written piecewise integer/slice
relation using bound native immediates and `int.from_bytes`. Rust uses the
existing byte-folding Reader. Expectations were frozen before these APIs existed.
Finite fixtures corroborate this partition argument; they are not an execution
of every native input or two independent target sources.
