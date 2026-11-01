# Independent pre-source proof: string padding request relation

Target: node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Primary actual FDE: ELF VA `0x1573450..0x1573889`, 1,081 bytes / 300 rows,
body SHA-256 `f958a0383269ead1a2056ba42785c9050e46a57aa0f990a27976fe27cb5eee77`.
Basis is the complete retained native rows/listing and admission
`175919e0989e668267383b26edb20b438d1ca6a9f75275be8cb3c8f38280efce`.
The published `Formatter::pad` symbol is correspondence evidence, not an
assumed original source implementation or private ABI. No proposed new Rust
or author's semantic proof was read for this independent derivation.

The separate fixed counter at `0x15796c0..0x1579c8b` (1,483 bytes / 365 rows)
has body hash `13c5b0904bd66520b303cc5513d2cf7fed55c20298a5bef6a979f81be0083f35`.
Its complete valid-UTF8 count relation and data were already closed in #1439;
they are reused with credit, not claimed as another new helper recovery.
The actual call field goes through unique RELATIVE slot `0x5770628` to it.

## Domain and observation

The immutable input is a valid UTF-8 string of N bytes, N <= isize::MAX,
with readable, nonwrapping storage. Formatter, method-table, input, code,
constants and frame roles remain appropriately separated. Writer callbacks
return normally with ordinary call preservation; no concurrent mutation is
admitted. The callbacks may sequentially change the explicitly supplied
header/data/table and table-method cells. Every table ID names a stable,
unique admitted logical descriptor. Pointer identities are projected to
opaque logical IDs; output rendering and the original renderer ABI are open.

Use an own logical u64 word W for the eight observed bytes at native +0x10:
low32 H, next16 width w, top16 precision p. This is a convenient selected-field
value representation, not an assertion about an original Rust struct.
All bit patterns are admitted as these raw fields. Let F=H & 0x1fffff,
A=(H>>29)&3, U=(H & 0x08000000)!=0, P=(H & 0x10000000)!=0.
Char requests carry the raw u32 F, even if it is not a Unicode scalar.

Observe the ordered Char/Str callback requests, cached data/table IDs,
method identity loaded at each request, raw supplied u8 reply, complete
context values before callback actions, final context/method cells, and
returned low byte. No nominal result object, hidden registers, faults,
unwind, physical read timing, renderer result or whole-node behavior is claimed.

## Fast path and selected text

The entry tests H & 0x18000000. If neither U nor P is set, it jumps directly
to `0x15737c1`: request the entire original input once and return the supplied
raw low reply byte. Raw nonzero w or p are ignored on this path. This is not
equivalent to always applying raw width/precision.

If P is set, `0x15734a1..0x1573536` selects the first min(p,C) Unicode scalars,
where C is the full string's scalar count. Its width decoder chooses 1 byte
for ASCII, 2 below E0, 3 below F0 and 4 otherwise. Valid UTF-8 guarantees that
each visited lead is a boundary with all required bytes present. Inductively,
the cursor advances by exactly one scalar width, remaining starts at p and
decreases once per scalar, and the byte accumulator is the consumed prefix
length. On p=0 both length/count are zero without reading input. On reaching
end with remaining>0, p-remaining is C; on exhausting p, remaining is set to
zero and count is p. Original text start is restored before any output call.
Thus selected text is a valid UTF-8 prefix and selected count c=min(p,C).
No grapheme, byte or display-column precision rule is inferred.

If only U is set, selected text is the entire string and c=C. For N>=32,
the actual fixed counter supplies C. For N<32 the inline count is closed below.
After either enabled-option path, `0x1573787` reads raw width w even when U
is clear. Therefore precision alone can still cause padding with nonzero raw w.

## Complete inline short count

For N=0 the count is zero. For 1<=N<4 the scalar tail counts a byte exactly
when its signed i8 value is >= -64 (`CMP ... C0; SETGE`), i.e. it is outside
80..BF. In valid UTF-8, these are precisely ASCII bytes and scalar leads.

For 4<=N<32 the bulk length is N & 0x1c = 4*floor(N/4), between 4 and 28.
Actual reused constant `0x2086a0` is
`bfbf0000000000000000000000000000`; actual `0x2088f0` is
`01000000000000000100000000000000`. Each zero-extended two-byte load is
compared signed against -65 in its first two lanes. Unpack and D4 shuffles
place the first source-byte predicate at the low bit of qword0 and the second
at the low bit of qword1. The qword-one mask therefore yields one count per
non-continuation source byte. The unrolled four-byte groups accumulate exact
small qword sums, and the horizontal reduction adds both lanes. The remaining
N mod4 bytes use the scalar tail. No load extends beyond the N-byte slice.
Consequently the result is C for every valid short string, independently of
input address alignment. These actual constant identities are reused from the
same-target #1439 report `6fb2cb8e78f28447e71e96f03229b368c9047c4551f47377181dfc91efeae01e`.

## Layout and exact statuses

If c>=w, the selected text is requested once through `0x15737c1..0x15737e0`
and its raw low reply byte is forwarded. Even the precision-truncated empty
string is still requested. There are no preceding callbacks.

Otherwise d=w-c is in 1..65535. The actual 16-byte table at `0x251b74` is
`491c32016e1c3201721c3201491c3201`, hash
`72439ee9a1eb7d5cff3c503ea1d5175da0f00a0ec49c48f8450d27a5883ab0e2`.
Signed displacements from the table base give targets
`[0x15737bd,0x15737e2,0x15737e6,0x15737bd]`.
Thus before counts a are `[0,d,floor(d/2),0]` for A=0,1,2,3; after is b=d-a.
Default code3 is LEFT here, unlike the integral helper's default-right rule.
The fresh supporting-data receipt and source table RELAs are bound by
`DATA-BINDINGS.json` hash
`880beb5befe1b1a2d7e8c1bb0d8c17cb5f1a116b77865dd866afb0bd877ab232`.

The requests are a individual Char(F) calls, one Str(selected UTF-8 bytes),
then b individual Char(F) calls. Any nonzero before-fill reply returns1
immediately and suppresses all remaining calls. Any nonzero Str reply on this
padded route similarly returns1, even if all padding precedes the string.
Successful padding returns0; any nonzero after-fill reply returns1 and stops.
This normalization differs from every unpadded/raw tail route.

The before loop starts with low16(a+1), decrements before each request and
therefore performs exactly a requests, including a=65535. For the after loop,
the saved arithmetic value is a+c-w = -b modulo2^32. Its initial low16 counter
is FFFF. Before the k-th succeeding step, the sentinel expression has low16
FFFF exactly when k=b; because 0<=k<=b<=65535, no earlier wrap collision is
possible. Completion copies b before the final comparison, producing0.
A failure on request j, 1<=j<=b, leaves low16(j-1)<b and therefore produces1.
The special a=65535 case necessarily has b=0 and makes no after request.
The maximum complete call has 65535 fills plus one Str: 65536 callbacks.

All narrowing arithmetic on c occurs only after c<w<=65535; it is exact.
Input-prefix lengths and counts are bounded by N. Width/precision and loop
bounds are u16, so the above finite loops and bit arithmetic require no
unmodeled overflow branch. This body has no panic/helper edge beyond the
already qualified pure counter and the deliberately supplied writer callbacks.

## Live state, caches and effects

All input selection, count, width and alignment decisions precede callbacks.
The padded route also caches initial data and table IDs at `0x15737f2/7f5`.
Every Char request reloads the current +0x20 slot of that cached table;
the single Str reloads its current +0x18 slot. Changing context data/table
does not retarget subsequent requests. Updating the cached table's method
cell does affect the next request of that kind. Fill and selected text stay
the initial decisions even if a callback changes the whole header word.

There is no direct store to the formatter header/data/table in this body and
no success-only restoration. Every admitted callback mutation survives unless
the supplied script later changes the same cell again. Context observations
in each event are taken before that invocation's ordered actions. Actions
occur before returning the supplied raw reply, including on a failure.

The safe implementation may expose own Cell-backed state and normal supplied
proxy callbacks. Those are a value/effect projection of this proved relation,
not a reconstruction of the renderer or hidden original ABI. The frozen
authority must send the actual client only raw UTF-8/header/IDs/method cells/
script/alignment, never preselected substrings, counts, layouts or answers.

## Independent finite support

The new oracle will use high-level Unicode scalar strings, Python prefix
selection/length and declarative Char/Str segments. A separate serializer
emits the original UTF-8 and supplied script, not the expected plan. Exact
event/state/raw-status JSON and adjacent-event RLE are comparison containers;
the Rust client must still perform every callback and ordered cell action.
RLE is lossless and supplies no normalization of requests, replies or effects.

No target, captured instruction evaluator, compiler or new Rust program is
executed for this proof. Finite support does not prove all valid strings;
the complete native/Unicode/loop argument above supplies the universal bridge.
All component gates, original source/compiler/type/ABI, invalid UTF-8, forged
pointers/aliases, unwind/fault/physical-timing and whole-node claims remain open.
