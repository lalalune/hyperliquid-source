# Normal string-padding request relation, before new Rust

This is a static mathematical relation for node #94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The primary complete FDE is `0x1573450..0x1573889`, 1,081 bytes / 300 native
instruction rows, body SHA256
`f958a0383269ead1a2056ba42785c9050e46a57aa0f990a27976fe27cb5eee77`.
The nearby original seed `0x15728c0` is a different 602-byte
`pad_formatted_parts` function. Adjacency was not used as its label or extent.

The primary body matches the complete published libcore `Formatter::pad`
section outside four actual four-byte code relocation fields at offsets
190, 268, 294 and 853. The actual call slot is `0x5770628`, whose unique
symbol-zero RELATIVE relocation binds `0x15796c0..0x1579c8b` (1,483 bytes /
365 rows). The latter byte-classification/count proof is already established
by integral-padding work and is credited as a dependency, not new recovery.
The same BF/ones classifier constants at `0x2086a0` and `0x2088f0` are reused
with their prior same-target data identities. The new actual alignment table
at `0x251b74` is separately bound to the published table's actual relocations.
The published artifact correspondence is attribution, not original compiler
or newly compiled Rust identity.

## Domain and observations

Work in x86-64 with immutable readable valid UTF8 string bytes, byte length
at most `isize::MAX`, a nonwrapping readable range, valid formatter field and
method-table storage, and normal callbacks with ordinary call preservation.
Callbacks may sequentially mutate chosen header/data/table/method cells, but
input/code/active-frame storage remains immutable and separated from invalid
aliases. No concurrent mutation, faults, unwind or invalid pointers are included.

Choose initial W0=QWORD(F+16), flags f=low32(W0), width w=bits32..47,
precision p=bits48..63, and valid unique logical writer/table/method tokens.
Observe each Char(raw_u32) or Str(raw_UTF8_bytes) request, its logical data,
table and current method token, current context cells at dispatch, normal raw
callback reply and final cells/lowAL. These are chosen values rather than a
native Rust layout or pointer-identity assertion. Physical rendering, hidden
registers and the writer's implementation remain outside the relation.

## Selection and precision

At `0x1573468`, f&0x18000000==0 goes directly to the final string tail call.
There is exactly one Str request of the entire original string, including an
empty string; width and precision fields are ignored on this path. No header
field is changed by the helper, and raw lowAL is forwarded unchanged.

Otherwise f bit28 selects scalar precision. For p=0, selected bytes are empty
and selected scalar count k=0. For p>0, cursor starts at the input start and
remaining count starts at p. End is checked before every lead-byte load.
Valid UTF8 lead bytes imply exactly lengths1,2,3,4 for the observed branches
ASCII, <E0, <F0 and >=F0. Induction therefore keeps the cursor at a valid scalar
boundary inside the range and decrements the remaining count once per scalar.
The byte accumulator is the sum of those disjoint valid scalar lengths.

Let c be input Unicode scalar count and q=min(p,c). At termination the selected
slice is exactly the first q scalars, at their complete UTF8 boundary, and k=q.
No code-unit, grapheme, display-column or byte precision is asserted. Since the
slice is valid UTF8, cursor advance never overshoots; its byte accumulator is
bounded by input length, so the arithmetic does not wrap in the stated domain.

If bit28 is clear, bit27 must be set on this nonfast path. Select the whole
string. For byte length<32, the short SIMD groups and scalar tail count
q(b)=1 for b<128 or b>=192. Each two-byte SIMD expansion/shuffle/mask gives
the same q value for its two real bytes; repeated four-byte groups cover
floor(N/4)*4 bytes and the remainder loop covers 0..3 bytes. These loads stay
within the slice. For N>=32, use the actual fixed character-counter dependency.
Its closed byte-lane/partition/batch proof gives the same sum of q(b). Valid
UTF8 has one non-continuation lead byte per scalar, so k=c.

## Width, alignment and methods

Every nonfast selection joins at `0x1573787`, which reads raw width16 even if
bit27 is clear. Therefore precision bit28 alone can reach width padding when
the chosen raw width field is nonzero; an implementation must not invent an
additional bit27 gate after precision selection.

If k>=w, exactly one Str(selected bytes) request is tail-dispatched. Its raw
lowAL is forwarded without Boolean normalization. Data/table are loaded from
the formatter before this sole request. Prior selection/counting makes no
callbacks or formatter writes, so these are the initial logical identities.

If k<w, A=w-k lies in1..65535. Actual table bytes at `0x251b74` are
`491c32016e1c3201721c3201491c3201`. Adding each signed32 entry to table base
gives targets `[0x15737bd,0x15737e2,0x15737e6,0x15737bd]`, each an actual
instruction start. Published table relocation addends give these same four
destinations. Alignment codes (f>>29)&3 therefore produce preceding counts
`[0,A,floor(A/2),0]`; trailing count is A-preceding. In particular code3 is
LEFT here, unlike the integer-padding helper's default. Fill is f&0x1fffff as
a raw u32, without imposing Unicode scalar validity on the supplied callback.

The padded route captures the formatter's initial writer data and table before
its first callback. All preceding fill, selected-string and trailing fill
requests keep these identities even if context cells change. Each actual call
reloads the current char/str slot at cached table+0x20/+0x18, so method-cell
changes made by a previous callback affect later dispatches. Fill, width,
alignment and selected input slice remain cached. No direct formatter/header
store exists in the primary function; all final cell changes are callback
effects and are never restored by this helper. Sign/alternate/zero-format bits
do not add integer-specific sign, prefix or zero-pad behavior here.

## Complete normal callback/error order

Request Char(fill) preceding times, then Str(selected bytes) exactly once,
then Char(fill) trailing times. Stop after the first nonzero reply. Preceding
fill errors and string errors explicitly set AL1. Every all-success padded
invocation returns0. Empty selected strings still request Str(empty).

The native16-bit leading loop initializes a count to preceding+1 and decrements
the low16 before its termination check. For preceding65535 the initial low16
is0; the first decrement yields65535, so exactly65535 requests occur, without
skipping the loop or adding one request. This stays within the width bound.

For trailing count t, after j>=1 attempted trailing requests the low16 failure
counter is j-1. Here j<=t<=65535, so the final unsigned comparison (j-1)<t is
true on every nonzero reply, including the last trailing request. On all
successes, termination assigns counter=t before comparing, yielding0. Thus
every padded failure returns exactly1; no raw nonzero status survives this
path. Total padded requests are A+1<=65536, and an observed maximum does not
stand in for whole-component completion.

This closes normal requests/header-cell effects/lowAL for the primary body
under the stated domain and the credited counter theorem. It does not recover
private ABI/types, original compiler, output rendering or whole-node behavior.
All component gates remain false. New Rust must follow an independently sealed
pre-source proof and corpus, not this author text alone.
