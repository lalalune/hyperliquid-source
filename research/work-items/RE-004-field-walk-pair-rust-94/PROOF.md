# Two field-derived stores: complete memory and register relations

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete entries are `[0x514ab20,0x514ab4a)` (42 bytes) and
`[0x514ab50,0x514ab64)` (20 bytes), 62 bytes/14 instructions in total.
Their grouped reconstruction closes two adjacent scalar store projections;
no shared source type, original API or exhaustive component census is inferred.
The predecessor `foundation-field-walk-shift-94` established only the first
leaf and explicitly left the second unclaimed. Both are reconstructed here
in one contribution, with independently checked complete bodies.

## Exact relation and full register widths

Let N=2^64. O, D and S are incoming full RDI, RDX and RSI. Every effective
address addition below is modulo N. Let q(A) read the complete little-endian
qword at A and d(A) read the four-byte little-endian unsigned word at A from
stable ordinary memory. The two members have these disjoint relations:

| Member | Original reads in order | Stored eight-byte value | Full RAX | Full RDX |
|---|---|---|---|---|
| ShiftedDifference | P=q(O+0x788); Q=q(P+0x30); A=q(Q+0xb20); B=q(Q+0xb18) | two's-complement floor(signed64((A-B) mod N)/16) | 1 | Q |
| SignedField | W=d(D+0x1438) | sign-extension of W from 32 to 64 bits | 1 | D |

The sole data write in either member is the entire qword at S. It is not a
pointer-return or boolean-only projection: RDX and the output bytes are also
observable. SignedField never reads O; ShiftedDifference overwrites incoming
D with Q. Neither leaf dereferences the stored result. Numeric zero receives
no special handling, and there is no bounds-order, alignment, nonzero-value,
stride-multiple or source-structure assumption.

The first entry starts with ENDBR64. Its REX.W loads read O+0x788 into RAX,
P+0x30 into RDX and Q+0xb20 into RAX. The 64-bit SUB reads Q+0xb18 and keeps
the low 64 bits of A-B. SAR's immediate is exactly four, followed by a qword
store through RSI. The second entry also starts with ENDBR64; REX.W MOVSXD
reads exactly four bytes at full RDX+0x1438 and sign-extends into RAX, then
stores the resulting qword through RSI. It never changes RDX.

Both entries finish with `mov eax,1; ret`. An EAX write zero-extends into
RAX, so every normally returning path has full RAX=1 independently of the
stored signed value and incoming register contents. The first retains full Q
in RDX even if its memory representation was overwritten by the output store.
The second retains all incoming D bits. Remaining GP-register preservation,
flags, ENDBR/CET, RET stack/control effects and native calling convention are
outside the explicit RAX/RDX/image API.

## Universal arithmetic proof

For arbitrary A,B in [0,N), define X=(A-B) mod N and its signed representative
T=X for X<2^63, otherwise T=X-N. SUB produces exactly X. The source's
`a.wrapping_sub(b) as i64` implements that residue followed by the same signed
interpretation; it never performs an overflowing signed subtraction.

Arithmetic right shift by four replicates the sign bit. For nonnegative T,
removing the four low bits produces floor(T/16). For negative T, the high
ones represent the negative quotient and removing those bits still gives
floor(T/16), including T=-1 through -15 producing -1. Division truncating
toward zero would differ on those cases. This covers both sign partitions
and all 16 residues. The quotient lies in [-2^59,2^59-1], so it fits i64.
Casting the quotient to u64 preserves its low 64-bit two's-complement pattern
for the little-endian eight-byte store.

The independent oracle expresses the same mathematical value as
`floor((((A-B+N/2) mod N)-N/2)/16) mod N`, using unbounded integers and floor
division instead of the source's cast/shift. It does not decode or step the
captured instructions. In particular, wrapping occurs before the signed
interpretation; subtracting wider signed values and shifting first would
not produce the same result at all overflow boundaries.

For SignedField, write W=L+256^3 H with L the low three bytes and H the
unsigned top byte. Its signed value is L+256^3 H for H<128 and
L+256^3(H-256) otherwise. This ranges over [-2^31,2^31-1] and fits i64.
The source's i32 little-endian conversion followed by i64 widening preserves
that value; the oracle instead weights the signed top byte. Only four input
bytes are required. An eight-byte source read would add an unsupported memory
requirement and could observe unrelated bytes.

## Arbitrary data aliases and safe admission

`apply(member,image,image_base,object,incoming_rdx,output)` is a new safe value
API. The enum is a new selector, not an original argument. Slice byte i
represents numeric address image_base+i; these numbers are never converted
to native Rust pointers. The supplied interval must not wrap: its u128
exclusive endpoint can equal N but cannot exceed N. No arbitrary target count
or image-length cap exists in the library; 128 bytes is only a fixture/client
record capacity.

Each load forms its own modulo-N address first, then checks subtraction from
image_base, conversion to usize, checked addition of its actual width and
containment in the slice. The output requires eight complete bytes under the
same rules. A represented qword cannot cross N, since the whole image does
not wrap. O itself, P, Q or D need not be represented if only their displaced
fields are reached. SignedField admits an entirely absent object field.

All original input reads precede the sole store. Thus every loaded pointer
and value can be evaluated from one immutable entry image, even if S partially
or completely overlaps any pointer field, either difference operand or the
four-byte signed input. The final image replaces exactly eight bytes at S;
all other active and inactive bytes retain their entry values. An early store
would change later observations on overlapping layouts. Loaded Q/D remain
register values after the store, without reloading their overwritten bytes.

Rust also completes all member-specific reads and full destination admission
before copying any byte. `None` is a new safe refusal and leaves the complete
slice unchanged. It is not an original return code or a claim about partial
writes/fault behavior. Invalid images, missing reads and missing destinations
are rejected without panics, unchecked indexing or unsafe code. The helper's
checked range precedes every slice access, array conversions are checked, all
address arithmetic explicitly wraps, and fixed signed shifts are in range.

Original correspondence assumes stable ordinary readable/writable memory
matching the supplied image and normally completing instruction/return
control. Faults, noncanonical/unmapped machine addresses, MMIO, races and
aliases into code/control storage are excluded. Synthetic wrapped address
metadata does not claim that a process actually maps those addresses. The
safe API qualifies its admitted memory images, not every possible original
process map or exceptional execution.

## Static closure and evidence independence

`verify_static.py` binds all 62 original bytes, both unique complete FDE/CIE
records, the preceding/following FDE extents and the separate 12/6/12 bytes
of INT3 padding. GNU, Apple LLVM and Capstone agree without normalization on
all 14 instruction boundaries. Each member has one final RET and no branch,
call, indirect transfer or RIP-relative data operand before it.

All 80,300 RELA records are checked. No relocation names either entry, and
no full or partial relocation writes either body or its bound padding. Unknown
relocation widths and REL tables are rejected. Full .text E8/E9 candidate
scans find no direct candidates for either entry. This is not a complete
indirect-reference census, a source identity or a proof of unreachability.
The runtime fields have no inferred logical layout beyond actual read offsets
and widths. There are no helper/import semantics or fixed data tables to fill
with guessed values. Structural corruption controls exercise body operands,
return/store widths, frames, padding and introduced relocation edges separately
from the whole-target digest check.

Before source creation, the static record, immutable-address-map oracle and
the original 46,654-case input/expected streams were frozen and hashed. The oracle uses the
centered-residue/floor and signed-top-byte equations above and creates final
images by numeric-address replacement. The Rust implementation uses checked
slice ranges, integer casts/shifts and a final little-endian copy. Neither
implementation calls the other. The input-only native driver receives member,
image and numeric metadata, never expected outputs or captured instructions.

Coverage includes all value bits, all 16 low residues around signed/wrapping
boundaries, signed32 endpoints, high addresses, every chain-output byte offset,
partial/exact source-output overlaps, exact read/store endpoints and absent
unused object fields. Finite native outputs and effective compiled controls
qualify the source against this proof; they do not establish original compiler
output identity, whole-node behavior or an exhaustive enumeration of memory.

## Qualification coverage correction retained separately

The initial native matrix exposed an ineffective global-image-overflow
control. Both original overflowing-image fixtures also lost reached fields
through wrapped addresses; later span checks therefore refused even when
the global image check was removed. The correct source still matched every
original case. The complete failed matrix and unchanged validator are retained
in `initial-native/`, rather than reporting the survivor as detected.

Two explicitly post-freeze admission descriptors now supplement the unchanged
primary stream. Each describes 128 bytes at base N-64, while every reached
read and the output lies entirely within the first 64 bytes. Thus the image
description overflows although its selected accesses fit. Removing only the
global image check admits these inputs and changes the result. Expectations
come from the unchanged pre-Rust algebraic oracle's image-domain rule, not
from Rust output. `post-freeze-admission.json` records timing, original freeze,
oracle/source hashes, exact inputs and full expected images. These two cases
are not represented as pre-Rust fixtures. Neither production source nor the
original oracle or frozen inputs/expectations changed for this correction.
