# Four complete cursor leaves: values, selective reads and aliased images

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The scoped entries are 0x52c6e50 (20 bytes), 0x52c6e70 (12 bytes),
0x52c6e80 (27 bytes) and 0x52c6ea0 (41 bytes): 100 complete bytes in one
coherent contribution. They share cursor/bounds fields; this is not a claim
that exactly four functions constitute an original source component. The
predecessor documented retreat alone and warned against mining its siblings
as separate submissions. This packet groups the bounded family and includes
the previously unclaimed intervening cursor dereference.

## Exact full-register and memory relation

Let N=2^64 and O be incoming RDI. Addition/subtraction on numeric addresses
and values is modulo N. `q(A)` means the little-endian qword actually read
at address A in stable ordinary memory. D is incoming full RDX. All qwords
can be arbitrary bit patterns; there are no ordering, alignment, length,
stride-multiple, nonzero or bounds-containment assumptions.

| Member | Reads in original order | Full RAX | Full RDX | Data write |
|---|---|---|---|---|
| Span /0x52c6e50 | P=q(O+16), E=q(P+8), B=q(P) | (E-B+40) mod N | P | none |
| Read /0x52c6e70 | C=q(O+32), V=q(C) | V | D | none |
| Advance /0x52c6e80 | P=q(O+16), C=q(O+32), E=q(P+8) | C if C=E, otherwise C+8 | P | none if equal; otherwise q(O+32)=C+8 |
| Retreat /0x52c6ea0 | P=q(O+16), C=q(O+32), B=q(P); E=q(P+8) only if C=B | E if C=B, otherwise C-8 | P | q(O+32)=RAX |

The only conditions are full 64-bit equality. Advance still increments when C>E,
and can wrap. Retreat subtracts when C differs from B regardless of order;
its equality path uses E directly, not E-8. Neither operation dereferences
the resulting cursor. Span's +40 is a byte arithmetic constant, not a division
or proof of source-level size. Read does not inspect O+16 at all. Span does
not inspect O+32. Advance does not read P. Retreat's non-equality path does
not read P+8. These omissions are part of admission behavior in the new API.

## Instruction proof and exhaustive paths

Every entry starts with ENDBR64. Span loads the bounds pointer into RDX,
loads E into RAX, subtracts the qword B and adds 40 before RET. No width is
truncated; all three operations are 64-bit. Read loads the cursor and then
the pointed qword into RAX. It never writes RDX, which therefore retains D.

Advance loads P and C, compares C to E and takes JE directly to RET when
equal. The non-equal path adds 8 to RAX and stores the complete qword before
that RET. Thus the only two disjoint paths are exactly the two rows of the
Advance relation. No unsigned/signed comparison or range gate occurs.

Retreat loads P and C, compares C to B and uses JE for the E-loading path.
The unequal path subtracts 8, writes the result and returns. The equal path
loads E, writes it and returns. A six-byte alignment NOP inside the FDE is
unreachable from either path; its exact bytes remain bound. Both paths write
the entire qword and preserve P in RDX. No other GP register is written by
any member, apart from the implicit RET stack effect; flags, ENDBR/CET,
stack/control and native calling convention are not part of the value API.

Each comparison partitions every possible pair of u64 operands. MOV leaves
the loaded bit patterns intact; ADD/SUB retain the 64-bit residue. Consequently
the table is universal over the stated normally returning memory domain,
including malformed-looking bounds, address/result wraps and zero addresses.
It is not extrapolated from a finite vector set.

## Data alias and safe image domain

The Rust API receives an explicit member selector, mutable byte slice,
image_base, numeric O and incoming RDX. Member is a new selector, not a
recovered machine argument. Slice byte i represents image_base+i in one
nonwrapping interval. The last represented address is checked before any
access; an overflowing image range is refused. The helper admits a qword
only when its address is at least image_base, the difference converts to
usize, difference + 8 does not overflow and all 8 bytes fit the slice. Individual
field-address additions wrap before this range admission, just as the
original 64-bit address formation does. O itself need not lie in the image
if every reached field does.

`None` is a new safe API refusal, not a reconstructed original return/fault.
Refusal leaves all bytes unchanged. The Rust control flow requires exactly
the selected reads in the table. Although the whole supplied slice is a
single mutable image, unused fields or followed pointers need not be mapped
within it. The original physical memory may have a broader domain; this API
qualifies only represented, ordinary memory, not every possible process map.

Every original input read precedes its sole possible data store. Therefore
all loads may be taken from one immutable entry image. The store's eight
bytes can overlap either bounds word, the bounds pointer, or any previous
read, partially or completely; their loaded values are already fixed.
The output image replaces exactly the cursor qword on a writing path and
otherwise is identical. No separate pointer-disjointness assumption is used.
On Advance's equal path, there is no store at all. A later read that would
see an overwritten bound is not present in these functions.

Rust likewise completes reads and destination-span admission before writing.
The cursor field was already read on a writing path, so the store range is
necessarily valid under the same fixed slice; the repeated span check does
not add an original-domain restriction. Its final returned RDX is the loaded
P even if the write overwrites P's memory representation. For the Read member
it is the supplied D, without normalization to a boolean or pointer.

No unsafe code, dynamic allocation or unchecked arithmetic is used. All
slice accesses are range-checked. The source match's Span/Read `unreachable!`
arm cannot be entered: those exact enum variants have returned earlier.
This control-flow fact holds for every constructible safe Member. The three
remaining concerns—data races/volatile or MMIO effects, invalid/native-fault
accesses, and aliases to executable/return-control memory—are outside the
ordinary stable-memory/normal-return correspondence. Numeric Rust addresses
are never converted to or dereferenced as host pointers.

## Static and reference closure

The four full bodies and exact unique FDE/CIE records are locked. GNU,
AppleLLVM and Capstone agree on complete bytes and all 30 instruction boundaries,
without masks or display joins. Following INT3 padding is 12/4/5/7 bytes,
separately authenticated. The complete conditional-edge and RET lists are
checked, including the internal alignment bytes. There are no calls,
RIP-relative data operands, helpers or indirect transfers in these leaves.

Each entry has exactly one raw-zero symbol-zero RELATIVE naming slot.
The complete .data.rel.ro/PT_LOAD mapping, record and unique overlapping
writer of every slot are checked. All80,300 RELA records are scanned for
naming addends, full eight-byte partial overlap with each slot and any writes into
body/padding. Unknown relocation types and REL sections are rejected. Full
.text E8/E9 pattern scans find no candidate targeting an entry. The result
is not a complete indirect-reference census, source component identification
or proof that the leaves are unreachable. No record/data element behind the
runtime pointers is inferred from their numerical offsets.

## Independent frozen expectations and native qualification

Before Rust existed, an oracle formed a dictionary from numeric addresses to
entry bytes. It evaluated the abstract table with unbounded integer modulo
arithmetic and produced new images by immutable replacement. It has no target
instruction decoder in its value relation, no register-step simulation, and
no dependency on new Rust code. The static record, oracle and full input/
expected byte streams were frozen and hashed before source creation.

Each of 22,300 descriptors has five u64 fields plus 128 synthetic bytes; it
selects an active image prefix of 0..128 bytes. Expected output contains status,
full RAX/RDX and all 128 bytes, including the unchanged inactive suffix. There
are 14,025 admitted cases and 8,275 new API refusals per profile. Every member
has admitted cases; layouts cover overlapping field/bounds storage, every
value bit, equality/order counterexamples, image endpoints, high bases,
wrapped field formation and full-width result arithmetic. A finite corpus
is not an exhaustive memory-map enumeration; the preceding proof closes
all admitted images under its premises.

Only the new Rust library/client are compiled. The client receives inputs
without expected values, oracle code or captured instructions. Native checks
compare every output byte with no mask and qualify repeated builds, distinct
optimization levels, compiled wrong implementations and framing corruption.
Neither original executable execution/emulation nor original compiler output
identity or a whole-node reconstruction is claimed.
