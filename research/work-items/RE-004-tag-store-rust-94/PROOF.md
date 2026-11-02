# Low32 tag dispatch, complete stores and full RAX

Target node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete `[0x5057700,0x505773d)` leaf is 61 bytes and 19 instructions.
This proof establishes final ordinary data memory and full RAX, with a
new safe image API. It assigns no source type or purpose to the tag,
stored address or copied bytes.

## Code and unread address context

The full 91,774,280-byte target is authenticated before parsing. GNU,
LLVM and Capstone agree on every instruction start and body byte. One
FDE exactly covers the leaf, and complete FDE/CIE records are retained.
The adjacent FDEs are `[0x50576b0,0x50576f4)` and
`[0x5057740,0x505774e)`, separated by twelve leading and three following
INT3 bytes. The five-byte NOP at `0x5057713` and ten-byte CS NOP at
`0x5057726` remain inside the body; neither lies on a reachable path.

All four branches land on decoded starts: JE `0x5057706` to
`0x5057730`, JNE `0x505770b` to `0x5057718`, JNE `0x505771b` and
JMP `0x5057724` to `0x5057710`. The last target clears EAX and returns,
so the backward edges are joins, not loops. The other return is at
`0x505773c`. There are no calls or unresolved control dependencies.

The LEA at `0x5057730` has next RIP `0x5057737` and signed displacement
`0x701b69`, yielding linked address `0x57592a0`. Under common code/data
load bias B, its numeric result is `(B+0x57592a0) mod 2^64`. This is
independent of the mutable image's base. Correspondence requires B to
describe a valid mapping of the captured code/data; arbitrary numeric
test biases are not asserted to be physically realizable mappings.

The linked address is inside `.data.rel.ro` and its writable PT_LOAD.
Its first file qword is zero. An actual `.rela.dyn` record at file
offset 1,926,104 targets that qword with type `R_X86_64_64`, symbol
index 260 and addend 16. Dynamic symbol 260 is an undefined GLOBAL
OBJECT named `_ZTVN10__cxxabiv117__class_type_infoE`; its version index
34 binds `CXXABI_1.3` from `libstdc++.so.6`, also in DT_NEEDED. The
verifier binds the exact relocation, symbol, strings, version records,
needed record, mapping and raw qword, rather than trusting a nearby label.

Crucially, the leaf never reads that qword or any pointed contents.
The tag-0 result depends on the LEA address, not on the external symbol's
runtime resolution or the file's placeholder zero. These records are
unread address context, not a semantic dependency or a claim about
the surrounding object's purpose. No library code was read or copied.

All 80,300 RELA records are scanned: none names the leaf entry or
overlaps its body/padding, and exactly one overlaps the retained target
qword. Complete `.text` E8/E9 encoding scans find no direct candidates.
Indirect entry paths, table ownership and a complete caller census
remain unestablished. Thirty structural corruption controls check code,
boundaries and unread address metadata separately from the full digest.

## Full register and memory relation

Let D=entry RDI, S=entry RSI, T=entry RDX, M=2^64 and
t=T mod 2^32. TEST EDX and the two CMP EDX instructions inspect exactly
those low 32 bits. Neither sign nor upper RDX bits affect equality with
0, 1 or 2. The complete normal-return relation is:

| t | Required data accesses | Final data effect |
|---|---|---|
| 0 | Write eight bytes at D | Little-endian `(B+0x57592a0) mod M` |
| 1 | Write eight bytes at D | Little-endian raw S |
| 2 | Read sixteen bytes at S, then write sixteen at D | One complete source snapshot |
| Any other u32 | None | No change |

Every path returns full RAX=0. Both return sites are preceded by XOR EAX,
EAX; a 32-bit write zero-extends the whole register. The LEA's temporary
address is not the returned RAX. Other registers, flags and SIMD state
are outside this projection.

Tag 1 treats S as an immediate numeric value; S need not point to mapped
memory. Tag 0 does not read S or the global target contents. Other tags
do not read or write either operand. Thus checking all operands eagerly
would introduce refusals on inputs whose selected original path needs
no such memory. The safe API checks only reached spans after validating
its global image representation.

For tag 2, MOVDQU completes a 16-byte load into XMM0 before MOVUPS stores
that same register. Let entry bytes be E and let source/destination
offsets in an admitted image be s,d. For each j in 0..15, final byte
d+j equals E[s+j]; every other byte equals its entry value. This formula
holds for identical ranges, all partial overlaps in either direction,
unaligned ranges and disjoint ranges. A bytewise forward or backward
copy can observe its own writes for some overlaps and does not satisfy
that relation. Rust first copies the source slice into `[u8;16]`, then
writes it, preserving the single-snapshot behavior.

There is no byte transformation in either SSE instruction and no byte
order issue in the 16-byte snapshot. The scalar stores explicitly use
little-endian encoding. Load-bias addition uses wrapping arithmetic,
matching LEA's 64-bit result; it neither saturates nor substitutes the
image base for the code/data bias.

## Safe domain and refusal atomicity

`store(image, image_base, load_bias, destination, source, tag)` maps byte
j of one mutable slice to numeric address `image_base+j`. The entire
image must be nonwrapping, with its last byte allowed at M-1. This is
a new API premise even on no-access tags, not an extra original memory
read. An empty valid image can return zero for any low32 tag above two,
regardless of the operand addresses.

A reached span uses checked address subtraction, fallible usize
conversion, checked width addition and the full slice bound. Its entire
8 or 16 bytes must fit. There is no alignment restriction or arbitrary
image-size cap in the library. Tag 2 checks the source first and holds
the snapshot before checking the destination; tags 0/1 require only
the destination. No actual write occurs until every reached requirement
has passed. Therefore ImageRange, Source and Destination refusals leave
every image byte unchanged, including any valid destination prefix.
These are new safe outcomes, not reproduced native faults or their
partial effects. Exact admitted widths prove all conversions/indexes
valid and the source snapshot unwrap cannot panic after admission.

Correspondence assumes stable initialized ordinary readable source and
writable destination data, valid code/control storage and the stated
runtime load bias. Faults, MMIO, concurrent mutation, instruction/control
aliases, flags, timing, physical access traces and ABI compatibility are
excluded. A single nonwrapping slice does not represent every native
layout. Numeric addresses in fixtures do not assert OS mapping support.

## Independently frozen expectations

The oracle, static record and full input/output streams were frozen
before the Rust directory existed. The oracle selects by integer modulo,
forms little-endian scalar bytes by positional arithmetic and applies an
immutable byte overlay. Rust uses a u32 cast, integer byte conversion,
checked ranges and a 16-byte array snapshot. Expected results were not
obtained by executing Rust, captured instructions or an instruction
interpreter.

The 16,756 fixtures include a complete source/destination grid over
offsets -16..64, both overlap directions, all low-byte tags with high32
patterns, full-width scalar/bias edges, exact endpoints, skipped invalid
operands and deterministic additional descriptors. There are 10,362
normal results and 6,394 new refusals: 12 ImageRange, 3,186 Source and
3,196 Destination. The input-only host client observes full RAX and all
64 backing bytes, including the untouched suffix outside the admitted
slice. Fixture capacity 64 is not a library limit.

Finite native cases support the path/bit-domain proof; they are not
enumeration of all tags, biases, addresses or images. Original compiled
bytes, source identity, runtime reachability, pointed-object meaning,
whole-node equivalence and completed component gates remain unclaimed.
