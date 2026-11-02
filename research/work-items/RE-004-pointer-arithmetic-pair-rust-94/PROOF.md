# Three-path pointer arithmetic and full return pair

Target node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete `[0x50fa260,0x50fa2b2)` leaf is 82 bytes, with 20 decoded
instructions, two returns and no calls. This establishes a readonly
memory relation and full numeric RAX/RDX, without recovering source
types or assigning meaning to the returned numbers.

## Static boundary and reference closure

The validator checks the entire 91,774,280-byte target before parsing.
GNU, LLVM and Capstone agree on every body byte and instruction start.
The sole overlapping FDE exactly matches the leaf. Its complete FDE/CIE
bytes are bound together with both neighboring records:
`[0x50fa170,0x50fa251)` and `[0x50fa2c0,0x50fa45d)`.
Fifteen leading and fourteen following bytes are INT3 padding. Inside
the leaf, a three-byte NOP and two-byte XCHG AX,AX are alignment padding,
retained as body bytes. Neither is on a reachable entry-to-return path.

The three branch targets are exact decoded starts:

| Branch | Destination | Role |
|---|---|---|
| JE at `0x50fa26b` | `0x50fa2a0` | Stored pair |
| JE at `0x50fa282` | `0x50fa298` | Subtract eight |
| JMP at `0x50fa29c` | `0x50fa284` | Join the common computed tail |

The backward JMP creates no cycle. Its destination loads the limit,
computes the result, copies the limit and returns at `0x50fa294`.
The stored branch returns at `0x50fa2b1`. Thus every admitted execution
has a finite straight path after at most two conditional decisions.

A full `.text` scan has zero E8 or E9 encodings targeting the entry.
This does not exclude indirect references. All 80,300 RELA records are
checked; one `.rela.dyn` record names the entry: type
`R_X86_64_RELATIVE`, symbol zero, addend `0x50fa260`, destination
`0x575ad00`. The destination qword is zero in the file and maps wholly
inside `.data.rel.ro` and its writable PT_LOAD. The exact relocation
record, file offset, section/segment metadata and raw slot bytes are
retained. No other relocation overlaps that slot, body or padding.

For a valid common runtime load bias B, the RELATIVE record supplies
the function address B+`0x50fa260` at B+`0x575ad00`. The file's zero is
not claimed as the relocated runtime value. This slot is an entry
reference, not a memory dependency read by the leaf. Its surrounding
table role and indirect callers remain unknown. No complete xref census,
source-level table identity or application ownership is claimed.

## Exact reads and all-u64 value relation

Let O be incoming RDI and M=2^64. Every object-relative effective address
below is `(O+offset) mod M`. Q reads an unsigned little-endian qword;
U reads an unsigned byte. The reached read order is:

```
p = U(O+0x240)
if p == 1:
    t = Q(O+0x310)
    s = Q(O+0x308)
    return (RAX=s, RDX=t)
else:
    q = U(O+0xd8)
    n = Q(O+0xa8)
    a = Q(O+0xa0)
    if q == 0: n = (n-8) mod M
    c = Q(O+0x300)
    return (RAX=(a+n-c) mod M, RDX=c)
```

The primary CMPB compares against exactly one, so 2, 128 and 255 all
take the computed branch. The secondary CMPB compares against zero.
The following two MOV loads preserve its flags, making the later JE
depend on that byte comparison, not on either loaded qword. Every
nonzero byte, including those with the high bit set, skips subtraction.

On the computed path, SUB RDX,RCX subtracts the limit from the possibly
adjusted span, ADD RAX,RDX adds the base value, and MOV RDX,RCX replaces
RDX with the original limit. For arbitrary a,n,c in `[0,M-1]` and
delta in `{0,8}`, reduction modulo M commutes with integer addition and
subtraction. Therefore the staged hardware result equals

```
(a + n - c - delta) mod M
```

even when adjustment underflows, limit subtraction underflows, or the
final sum overflows. Rust uses explicit wrapping subtraction/addition
for every such step. It neither saturates nor treats high bits as signs.
No result is dereferenced, so all 2^64 numeric values are admitted as
results; a returned number need not be a canonical or mapped pointer.

The stored branch loads complete qwords without arithmetic. Both
return paths write all 64 bits of RAX and RDX, so no incoming upper
register bits survive. The new `Registers` result exposes both u64
values. Narrowing either word, returning the adjusted span in RDX or
swapping the pair changes the established relation.

## Safe image projection

`select(&[u8], image_base, object)` maps byte j to numeric address
`image_base+j`. The complete image must be nonwrapping; its last byte
may equal M-1. Field addresses wrap first, independently of the image.
For each reached byte/qword, checked subtraction finds its image offset,
fallible conversion establishes host-index representability, checked
addition establishes the end, and slice bounds admit the complete span.
No unchecked pointer, alignment requirement, allocation or unsafe code
is introduced. Image contents remain immutable.

The object address itself need not be in the image. For example,
O=M-0x240 maps the primary flag to zero; the stored fields map to 200
and 208. A 216-byte image can satisfy that branch while the skipped
computed fields are unmapped. Conversely, a computed-path image can
end immediately after its limit qword, excluding both stored fields.
Admission checks follow the actual branch gates rather than requiring
one guessed complete source struct.

The new error order is ImageRange, PrimaryFlag, then either StoredPair
or SecondaryFlag followed by ComputedWords. Original faults are not
modeled as these errors; the projection refuses invalid spans safely.
The checked slice range also proves each helper's byte index and qword
conversion are valid, so successful admission cannot panic. Both
success and refusal leave the input unchanged.

Correspondence assumes initialized stable ordinary readable memory
and valid native instructions, stack and control state. It excludes
concurrent mutation, MMIO, faults, unwinding, control/instruction aliases,
timing, flags, intermediate observations and other registers. A single
nonwrapping image cannot represent every discontiguous native layout.
Large numeric fixture addresses are not claims about operating-system
mapping support. This is a value API, not an original System V ABI
replacement or an inferred struct definition.

## Independent oracle and native limits

The oracle, full static record, input/output streams and metadata were
frozen before the Rust directory existed. Its arithmetic is one
unbounded integer affine expression followed by modulo M; Rust follows
the separately proved staged wrapping arithmetic. The oracle builds
little-endian integers by positional byte weights, while Rust uses
checked slices and `from_le_bytes`. It is not an instruction evaluator
and accepts no result supplied by the Rust implementation.

The 76,421 fixtures include all 65,536 primary/secondary byte pairs,
cross-products of arithmetic edge values, every single-bit width,
stored high-bit pairs, exact endpoints, all five safe errors, wrapped
field addresses, skipped unmapped fields and digest-derived records.
There are 75,341 normal results and 1,080 new refusals. The input-only
native client supplies actual image bytes and observes the complete
returned pair. Finite cases support this proof of the admitted domain;
they do not prove equivalence by enumeration of every image.

Original compiled-byte identity, runtime entry-slot use, source names,
whole-node behavior and component completion remain unmeasured. No
captured binary or instruction emulator is executed.
