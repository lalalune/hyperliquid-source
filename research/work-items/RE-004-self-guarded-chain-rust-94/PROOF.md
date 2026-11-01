# Self-compare gate and complete RAX/RDX field-chain result

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete entry is `[0x5172e50,0x5172e77)`, 39 bytes/10 instructions.
The predecessor established the static scalar rule but supplied no Rust
reconstruction. This projection adds complete RAX/RDX and an explicit safe,
selective memory domain. No original type or meaning of the sentinel is inferred.

## All paths and exact register widths

Let N=2^64, O be incoming full RDI and q(A) the eight-byte little-endian value
observed at numeric address A. Effective-address additions are modulo N.
The complete relation is:

```
P = q((O+8) mod N)
G = q(P)
if G = P:
    V = N-1
else:
    Q = q((P+8) mod N)
    R = q((Q+16) mod N)
    V = q((R+0xcb8) mod N)
RAX = V
RDX = V
```

The first MOV loads P into full RAX. `48 c7 c2 ff ff ff ff` stages a signed
32-bit immediate -1 in a 64-bit RDX destination, yielding all 64 bits set.
The memory CMP reads G and compares all 64 bits with P. JE takes exactly the
equality path, preserving that default. The unequal path performs all three
listed qword loads in order, placing the final raw value in RDX. The shared
`mov rax,rdx` copies all 64 bits before RET. There is no normalization,
zero extension from a narrower data load or boolean return.

Equality and inequality partition every possible P,G pair. Neither ordering
nor signedness changes equality; the upper 32 bits participate. This is a
self-compare, not a null check: P=0 still requires reading q(0). A represented
zero pointer with G!=0 takes the chain, while a nonzero P with G=P returns the
default. The loaded chain value can itself equal N-1; that remains a successful
raw value, not a new safe API refusal. Zero and every other u64 value are also
legitimate chain results.

Each path terminates after a fixed number of reads: two on the self path and
five on the chain path. Cyclic-looking or overlapping data pointers cannot
create a loop because the instruction sequence does not iterate. Neither
incoming RAX nor incoming RDX affects the result. Flags, transient RAX values,
remaining GP-register preservation, ENDBR/CET, RET stack/control and the
original calling convention are outside the RAX/RDX projection.

## Selective reads, wrapping and immutable aliases

The first two reads are always required. Only G!=P reaches P+8, Q+16 and
R+0xcb8. In particular, a self path does not require any of those later fields,
and the source does not eagerly follow them. The field addresses wrap
independently after their loaded bases are known. A saturating or narrowed
address expression is a different relation.

The new `load(image,image_base,object)` API treats slice byte i as numeric
address image_base+i in one nonwrapping interval. Its exclusive endpoint may
equal N but cannot exceed N. Object is O, not an offset or a Rust pointer.
Object itself need not be represented if O+8 wraps to a represented field.
Each reached word requires checked subtraction from image_base, checked
conversion to usize, checked addition of eight and a complete slice span.
A single qword cannot cross N within this admitted image.

`None` is a new safe refusal for an invalid image or a missing reached span;
it does not reconstruct original faults, exception handling or a numeric
sentinel return. `Some(Registers { rax: N-1, rdx: N-1 })` is distinct from None.
A global overflowing-image description is refused even when particular reads
would fit below N; this is a documented API-domain rule. There is no arbitrary
image-size cap in the library. The 128-byte image capacity belongs only to the
native fixture/client format.

The entire projection is read-only. The two-to-five input spans may overlap
partially or exactly, including self references, object fields and later data.
All reads use the same immutable entry bytes. A requested test-layout value
that was overwritten while constructing overlapping fields is not assumed to
survive; the oracle evaluates the final constructed image. Numeric addresses
never become host pointers. Checked accesses and fixed bounded control flow
leave no unchecked indexing, heap allocation, unsafe code or overflow panic.

Correspondence requires stable ordinary memory matching these bytes, normal
completion of the reached original reads and normal instruction/return control.
MMIO, racing mutation, faults/noncanonical mappings, control-data aliases and
handlers are excluded. Synthetic high/wrapped numeric addresses do not assert
that a real process maps them. The API qualifies its represented memory domain,
not every possible original process map or exceptional execution.

## Static and caller closure

The actual full body, unique FDE/CIE, preceding/following FDE extents and
separate seven/nine INT3 padding bytes are bound. GNU, Apple LLVM and Capstone
agree without normalization on every instruction boundary. The one forward
JE targets 0x5172e73, and the sole RET is at 0x5172e76. There is no helper call,
indirect transfer before RET or RIP-relative data operand in the leaf.

The complete .text E8/E9 scan finds one E8 candidate at 0x51523bc and no E9
candidate. The full caller `[0x5152280,0x51524a9)` is 553 bytes/130 instructions;
all caller bytes, its FDE/CIE and the selected call instruction/target are
independently bound. This is boundary context, not reconstruction of its
algorithm or other callees. Its LSDA/personality behavior is not projected;
raw CIE/FDE augmentation and decoded LSDA address remain context evidence.

Every one of 80,300 RELA records is scanned for entry naming and partial
writes into protected body/padding/caller bytes. No relocation names the leaf
and no such writer exists. Unknown relocation widths and REL tables are
rejected. These direct/relocation scans are not a complete indirect-reference
census or evidence of source ownership. The runtime fields have no invented
structure identity or logical extent beyond the actual read spans.

The 32 structural corruption controls change instructions/operands, branch,
return, padding, full frame/augmentation records, the caller edge and introduced
entry/code relocations separately from the initial whole-artifact digest check.
They qualify the static evidence used in this proof, not execution equivalence.

## Independent pre-Rust expectations

Before Rust existed, the static record, original oracle and every fixture were
frozen. The oracle evaluates an immutable numeric-address map with unbounded
byte-weight arithmetic and a difference residue to classify equality. The
conditional memory relation composes address functions; it does not step
instructions or model registers/flags. Rust instead uses checked slice reads,
u64 equality and explicit wrapping additions. Neither implementation calls
the other, and the native client receives inputs only.

All 7,492 cases predate Rust: 1,302 self results, 3,921 chain results and 2,269
new refusals. Coverage includes every value bit, zero/all-ones/high results,
partial/exact input aliases, wrapped and high addresses, exact span ends and
missing fields at every stage. There are 128 successful self cases without
a represented next span, 44 successful zero-pointer chain cases and 1,021
chain cases whose guard differs only above the low32 bits. Two overflowing
image descriptors keep every reached read below N to isolate the global range
rule rather than relying on a later missing read.

Native optimization/repeat comparisons and actual compiled wrong implementations
qualify the finite fixtures and implementation. The universal argument above
covers the admitted full-value/memory domain; no original compiled-byte identity,
whole-node reconstruction or exhaustive enumeration of memory maps is claimed.
