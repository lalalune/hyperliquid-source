# Three complete three-hop accessor/store leaves

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This closes the Rust reconstruction gap in historical static packet
foundation-three-hop-trio-94 (merged PR#1286). The three leaves share their
first two reads and output protocol; their final offsets differ.

| Entry | Exclusive end | Final offset F | Bytes | Instructions |
|---|---|---|---:|---:|
| 0x514acc0 | 0x514ace2 | 0xcd0 | 34 | 7 |
| 0x514acf0 | 0x514ad12 | 0xa70 | 34 | 7 |
| 0x514ad20 | 0x514ad42 | 0xa78 | 34 | 7 |

All102 bytes/21 instructions are included, and14 following INT3 bytes per body
are separately bound. The neighboring two-hop reader0x514ad50 (PR#1287) follows
a different second field and is not claimed as a fourth member. PR#1296's
call-sum pair is separate caller-context discussion, not this implementation.
No source-level struct type, field meaning or owning component is inferred.

## Complete memory and register relation

Let N=2^64, incoming RDI=O, RSI=D and RDX=E. Let q(A) be the eight-byte
little-endian value at numeric address A in stable entry memory. Each field
address addition below is independently reduced modulo N. For the selected F,

```
P = q((O+0x788) mod N)
Q = q((P+0x8e8) mod N)
V = q((Q+F) mod N)
store the eight little-endian bytes of V at D
RAX = 1
RDX = E
```

The body is ENDBR64, three full-width MOV loads into RAX, one full-width MOV
store through RSI, MOV EAX,1 and RET. The full RAX result is therefore exactly1:
the final32-bit destination write clears its upper32 bits. V is output memory,
not the return register. RDX is never written or consulted, so every incoming
u64 value is preserved. RDI and RSI are also unchanged input addresses; their
preservation is outside the two-register return object. Flags, CET, RET/control
state and the original native calling convention are outside this projection.

There are no data branches, null checks or loops. All three reads and the store
are reached on every normal return. A numeric zero P or Q is not an implicit
refusal: only its actual reached offset field must be represented. Repeated,
cyclic-looking or overlapping read roles do not cause iteration; exactly three
loads occur. No logical object extent or alignment is assumed.

## Arbitrary aliases and output preservation

Every input read finishes before the sole data store. Thus V is a composition
of reads from one immutable entry image. D may equal or partially overlap any
of the three reached qword spans, including unaligned overlaps. Such output
aliasing cannot retroactively change P, Q or V. Computing the whole source
composition before writing eight bytes is exact. No byte outside[D,D+8) changes.

Read roles may also overlap each other. The construction uses the actual final
entry bytes at each reached address; it does not assume separately requested
field values survive overlapping fixture writes. A pointer field and a value
field can denote the same bytes when their numeric contents permit it. No
mutually inconsistent abstract object layout is imposed on admitted images.

## Safe finite-image domain

`apply` uses one mutable slice with numeric base B. Byte i represents B+i;
the exclusive image end may equal N and must not exceed it. The object and
loaded pointer numbers themselves need not be in the image. Only their reached
field addresses, after modulo-N addition, require eight contiguous bytes.
D requires eight writable bytes. Each span is established by checked subtraction
of B, checked conversion to usize and checked end arithmetic.

These checks guarantee every subsequent fixed eight-byte slice access. There
is no unchecked pointer conversion, unsafe code, allocation, data-dependent loop
or overshift. Original successful-access correspondence assumes ordinary stable
memory, valid normal control and data disjoint from executable/return-stack
storage. MMIO, concurrent observations, faults/noncanonical mappings and original
ABI behavior are excluded. Synthetic numeric wrapping cases are value-domain
fixtures, not claims that such virtual mappings exist in a native process.

None is a new refusal for an invalid global image or missing required span.
All validation/reads occur before any store, so refusal leaves the image
unchanged. Destination validation may precede input validation in Rust because
no target fault order or partial faulting execution is claimed. A read or store
that crosses N cannot fit this single nonwrapping image; separate field
formation may wrap into it. No arbitrary library image-size cap is imposed.
The native fixture/client's1280-byte capacity is only a serialization choice.

## Independent expectation and evidence closure

Before Rust exists, the independent oracle composes whole-word reads from an
immutable numeric-address dictionary and computes the final image with a
single immutable byte overlay. Each word is an unbounded base256 sum. Rust
separately uses checked slice spans, from_le_bytes and one final copy. The
oracle imports no Rust, receives no native result and does not execute captured
instructions or emulate a processor. All inputs/expectations are frozen before
implementation; native clients receive inputs only.

All three bodies have unique exact FDEs with their actual CIE records. GNU,
Apple LLVM and Capstone must agree on every retained byte and instruction
boundary. Complete .text E8/E9 scanning finds no direct candidates, and none
of80,300 RELA records names a selected entry or writes its body/padding. This
is not a complete indirect-reference census or a claim of unreachability.
There is no called helper, RIP-relative data, table or external transfer before
RET in this closure. Static corruption controls qualify these structural locks
separately from the whole-artifact digest admission.

The final-value argument covers every admitted ordinary-memory image. Finite
native cases and compiled wrong implementations test output preservation,
register width, exact offsets, aliases, zero field bases and safe-domain limits;
they do not exhaust all memory maps or prove original compiled-byte identity,
whole-caller behavior, whole-node equivalence or a component-completion gate.
