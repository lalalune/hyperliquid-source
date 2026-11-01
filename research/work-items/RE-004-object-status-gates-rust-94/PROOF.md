# Three complete object-status gates

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The closure comprises three separate complete leaves, grouped because their
predicates reuse the same object status fields. No source type or application
meaning is inferred from those fields.

| Entry | Exclusive end | Bytes | Instructions |
|---|---|---:|---:|
| 0x5382c90 | 0x5382caf | 31 | 8 |
| 0x5382d30 | 0x5382d4f | 31 | 10 |
| 0x5382d50 | 0x5382d8b | 59 | 16 |

There are 121 bytes and 34 instructions. Separate following INT3 padding is
1/1/5 bytes. The third body includes an internal five-byte NOP and two RETs;
its first RET is not its FDE endpoint. Nearby setter, indirect-call and
indirect-tail functions are outside this closed leaf family.

## Domain and full observations

Let N=2^64, incoming RDI=O and incoming RDX=E. All numeric inputs are arbitrary
u64 values. Each field address below is formed modulo N. b, d and q denote
one-byte, little-endian four-byte and little-endian eight-byte reads. Original
normal-return correspondence requires only the accesses actually reached below,
stable ordinary memory and valid disjoint control/stack state. Read-role aliases
and unaligned data are permitted. The new API returns full RAX and RDX values;
flags, native ABI, CET, return-stack effects and other entry-preserved registers
are outside its numeric projection. It does not execute pointers or SIMD code.

### Three-valued gate at 0x5382c90

Read F=b(O+0x28a). If F!=0, RAX=1 and there is no dword read. Otherwise read
C=d(O+0x28c): RAX=2 when C=1, and RAX=0 otherwise. RDX=E on every path.
The MOV EAX,1 occurs before JNE and clears the upper32 bits. On the F=0 path,
SETE writes AL but EAX's other24 bits are already zero; ADD EAX,EAX therefore
produces exactly0 or2 with full64 zero extension. Any nonzero byte F selects1,
not merely the bit pattern1. This return is a three-valued number, not a bool.

### Pointer-gated byte at 0x5382d30

Read P=q(O+0x50), then stage RAX=0. If P=0, return RAX=0 and RDX=0 without
reading P+0x20 or O+0x289. If P!=0, read G=b(P+0x20). If G=0, RAX=0;
otherwise read H=b(O+0x289) and return RAX=H without booleanizing it.
RDX=P on all paths, including the zero path. MOVZX EAX clears every other bit,
so all nonzero bytes up to255 remain visible in the full RAX observation.
Neither G nor H changes RDX, even when their read roles alias the pointer bytes.

### Ordered status/counter gate at 0x5382d50

RAX starts at zero. The exact ordered decision relation is:

1. Read F=b(O+0x28a); F!=0 returns0 with no later read.
2. Read T=b(O+0x290); T!=0 returns that exact byte T.
3. Read H=b(O+0x289); H=0 returns0.
4. Read A=d(O+0x98), then B=d(O+0x9c). Return
   `(A & 0xffffff00) | [B < A]`, using unsigned32 comparison.

RDX=E throughout. CMP [O+0x9c],EAX computes B-A and SETB writes only AL.
The preceding MOV EAX,[O+0x98] cleared RAX's upper32 but left A's bits8..31
in EAX. SETB preserves those24 bits. Therefore the final full RAX is often
larger than255, even though its low byte is a boolean. For example,
A=0x1234abcd and B=0x1234abcc gives RAX=0x1234ab01; A=B gives0x1234ab00.
Replacing the result with a zero-extended boolean would change the observed
register. Early nonzero T remains an exact byte rather than this packed dword.

These three derivations exhaust every branch and normal return in the complete
bodies. Each integer read has its explicit width; no sign extension or guessed
logical field range is used. All possible bytes/dwords, including negative-looking
bit patterns, are admitted as raw unsigned data.

## Selective finite-image admission

A slice byte i represents address base+i in one nonwrapping interval whose
exclusive end may equal N. A wrapping global image is refused before reads.
A numeric field address is reduced modulo N before checked subtraction of base,
conversion to usize, checked width addition and comparison with the slice length.
Numeric O and P need not themselves be in the image if the reached field is.
A multibyte read must fit contiguously; wrapping a read across N cannot fit this
single nonwrapping representation. This matches the stated successful-access
domain without fabricating split reads or native pointer provenance.

Only reached fields are requested. In particular, a missing C is valid when
F!=0 in the first gate; missing G/H is valid when P=0 in the second; and missing
counter fields is valid when an earlier status byte returns in the third.
An eager validation of every possible field would incorrectly reject these
admitted paths. None denotes the new safe API refusal on a reached missing span
or invalid image; it is not an original exception or return value.

The slice is immutable and the source forbids unsafe code. No call can alter
input bytes, on success or refusal. Stable reads permit all read-role aliases,
including partial overlap between pointer and byte fields. Original faults and
their ordering, MMIO, concurrent mutation, native stack/control aliases and
instrumentation that changes observations are excluded; no artificial alignment
or logical-bool premise is added.

## Independent expectations and static closure

The independent oracle constructs an immutable address-to-byte map, selects
ordered decision alternatives, compares reversed four-byte strings
lexicographically, and preserves the upper three bytes of A explicitly. The
Rust implementation separately uses checked slice reads, typed unsigned32
comparison and a bit mask. Neither executes captured instructions or steps a
register/flag model. The oracle and full expected stream are frozen before the
Rust directory exists. Native input receives descriptors and images only.

All three complete bodies and unique actual FDE/CIE records are authenticated
with GNU, Apple LLVM and Capstone bytes/boundaries. No body calls a helper,
uses RIP-relative data, or has a branch outside its own body. The whole .text
E8/E9 candidate scan finds none for these entries; this does not imply they are
unreachable. Five symbol-zero RELATIVE records name them: three destination
slots are in .data.rel.ro and two are in .got. Every raw slot, section/PT_LOAD
mapping, relocation addend/type and unique overlapping writer is bound.
All80,300 RELAs are scanned for entry names and body/padding writes. Indirect
reachability beyond this evidence is unclaimed.

The initial verifier assumed every naming slot was in .data.rel.ro. Actual
mapping evidence rejected that assumption for the two .got slots. The original
verifier/diagnostic is retained; the corrected check binds each exact mapped
section instead. This static correction preceded oracle freezing and Rust.
No bytes, slot records or successful-control expectations were weakened.

Finite fixtures cover the full256-byte flag range, unsigned dword boundaries,
retained upper return bits, all early-exit omissions, address aliases, wrapping
field formation and new-API refusals. Compiled wrong implementations and static
corruption controls qualify these distinctions. The universal relations above
supply the all-admitted-domain argument; finite cases do not establish exhaustive
images, original compiled-byte equality, caller algorithms or whole-node behavior.
