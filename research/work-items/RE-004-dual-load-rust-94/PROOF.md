# Complete byte-indexed windows after relocation

The target is node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This proves the numeric RAX/RDX output of complete ELF VA
`[0x4e48600,0x4e4861d)`, under a successfully loaded, unchanged data image.
It closes the earlier static packet's explicitly unresolved B-window
relocations. It does not infer a source type, logical table length, valid
semantic index subset or meaning of either returned number.

## Function and data closure

The unique 29-byte FDE contains seven instructions. GNU, LLVM and Capstone
agree on all bytes and boundaries. Three INT3 bytes follow outside the
FDE. There is one RET, no branch, call or exceptional arm in the body.
The full `.text` E8 scan finds no direct candidate; one complete
symbol-zero R_X86_64_RELATIVE record at slot `0x57494c0` names the entry.
Its zero file word, type, addend and full raw record are bound. Neither
that slot nor the direct encoding scan establishes all indirect users.

MOVZBL reads an unsigned byte i, zero-extending it into EAX and RAX.
SHL EAX,3 gives exactly 8i in [0,2040]; its 32-bit width loses no bits.
The two RIP-relative LEAs resolve to A=`0x7c13f8` and B=`0x5749c90`
before a common load bias L. Their effective qword reads cover exactly
the 2,048-byte windows A..A+2048 and B..B+2048 for the full u8 domain.
The first read writes RDX; the second writes RAX; RET changes neither.
RCX, flags, timing and the original input-pointer ABI are not projected.

Both complete windows are mapped and file-backed. A is in `.rodata`
(file offset equals VA); B is in `.data.rel.ro` (file offset is VA-8192).
The verifier uses actual section/PT_LOAD mappings and retains all 4,096
data bytes, rather than applying one global address conversion. This
reachable window is not asserted to be one logical array: later words
may belong to neighboring data. The byte load permits them numerically,
so the value projection includes them without guessing an index bound.

## Every relocation in the reachable windows

The complete RELA scan checks interval overlap, including writes starting
before either window. No relocation touches A. Exactly 127 records touch
B. Each starts at B+8i for a unique i in 0..255, has the full `r_info=8`
(symbol zero and type R_X86_64_RELATIVE), and writes one complete qword.
There are no partial, duplicate, symbol-resolved or other relocation
writes in either window. The full records and their order have a pinned
digest, independently of the full ELF identity. The other 129 B words
retain file bytes. The code intervals have no overlapping relocation.

For a successfully loaded ELF, each of those 127 destination words is
`(L + signed_addend) mod 2^64`; its initial file bytes are not the result.
This proof uses the RELATIVE relocation contract as a loader premise,
not a new dynamic linker implementation. No symbol resolver or IFUNC
result is required for these windows. Other relocations elsewhere are
enumerated for overlap but their semantics are not reconstructed here.

Let `a_i` be the little-endian A file word, `b_i` the B file word,
R the set of relocated B indices, and `d_i` each RELATIVE addend. Then:

```
RDX = a_i
RAX = (L + d_i) mod 2^64   if i belongs to R
      b_i                 otherwise
```

For example i=0 gives `(RAX,RDX)=(L+2142632 mod 2^64,8)`. Index 20
is unrelocated and yields `(98,13637704200709732)` for every bias.
That raw word must not receive L merely because it is in `.data.rel.ro`.
Index 253 is relocated with addend 2032517; a numeric bias of
`-2032517 mod 2^64` produces RAX zero. This arithmetic witness does not
assert that this bias describes an actually loadable process image.

## Rust correspondence

`lookup(index:u8,load_bias:u64)` receives the already-read entry byte.
`A` holds all 256 measured file words. `B` holds the addend reduced to
u64 for each relocated index and the unchanged file word elsewhere.
Four u64 mask words encode exactly R. Dividing i by 64 selects the mask
word and taking i modulo 64 selects a bit; all indices and shift counts
are in bounds. The source adds load_bias with wrapping u64 arithmetic
exactly when the bit is set, then returns the A word in RDX.

The constants are measured numeric evidence from the pinned ELF and
records, not copied inferred source or hand-transplanted instructions.
The implementation independently expresses selection and arithmetic;
it has no dependencies, unsafe code, host pointer dereference, dynamic
loading or hidden runtime table mutation. The pre-Rust oracle instead
materializes all 2,048 B bytes using the exact relocation records, then
extracts byte ranges. Its byte-image construction and the Rust bit-mask
selection are different representations of the bound relation.

All u8 indices and u64 biases have defined numeric outputs in the API.
Correspondence to an actual target run additionally requires a successful
mapping with a common bias, ordinary readable stable input and table
memory, and no subsequent modifications of these windows. Code/control
storage must also be valid. The model does not make all numeric biases
canonical or loadable. It does not emulate a loader failure, arbitrary
mutated runtime tables, unmapped input, concurrent writes, MMIO or faults.
The index byte may alias either table if the provided value equals that
initial byte; only reads occur. No target pointer or return ABI is exposed.

## Qualification and remaining limits

The static record, independent oracle and exact streams were frozen
before Rust existed. The fixed 38,140 records cover all 256 indices at
each of 131 shared bias values, directed wrap boundaries for every one
of the 127 relocations and 4,096 seeded additional values. Across 4,494
distinct biases, 19,119 cases use a relocated word and 19,021 use raw
file words. The freeze binds the complete static record and oracle hash.

All 152,560 native observations match across two builds each at opt0 and
opt3, including repeated library/client/output hash equality. Three units
per profile, malformed-input rejection, two comparator controls and all
15 compiled semantic mutants pass their expected checks. Thirty static
controls corrupt body operands, CIE/FDE, padding, naming slot/record,
early/middle/last data words and relocation targets/types/symbols/addends.
These downstream checks do not rely on the changed whole-file digest.
Exact raw streams, tools, compiler/source hashes and first divergent
records are retained losslessly.

Native execution runs only the newly authored aarch64 Rust client with
pinned rustc 1.94.1. No captured executable or instruction emulator runs.
Finite input agreement supports the algebraic proof and is not original
machine-code identity, a complete xref map, source provenance, whole-node
equivalence or completion of the foundation component gate.
