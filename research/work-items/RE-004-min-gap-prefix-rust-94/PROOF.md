# Min-gap prefix equality under an explicit memcmp contract

Target node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Scope: complete `[0x5430db0,0x5430e07)`, 87 bytes and 30 instructions.
This proof reconstructs a readonly memory/RAX relation. It closes the
actual external import and states its required behavior explicitly;
it does not claim a captured libc implementation or runtime resolution.

## Complete bytes and import boundary

The full target digest and 91,774,280-byte size precede parsing. GNU,
LLVM and Capstone agree on every byte and instruction boundary of the
leaf, its 16-byte PLT stub and eight complete caller FDEs. The leaf has
one exact FDE; adjacent FDEs are `[0x5430d60,0x5430dab)` and
`[0x5430e07,0x5430e4c)`. Five INT3 bytes precede the leaf and there is
no trailing padding. Every local branch targets an instruction start;
there is one RET at `0x5430e06` and one call at `0x5430dd7`.

The call targets `0x5660150` in `.plt`, not an FDE. Its first instruction
loads the target from GOT slot `0x5778dd0`; the file value in that slot
is `0x5660156`, the stub's lazy resolver continuation. The stub pushes
relocation ordinal 6 and jumps to PLT0 at `0x56600e0`. The actual
`.rela.plt` record at file offset `0x1dba60` is a `R_X86_64_JUMP_SLOT`
for symbol index 12, with destination `0x5778dd0` and addend zero.

Dynamic symbol 12 is the undefined GLOBAL FUNC `memcmp`, with zero
value/size and ordinary visibility. Its `.gnu.version` entry is 3;
the corresponding version-need auxiliary record names `GLIBC_2.2.5`
from `libc.so.6`, which also appears in DT_NEEDED. The validator parses
and binds the actual symbol/string/version/needed records and raw GOT
bytes, not just objdump's nearest-name label. This is an import ABI
version requirement, not proof that the runtime libc package is version
2.2.5 or that interposition is absent.

The external semantic premise is an ABI-conforming, normally returning
`memcmp` that preserves callee-saved registers and does not mutate
ordinary memory. It returns zero in its low 32 bits exactly when all n
selected bytes agree. GNU's primary manual specifies comparison of the
requested bytes, zero for equal blocks, and a nonzero sign determined
by the first differing unsigned byte pair. Only zero/nonzero matters
here. [GNU C Library, String/Array Comparison](https://sourceware.org/glibc/manual/latest/html_node/String_002fArray-Comparison.html)

The Rust component compares the actual image bytes; it does not accept
a fabricated callee result. Behavior under a replaced, nonconforming,
faulting or nonreturning import is outside this theorem. The original
libc machine code and its allocation of reads are neither present in
this packet nor reconstructed.

The eight direct E8 candidates are confirmed as decoded call starts in
their full containing FDEs:

| Call | Full caller interval | Bytes | Instructions |
|---|---|---:|---:|
| `0x522d600` | `[0x522d4b0,0x522d933)` | 1,155 | 256 |
| `0x52464c1` | `[0x52462e0,0x5246a4e)` | 1,902 | 409 |
| `0x52fa39e` | `[0x52fa110,0x52fb0c3)` | 4,019 | 782 |
| `0x531c27c` | `[0x531beb0,0x531c7a8)` | 2,296 | 460 |
| `0x531f8f9` | `[0x531f770,0x531ff4f)` | 2,015 | 406 |
| `0x53218ee` | `[0x5321720,0x53220a5)` | 2,437 | 485 |
| `0x54265c8` | `[0x5426550,0x5426dff)` | 2,223 | 472 |
| `0x5426ebd` | `[0x5426e40,0x54276ff)` | 2,239 | 475 |

The full `.text` E9 scan finds no direct jumps to the entry. All 80,300
RELA records are checked: none names the leaf as addend, none writes
into retained code, and exactly one supplies the memcmp GOT slot.
These scans do not prove all indirect entry paths or caller application
behavior. The old packet retained one caller and seven raw candidates;
this packet confirms all eight in complete caller decodes.

## Full-u64 arithmetic proof

Let incoming RDI=A and RSI=B. All effective-address additions below wrap
modulo M=2^64 before admission. The leaf first saves `y=Q(B+8)` in RBP,
then `x=Q(A+8)` in RBX, where Q reads an unsigned little-endian qword.
CMP/CMOVBE produce `n=min_u64(x,y)`. There is no signed min or low-word
truncation.

If n is zero, the leaf skips the two pointer fields and the import call.
Otherwise it reads the pointer qword at B, then that at A, and calls
`memcmp(Q(A),Q(B),n)`. The saved lengths survive by the stated ABI
premise. A nonzero low32 result reaches a zero return. For a zero result,
or on the n=0 path, the leaf calculates `g=(n-y) mod M` and interprets
g as signed64 for the two comparisons with −2^31 and 2^31−1. It returns
one only when that signed value is in this interval and `low32(g)==0`.

The signed interval `[−2^31,2^31−1]` contains exactly one multiple of
2^32: zero. Therefore the guarded low32 test accepts iff g=0 as a full
64-bit value. Since `0<=n<=y<=M−1`, the integer difference n−y lies in
`[−(M−1),0]`, whose only multiple of M is zero. Thus g=0 iff n=y,
equivalently y<=x unsigned. This argument does not assume signed(g)
stays negative: modular underflow can give a positive signed residue.
For example n=1,y=M−1 gives g=2 and is correctly rejected. Likewise
n=0,y=2^32 has zero low32 bits but is rejected by the signed range.

Combining the call gate gives the final relation:

```
RAX = 1 iff y <= x and (n == 0 or all n selected byte pairs agree)
RAX = 0 otherwise
```

On n=0 this is exactly `y==0`, because if y>0 then x must be zero.
Rust therefore uses that shortcut, then actual full-prefix equality and
the unsigned y<=x test for n>0. The source still admits both payload
spans before evaluating the final length result; it does not pre-reject
y>x and thereby conceal a required input-range failure.

Both captured paths explicitly clear EAX before reaching RET or SETE
AL. Clearing EAX zero-extends the full RAX; SETE changes only its low
byte. Accordingly the complete returned register is 0 or 1, independent
of upper bits returned by memcmp. The new API returns a u64, so native
qualification observes the full value rather than only a Boolean byte.

## Checked readonly memory domain

One immutable slice at numeric base C represents byte address C+j.
The whole image must be nonwrapping, with its last byte allowed at
M−1. For each reached qword, address formation wraps first; the complete
eight-byte range must then lie in that image. A or B itself need not
be admitted when n=0: only their length fields are read. This includes
A=M−8 with a length field at address zero.

When n>0, both pointer fields and each complete contiguous n-byte
payload span must be admitted. All fields and payloads may alias each
other at arbitrary byte offsets, because they are readonly and stable.
No alignment constraint, disjointness requirement or guessed allocation
length is introduced. Width n is converted to usize without truncation;
offset/width addition is checked before slice indexing. Invalid or
unrepresentable spans are refused before comparison. There is no
arbitrary maximum count: every count whose full spans fit is accepted,
although fixtures do not allocate huge buffers merely to test refusal.

The new errors are ImageRange, Lengths, Pointers and Bytes. Global image
validity is checked first, then both length fields; pointer and byte
checks occur only for n>0. Errors are safe API outcomes, not original
fault results. Neither success nor refusal mutates the image. The
readonly API needs no allocation and no unsafe code; checked additions
also prove every host index representable. A finite admitted slice
comparison terminates; the native leaf has no internal loop and the
external premise requires normal return.

Correspondence requires stable initialized readable data, valid native
instruction/stack/control storage and the external contract above.
Concurrent changes, MMIO, instruction/control-stack aliases, faults,
unwinding, replaced imports, discontiguous or wrapping layouts absent
from the single image, flags, other clobbered registers, timing and
intermediate reads are not modeled. High numeric addresses in fixtures
do not assert that Linux/x86-64 can map them. This is not an original
System V ABI replacement or recovered source type.

## Independent expectations

Before the Rust directory existed, the static record and `oracle.py`
were frozen with complete input/output streams and hashes. The oracle
uses an unbounded sum of squared byte differences for equality, then
the original bounded signed modular-gap relation. Rust uses complete
slice equality and the proved unsigned ordering reduction. This gives
independent mathematical formulations, not a CPU/instruction evaluator
or results copied from executing Rust or the captured node.

The 69,063 fixed cases include every one of the 65,536 single-byte pairs,
longer prefixes with first/middle/last differences and embedded NULs,
high-bit length/min/gap boundaries, all four errors, skipped invalid
pointer fields, metadata/payload aliases, exact endpoints, wrapped field
addresses and digest-derived images. There are 67,576 admitted normal
results (66,686 zero, 890 one) and 1,487 new refusals. The independent
input-only client supplies memory, never a helper result or expectation.
Finite cases support the full-domain proof; native runs do not establish
original compiled bytes, runtime libc identity or whole-node equivalence.
