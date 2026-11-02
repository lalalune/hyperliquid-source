# Two complete chained-field reads and aliased output stores

Target node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This closes the complete 31-byte functions `[0x514ac20,0x514ac3f)` and
`[0x514ac40,0x514ac5f)` together. Their common chain/store protocol and
different final read widths form one family question. The adjacent
indexed accumulator at `0x514ac60` is a separate function and excluded.

## Exact bodies and dependencies

The entire 91,774,280-byte target is authenticated before parsing. Each
member has exactly one overlapping FDE describing its complete interval;
the actual FDE/CIE records and linkage are bound. GNU, LLVM and Capstone
agree on all 62 bytes and fourteen instructions. Each member has one
separately bound INT3 padding byte, a final RET, no branch or call and
no RIP-relative dependency. Seventeen corruption controls exercise
body fields, read opcode, output store, return immediate, padding and
FDE/CIE structure separately from the target digest.

Every one of the 80,300 RELA records is scanned. None names either entry
or overlaps either body/padding. Complete `.text` E8/E9 pattern scans
find no direct candidates to these starts. Short/indirect transfers and
other data-pointer references are not a complete caller census. The
predecessor static packet established the two leaves; it supplied no
Rust memory reconstruction or arbitrary output-alias contract.

## Ordered memory relation

Let O be incoming RDI, D incoming RSI, M=2^64, Q a little-endian qword
read and W a little-endian dword read. Every field-address addition
below wraps modulo M before the memory read:

```
P = Q((O + 0x788) mod M)
R = Q((P + 0x30) mod M)
first member: V = sign_extend32_to64(W((R + 0xb30) mod M))
second member: V = Q((R + 0x1008) mod M)
store V as eight little-endian bytes at D
RAX = 1
```

The first member uses MOVSLQ: if the dword x is below 2^31, V=x;
otherwise V=x+2^64-2^32. For x=0x80000000, the stored value is
0xffffffff80000000. The second member reads all eight bytes without
truncation or sign transformation. Its high bits are data, not an
admission condition.

All three reads finish before the sole output store. The output can
overlap either pointer field or the value field at any byte displacement;
no later read can observe the store. The two pointer reads themselves
may overlap other readable data: their values are simply those obtained
from the stable entry image. There is no disjointness or alignment
requirement in the relation. Fixed displacement does not establish a
complete source struct or require mapping the unused surrounding bytes.

After the store, MOV EAX,1 zero-extends the full RAX. The stored V is
therefore not the returned register value. RAX is the only written GP
register; RDI and RSI are unchanged. Flags and ordinary RET control
effects are outside this data-state projection. No additional callee
or fabricated helper return remains unresolved.

## Safe image projection

The Rust API maps byte j of one mutable slice to numeric address B+j.
The complete image must not wrap; its last byte may be M-1. Reached
field addresses wrap first, then each complete actual span must fall
inside the image. A checked subtraction and fallible usize conversion
establish the start; checked width addition and the slice bound establish
the end. There is no alignment or guessed allocation-length constraint.
The container/pointer values themselves need not be mapped if their
derived field addresses are valid.

The selected Field enum is a new family selector, not an original native
argument. Signed32 reads exactly four bytes and converts through i32/i64
to produce the sign-extended u64 bits. Word64 reads exactly eight bytes.
The output always requires eight bytes, independently of field width.
The value is copied into a Rust scalar before the output slice is formed,
so arbitrary readable/output aliases cannot alter its source. The sole
store replaces precisely the eight destination bytes and returns one.

ImageRange, FirstPointer, SecondPointer, Value and Output are new safe
refusals, checked in that order. No actual image write occurs before
every reached requirement passes. Thus every refusal preserves the
entire image, including any valid output prefix. These errors and their
atomicity are new API behavior, not an attempt to reproduce native fault
timing or partial effects. Each successful slice conversion has its
required exact width, proving the unwraps cannot panic after admission.

Correspondence assumes stable initialized ordinary readable input and
writable output, valid code and return control. It excludes native
faults, MMIO, concurrency, code/control-storage aliases, flags, timing,
physical access traces and the original ABI. A single nonwrapping image
cannot represent every discontiguous native layout. Synthetic high
numeric fixture addresses do not assert that a particular OS can map
those addresses. All final image bytes and full RAX are the observations.

## Independent pre-Rust expectations

The oracle, static record and full input/expected streams were frozen
before either Rust file existed. It uses positional base-256 sums,
arithmetic sign extension and a replacement byte sequence. Rust uses
checked slices, native endian conversions and signed integer casts.
The input-only driver observes the returned value and all image bytes,
including the untouched suffix outside the selected slice length.
Neither captured instructions nor an instruction interpreter runs.

The 8,890 fixtures include both field widths, signed/high-bit boundaries,
every value bit and neighbors, every output-byte position, all read/output
boundary widths, wrapped field formation, pointer/value overlaps and
deterministic additional layouts. Of these, 6,641 return normally and
2,249 are new refusals: 6 image, 401 first-pointer, 818 second-pointer,
676 value and 348 output errors. The native fixture image capacity is
256 bytes; the API has no such hard-coded capacity. Finite cases support
the full admitted-image proof rather than enumerating every possible
image, alias layout or pointer value.

No original source identity, compiled-target-byte equality, runtime
reachability, application meaning, whole-node equivalence or completed
component gate is claimed.
