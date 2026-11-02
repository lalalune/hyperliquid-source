# Complete three-byte decimal language and full RAX

The target is the complete 85-byte node94 function
`[0x1683670,0x16836c5)`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Its thirty instructions have two closed conditional edges, two returns,
no calls, no static data dependency and no stores. Eleven INT3 padding
bytes are outside the function. The claim is full RAX, with explicit
ordinary-memory admission; other registers and flags are not projected.

## Exact relation

Let L be the full incoming RSI value. If L is not exactly 3, full RAX is
zero and the function does not access input data. Otherwise let a,b,c
be the three readable bytes beginning at incoming RDI. Define

```
valid = a in ASCII '1'..'9' and b,c in ASCII '0'..'9'
RAX = 100*(a-48) + 10*(b-48) + (c-48), if valid
RAX = 0, otherwise
```

The full 64-bit CMP RSI,3 excludes every length with nonzero high bits,
even if its low32 or low8 is 3. The rejected-length branch reaches XOR
EAX,EAX and RET directly. The dword write clears all of RAX, independently
of any entry register values. No pointer is used on this path.

When L=3, the three MOVZBL instructions load a,b,c before any digit flag
can select a return. The additions of 0xd0 to AL and DL produce
`(b-48) mod256` and `(c-48) mod256`. Their unsigned comparisons against
10 reject precisely the complements of bytes 48..57: the modular
subtraction is a bijection on the 256 byte values, and residues 0..9
have exactly those ten preimages.

For a, the LEA forms low32 `a-58`, then CMP SIL,0xf7 and SETB inspect
only its low byte. The invalid flag is zero exactly when
`(a-58) mod256 >=247`. Residues 247..255 have preimages 49..57, exactly
ASCII '1'..'9'. In particular '0' gives residue 246 and is rejected.
Sign extension, whitespace, signs and non-ASCII numeral meanings play
no role in these byte predicates.

Each SETcc produces a one-byte Boolean. The two ORs in R8B combine the
three flags and set ZF iff all three are zero. The JE selects the value
path exactly for valid triples. Otherwise XOR EAX,EAX again gives full
RAX zero. Although these instructions partially overwrite RSI, RDI and
R8, those scratch results do not enter the RAX API or any further read.

On the valid path, MOVZBL DL,EDX gives c-48 in 0..9. The CL addition and
MOVZBL give a-48 in 1..9, and IMUL by 100 gives 100..900. MOVZBL AL,EAX
gives b-48 in 0..9; ADD doubles it and LEA with scale four multiplies that
result by five. The following MOVZBL AL,EAX changes nothing because the
tens contribution is at most 90, below 256. The two final additions
produce 100..999. No intermediate overflows a dword. Every contributing
EAX write zero-extends full RAX. The two cases therefore cover every
u64 length and every one of the 2^24 byte triples; exactly 900 triples
return nonzero when L=3.

## Safe source and domain

`parse(length, bytes)` keeps the native length separate from the length
of a supplied readable prefix. This is necessary to preserve the no-read
path for arbitrary native lengths without requiring an enormous slice.
All u64 lengths are admitted numerically. When length differs from 3,
the function returns `Ok(0)` before checking any supplied bytes.

When length equals 3, `bytes.get(..3)` requires the complete three-byte
prefix before evaluating any digit predicate. An unavailable prefix
returns the new `TooShort` refusal, even if an available first byte would
be invalid. That refusal is not the original zero result or a simulation
of its fault. Additional bytes do not affect the result and are not read.
The driver's four-byte capacity is a fixture framing limit, not a library
limit; the library accepts arbitrary slices.

The source's ASCII range tests are exactly the derived byte preimages.
Its subtractions are written with wrapping operations; on the admitted
valid path all operands are at least 48, so these equal ordinary
nonnegative subtraction. Widening and the weighted sum are bounded by
999. The preceding slice check bounds all three indexes. Consequently
there is no panic, allocation, unsafe operation or mutation for any
supplied slice and u64 length. `Ok(0)` and `Err(TooShort)` remain distinct.

For correspondence, the original code and return control must be valid.
When L=3, the three bytes must be initialized, readable and stable ordinary
memory at the original addresses; when L differs from 3, no input-memory
premise is needed. A supplied slice's native pointer is not reconstructed.
Fault timing, wrapping pointer layouts, MMIO, concurrent changes, flags,
other registers, stack/control transitions, physical access traces and
original ABI are excluded. Native load ordering establishes the required
three-byte admission, not a promise of identical host machine accesses.

## Static and caller boundary

The full 91,774,280-byte target is authenticated before parsing. All body
bytes, the unique complete FDE and its actual CIE are retained. GNU,
LLVM and Capstone agree on all thirty instruction boundaries. Both
conditional targets are decoded internal starts and the two RET sites
close all paths. The full 1,301-byte/318-instruction caller
`[0x1682220,0x1682735)` is independently decoded, with its actual FDE/CIE.
Its call at `0x1682606` is a qualified direct edge to the parser. The
caller is reference context, not a reconstructed parent operation; its
outgoing dependencies and semantic purpose are not claimed.

Full `.text` E8/E9 encoding scans find exactly that E8 candidate and no
E9 candidates. Every one of the 80,300 RELA records is checked: none names
the parser or overlaps either retained body or the parser padding.
Indirect, short and other pointer paths remain outside this census.
All 27 structural corruptions reject without relying on the full-target
digest comparison. A nearby stripped-symbol label is not an identity.

## Independent expected values

Before Rust existed, the oracle enumerated decimal strings for integers
100..999 into a finite language dictionary. Expected values use exact
three-byte dictionary membership, rather than the source's digit tests,
subtractions or weighted sum. All 900 accepted words are present in the
frozen corpus. The oracle, static record and raw input/output hashes were
fixed before source creation; captured instructions and instruction
emulation supplied no expected values.

The 227,140 fixtures include every 65,536-value pair of byte positions
with the remaining position fixed to a valid digit, all 1,000 decimal
triples including leading-zero cases, each prefix availability, every
high length bit, all fourth-byte values and deterministic extra inputs.
Deduplication occurs before the freeze. There are 19,008 length rejections,
7,360 new safe refusals, 198,211 invalid complete triples and 2,561 valid
observations covering all 900 distinct accepted words. This is a finite
qualification, not an exhaustive 2^24-triple or 2^64-length run. The byte
preimage and arithmetic proof supplies the universal relation.

No source-level function/type identity, interpretation of the parsed
number, original compiled-byte equality, whole-node equivalence or
component completion follows from this bounded reconstruction.
