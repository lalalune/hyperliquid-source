# Tag-selected numeric address pair: complete leaf proof

The sole semantic target is node94 linked ELF VA `[0x15d65b0,0x15d65f3)`.
`static/records.json` binds all 67 bytes, all 18 instructions, the unique actual
FDE and CIE, the adjacent boundary, and the three relevant relocation slots to
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
GNU and LLVM decode the identical full instruction partition. The name here is
descriptive; no source type, compiler identity or original signature is inferred.

## Domain and observation

Let `M=2^64`, `H=2^63`, `O` be entry RDI, and `T` the little-endian qword actually
read at address `O` by the first instruction. Let `B` be the common numeric load
bias of this image. The safe Rust API receives `(O,T,B)` as three `u64` values
and returns numeric `Registers { rax, rdx }`. Every possible triple is accepted;
there is no hidden restriction to small tags, positive pointers, zero load bias,
or nonwrapping output arithmetic. This total value projection does not assert
that every triple can occur in a running process.

For correspondence to a normally returning native call, the qword read must
be valid ordinary memory with the supplied value, code and return-control
memory must be valid under the common bias, and concurrent changes, MMIO,
faults, signals and instrumentation that alter the instruction behavior are
excluded. No alignment beyond what the original ordinary x86 load permits is
imposed. There is only one input data read and no data store. The snapshot can
therefore be supplied without a heap image or invented field-layout extent.
The Rust function does not check readability and never dereferences `O`, `O+8`
or either returned slot address. In particular, producing an address with LEA
does not require that address to be mapped or readable. Native pointer ABI,
RCX/flags, stack/RET effects, unwinding and exception behavior are outside the
claim. Rust's return ABI need not use the original physical registers.

## Exhaustive partition

The first instruction loads `T` into RCX. MOVABS sets RDX to `H+2`; CMP and JAE
perform an unsigned comparison. Thus every `T>=H+2` reaches `0x15d65dc` with
RDX still equal to `H+2`. XOR EAX,EAX clears all 64 bits of RAX before RET.
That entire upper interval therefore returns `(0,H+2)`, not `(0,T)` or `(0,0)`.

For the complement `T<H+2`, MOV copies `O` into RAX and `T` into RDX, then NEG
sets the signed overflow flag. To prove the overflow condition universally,
interpret the qword as the signed integer `s` in `[-H,H-1]`. When `s=-H`, its
mathematical negative `H` is outside that signed interval; for every other `s`,
`-s` lies in the interval. Hence NEG overflows exactly for the bit pattern
`T=H`. Zero is not an overflow case. JO at `0x15d65cb` therefore selects exactly
`T=H`, adds eight to RAX modulo `M`, and loads a RIP-relative address into RDX.
The LEA ends at linked VA `0x15d65ea` and has displacement `0x40a05be`; the sum
is `0x5676ba8`. Under the common image bias the numeric result is
`(B+0x5676ba8) mod M`. This path returns `((O+8) mod M,(B+0x5676ba8) mod M)`.

The remaining tags satisfy `T<H+2` and `T!=H`, so they are exactly `[0,H)` and
`{H+1}`. MOVABS overwrites the NEG result with `H+1` in RDX. Equality with RCX
makes `T=H+1` fall through to XOR EAX,EAX and RET, giving `(0,H+1)`.
All `T<H` take JNE to the final LEA. That LEA ends at `0x15d65f2`; adding its
signed displacement `0x40a062e` gives `0x5676c20`. RAX remains `O`, so this path
returns `(O,(B+0x5676c20) mod M)`.

These intervals are disjoint and exhaust all `2^64` tags. Every return path
assigns both claimed registers independently of their incoming values. Flags
from the object-address ADD have no subsequent consumer. Both ADD and LEA
retain low 64 bits; neither has a saturating or checked-result branch. The Rust
implementation directly expresses these intervals with unsigned comparisons
and `wrapping_add`. A zero RAX does not itself identify a tag path: `O=0` or
wrapping `O+8` may also yield zero on an address-producing path.

| Tag | Full RAX | Full RDX |
| --- | --- | --- |
| `0 <= T < H` | `O` | `(B+0x5676c20) mod M` |
| `T = H` | `(O+8) mod M` | `(B+0x5676ba8) mod M` |
| `T = H+1` | `0` | literal `H+1` |
| `H+2 <= T < M` | `0` | literal `H+2` |

## Code, caller and data closure

The body has no outgoing calls or branches outside this bound leaf. Complete
`.text` scans of 70,370,352 bytes find no E8 or E9 rel32 candidate naming its
entry. That result excludes such byte patterns, not indirect callers or all
possible xrefs. There is no concrete direct caller body to close. The complete
121,299-FDE/3-CIE inventory has exactly one overlapping FDE. The 13 `CC` bytes
after the body are padding, followed by another FDE at `0x15d6600..0x15d6603`;
that adjacent body is not reconstructed.

All 80,300 RELA records are scanned for code writers, entry naming and any
partial overlap with the three bound qwords. Each qword lies in `.data.rel.ro`,
is file-backed by the recorded PT_LOAD segment, has raw value zero, and has
exactly the following symbol-zero `R_X86_64_RELATIVE` writer:

| Slot address | RELA file offset | Addend |
| --- | --- | --- |
| `0x5676ba8` | `0x20f30` | `0x15d3e70` |
| `0x5676c20` | `0x21038` | `0x15d44e0` |
| `0x5678ee8` | `0x23810` | `0x15d65b0` |

The third slot names this entry; its actual consumer is unknown. For the first
two slots the loader would write `(B+addend) mod M` into the slot. **The leaf
returns `(B+slot_address) mod M`, not those contents.** LEA performs no data
read; neither pointee is called here. Those relocation records close the
numeric address context but do not make either pointee function a semantic
helper dependency. No descriptor, vtable or library type is inferred. The
prior static packet left pointees unidentified; this packet binds their actual
relocation addends while preserving its historical files.

## Independent expectations and finite qualification

`oracle.py` was frozen before the Rust directory existed. It ranks `T` among
three interval boundaries with `bisect_right`, then selects from a table of
closed-form pairs. Address arithmetic uses unbounded Python integers followed
by modulo `M`. It does not execute instructions, model flags or import the Rust
implementation. Its justification is the exhaustive partition above, rather
than similarity to native control flow. Source-independent expected pairs and
input bytes, their compressed bytes, the oracle file, and freeze time are
hashed. Regeneration checks every hash and coverage count.

The corpus includes all four classes, dense boundary bands, every tag bit and
neighbors, both output-address wrap thresholds, the object-plus-eight wrap
threshold, each object/bias bit, and deterministic synthetic random triples.
The input-only Rust client receives only IDs and `(O,T,B)` triples on stdin;
expected pairs remain in the Python comparator. Every comparison includes all
64 bits of both registers, with no normalization masks. Four native builds
(opt0/opt3, each twice), reproducible artifacts and observable compiled mutants
qualify the new implementation against that independent relation. They do not
constitute captured-target differential execution or byte identity. Finite
cases support implementation checking; the universal target relation rests on
the explicit instruction/interval proof, not test-count extrapolation.
