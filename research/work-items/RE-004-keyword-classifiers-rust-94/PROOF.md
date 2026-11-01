# Three keyword classifiers: complete value and memory relation

Target node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This is one reconstruction of three existing foundation classifier packets,
with their common two-byte output contract. It introduces no additional
members inferred from a matching instruction shape.

| Classifier | Complete leaf | Bytes | Tag 0 | Tag 1 |
|---|---|---:|---|---|
| UntilRequiredMatches | `[0x1437b90,0x1437be4)` | 84 | `until` | `required_matches` |
| VipMm | `[0x1e6d560,0x1e6d5a6)` | 70 | `vip` | `mm` |
| InputGasLimit | `[0x25903d0,0x2590426)` | 86 | `input` | `gas_limit` |

Every other input has tag 2. These are byte spellings from the target;
no application meaning, source type or library identity is inferred from
them. The output marker 9 and tags 0/1/2 are numeric observations.

## Static closure

`verify_static.py` checks the entire 91,774,280-byte target digest before
parsing. Each leaf and caller has one exact overlapping FDE, whose full
raw FDE/CIE records are retained. All three leaf CIEs are `zR`, and none
has an LSDA. The previous and next FDE extents separately establish
leading/trailing padding: 10/12 bytes for until, 15/10 for vip and 13/10
for gas, all INT3. The bodies contain 28, 25 and 29 instructions,
including their three returns each. Every branch target is a local
instruction boundary. There are no helper calls or loops.

The until classifier's one memory comparand is `required_matches` at
ELF VA `0x204b10`, exactly 16 readonly `.rodata` bytes. The actual
PCMPEQB instruction at `0x1437bbe` has bytes `66 0f 74 05 4a cf dc fe`:
its signed displacement is −0x12330b6, and next PC `0x1437bc6` plus that
displacement equals `0x204b10`. The old packet's prose instruction table
prints the target address as a displacement; its retained raw bytes and
checker already use the correct displacement. This packet binds the
actual operand rather than repeating that prose notation. Other
comparands occur entirely as immediate bits in the pinned bodies.

The `.text` E8/E9 candidate scans find one direct call and no direct jump
to each leaf. Each call is confirmed by three decoders from its actual
complete caller FDE start:

| Leaf | Call | Complete caller | Bytes | Instructions |
|---|---|---|---:|---:|
| until | `0x13ba4c6` | `[0x13b9560,0x13baf1a)` | 6,586 | 1,410 |
| vip | `0x171c697` | `[0x171b780,0x171d0fd)` | 6,525 | 1,445 |
| gas | `0x18fa9ee` | `[0x18f9940,0x18fb1d2)` | 6,290 | 1,353 |

The vip predecessor calls its caller 7,037 bytes; the actual endpoint
difference is 6,525 bytes. This packet records the complete actual extent.
The gas predecessor preserves a flawed short export that begins inside
an instruction, together with a corrected export. Here both disassemblers
start from the full caller FDE and agree with Capstone at every boundary.
Caller bytes establish call sites, not the full callers' behavior.

All 80,300 RELA records are checked. None names these entries as an
addend, and none writes into the six retained code intervals or the
16-byte constant. Runtime comparand bytes must remain those immutable
captured bytes. Indirect entry paths and computed addresses remain
unenumerated. The local proof does not infer a complete xref census or
the absence of all possible indirect callers.

## All-length and all-byte proof

Let incoming RDI=O, RSI=S and RDX=L, with all 64 bits significant. Each
leaf starts `mov rdi,rax` and never subsequently writes RAX. Thus RAX on
every normal return is exactly O, including O=0 or high-bit-set values.
It is not the tag, a Boolean or the number of bytes written.

Each leaf compares L against its two distinct exact lengths. There is
no length truncation, signed comparison, or prefix acceptance. If neither
length matches, it reaches tag 2 without reading input memory. If a length
does match, the selected path reads every selected input byte before any
output store. Its comparisons have the following complete meanings:

- `until` and `input`: a four-byte little-endian XOR, followed by a
  zero-extended final byte XOR, combined by OR32. The OR is zero iff
  both terms are zero, exactly the five-byte literal equality.
- `vip`: a zero-extended u16 XOR with `0x6976` and a zero-extended byte
  XOR with `0x70`, joined by OR16. Each difference already occupies at
  most 16 bits, so this narrowing discards no mismatch bit.
- `mm`: the entire little-endian u16 equals `0x6d6d`.
- `gas_limit`: a full u64 XOR with `0x696d696c5f736167`, and a final
  byte, zero-extended through EDX then XORed with `0x74`. OR64 is zero
  precisely when all nine bytes match.
- `required_matches`: MOVDQU loads all sixteen bytes. PCMPEQB produces
  0xff for equal byte lanes and 0x00 otherwise. PMOVMSKB extracts their
  sixteen high bits into zero-extended ECX. Equality to 0xffff holds
  iff all sixteen input bytes equal the retained constant.

Those cases exhaust every branch. Rust selects the corresponding literal
by the full u64 length and compares the complete slice. It checks the
tag-0 length before tag-1, whereas the captured leaves check tag-1 first;
the distinct lengths make the predicates disjoint, and length checks
have no memory effects. Therefore the alternative comparison order
changes neither reached input range nor result.

## Output, aliases and admission

For every tag T, the target stores T at O+1, then 9 at O, then returns O.
The two destination bytes are distinct. All input loads precede both
stores. Therefore arbitrary overlap between the admitted input interval
and those destination bytes preserves the same *initial* input
classification. No snapshot of unrelated memory is needed. The Rust
match evaluates its slice comparison before storing the tag and marker
in the same order. In particular, it must not initialize output[0]=9
before reading input when O aliases S.

The new API uses one mutable byte image at numeric base B, where byte j
represents address B+j. The image itself is nonwrapping, with a final
byte at 2^64−1 allowed. The selected input must be a contiguous readable
range of its exact literal length in that image; O must identify a
contiguous writable two-byte range. A nonmatching length has no input
range requirement. The full u64 values S, O and L are preserved; no
conversion truncates an address before mapping it. `checked_sub`,
fallible usize conversion, checked span addition and the slice bound
prove each admitted range is representable and in bounds. Consequently
the selected field offsets also cannot overflow on admitted ranges.

Global `ImageRange` refusal precedes `Input` refusal (only for a selected
length), then `Output` refusal. All span checks precede every write;
errors leave the whole image unchanged. This is a new atomic safety
policy. The captured stores could partially complete before a later
fault, and a runtime may provide discontiguous or wrapping address
layouts that this single-image API does not represent. Such faults or
unrepresented layouts are outside the correspondence domain.

There is no loop or arithmetic whose value can overflow after admission;
the only output offset is bounded by the checked two-byte span. All
ordinary input bits, every u64 length and all byte alignments are covered
by the case proof. The projection assumes stable initialized ordinary
memory, valid original accesses, unchanged readonly comparand data and
valid instruction/control storage. Code/control-stack/constant-write
aliases, concurrent mutation, MMIO, flags, XMM state, other clobbered
registers and intermediate external observations are excluded. The API
projects final memory and numeric RAX, not the System V calling convention.

## Independent expectations

Before the Rust directory existed, `oracle.py` froze complete inputs,
outputs, its own hash and the static-record hash. It turns each literal
into an unbounded base-256 polynomial and performs a dictionary lookup
using `(classifier, full length, complete integer)`; the Rust uses a
selected slice comparison. The oracle constructs final output bytes
from an immutable initial image. No target execution, instruction
interpreter or Rust output supplies expected values.

The fixed corpus has 12,443 rows: 11,359 normal results, nine ImageRange,
615 Input and 460 Output refusals. It covers all three tags for every
classifier; all 10,240 single-position byte substitutions across all six
keywords before shared-baseline deduplication; every input/output overlap
displacement for eight source alignments; exact last-byte admission;
high-bit lengths with matching low 32 bits; unmapped unused input;
numeric-zero/high outputs; and digest-derived images. Finite samples
exercise these boundaries; the preceding proof covers all admitted
inputs. Native host execution validates the new component, not target
compiled-byte identity or whole-node equivalence.
