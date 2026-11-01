# Three indexed-OR functions over their complete reachable read windows

Target node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The family comprises complete 21-byte functions at `0x15625e0`,
`0x1566100` and `0x1568bb0`. Each has five instructions and eleven
separate INT3 padding bytes. These three explicitly listed members form
one contribution; no claim is made that all similar code has been found.

## Complete code, data and reference closure

The verifier authenticates the full 91,774,280-byte target before parsing.
Every member has exactly one overlapping FDE describing its complete
21-byte interval. Actual FDE/CIE records and linkage are retained. GNU,
LLVM and Capstone agree on all 63 bytes and fifteen instruction starts.
Each function ends in RET and has no outgoing call or branch.

The actual signed RIP displacement of each LEA selects its table base;
the actual OR operand encodes its field displacement:

| Entry | Table base T | Field displacement d | Union word offset |
|---|---|---|---:|
| `0x15625e0` | `0x2516ec` | `0x1a0` | 0 |
| `0x1566100` | `0x25178c` | `0xa8` | 40 |
| `0x1568bb0` | `0x251894` | `0x1a0` | 106 |

MOVZBL SIL,EAX permits every index in 0..255. The following dword load
therefore reaches exactly `[T,T+1024)`. Each complete window is file-backed
readonly `.rodata`. The three windows overlap; their union is the 1,448
bytes `[0x2516ec,0x251c94)`, or 362 little-endian u32 words. The validator
binds every window byte, its mapping and digest, and proves that its bytes
equal the corresponding union slice. The Rust source stores this measured
union once. This is a reachable read window, not a recovered logical table
extent, array allocation or source-level ownership claim.

The first member's first twenty words are the previously characterized
single-bit permutation. Index 20 instead reads 0x01314a6c. Later words
include arbitrary multi-bit values and all ones; no flag meaning is
assigned to them. All three byte-index domains are covered by actual
bytes, without restricting the argument to an invented 0..20 range or
claiming that every index is reached by a real caller.

Each member has four naming symbol-zero RELATIVE records, for twelve
total. The exact records, pre-relocation zero qwords and `.data.rel.ro`
slot mappings are bound. Every one of the 80,300 RELA records is scanned:
none overlaps code, padding or any read-window byte, and each entry slot
has precisely its expected complete eight-byte writer. Other-addend and
partial-overlap writers are rejected as well. Full `.text` E8/E9 pattern
scans find no direct candidates for the three entries. Short/indirect
transfers, slot consumers and other pointer paths remain outside that
census. Relocated entry slots are reference context, not data read by
these functions.

## Full numeric and field relation

Let I be the complete incoming RSI bits, O incoming RDI, B the common
load bias, W=2^64, and F the entry u32 value of the writable field. For
the selected member, let T,d be the row above and V_j the measured
little-endian u32 at linked address T+4*j. Define

```
j = I mod 256
V = V_j
C = (B + T) mod W
A = (O + d) mod W
```

MOVZBL reads SIL, so upper 56 bits of I do not affect j. Its EAX result
is zero-extended; scaling by four yields an offset between 0 and 1020.
LEA computes RCX=C without reading table bytes. The indexed MOV reads
exactly the four bytes for V, replacing EAX and clearing full RAX's high
32 bits. The OR then reads and writes the four-byte field at A, producing
F OR V. It changes flags but does not alter EAX or RCX. RET preserves
both. The complete data/result relation is therefore:

```
field at A := F OR V, as four little-endian bytes
RAX := zero_extend32(V)
RCX := C
```

RDI and RSI are unchanged; the written data registers are RAX and RCX.
RET's RSP/control transition is excluded from this numeric projection.
The returned RAX is the selected word, not the updated field. For member
zero, I=0 and F=2, the field becomes 3 while RAX is 1. A selected all-ones
word gives RAX=0x00000000ffffffff, not a sign extension. RCX remains the
table base, not the selected element address. The reported store address
A is an address observation, not another original return register.

RIP-relative address formation under a common load bias gives C because
the linked next-RIP plus the signed displacement equals T. Reduction
modulo W commutes with adding B. The positive field displacements similarly
give A for arbitrary O bits. Neither numeric output address is itself
dereferenced by the safe projection.

## Source correspondence and domain

`apply(family, index_bits, load_bias, object, &mut u32)` is a numeric
field-state API. Its enum selects one of the three entries; it is not a
recovered native argument. The supplied u32 represents precisely the
four-byte field at A, and its host address is unrelated to A. The API
accepts every u64 I/B/O and every initial u32 field value. It returns
RAX, RCX and A and replaces the field value.

Casting I to u8 gives I mod 256. Adding the member word offset reaches
0..255, 40..295 or 106..361, always inside the 362-word array. These
indices cannot overflow or panic. The selected u32 exactly equals V
because every union word was measured with little-endian decoding.
The source OR writes F OR V, and widening V to u64 zero-extends it.
Explicit wrapping additions produce C and A. No other state or dependency
is needed. These arguments establish the value relation for all three
members and every admitted numeric/field combination.

Original-memory correspondence additionally requires unchanged code and
the bound stable readonly windows under the stated common load bias,
a complete ordinary readable/writable field at A, and valid return control.
The field must not alias the readonly tables, executed code or control
storage. Numeric biases/addresses accepted by the projection are not
claims that every corresponding OS process mapping exists. Original ABI,
fault timing, MMIO, concurrent mutation, flags, physical access traces and
atomicity are outside the claim. This scalar API models the little-endian
field value, not the native pointer layout or a recovered struct.

## Independent expectations

Before Rust existed, the oracle froze its source, full static facts and
98,880 input/expected records. It builds selected words by positional
base-256 sums and computes the updated field as a sum of base-two digits
present in either operand. Rust instead reads a u32 constant and uses OR.
The oracle uses unbounded addition/remainder for addresses; Rust uses
explicit machine-width wrapping. No instruction interpreter or captured
code supplies expected results.

Every member and every byte index is exercised with all 32 old-field bit
bases and complements, mixed bit patterns and extremes. Further rows vary
each ignored index bit, full-width addresses, exact wrap boundaries and
deterministic additional values. There are 46,581 cases with high index
bits, 23,170 selections with the mask's high bit set, 83,138 selections
of multi-bit words, 28,725 wrapped table bases and 28,638 wrapped store
addresses. These are finite qualifications, not an enumeration of all
numeric inputs or a statement about runtime reachability.

No source/function/type identity, meaning of any field/bit, original
compiled-byte match, whole-node equivalence or component gate is claimed.
