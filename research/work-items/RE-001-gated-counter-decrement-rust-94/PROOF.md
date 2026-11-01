# Five-pair gate with a closed counter-decrement tail

## Bound bytes and scope

This argument concerns node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
ELF VAs `[0x50a90a0,0x50a910d)` and its actual called body
`[0x5334d60,0x5334d65)`. Both are complete, unique-overlap FDE extents
in the decoded inventory of 121,299 FDEs and three CIEs. The shared CIE and
both complete raw FDE records are bound independently of instruction bytes.
GNU and LLVM agree on every byte and instruction boundary: 28 instructions
in the 109-byte primary and two in the five-byte helper. The three `int3`
bytes after the primary are padding, outside its FDE. The helper ends at its
ordinary `ret`; neighboring cold code is outside this claim.

The only outgoing call is the complete `e8 60 bc 28 00` at `0x50a90fb`,
whose signed displacement resolves to `0x5334d60`. The helper is exactly
`f3 0f 1e fa c3` (`endbr64; ret`), without an argument read, data access,
conditional edge, register assignment, or further dependency. All other
primary control transfers stay within its bound body or return. There are
no RIP-relative data accesses. Scanning every `.text` byte finds zero E8
candidates targeting the primary and 116 targeting the helper. Only the
primary's internal helper call is asserted as an instruction boundary here;
the other candidates and their callers are outside this API's scope. The
absence of E8 candidates is not a proof of no indirect references. All
80,300 RELA records are checked: none names either entry as its addend and
none writes over either body. There is no inferred global/table dependency.

## Exact data and return relation

Let `Q(a)` be an ordinary little-endian qword load at abstract address `a`,
`D(a)` a little-endian dword load, and `+` on addresses mean addition modulo
`2^64`. Let `O` be entry RDI. The body reads `P = Q(O)` into RAX. In this order
it compares the qwords at the following offsets from `P`:

| Gate | First offset | Second offset | Branch after comparison |
| --- | ---: | ---: | --- |
| 1 | 8 | 16 | equal continues; unequal returns at `0x50a90b1` |
| 2 | 56 | 64 | unequal returns at `0x50a90b1` |
| 3 | 104 | 112 | unequal returns at `0x50a90b1` |
| 4 | 128 | 136 | unequal returns at `0x50a90b1` |
| 5 | 176 | 184 | unequal returns at `0x50a90b1` |

At each gate the first word is loaded before the second comparison read.
If any pair differs, there have been no data stores and RAX still equals
`P`. Later pairs and all owner/counter fields are unused on that path.
Equality is equality of all 64 bits, not order, signedness or low halves.
The alignment `nop` makes no operand memory access. No range/container,
reference-count, release, destructor or text-encoding meaning is asserted.

When all pairs match, the body saves RBX on the control stack, reads
`A = Q(O+8)` into RAX, saves `O` in RBX, and forms `A+1792` in RDI with LEA.
LEA performs no load. The bound helper does not read its argument. After
its ordinary return the body reloads `A = Q(O+8)`, then performs exactly
one data store, the four bytes encoding

`D(A+5276) := (D(A+5276) - 1) mod 2^32`.

It restores RBX and returns. The `subl` memory destination does not change
RAX; hence full raw RAX equals the owner value sampled before the store.
The upper 32 bits of this return value are not cleared. A zero counter
becomes `0xffffffff`; `0x80000000` becomes `0x7fffffff`. Bytes outside the
four-byte counter are unchanged. Other scratch registers and flags are not
claimed outputs.

## Why the safe image API preserves the admitted relation

`decrement_if_equal(image, base, outer)` uses a single mutable byte slice
whose abstract interval is `[base, base+len(image))`. Its entire interval
must lie within `[0,2^64)`, allowing the exclusive endpoint `2^64`. Every
used qword/dword must fit wholly in that image. Each effective field address
is calculated modulo `2^64` before the field's mapped range is checked.
Thus a pointer value itself may be outside the image, even near `u64::MAX`,
while a used positive-offset field wraps into it. There is no mapping
requirement for `A`, for `A+1792`, or for an unvisited gate. The abstraction
does not promise that every numeric image is an available canonical process
mapping; its target correspondence is conditional on valid ordinary native
accesses for that same numeric relation.

The target's control stack, saved RBX slot, call return slot, code and unwind
machinery are valid and disjoint from this data image and all data fields
used by the path. We exclude faults and fault timing, MMIO/volatile effects,
concurrent/asynchronous changes, code modification, stack/data aliases,
nonordinary returns and pointer-ABI/calling-convention compatibility. This
is essential: if saving RBX or a call return address could overwrite the
owner field, eliminating the helper and the repeated owner load would not
be justified. In the stated domain neither those control actions nor the
helper changes data, so both owner loads observe the same entry bytes.

All data fields may otherwise alias arbitrarily, including partial,
unaligned overlaps. Until the final decrement every access is a read.
Therefore the five comparisons and the owner read observe the entry image.
The counter read also observes that entry image, even if its bytes overlap
outer/inner pointers or any pair. The sole store happens after all reads.
Rust's saved `owner` preserves the original raw RAX if the store overwrites
part or all of `Q(O+8)`; reloading the pointer afterwards would be wrong.
No snapshot of an entire struct, disjoint-data assumption, or alignment
assumption is required.

The API first validates the image and then each actually needed range in
read order. A mismatch returns immediately. On the all-equal path it
validates the counter before performing the only store. Consequently
`Err(Unavailable)` always leaves the image unchanged. This refusal is an
explicit API extension for missing ranges, not a claim about native fault
recovery or partial effects. On every admitted path, qword equality,
modular addresses, the four output bytes and full raw RAX match the relation
above. There is no arbitrary pointer dereference or unsafe Rust.

## Independent frozen oracle and finite qualification

Before the Rust source directory existed, `oracle.py --freeze` generated
8,472 exact input/output rows, recorded its own hash, and froze both raw
TSV hashes and deterministic compressed files. The expected relation uses
byte-string equality for each required pair, positional base-256 sums for
pointer/counter values, and a mathematical modulo-`256^4` residue for the
four changed bytes. It contains no x86 decoder, flags, opcode dispatch,
register-state interpreter or captured execution. The Rust implementation
instead uses safe qword loads, integer equality and a wrapping u32 subtract.
Both independently implement the proved relation; the finite comparison
supports that proof, and is not native-target differential execution.

The fixtures exercise all 32 gate-match patterns with seven distinct
low/high-bit differences and nine counter edges; every counter offset
through the image and all earlier fields; all buffer cutoffs across the
read prefix; outer/inner partial aliases; high base values; wrapped effective
addresses; and deterministic randomized entry images. Initialization
collisions are resolved before oracle evaluation. The final entry bytes,
not the intended fixture labels, define the case. Coverage records distinguish
every first-mismatch position, actual decrements, image refusal and missing
required-access refusal.

The client receives only input TSV through stdin and emits the full return
status/value plus exact changes over every image byte. It has no expected
output file path or expected values. The comparator checks row IDs, order,
count, status, the entire 64-bit return and every image-byte change, without
normalization masks. Optimization levels 0 and 3 are each built/run twice;
artifact hash equality is required within each level. Compiled source
mutants must finish normally and produce an actual observable mismatch.
Static corruptions bypass only the outer digest gate when testing internal
body/FDE/call/relocation checks. Exact stdout streams, commands, witnesses,
hashes and limits accompany the native result.
