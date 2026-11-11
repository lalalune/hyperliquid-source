# RE-004: consumed signed quantities and conditional positive accumulation

The merged portfolio packet #2154 leaves `0x3f10c10` opaque, explicitly asking
how its two resulting collections are formed. This packet resolves the private
body's sign split, arithmetic domains, call order, descriptor writes and normal
input disposal. Entry creation, duplicate keys and the tree iterator remain
opaque; no complete collection transform or financial algorithm is claimed.

- Component: assets, with the portfolio caller credited as exchange context.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Full FDE: `0x3f10c10..0x3f10ecf`, 703 bytes, including cleanup.
- Own source Location: `0x6487460` binds `l1/src/qtys/mod.rs:835:1`;
  actual LEA at `0x3f10e0c`. Addresses are ELF virtual coordinates; records
  additionally retain file offsets, full body hash, FDE/CIE/LSDA and relocations.

## Observed flow

Incoming RDI is retained as the output pointer. Incoming RSI is the consumed
collection descriptor; incoming RDX points to a second, mutable descriptor.
The local first result starts as four raw words `(0,8,0,0)` at frame `+0x68`.
This is an observed representation, not a recovered Rust container declaration.

Negating the consumed descriptor's first word selects the alternate iterator
path only when the raw word is `0x8000000000000000`. That path prepares state
for opaque iterator `0x37c3750`. The other path computes up to two spans of
16-byte records and advances by 16, swapping the second span into the first
when exhausted. Valid descriptor bounds and storage are premises. A returned
record supplies a key qword and signed value qword. MOV of the key preserves
the flags from TEST of the value, so JS separates negative from positive.

Zero values skip the per-entry helper calls. Negative values are negated,
except signed MIN maps to signed MAX (`0x7fffffffffffffff`). The resulting
magnitude, unchanged key, and first local result are passed to `0x3cde300`.
This path does not multiply by 100. Whether this helper inserts, overwrites,
aggregates or rejects duplicate keys is not recovered.

Positive values use unsigned MUL by 100. A nonzero high half takes JO back to
iteration without calling the entry helpers. Thus the largest admitted input
for this stage is `floor(u64::MAX / 100) = 184467440737095516`. Only signed
positive inputs reach this instruction; high-bit-set raw values were already
handled by the negative branch. A successful multiply retains its product in
R14 and calls `0x3cd0da0`, then `0x3f14f20`, to obtain a mutable entry pointer.
Initial values, allocation, lookup and source-level entry semantics are unknown.

The body saves that pointer in RBX and its old qword in R12. ADD of old plus
the product stores directly if there is no unsigned carry. On carry, the body
calls slot `0x64e4ea8` with EDI zero and the source Location pointer. **If this
helper returns normally with ABI preservation**, it recomputes from the saved
R12/R14 operands and stores `u64::MAX` on carry through the saved RBX pointer.
It does not reload the old entry after the diagnostic. No diagnostic purity,
normal return guarantee, atomicity or rollback is inferred.

On normal iteration completion, the first local descriptor is copied to output
bytes `0..32`; the supplied second descriptor is then shallow-copied to output
bytes `32..64`. These writes precede disposal of the consumed input. Its tag is
re-read: raw MIN selects `0x39340c0` with descriptor `+8`; a nonzero ordinary
capacity requests deallocation with size `capacity << 4` through `0x64df4a0`.
An unwind tail is exported but not given invented Rust ownership semantics.
Valid disjoint storage, ordinary helpers and ABI preservation are premises;
aliasing, lifetime guarantees, map order, units and full financial meaning
remain unresolved. The caller mapping comes from the preserved #2154 packet,
not a new exhaustive incoming-call census.

## Reproduction and evidence

From the repository root, with Python and GNU binutils/Capstone available:

```sh
python3 research/work-items/RE-004-quantity-signed-split-115/collect.py --output work/quantity-split-replay --check
python3 research/work-items/RE-004-quantity-signed-split-115/analysis.py
python3 -m unittest discover -s tests -p test_quantity_signed_split115.py -v
```

The collector authenticates the whole ELF before tools or output, checks its
complete Python/readelf unwind extents and call-slot/Location relocations, and
compares full GNU and Capstone instruction partitions. Actual direct branches
must land on decoded instruction starts within this FDE. The temporary copy is
read-only and never executed. Tool versions and exact validation commands are
retained beside raw exports. Execution platform: macOS arm64, Python 3.12.14,
Capstone 5.0.6 and GNU binutils 2.47.20260726, not the original Linux compiler.

Twenty-six selected real-byte structural corruptions are rejected below the
whole-image digest guard. They authenticate local obligations, not mutated
runtime results. Fifty local scalar illustrations cover signed MIN, zero,
positive scaling boundaries and unsigned addition carries. Their supplied old
values are mathematical arguments, not fabricated returns from an entry helper;
they are not composed into a trace or used as a native/Rust differential oracle.

No Rust implementation, captured code execution, instruction interpreter,
complete transform, native output comparison, compiled identity or completion
gate is submitted. New code is MIT, with collector scaffolding adapted from
the project-authored limiter packet. Original #2154 evidence, tools, captures,
imports and pins remain unchanged. All 92 gates and registered windows remain
unchanged. Next close the entry creation/duplicate-key contract before writing
a faithful collection-level reconstruction.

Catalogue generation/check alone uses the already-submitted #2655 snapshot-read
fix for the measured repeated-read blocker. The exact baseline helper is restored
before actual reproduce and final audit. Local validation is qualified by that
overlay; new-head full repository tests and hosted CI remain pending.

Fresh collection passed in 33.704 seconds: the complete 703-byte / 182-instruction FDE agrees across both decoders. Twenty-six structural controls passed in 5.685 seconds. Seven focused tests passed in 6.998 seconds. These runs perform static parsing and local arithmetic only.

Integration passed in 335.734 seconds: five generated files byte-exact, 12 packet-integrity tests, doctor, verify, catalogue/check and actual reproduce. The baseline helper was restored before reproduce. Full hosted CI remains pending.

Final audit passed in 3.127 seconds: 25 manifest entries at audit time, all five regenerated files, original packet/tools/imports/captures preservation and three scope tests. Archiving this receipt adds one manifest entry.
