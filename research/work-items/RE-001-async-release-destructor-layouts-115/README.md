# RE-001: flag-selected async release destructor layouts

Question: why does the flag in `RE-001-async-gate-release-52790-115` select
`0x5ce86d0` versus `0x5ce8da0`? The TCP shared-drop packet also stops at these
same callbacks. This packet recovers their normal-return cleanup sequences;
it does not duplicate either caller's gate or claim source-level type names.

Target: node #115 Linux x86-64, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
Actual FDEs: `0x5ce86d0..0x5ce8855` (389 bytes / 95 instructions) and
`0x5ce8da0..0x5ce90c1` (801 bytes / 200 instructions). All bytes, FDE/CIE
records, calls, direct branches and relocated tail jumps are retained.

## Observed ownership operations

Both callbacks first load `B = [RDI]`. The caller passes the address of its
counter-pointer field, so the callback dereferences that field once before
accessing the allocation. Offsets below are relative to B. Helper names such
as drop/deallocate are inferred from argument patterns; the offsets, tests,
atomic instructions and call targets are observations.

| Stage | `0x5ce86d0` | `0x5ce8da0` |
| --- | --- | --- |
| Initial sentinel-gated buffer | count +0x2d8, pointer +0x2e0 | count +0x10, pointer +0x18 |
| 24-byte element storage | count +0x178, pointer +0x170 | count +0xb0, pointer +0xa8 |
| First nested drop | helper `0x5ce7e50` on B+0x100 | helper `0x5ce7e50` on B+0x28, after additional collections below |
| Second nested drop | helper `0x5ce7f40` on B+0x240 | helper `0x5ce7f40` on B+0x160 |
| Required reference | pointer field +0x238 | pointer field +0x1f8 |
| Optional references | pointer fields +0x200, +0x210 | pointer fields +0x210, +0x220 |
| Outer weak-count decrement | locked qword B+8 | locked qword B+8 |
| Final deallocation arguments | RDI=B, RSI=0x300, EDX=7 | RDI=B, RSI=0x230, EDX=0 |

The initial gate is NEG followed by JO and JAE. It skips the buffer operation
for count 0 or `0x8000000000000000`; all other bit patterns take the call.
It is not a signed-positive test: `0xffffffffffffffff` also takes the call.
The call receives EDX=0. For the 24-byte storage, nonzero count is scaled by
`shl 3; lea x+2*x`, with 64-bit wrapping arithmetic, before the same slot call.

Each required reference loads its pointer, performs `lock dec qword [pointer]`
and invokes the callback only when the result is zero. Optional references
first test the pointer against zero. The zero-count callback receives the
address of the pointer field, not the pointer value. The required-field call
uses relocated slot `0x64e17e0`; optional fields use `0x64e17c8`.

Only after nested cleanup does the outer code compare B to -1 and skip the
weak-count decrement for that sentinel. This late test does not make B=-1 a
valid entry input: earlier field reads already dereferenced B. On ordinary
non-sentinel B, the final deallocation is a tail jump only if `lock dec [B+8]`
reaches zero, through slot `0x64df4a0` in both bodies.

## Additional collections in the second layout

The second callback has these extra normal-return operations, in order:

1. If count B+0xa0 is nonzero, take the array at B+0x98 and walk count pairs
   with 16-byte stride. Decrement the first reference at entry+0 and then
   the second at entry+8, calling their respective zero-result callbacks.
   R13 loads slot `0x64e17b0` (RELATIVE addend `0x5ce8880`); RBP loads
   `0x64e17a8` (addend `0x5ce8620`). The stored slot bytes and relocations
   are exported separately. Afterwards call the storage-release slot with
   length count*16 and EDX=0.
2. Release the 24-byte storage in the table, then nonzero B+0x110 elements
   of storage at B+0x118 with size count*8, EDX=0.
3. Walk pointers at B+0x150 for length B+0x158, in ascending index order,
   calling `0x5cfcae0` for each. Release that storage only when capacity
   B+0x148 is nonzero, with capacity*8 and EDX=0.
4. Call `0x5ce7e50` on B+0x28. Release storage at B+0xe0 when count
   B+0xe8 is nonzero, with size count*128 and EDX=7. Then continue with
   B+0x160, required/optional references and outer weak release in the table.

Thus the flag selects distinct allocation layouts and cleanup sequences; it
does not merely select two names for identical drops. Concrete Rust types,
allocator identity and the upstream reason for choosing either layout remain
unknown. Counters are treated as valid owned references; malformed zero counts
wrap rather than satisfy the callback condition.

## Reproduce, controls and limits

```sh
python3 research/work-items/RE-001-async-release-destructor-layouts-115/verify.py
```

Dependencies: Python, Capstone 5.0.6 and pyelftools 0.32. `--write` regenerates
the body/relocation exports and listing. Full-image SHA verification precedes
extraction. Fourteen operative instruction mutations must fail with that SHA
guard disabled. Complete decoding, FDE bounds, instruction pins, internal
direct branches and unique GOT relocations are checked. Independent scalar
models cover seven sentinel vectors, required/optional zero-result cases and
forward pair order for lengths 0..64 (93 cases plus sentinel vectors).

The exports retain cleanup-pad instructions, but LSDA call-site selection is
not decoded and no unwind path is claimed complete. R13/RBP targets are linked
through observed loads; their internal semantics remain opaque. Valid storage,
nonaliasing, stable collection metadata and normally returning helpers are
assumptions. Atomic decrement syntax does not prove a concurrency protocol.
No target instructions were executed; no component gate changes.

Next question: recover the pair-loop callbacks `0x5ce8880` and `0x5ce8620`
and the pointer element callback `0x5cfcae0`, including which resources each owns.
