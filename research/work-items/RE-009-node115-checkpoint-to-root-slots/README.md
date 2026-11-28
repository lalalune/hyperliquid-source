# RE-009 node #115 checkpoint keys and state-root slots

A raw ABCI hash tree labels its top-level entries by integer slot. This packet identifies the corresponding checkpoint field for every slot, so a mismatch can be attributed to a field before tracing its nested hash inputs.

Target is Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source baseline is `2da45cb0a761cff6b478e40421699857d87a94df`. All addresses are ELF virtual addresses.

The [existing field map](../RE-008-abci-state-fields-115/README.md) named the slots from the key pool, checked selected decoder comparisons and explicitly left most identities as an inference from order. Here, both named MessagePack writers supply independently pinned key-pointer, key-length and state-argument bytes for each row. The [capture table](../RE-008-abci-hash-slots-115/README.md) independently selects those same input addresses in compact layout. The [latest source matching wave](../RE-009-node115-storage-abci-logic-wave3-byte-matches/README.md) includes serializer wrappers, and the [snapshot handoff](../RE-017-state-snapshot-handoff-115/README.md) reaches the compact writer from the local serializer. The contribution here is the per-field writer-to-root join.

- Compact writer `0x5480950` and expanded writer `0x5481900` advertise 59 Exchange fields. They emit the same key names in the selected order and dispatch the same value helpers at the recorded call sites. The expanded addresses move by `0xb70` for captured inputs at and above compact offset `0x7c0`. The `ctx` base and Locus inputs `scl` and `blp` are below that threshold.
- Root capture `0x4e34ce0` builds 74 pointers. Its job setup `0x54423c0` uses the grouped Locus descriptor for slot 0. For slots 1 through 58 it selects pointer index `slot + 15`. The root slot input and the compact checkpoint helper's first state offset agree for all 58 fields. For fields assembled from multiple loads, the packet records the secondary operands too.
- Both checkpoint writers give Locus a 17-field container. Its first 16 source locations match the 16 pointers in the grouped root descriptor, from `ctx` through `msc`. The last named field is `aux`. Its helper `0x5673860` receives no state value and requests a zero-element array. No input pointer for `aux` is present in the root descriptor.
- Each [record](records.json) provides the key, index, selected writer operands and value call for both layouts. Exchange indices are root slots. Locus indices enumerate nested checkpoint keys and the associated group pointers. They do not name child digest positions after reduction.

Run the static check from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-checkpoint-to-root-slots/verify.py
```

The verifier authenticates the ELF and checks the original instruction spans within FDEs, the name bytes, both writer paths, and the complete compact pointer and descriptor tables. The controls perturb the Bridge offset, apply the expanded layout shift to a shared low offset, and insert a fabricated pointer for the Locus trailer. The [offline run](offline-log.txt) records the results. To inspect an original span, use LLVM objdump 23.1.4 with `-d --x86-asm-syntax=intel --start-address=START --stop-address=END artifacts/node/115/hl-node` and a recorded instruction address.

The field join assumes the selected successful serializer and capture paths. It identifies the root input owner for each field. The serializer's complete wire bytes, root-child encoding, reference-root authority and replay agreement are separate questions. No captured code was executed.
