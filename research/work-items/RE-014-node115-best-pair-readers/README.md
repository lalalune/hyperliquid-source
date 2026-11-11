# RE-014: #115 best-pair readers

This packet studies the pair readers called by the mid-market order builders, an explicit next question of [the previous builder packet](../RE-014-mid-market-order-builder-115/README.md). It resolves selected raw data flow, not the full book representation or source-level type. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are virtual addresses. All evidence is static; target instructions are neither executed nor emulated.

## Observations

The FDEs at `0x50eaf10..0x50eb19a` and `0x22f6370..0x22f65fa` each contain 0x28a bytes. Their bytes are identical after normalizing only the four-byte displacements of the calls at offsets 0x169 and 0x25b. The former calls `0x5138500`, the latter `0x2389af0`, twice each. This byte equality does **not** establish that the different callees have identical behavior.

Each reader receives an output pointer in `rdi` and an input pointer in `rsi`. It reads two input substructures based at input offsets `+0` and `+0x20`. In each, the first word distinguishes the value `0x8000000000000000` (the first `neg` sets overflow only for that value); other words are read at offsets `+8`, `+0x10` and `+0x18`. In the non-sentinel arm, the address arithmetic multiplies indices by `0x88`, and one direct non-empty path advances a pointer by `0x88`. In the sentinel arm the reader can delegate iteration to its helper. This is a description of observed offsets and control flow, not a claim that the substructures are a specific Rust container.

On a path yielding a non-null first record pointer, the first word of that record is loaded. `neg` followed by `cmovs` yields its unsigned magnitude as a 64-bit pattern, including `0x8000000000000000` for that input. A path with no record produces zero. The two resulting words are written at output offsets `+0` and `+8`. This is **not** evidence that every non-empty structure yields a particular record, because the helper and all iterator invariants are outside this packet.

As a bounded empty example, assume both first words differ from the sentinel, both words at substructure offset `+0x18` are zero, and the memory ranges used by the reader are valid. Both selected paths construct equal begin/end pointers without dereferencing a row, so the two output words are zero. No claim is made for malformed or inaccessible pointers.

At selected callsites, builder `0x58f4c70` passes its saved second argument plus `0xa8` to `0x50eaf10` at `0x58f4cfe`, while builder `0x23e3b40` passes the analogous pointer to `0x22f6370` at `0x23e3bce`. Both then load the two output words and test each for zero; their arithmetic and subsequent order construction are already treated in the previous packet. The names bid and ask remain inferred, not established here.

## Evidence and limits

`instructions.tsv` records all decoded instructions of both readers and the two selected caller windows. `verify.py` authenticates the complete image digest, indexed FDE boundaries and body digests for four functions, checks complete disassembly of each, verifies 426 selected instruction bytes and 25 explicit pins, resolves six calls, compares the normalized readers, and rejects six mutated instruction records. The two helper bodies, iterator invariants, real book contents, more callers, allocator behavior, runtime execution and cross-version equivalence remain unproved. No component-completion gate is requested.

Reproduce from repository root with `PYTHONPATH=tools python research/work-items/RE-014-node115-best-pair-readers/verify.py`, using Python with Capstone installed. No live network, chain action or captured instruction execution is needed.
