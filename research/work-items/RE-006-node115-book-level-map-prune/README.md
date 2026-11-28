# RE-006: book-level auxiliary map selection after ring consumption

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Selected static observations and interpretations only. No captured executable is run or emulated and no component gate is claimed.

## Question and prior work

[#7835](https://github.com/lalalune/hyperliquid-source/pull/7835) traces a guarded book-level ring pop, saving a row's qword/dword key in `r13/r14d`, and calling map helper `0x4de02d0`. When its return is 1, what follows before the caller returns to ring processing? This packet traces representation selection, candidate access and the comparison-controlled helper loop. It does not claim to reconstruct the map helpers or the whole book-level operation.

## Static observations and interpretation

The non-1 return goes directly back to ring processing. On return 1, the code reads level `+0x50` and `+0x68`; it selects conversion only when the first word is signed MIN and count is below 32. The conversion path takes root and height from `+0x58/+0x60`, zeros `+0x58/+0x68`, assembles an iterator-like stack descriptor, calls `0x5ba3a60` and installs three returned words at `+0x50`, `+0x58`, `+0x68` while zeroing `+0x60`. This is a caller-specific handoff; the callee's materialization and error behavior are not established. Generic tree-to-flat conversion evidence elsewhere is not re-claimed. The existing `RE-001-node115-loc-edge-4da89ee` packet studies a different conditional edge inside `0x4da8860`; its helper internals are not re-claimed here.

If the resulting first word is still signed MIN, a non-null root follows `+0x118` child pointers according to the height at level `+0x60`, with a remainder loop and an eight-step unrolled loop. A zero 16-bit count at the reached node `+0x112` returns to ring processing; otherwise that node is used as the candidate and a descriptor is prepared. This is a leftmost-style descent under valid-tree invariants; the packet does not prove ordering, balanced shape or malformed-node safety.

For the non-MIN form, a zero count returns to ring processing. Otherwise the code uses the head at level `+0x60`, subtracts capacity once if needed, multiplies by 24, and adds the base at `+0x58` to choose a candidate row. The same candidate comparison then serves both forms. It compares saved `r14d` against candidate dword `+8`; if equal it compares candidate qword `+0` against saved `r13`. An unsigned-above branch returns to ring processing; otherwise the prepared descriptor is passed to `0x4da8860`, and control returns to the representation check. The operands occur in different orders in the two comparisons, so this packet does not simplify them into an unproved lexicographic rule. We assume normal calls obey the x86-64 ABI and valid native structures; the helper's complete result, side effects and termination are not proved.

`records.json` retains 560 bytes / 115 instructions in three windows of FDE `0x518e690..0x518f039`, including the marker and descriptor-base setup. Fifty-three instruction facts and 23 in-memory mutations pin the selected branches, accesses and calls. They verify static instruction properties against the authenticated ELF, not runtime behavior or equivalence. `offline-log.json` records the actual result.

## Reproduce

From the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-level-map-prune/verify.py
(cd research/work-items/RE-006-node115-book-level-map-prune && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the entire target and decodes from the FDE start. Mutation controls bypass the digest only for altered in-memory views.

## Limits and next question

The selected 560 bytes are not full coverage of the 2,473-byte helper. The helper calls' contracts, iterator and row types, exact key-order semantics, data invariants, unwind behavior, loop termination, and end-to-end cancellation are unresolved. Next, establish the contract of `0x4da8860` for the prepared descriptor and the relation between both compared fields.
