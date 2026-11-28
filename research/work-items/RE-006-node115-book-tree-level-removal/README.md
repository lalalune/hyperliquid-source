# RE-006: tree-represented empty book-level removal

- Component: order-book removal, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Static observations and interpretations only; no captured executable is run or emulated, and no component gate is claimed.

## Question and prior evidence

`RE-006-node115-book-level-removal` traces the caller's use of the same side map and saved price key for post-unlink cleanup, and the flat branch of `0x4dded40`; it explicitly leaves tree deletion open. What does that helper do on its tree branch before possible conversion to flat form? The tree lookup in #7806 is an earlier operation that selects the level to unlink; this packet examines the later, separate removal handoff and count/root updates.

## Static evidence and interpretation

The caller's existing packet establishes that it calls `0x4dded40` with the selected map and saved key when the unlink result reports an empty level. At `0x4dded56..0x4dded6f`, this helper selects the tree path when negating the map's first word overflows, calls `0x51d6200` with a pointer to the descriptor at map `+8` and the still-live key argument, then reads the resulting count from map `+0x18`. The flat path is outside this packet.

`0x51d6200` initializes the result tag to 2, reads the root and tree height from descriptor `+0` and `+8`, and reads the signed qword key from its argument. Its count/child layout and signed comparison sequence match the earlier lookup; null root or an exhausted height branches to the tag-2 return path. On equality, it assembles the current node, height, index and descriptor into a temporary structure and calls `0x4d34e60`. The latter's deletion and balancing internals are not established here. After that call returns, this helper copies a 136-byte result and decrements the descriptor count at `+0x10` (map `+0x18`). The count decrement is on the found-key path; the helper's normal return and valid-tree invariants are assumptions.

The downstream byte flag can select a root update: the helper loads the first child at old root `+0x5e8`, publishes it as the new root, decrements height, clears the new root's `+0x580` parent field and passes the old node to an indirect helper with size `0x648`. The role of that indirect helper is not independently resolved here; failure and unwind behavior are excluded. A null-root and zero-height check precedes this update.

Back in `0x4dded40`, the descriptor is sent toward its conversion path only when the map marker is signed MIN and the post-call count is below 32. The materialization implementation is not newly established. This conclusion covers the branch condition and selected calls, not tree balance correctness or end-to-end cancellation.

`records.json` retains 405 bytes / 101 instructions over four selected windows in two FDEs (`0x4dded40..0x4ddf0d8` and `0x51d6200..0x51d645a`). It checks 42 interpretation-driving instruction facts and rejects 20 in-memory opcode/operand mutations. Those checks validate selected target bytes and disassembly, not target runtime results. The offline output is preserved in `offline-log.json`.

## Reproduce

From the repository root, using Python 3.11 and Capstone 5.0.6:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-tree-level-removal/verify.py
(cd research/work-items/RE-006-node115-book-tree-level-removal && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and reuses its ELF/FDE support. It authenticates the entire pinned ELF and decodes each window from its owning FDE boundary; corruption controls bypass the global digest only for the altered in-memory views.

## Limits and next question

The selected snippets do not prove complete CFG behavior, the deletion/balancing implementation, allocation/deallocation targets, the branch that produces the root-update flag, conversion materialization, malformed-state behavior, unwind safety, other caller copies, or full order-book equivalence. Next, establish the `0x4d34e60` result and flag contract and trace the empty-level conversion output without executing the capture.
