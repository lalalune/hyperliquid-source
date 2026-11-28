# RE-006: auxiliary-map entry helper in book-level cleanup

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Selected static observations and interpretations only. No captured executable is run or emulated and no component gate is claimed.

## Question and prior work

[#7846](https://github.com/lalalune/hyperliquid-source/pull/7846) follows a book-level cleanup loop to a conditional call of `0x4da8860` with a descriptor identifying an auxiliary-map candidate. What count and descriptor changes can be observed in this callee's tree and flat paths? The existing `RE-001-node115-loc-edge-4da89ee` packet studies only a separate flat-path bounds-error edge and source-location record in this FDE; that prior evidence is not repeated as a new finding.

## Static observations and interpretation

The helper checks the first qword of its descriptor. If nonzero, it initializes a stack flag, calls `0x4d366c0` with the descriptor and flag address, and saves 24 bytes from the callee's output. On normal return it loads a pointer from descriptor `+0x18` and decrements the qword at that pointer `+0x10`. If the flag is 1, it checks that pointer's root and height, promotes old root `+0x118` to root, decrements height, clears the new root's `+0xb0`, and calls an indirect slot with the old root and size `0x178`. The target and effect of that indirect call are not independently resolved. The code returns the saved 24 bytes through the output pointer.

If the descriptor's first word is zero, it obtains a map pointer from descriptor `+8`, an index from `+0x10`, and a count from map `+0x18`. When count is at most the index it branches to the previously documented error path. Otherwise it computes a physical index from map head `+0x10`, index and capacity at `+0`, subtracting capacity once when needed, then reads a 24-byte row from the buffer at map `+8`. It compares the number of rows before and after that position to choose arguments to `0x5817e50`; one branch also advances the stored head. After that helper returns normally, this code decrements and stores map count and returns the saved row. The copy/shift helper itself is not reconstructed here.

In the specific [#7846](https://github.com/lalalune/hyperliquid-source/pull/7846) caller, the nonzero descriptor carries the level map's tree descriptor pointer at `+0x18`, while the zero descriptor carries its flat map pointer at `+8`. Under valid structures and normal helper returns, the selected callee therefore decrements that map's count on either path. This connects the previously opaque call to a count update; it does not prove its lower-level balancing, shifts, error or unwind safety, cycle-free cleanup, or complete order semantics.

`records.json` retains the contiguous 353-byte / 91-instruction interval `0x4da8860..0x4da89c1` of FDE `0x4da8860..0x4da8a00`. Forty-eight instruction facts and 23 in-memory opcode/operand mutations bind the selected branches, loads, count stores, and calls to the authenticated ELF. They are static checks, not target runtime tests. `offline-log.json` contains the actual verifier result.

## Reproduce

From the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-aux-map-remove/verify.py
(cd research/work-items/RE-006-node115-book-aux-map-remove && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the entire target and decodes from the FDE start. Mutation controls bypass the digest only for altered in-memory views.

## Limits and next question

The 353-byte selection omits the FDE's error blocks. Valid native pointers, indices, capacity, normal calls and ABI preservation are premises. The tree removal and flat shift internals, indirect deallocation target, concurrent modification, unwind, and full cleanup-loop semantics remain unresolved. Next, inspect the `0x4d366c0` and `0x5817e50` contracts in this descriptor context.
