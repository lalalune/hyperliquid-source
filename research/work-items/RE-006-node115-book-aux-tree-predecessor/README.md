# RE-006: auxiliary-map tree predecessor replacement

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Static observations and interpretations only. No captured executable is run or emulated and no component gate is claimed.

## Question and prior work

[#7851](https://github.com/lalalune/hyperliquid-source/pull/7851) traces the auxiliary-map entry helper's nonzero-descriptor call to `0x4d366c0`, subsequent count decrement and optional root update, leaving this callee opaque. What selected tree path replaces an internal key/value pair before returning? Existing [#6842](https://github.com/lalalune/hyperliquid-source/pull/6842) identifies the FDE and its entry/first traversal but leaves its source ownership and complete behavior unresolved. This packet adds the caller connection, qword/dword key and value-column swap and the returned fields; it does not mark the earlier generic traversal as a new discovery.

## Static observations and interpretation

The caller at `0x4da8879..0x4da88b3` initializes a byte flag, passes the nonzero descriptor and its flag pointer to `0x4d366c0`, then decrements the tree count after the call. The selected callee reads a node pointer, height-like field and index from descriptor `+0/+8/+0x10`. When the height field is zero it directly passes a node/index descriptor to `0x4d20bc0`; that helper's internals are outside this packet.

For nonzero height, the callee loads the indexed child at node `+0x118+8*index`. It then repeatedly reads the 16-bit node count at `+0x112` and follows child `+0x118+8*count`, using a remainder loop followed by an eight-step unrolled loop. Under valid ordered-tree and nonempty-node invariants, this is a rightmost descent in the selected child. At the reached node it forms an index of `count-1`, calls `0x4d20bc0`, and reads a qword/dword key pair and qword value from the returned structure. The deletion, balancing and cursor contract of that lower helper are not independently proved.

Using the returned cursor, the callee may climb via node `+0xb0` and a 16-bit parent index at `+0x110`. At the selected node and position it reads a qword and dword at `node+16*index` and `+8`, overwrites those two lanes with the returned pair, then reads and overwrites the qword value at `node+0xb8+8*index`. The old qword, dword and value are stored at output `+0/+8/+0x10`; later cursor-related words are also populated. This establishes the selected data movement, not the meaning of the key lanes, memory safety on malformed trees, or full B-tree equivalence.

`records.json` retains the entire 644-byte callee FDE `0x4d366c0..0x4d36944` and a 58-byte caller window: 702 bytes / 146 instructions total. Forty-five instruction facts and 25 in-memory opcode/operand mutations bind the selected entry, descent, call, replacement and output operations to the authenticated ELF. These are static checks, not target runtime tests. `offline-log.json` is the actual verifier output.

## Reproduce

From the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-aux-tree-predecessor/verify.py
(cd research/work-items/RE-006-node115-book-aux-tree-predecessor && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the entire target and decodes from the FDE start. Mutation controls bypass the digest only for altered in-memory views.

## Limits and next question

Only one caller window is bound; no full caller census is claimed. Tree ordering, nonempty nodes, valid indices and normal helper returns are premises. `0x4d20bc0`, post-deletion rebalancing, flag production, all malformed states, unwind behavior and complete book semantics remain unresolved. Next, establish the lower helper's leaf-removal and flag contract for this specific 16-byte-stride key / 8-byte-value node layout.
