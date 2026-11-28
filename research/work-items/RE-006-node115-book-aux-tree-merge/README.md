# RE-006: auxiliary-map leaf sibling merge handoff

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Selected static observations and interpretations only. No captured code is executed or emulated; no component gate is claimed.

## Question and prior work

[#7860](https://github.com/lalalune/hyperliquid-source/pull/7860) shows this auxiliary map's leaf removal and low-count sibling dispatch but leaves `0x4ca2920` opaque. What selected operations combine the siblings with the parent separator? Earlier #7738 covers a different quantity-tree node layout; this packet binds the auxiliary map's 16-byte-stride key lanes, 8-byte value column and child metadata to this caller.

## Static observations and interpretation

The leaf caller adds the sibling count to the pre-removal count. When that sum is below 12, both selected sibling cases reach `0x4ca2920` with side argument 1 or 0; the alternative paths are outside this packet. The callee checks a selected index against a count chosen by the side argument, then computes `left_count + right_count + 1` and branches out if that result is at least 12. Under the caller's established decrement and valid-tree invariants, this is consistent with the caller's lower-sum gate. The check failures' behavior is not analyzed here.

On the selected path, the helper stores the combined count into the node from descriptor `+0x18`. It saves a qword/dword pair from the parent node's 16-byte-stride separator position, shifts later parent key slots through a `memmove` slot, writes the separator lanes after that node's existing keys, and calls `memcpy` for the other node's key slots. In the parallel qword value column at node `+0xb8`, it similarly saves the parent separator value, shifts the parent suffix, writes the separator value and copies the other node's values. The retained instructions bind the byte strides and ordering; they do not prove the key's higher-level type or the external copies' behavior on invalid overlap.

The helper then moves a suffix of parent child pointers, rewrites selected remaining children's parent pointers at `+0xb0` and 16-bit indices at `+0x110`, and decrements the parent count at `+0x112`. The later helper continuation, merged-node child handling, allocation/free operations and returned cursor are outside this packet. Five RIP-relative calls resolve to dynamic slots for `memmove` and `memcpy`; the verifier checks both relocations and symbol names, not the runtime loader binding.

`records.json` retains 631 bytes of callee entry plus 81 bytes in two caller windows: 712 bytes / 156 instructions across two FDEs. Fifty-nine static instruction, address and relocation facts and 29 in-memory opcode/operand or relocation mutations bind the selected statements to the authenticated ELF. They are static checks, not target runtime tests. `offline-log.json` contains the actual verifier result.

## Reproduce

From the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-aux-tree-merge/verify.py
(cd research/work-items/RE-006-node115-book-aux-tree-merge && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the full target and decodes each window from its FDE start. Mutation controls bypass the digest only for altered in-memory views.

## Limits and next question

The selected 631 bytes do not cover the entire 1,045-byte merge helper. Valid indices, nonoverlap where required, tree structure and normal library returns are assumptions. Error branches, merged-node children, deallocation, cursor results, sibling-transfer alternatives, unwind and complete map correctness remain unresolved. Next, trace the merge continuation and distinguish the two higher-count sibling-transfer paths without claiming full B-tree equivalence.
