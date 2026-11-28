# RE-006: auxiliary-map tree leaf removal and repair dispatch

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Selected static observations and interpretations only. No captured code is executed or emulated; no component gate is claimed.

## Question and prior work

[#7855](https://github.com/lalalune/hyperliquid-source/pull/7855) traces the auxiliary-map tree predecessor path to `0x4d20bc0` but leaves the selected leaf operation open. What columns are shifted after a leaf item is selected, and when is repair dispatched? Earlier quantity-tree work such as #7723 studies a different node layout; this packet binds this book auxiliary map's qword/dword key lanes, 16-byte key stride and 8-byte value column to its caller.

## Static observations and interpretation

The predecessor caller reads the reached node's 16-bit count, subtracts one, forms a node/index descriptor and calls `0x4d20bc0`. At the callee entry, the selected node and index come from descriptor `+0/+0x10` and the old count from node `+0x112`. The selected key qword and dword are saved from `node+16*index` and `+8`. The code computes `old_count-index-1` and moves that many 16-byte key slots from the following slot into the selected position. It separately saves the qword at `node+0xb8+8*index` and moves the same number of 8-byte value slots from the following position. Both indirect calls use the dynamic relocation at `0x64df568`, whose ELF symbol is `memmove`; the actual loader binding is not observed. Valid indices and normal calls are premises.

The new count is stored at node `+0x112`. If it is greater than 4, control takes the non-underflow continuation. Otherwise the code checks node `+0xb0` for a parent; a null parent follows a separate root path. With a parent, it reads the 16-bit parent index at node `+0x110`: a nonzero index selects an adjacent child on one side, while zero selects the other side after a parent-count check. In either selected sibling path, the code adds the sibling's count to the **old** node count and compares that sum with 12 before choosing a continuation. The selected lower-sum path reaches `0x4ca2920` with an explicit side argument. This packet binds selection and dispatch only; it does not establish the repair helper's effects or the other continuations.

`records.json` retains a 476-byte callee entry window in FDE `0x4d20bc0..0x4d21388` and a 44-byte predecessor-caller window: 520 bytes / 103 instructions. Forty-five instruction and dynamic-relocation facts, plus 28 in-memory opcode/operand or relocation mutations, bind the selected operations to the authenticated ELF. These are static checks, not target runtime tests. `offline-log.json` contains the actual verifier result.

## Reproduce

From the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-aux-tree-leaf/verify.py
(cd research/work-items/RE-006-node115-book-aux-tree-leaf && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the full target and decodes from each FDE start. Mutation controls bypass the digest only for altered in-memory views.

## Limits and next question

The remaining 1,516 bytes of the callee, repair and root continuations, helper side effects, dynamic loader binding, malformed structures, unwind behavior and full map correctness are not established. Node ordering, nonzero valid count, selected index bounds and normal helper returns are assumptions. Next, connect the selected repair helper and root continuation to the returned cursor and flag without treating the whole B-tree as complete.
