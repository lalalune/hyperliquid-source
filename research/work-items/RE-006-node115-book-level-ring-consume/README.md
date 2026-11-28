# RE-006: guarded consumption of book-level ring rows

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Selected static observations and interpretations only; no captured code is executed or emulated and no component gate is claimed.

## Question and prior work

The shared book-level helper `0x518e690` is reached from both insertion and removal. [#7820](https://github.com/lalalune/hyperliquid-source/pull/7820) describes its initial optional-slot screening, and [#7828](https://github.com/lalalune/hyperliquid-source/pull/7828) the separate guarded slot-link advancement. What does the helper do with its level `+0x30..+0x48` sequence when `+0x48` is nonzero? This packet traces selected row access, the comparison, sequence advancement and the downstream map-removal call. It does not assign units to the values used by the comparison.

## Evidence and interpretation

At `0x518e870`, a zero qword at level `+0x48` returns; otherwise the helper reads a head-like qword at `+0x40`, capacity-like qword at `+0x30` and base pointer at `+0x38`. It subtracts the capacity once if the head is at least that value, then multiplies the resulting physical index by 32. From the selected row it reads three dwords at `+0x10/+0x14/+0x18`, plus a qword and dword at `+0/+8`; the latter pair is copied to a 12-byte stack key. Calling these fields head, capacity and length is an inference under valid circular-buffer invariants, not a claim about arbitrary corrupt values.

The intervening arithmetic computes a value from the row's other fields. At `0x518e97a`, the code adds a separately computed operand, selecting all-ones on unsigned carry. If the computed threshold exceeds the qword at stack `+0x10`, control returns before the selected sequence updates. The full arithmetic window is retained, but this packet does not infer calendar or time semantics and does not independently establish either operand's meaning.

Otherwise, `0x518e99c..0x518e9b5` increments the earlier head, subtracts capacity once if the result reaches capacity, stores the new head at level `+0x40`, decrements the earlier nonzero count and stores it at `+0x48`. The helper then passes level `+0x50` and the saved 12-byte row key to `0x4de02d0`. If `RAX != 1`, it loops to re-read the count. The existing `RE-006-node115-order-unlink-level` packet covers the separately called map helper in another context; its complete effect and the path taken on `RAX == 1` are not newly claimed here.

`records.json` retains the contiguous 359-byte / 83-instruction interval `0x518e870..0x518e9d7` inside FDE `0x518e690..0x518f039`. Thirty-four instruction facts and 17 in-memory instruction mutations bind selected operations and branches. The verifier additionally checks that the intervening decoded instructions do not write the registers carrying the earlier head, capacity or count before the updates. These checks bind disassembly to the authenticated ELF; they do not execute the target or establish behavioral equivalence. `offline-log.json` is the actual result.

## Reproduce

From the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-level-ring-consume/verify.py
(cd research/work-items/RE-006-node115-book-level-ring-consume && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the full target and decodes from the FDE boundary. Mutation controls bypass the digest only for altered in-memory views.

## Limits and next question

The selected interval is not complete coverage of the 2,473-byte helper. It assumes a valid nonempty ring, valid base and capacity, normal map-helper return, and no concurrent mutation. The row-field calculation and units, the `RAX == 1` continuation, queue production, malformed-state handling, unwind behavior, and end-to-end order semantics remain open. Next, trace the non-looping map-helper result and its effect on level `+0x50` representation.
