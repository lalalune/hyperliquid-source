# RE-006: cached book-level slot chain advancement

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Static observations and dataflow interpretations only. No captured code is executed or emulated; no component gate is claimed.

## Question and prior evidence

[#7820](https://github.com/lalalune/hyperliquid-source/pull/7820) establishes the shared book-level helper's initial range and tag checks for its cached slab slot. What happens when that in-range, non-2 slot reaches the later selected comparison, and how are subsequent slot references checked? This packet covers the later link-advance loop and its guarded stores. The preceding numeric computation and the broader operation's purpose are not established here.

## Evidence

After the earlier check, `0x518ec00..0x518ec13` saves the slab length and base and forms the initial slot pointer. At `0x518ed91..0x518ed9f`, a computed unsigned sum is saturated on carry and compared with another computed value; if that other value is smaller, execution returns to the helper's `+0x48` path without the selected link update. This report treats both numeric operands as opaque; it does not assign them time units or claim to reconstruct their calculation.

Otherwise, the helper copies qwords from the current slot at `+0x10/+0x18` into the level at `+0x20/+0x28`. When the copied first qword is exactly 1, it retrieves the saved slab length and base and enters the next-reference loop; another first qword leaves that loop. Within the loop the next index is rejected if it is at least the saved length or the target slot's first dword is 2. Either rejection clears the qword at level `+0x20`.

For a non-2 in-range slot, the loop reads the qword at slot `+0xb8`, adds an already-computed operand, selects unsigned maximum on carry, and compares that result with another computed operand. If the latter is smaller, the loop exits without copying that slot's link. Otherwise it copies that slot's `+0x10/+0x18` qwords to level `+0x20/+0x28`, looping if the copied first qword is nonzero. The initial transition tests equality to 1 while the loop tests nonzero; these checks are recorded separately. Valid native slot structures and normal control flow are assumed. Slot meaning, equality of reused slots, cycle freedom, the computation preceding the windows, and semantics of the later helper are not proved.

`records.json` retains 215 selected bytes and 46 instructions across four windows of FDE `0x518e690..0x518f039`, including the load of the all-ones saturation value. Thirty-six instruction facts and 18 in-memory opcode/operand mutations pin the selected dataflow and branches. These checks bind disassembly to the pinned ELF; they do not execute the target or independently prove runtime behavior. `offline-log.json` contains the actual verifier output.

## Reproduce

From the repository root, using Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-level-link-advance/verify.py
(cd research/work-items/RE-006-node115-book-level-link-advance && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the full target and decodes from the FDE boundary. Mutation controls bypass the digest only for the altered in-memory views.

## Limits and next question

The 215-byte selection is not full coverage of the 2,473-byte helper. The source and units of both computed operands, native data invariants, downstream `+0x48/+0x50` processing, errors and unwind, concurrent mutation, and end-to-end order semantics remain unresolved. Next, trace the calculation feeding the first comparison and identify the associated literal and indirect helper provenance.
