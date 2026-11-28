# RE-006: cached slot screening in a shared book-level operation

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Selected static observations and interpretations only. No captured code is executed or emulated, and no component gate is claimed.

## Question and incremental scope

The existing `RE-006-node115-book-ring-append` and `RE-006-node115-book-level-removal` packets identify a shared operation at `0x518e690` on insertion and removal respectively but leave its internals opaque. How does that operation screen the optional cached slab slot at level `+0x20/+0x28` before proceeding? The unlink packet separately documents replacing that level link; screening it in this common callee is a distinct question.

## Evidence

In the insertion owner, the call at `0x5911929` passes a level handle and slab `book+0x80`. In the removal caller, `0x58e1a4f..0x58e1a59` passes its selected level and the same book-relative slab. These call-site bindings build on the existing packets; they do not establish all callers or the level helper's whole behavior.

At the shared helper entry, a dword equal to 1 at level `+0x20` selects the cached-index check. The qword at level `+0x28` is compared as an unsigned index with slab `+0x10`; an index at or above that length branches to clear the qword at level `+0x20`. Otherwise the code loads the slab base from `+8`, uses a `0x110` byte stride, and compares the selected slot's first dword with 2. Tag 2 reaches the same clear; a different tag branches to `0x518ec00`, where the pointer `slab_base + index*0x110` is formed and used by the remaining helper. The evidence establishes those two checks, not that any other non-2 tag denotes a valid order or that a reused slot still identifies the same order.

When the initial level dword differs from 1, or the cached reference was cleared, control reaches `0x518e6de`, reads level `+0x48`, and returns if that qword is zero. A nonzero value proceeds into other calculations, which are outside this packet. It does not establish the later effects of a valid cached slot, stale-reference lifecycle, or concurrent mutation safety.

`records.json` retains four windows totaling 178 bytes and 45 instructions across the helper FDE `0x518e690..0x518f039` and two caller FDEs. Twenty-six instruction facts and 14 in-memory opcode/operand mutations bind the documented comparisons, stores and calls. These are static disassembly checks, not target runtime tests. `offline-log.json` records their actual result.

## Reproduce

Run from the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-level-cached-slot/verify.py
(cd research/work-items/RE-006-node115-book-level-cached-slot && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the target, checks complete selected instruction boundaries from each FDE start, and bypasses the digest only for synthetic in-memory mutation controls.

## Limitations and next question

The retained windows cover 178 selected bytes, not the complete 2,473-byte helper or its full callers. Field names and their lifecycle are inferred from surrounding evidence. Other tags, `+0x48` semantics, downstream numerical operations, helper calls, errors, unwind behavior, and complete matching or cancellation remain unresolved. Next, trace the valid-slot path's consumers and the `+0x48`-driven calculation, without executing the capture.
