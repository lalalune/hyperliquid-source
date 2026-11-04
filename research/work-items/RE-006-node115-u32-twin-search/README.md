# RE-006 node #115 — u32 twin cursor search

## Scope

Answer for node #115 only. This packet pins the u32 twin of the
runner-up layout (#2546): the cursor-search body at `0x35bf500`, the
sixth shape of the RE-006 family to be pinned after the clones
(RE-006 main packet), variants A and B (#2530), the sibling (#2542)
and the runner-up itself. The variant packet's family census counted
this body with 6 direct call sites. The packet answers who consumes
its records — field by field, per call site — and settles the height
question for it: whether any consumer reads the record's height field
as a number.

The body, its 6 caller extents and every retained fact are checked by
`tools/u32_twin_search_static.py`; `analyze()` checks everything
without authenticating, so a counterfactual byte flip fails the
specific check rather than a whole-file digest. `generate()`
authenticates the artifact first and regenerates `records.json`,
`frames.txt` and the body export byte-for-byte.

## Short answer

- The body at `0x35bf500..0x35bf592` (146 bytes, SHA-256
  `90fda960e4f1a5fbffb665662ff5ae5384a64c5c54ac1443f37536c1d5400142`)
  walks **u32 keys at node + 0x2c8, 11 per node**, with the count word
  at node + 0x2f6 and child edges from node + 0x2f8. Only the key base
  is shared with the runner-up's u64 layout (count +0x322, edges
  +0x328 there); the bodies are layout twins, not instruction twins.
- All **6 call sites are flag-only**. The byte flag test immediately
  follows each call, and no site reads the record's node, height or
  position in its window: the search is a pure membership oracle for
  its callers.
- The record's **height is never read as a number**: all 219
  height-slot reads across the 6 census units are wholesale vector
  copies of the frame struct (96) or other-phase scalar reads (123);
  consumed reads: 0.
- The callers fall into two clone triples — three giants of
  44.5–45.9 KB and three clones of one 2,111-byte function — each
  holding exactly one twin call and one fallback call to `0x4556c50`,
  a different fallback from the u64 family's `0x4556410`.

## Method

1. Premises re-derived from the binary: the body's range and digest,
   an executable-section byte scan for direct and tail branches naming
   it (exactly 6 `E8` calls, no `E9` tails), and a `.rela.dyn` census
   (no `R_X86_64_RELATIVE` names the body).
2. Each call site's caller FDE is digest-pinned, and the record's use
   at the site is read from a retained window of pinned instructions
   around the call.
3. Consumption is settled by a whole-FDE slot census per
   (caller, record-base) unit: every instruction in the caller whose
   operand text references the flag / node / height / position slot,
   excluding `lea` address computations and stores to the slot. The
   census is recomputed from the current decode and must equal the
   retained lists exactly.
4. Every height-slot read is attributed: wholesale vector copies of
   the frame struct are recognised by mnemonic; each remaining scalar
   read carries a retained context window pinning the read itself, so
   the attribution is auditable instruction by instruction.

## Trace

### The body

- The key pointer in `rcx` is dereferenced exactly once
  (`mov ecx, DWORD PTR [rcx]` at `0x35bf503`): a **u32** key.
- Count: `movzx r8d, WORD PTR [rsi + 0x2f6]` at `0x35bf505`.
- The scan starts at index −1 and compares
  `cmp ecx, DWORD PTR [rsi + rdi*4 + 0x2cc]` at `0x35bf525`, so the
  keys sit at **node + 0x2c8 as u32, 11 per node** (the word at
  +0x2f4 is where the child-index word would sit by the family
  layout arithmetic `(0x2f6 − 0x2c8 − 2) / 4 = 11`; it is never read).
- The three-way compare (`seta` / `sbb`) yields 0 = equal, 1 = key
  greater (keep scanning), 0xff = key smaller (descend or miss).
- Descent: `mov rsi, QWORD PTR [rsi + rdi*8 + 0x2f8]` at `0x35bf56c`
  — child edges from **node + 0x2f8**.
- One shared epilogue stores the record: node at `0x35bf57b`, height
  at `0x35bf57f`, position at `0x35bf583`, flag at `0x35bf587` — the
  family-standard 32-byte record `{flag +0x0, node +0x8, height
  +0x10, position +0x18}`. The hit arm sets the flag to 0
  (`xor ecx, ecx` at `0x35bf579`); the miss arm sets it to 1
  (`mov ecx, 0x1` at `0x35bf58b`).
- The body is call-free and branches only within itself.

Against the runner-up body `0x35be560`, the twin differs in more
than key width: count at +0x2f6 vs +0x322, scan displacement +0x2cc
with a ×4 scale vs +0x2d0 with ×8, edges at +0x2f8 vs +0x328, and a
different register allocation with a byte-count scan loop. Only the
key base +0x2c8 and the record layout are shared.

### The callers

Both shapes present the tree handle the same way as the rest of the
family: a handle embedded at +0x30 in a parent object, root loaded
from +0x38, height from +0x40; a non-sentinel tag routes to the
fallback `0x4556c50` with the handle in `rdi` (sentinel
`0x8000000000000000`). Both also gate on the key count: fewer than
0x32 (50) keys bypass the search, and the surrounding phases are
discriminant-gated (a `movzwl` tag compared against 0x1a2). The key
reaches the search as a pointer to a plain dword stored in a frame
slot.

- Giants `0x28cd7a0`, `0x538cd30`, `0x5397b50` (presentation
  `embedded_frame`, record form `lea`): the parent-object pointer
  comes from a frame slot, the tag check dereferences a second frame
  slot holding the handle pointer, and the record is materialised
  with `lea 0x20(%rsp)` — base **0x20**. The first is a distinct
  clone; the other two are adjacent clones of one function.
- Small callers `0x2c440c0`, `0x55a5f10`, `0x55a6750` (presentation
  `embedded_register`, record form `register`): clones of one
  2,111-byte function. The parent pointer is walked in a register,
  advancing by the 0x30 handle size between elements, and the record
  is passed in `rbp`, proven to be `rsp + 0xa0` by the
  `lea 0xa0(%rsp), %rbp` pinned in each clone's window — base
  **0xa0**.

## Consumption verdict

All 6 sites are flag-only: the flag test is a byte compare
(`cmpb $0x0`) at site + 5, immediately after the call, and the tool
verifies that no other instruction in each retained site window
touches a record slot after the call. On a hit, each caller proceeds
to work that does not involve the record: the giants continue with
vector housekeeping on neighbouring frame slots, and the small
callers append an {element, key} pair to a 0x10-stride vector. The
search answers membership and nothing more.

Whole-FDE slot census (reads per unit; stores and `lea` excluded):

| unit (caller \| base) | flag | node | height | position |
|---|---|---|---|---|
| 0x28cd7a0 \| 0x20 | 133 | 113 | 69 | 55 |
| 0x538cd30 \| 0x20 | 130 | 113 | 69 | 55 |
| 0x5397b50 \| 0x20 | 130 | 113 | 69 | 55 |
| 0x2c440c0 \| 0xa0 | 8 | 3 | 4 | 1 |
| 0x55a5f10 \| 0xa0 | 8 | 3 | 4 | 1 |
| 0x55a6750 \| 0xa0 | 8 | 3 | 4 | 1 |

The large read counts in the giant units are the frame struct being
worked on by the callers' many phases — the record occupies the head
of a larger struct (0x40 bytes in the giants' case) that the whole
function reads and copies field by field; the census attributes them
all, and none of them is a consumption of the search result beyond
the flag test at the site itself.

### Height verdict

The height slot (+0x10) is read 219 times across the 6 units: 96
wholesale vector copies of the frame struct (`movaps` / `movapd` /
`movupd` / `movdqa` sequences spanning the struct) and 123 scalar
reads belonging to other phases — the +0x10 slot is an ordinary
field of the frame struct, read in identical idioms before and after
the call, for example as a ×24 index into descriptor tables, as a
floating-point field (`movsd`), or inside field-wise struct copies.
The first height read after the giant `0x28cd7a0`'s call site, at
`0x28d3f5b`, already belongs to the next phase (descriptor-index
idiom, after a phase boundary). **No consumer reads the twin
record's height as a number: consumed reads 0.**

## Negative results

- No tail calls and no other direct branches name the body; no
  `R_X86_64_RELATIVE` relocation names it.
- No site has a consumption triple — there is no `mov` of the
  position slot, shift and node-scaled add anywhere after any call.
- Each caller contains exactly one twin call and one fallback call;
  none of the 6 callers calls any other family search body.

## Boundaries

- Static evidence only, node #115 only; nothing here executes the
  binary or observes a live tree.
- Phase attribution for the scalar height reads rests on the retained
  context windows and the read idioms, not on whole-FDE control-flow
  proofs; the windows are pinned so the attribution can be audited.
- The child-index word at node +0x2f4 is named by layout arithmetic
  only — no instruction in the body reads it.
- What the small callers' appended {element, key} pairs and the
  giants' post-hit vector work mean semantically lies outside the
  traced windows and is not claimed here.

## Next question

The family's six remaining small members from the variant packet's
census — `0x35bd8a0` (2 sites), `0x35bddb0` (1), `0x35be3b0` (2),
`0x35bf3c0` (2), `0x1d65b20` (1) and `0x4d380a0` (1) — and the field
layout of the 0x40-byte frame-struct elements the giant callers copy
wholesale, whose head the twin's record occupies.

## Reproduction

```sh
TMPDIR=<scratch> python3 -m unittest tests.test_u32_twin_search_static -v
python3 tools/u32_twin_search_static.py generate <scratch-dir>
# then byte-compare records.json, frames.txt and
# u32_twin_search_full_body_35bf500_35bf592_objdump.txt against this packet
cd research/work-items/RE-006-node115-u32-twin-search && sha256sum -c MANIFEST.sha256
```
