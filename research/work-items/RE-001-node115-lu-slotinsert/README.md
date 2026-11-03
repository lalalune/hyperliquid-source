# RE-001: the node #115 lu slot-insert helper — zero, compare, splice, walk

This packet answers packet #218's next question: what the `0x63ac0d0`
slot-insert helper does with (slot, node), how it sorted-inserts the
node by its (`+0x20`, `+0x8`) key, and when (if ever) it drops the node.

## Summary

`0x63ac0d0(slot, node)` = (rdi, rsi) inserts the node into the slot's
intrusive chain and never drops it. Entry zeroes the node's `+0x28`
pair and `+0x38` word. An empty slot takes the node as head. Otherwise
the node's key is compared against the head's key with the `setb`/`sbb`
signum idiom (first `+0x20`, then `+0x8` as tiebreak): a result of -1
(new key smaller) inserts the node before the head; any other result
splices it right after the head in the `+0x30` chain and bumps the
slot's second word, then — when the new second word exceeds 1 — a
merge walk re-splices adjacent chain nodes for at most `tzcnt` steps,
where the bound comes from the old second word. The function makes no
calls at all and returns nothing meaningful (void): both `ret` sites
only restore callee-saved registers. Equal keys insert after the head;
no path frees the node, returns NULL, or leaves the node unlinked.

## Entry and slot layout

- Slot entry, 16 bytes: `[slot]` = chain head, `[slot+8]` = second
  word (incremented on the after-head insert, zeroed on the
  insert-before path; its semantic identity is unresolved, see below).
- Node words used here: `+0x8` and `+0x20` = two-word sort key,
  `+0x28` = 16-byte link pair, `+0x30` = chain link,
  `+0x38` = second link word. Same words as #217's slot-claim walk.
- Entry (exhibit `si_entry`): `endbr64`, zero the `+0x28` pair
  (`movups %xmm0`), zero `+0x38` (`movq $0`), load `[slot]` as head,
  and branch to the empty-slot path when the head is NULL. This
  confirms #218's entry claim exactly.

## The three insert paths

- **Empty slot** (`0x63ac3e0`): `[slot] = node`, then the shared exit
  check on the old second word (greater than 1 runs the merge walk,
  otherwise return). A genuinely fresh slot has second word 0, so it
  returns immediately.
- **Insert-before** (`si_before`, `0x63ac428`): taken when the key
  comparison is -1 (node key smaller than head key). `node+0x38 =
  head`, `head+0x28 = node`, `[slot] = node`, `[slot+8] = 0`, return.
  The old chain is preserved behind the new head.
- **After-head splice** (`si_splice`, `0x63ac13c`): taken when the
  node key is greater than or equal to the head key. `[slot+8]++`,
  `node+0x30 = old head+0x30`, the old successor's `+0x28` backlink
  is set to the node when it exists, `node+0x28 = head`,
  `head+0x30 = node`. Then, when the new second word exceeds 1, the
  merge walk runs.

## The merge walk

- Setup (`si_merge`, `0x63ac170`): `rbp = old second word`,
  `tzcnt` of it into the step budget (`r10d`); a zero budget returns
  at once, as does a NULL current node. The parity of the `tzcnt`
  value selects the starting block; blocks alternate.
- Each step compares the current pair of adjacent chain nodes with
  the same (`+0x20`, `+0x8`) signum idiom; the -1 outcome takes one
  splice branch, any other outcome the other. Splices are 16-byte
  `movups` pair stores into `+0x28` slots plus backlink writes, and
  passed-over nodes get their `+0x28` pairs zeroed. The walk advances
  one `+0x30` link per step and stops on a NULL link, on a NULL next
  node, or when the step counter reaches the `tzcnt` bound.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Insert helper `0x63ac0d0`: 6 direct E8, 0 E9, 0 LEA,
0 GOT. E8: `0x635f3f7` and `0x635f497` (FDE `0x635f3a0..0x635f4a6`),
`0x636370d` and `0x63637c7` (FDE `0x6363660..0x63637e2`),
`0x636a035` (remainder helper, #218), `0x63b0675` (join FDE
`0x63b0560..0x63b077a`, #212). The non-remainder callers' purposes
are cited by address only, not decoded here.

## Corrections to earlier packets

- **#218 confirmed.** The insert helper's entry zeroes the node's
  `+0x28` pair and `+0x38` word; the remainder call site `0x636a035`
  passes (slot, node); the helper returns nothing, consistent with
  #218's note that the remainder helper does not test its return.
- **#217 confirmed.** The chain words (`+0x28` pair, `+0x30` link,
  `+0x38` word) and the (`+0x20`, `+0x8`) comparison idiom are the
  same ones the slot-claim walk uses.
- No bytes claimed by packets #183–#218 are re-claimed. All exhibits
  lie strictly inside the insert FDE; caller FDEs and the slot-claim
  FDE are cited by address only.

## Unresolved, stated not inferred

The exact invariant of the slot's chain (binary search tree versus
sorted list, and which node a multi-node chain presents first); what
the slot's second word counts, and why the merge walk is bounded by
its `tzcnt`; the purposes of the five non-remainder callers; what
populates the chain for a fresh pool slot.

## Next question

Decode the FDE `0x6363660..0x63637e2` end to end: what it does with
its slot and node, why it calls the slot-insert helper twice
(`0x636370d`, `0x63637c7`), and how its slot relates to the
allocator's pool slots.
