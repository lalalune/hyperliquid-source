# RE-001: the node #115 lu class-merge consumer — chain min-selection, relink, head return

## Question

Packet #230's class-search helper tail-calls the consumer at `0x63b9690`
with the slot entry `record + found * 16`. What does the consumer do with
that entry, how does it merge and relink the chain it reads there, and what
does it return? This decides what the class search actually dispatches to.

## Answer

The consumer is a single FDE, `0x63b9690..0x63b99c8` (824 bytes, one `ret`
at `0x63b9925`, **zero `call` instructions**). It takes the chain rooted at
`[slot]`, restructures it in place into a left-child/right-sibling
min-ordered tree, and returns the minimum-key node — writing it back to
`[slot]`. It allocates nothing, calls nothing, and frees nothing.

Entry contract: `rdi` is a 16-byte slot entry. `[slot]` is the chain head
node (or NULL); `[slot+8]` is a second word the consumer zeroes on every
non-empty path. Node words used here: `+0x08` is the sort key (a single
word — see the key note below), `+0x28` is the parent pointer (low word of
a 16-byte pair), `+0x30` is the next-sibling / chain link (high word of
that pair), `+0x38` is the first-child pointer. No other node word is read:
the FDE contains no `0x20(` operand at all, and every `+0x10` access is
pair-relative (`node+0x28` plus `0x10` = `node+0x38`).

Behaviour, in order:

1. **Empty head.** `head = [slot]`; if NULL, return NULL immediately.
   `[slot+8]` is left untouched on this path.
2. **Slot preparation.** `[slot+8] := 0`; the head's `+0x28` pair is zeroed.
3. **Single-node chain.** If `head+0x30` is NULL, return the head
   (`[slot+8]` already zeroed).
4. **Phase A — pairwise min-selection over the `+0x30` chain.** Adjacent
   pairs are compared on `+0x08` only, with the two-sided `setb`/`sbb`
   signum idiom (three sites: first pair, inner loop, phase B). The
   smaller node stays on the `+0x30` chain; the larger becomes the
   smaller's `+0x38` first child, with the loser's `+0x28` pair rewritten
   to `(winner, winner's old first child)` and the loser's `+0x30` set to
   the winner's old first child. Winners are linked through the previous
   winner's `+0x30`. Each node's `+0x28` pair is zeroed as the walk
   reaches it, and the second node's `+0x30` is severed before pairing.
5. **Phase B — winner merge.** Starting from the second winner, each next
   winner is merged into the running-minimum accumulator the same way:
   the smaller stays the accumulator, the larger becomes its `+0x38`
   first child, and accumulator generations are linked via
   `[prev-acc+0x30] = new-acc`.
6. **Final head comparison.** The final accumulator's `+0x08` is compared
   against the head's `+0x08` with the same signum idiom. If the
   accumulator key is greater than the head key, the accumulator becomes
   the head's first child and the head stays. Otherwise (accumulator key
   less than or equal to the head key) the head becomes the accumulator's
   first child and `[slot] := accumulator`.
7. **Return.** Every path funnels through `0x63b9914`: `[slot] := rbx`
   (the head, possibly replaced), `rax := rbx`, pops, `ret`. So the
   returned value is the minimum-`+0x08` node of `{head} ∪ {chain}`,
   and the slot entry is left pointing at it with its second word zeroed.

So the class search in #230 does not dispatch to a lookup, a free, or a
drop: it hands the found class's slot chain to a merge that normalizes
the chain into a min-ordered tree keyed on `+0x08` alone and returns the
minimum node. What the caller does with that returned minimum is the next
question.

## Key note: single-word key, unlike #225

Packet #225's slot-head helper compared a two-word key (`+0x20` first,
then `+0x8`). This consumer compares `+0x08` only — no `+0x20` operand
occurs anywhere in the 824-byte FDE. Either these chains are ordered by
`+0x08` alone, or `+0x20` is irrelevant to this merge. The bytes prove the
former behaviour (single-word compare); they do not prove which
interpretation of the key is intended. See "Unresolved".

## Exhibits (5 excerpts, 317 bytes, 86 strict instructions)

| Exhibit | Range | Bytes | Strict | What it shows |
|---|---|---|---|---|
| `cs_entry` | `0x63b9690..0x63b96c6` | 54 | 16 | Entry, head load, NULL guards, `[slot+8] := 0` |
| `cs_pair` | `0x63b9700..0x63b9758` | 88 | 23 | First-pair signum + attach (smaller stays) |
| `cs_loop` | `0x63b97d4..0x63b97f6` | 34 | 9 | Inner-loop signum core |
| `cs_phaseb` | `0x63b9840..0x63b9887` | 71 | 18 | Phase-B compare + attach |
| `cs_final` | `0x63b98d1..0x63b991b` | 74 | 20 | Final head compare, `[slot]` store, return |

Strict counts are mnemonic-line counts (address + bytes field + tab +
mnemonic; objdump byte-continuation lines excluded) and match across
README, `records.json`, and the PR body.

## Census

- Direct `E8` call sites to `0x63b9690`: **0**.
- Direct `E9` jump sites to `0x63b9690`: **1** — `0x63d940a`, the
  class-search helper's tail call (packet #230; cited, not re-claimed).
- Rip-relative `LEA` sites to `0x63b9690`: **0**.
- `.rela.dyn` addends equal to `0x63b9690`: **0** of 60,723 entries.
- Internal calls within the FDE: **0**. Internal jump targets: all 28
  distinct targets lie inside `0x63b9690..0x63b99c8`.

## Corrections to earlier packets

- **#230 confirmed and completed.** Its tail-call target is this FDE, and
  its "next question" is answered here: the consumer merges the slot
  chain and returns its minimum node. #230's description of this FDE as
  "the consumer" is confirmed; no correction to #230's bytes or counts.
- **#225 refined, not contradicted.** #225's slot-head helper also builds
  a min-ordered tree by pairwise selection, but it compares a two-word
  key and runs two explicit rounds. This consumer compares one word and
  runs a sequential tournament (pairwise pass, then winner merge). The
  two helpers share the `+0x28` pair / `+0x30` / `+0x38` node shape and
  the `setb`/`sbb` signum idiom, but they are different FDEs with
  different keys — the single-word key here is a new observation, not a
  correction to #225's two-word claim.
- **#224 confirmed.** The `[slot+8] := 0` write on entry matches #224's
  observation that the slot's second word is zeroed by the release path's
  consumers; here the consumer itself zeroes it before merging.

## Unresolved

- What the caller (the class-search caller, via #230's two callers)
  does with the returned minimum node: consume it, free it, or reinsert
  it elsewhere. The return contract is established; the use is not.
- The identity of node words the FDE never reads (`+0x00`, `+0x10`,
  `+0x18`, `+0x20`, and the `+0x30`/`+0x38` words' full roles outside
  this merge). In particular, whether `+0x20` participates in ordering
  anywhere else in the chain's lifecycle.
- Whether the `+0x30` links written between accumulator generations in
  phase B form a traversable chain after the merge, or are bookkeeping
  overwritten by later passes. The bytes write them; no later pass in
  this FDE reads them.
- The purpose of the head's `+0x28` pair being zeroed before the walk
  while the head's `+0x30` link is left stale until the final attach.
- `.bss` contents are runtime-filled and not readable from the file;
  nothing here depends on them.

## Next question (#232)

Decode the caller that receives this consumer's returned minimum node:
what does the class-search caller do with the merged chain's minimum —
and does the returned node leave the class's slot, or stay linked there?
