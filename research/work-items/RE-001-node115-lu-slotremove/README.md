# RE-001: the node #115 lu slot-remove helper — unlink, merge, relink

- Component: lu pool slot chain maintenance; bounded static behaviour mapping.
- Target: node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: upstream main `8fd8db6` (fetch-confirmed unmoved before analysis).
- Question: what does the `0x63acb40` slot-remove helper do with (slot, node),
  how does it unlink the node, how does it use the (`+0x20`, `+0x8`) key idiom,
  what happens to the node's `+0x28` pair and `+0x30` link, and what do its
  three callers share?

## Answer

`0x63acb40(slot, node)` = (rdi, rsi) unlinks the node from the slot chain
and never frees it, never returns a status, and never calls anything: one
`ret` site (`0x63acd43`), zero `call` instructions in the whole 2626-byte
FDE. Entry compares `[slot]` with the node and dispatches on head versus
non-head.

The key idiom does **not** locate the target node: the node arrives as an
argument, and no path searches for it by key. The ten (`+0x20`, `+0x8`)
`setb`/`sbb` signum sites (20 `setb` instructions) all sit in merge walks
that re-splice the two sides left behind after the unlink, comparing
adjacent chain nodes with exactly the idiom #217's slot-claim and #219's
slot-insert helpers use.

## Unlink mechanics

Non-head path, with P = `[node+0x28]` and B = `[node+0x38]`. The fast
paths run only when P is nonzero and `[P+0x38] == node`; otherwise the
merge walks run:

- B == 0: `[P+0x38] := [node+0x30]`, and the successor's `+0x28` := P
  (`0x63ad100` block).
- B != 0 and `[B+0x30] == 0`: `[B+0x28] := P`, `[P+0x38] := B`,
  `[B+0x30] := [node+0x30]`, and the successor's `+0x28` := B
  (`0x63acd21` block).
- B != 0 and `[B+0x30] != 0`: a merge walk re-splices B's `+0x30` chain
  by key (first loop at `0x63acb99`), ending in the same relink.

Head path (`[slot] == node`, `0x63acd70`):

- `[node+0x38] == 0`: `[slot] := [node+0x30]`, and the successor's
  `+0x28` := 0 (`0x63ad230`).
- `[node+0x38] != 0`: `[slot+8] := 0`, the node's `+0x28` pair is zeroed
  (`movups %xmm0` at `0x63acd9d`), the successor's `+0x28` is zeroed,
  and a merge walk runs over the successor chain, including the rotation
  block at `0x63ad078` which reassigns `[slot]` by key comparison
  between the node and its `+0x30` successor.

## The node's own link words

Outside the head path, no store in the FDE targets the removed node's own
`+0x28`, `+0x30` or `+0x38` words: the merge loops rewrite only
chain-neighbor words, so on the non-head paths the node's words are left
stale. On the head path the node's `+0x28` pair is zeroed, and in the
`0x63ad078` rotation block it is rewritten as a pair
(`node+0x28 := successor`, `node+0x30 := [successor+0x38]`) while
`[successor+0x38] := node` and `[slot] := successor`. The node's `+0x30`
is read as the successor on every path and written only through that
pair write.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Remove helper `0x63acb40`: 3 direct E8, 0 E9, 0 LEA,
0 GOT. E8: `0x636359f` (FDE `0x6363560..0x636365a`),
`0x6363a6f` (FDE `0x63637f0..0x6363d50`), `0x63b0847` (FDE
`0x63b0780..0x63b097f`).

## What the three callers share

All three pass (slot, node) = (rdi, rsi) and update counters around the
call. The two `0x6363`-region callers are structural twins: the same
table-index math (`shr $0x14`, `movzbl`, `*5`, `*8`), the same guard
(table entry `+0x10 == 1` skips the call), the same slot base
(`rbx+0xc8`), and the same post-call decrement (`[rbx+0xb8] -= 1`).
The `0x63b0`-region caller differs: no `+0x10` guard, its own counter
updates before the call, and it immediately calls `0x63abcf0` with the
same slot — a paired remove-then-next sequence.

## Corrections to earlier packets

- **#219 confirmed.** The chain words (`+0x28` pair, `+0x30` link,
  `+0x38` word) and the (`+0x20`, `+0x8`) comparison idiom are the same
  ones the slot-insert helper uses; this helper re-splices with that
  idiom after unlinking.
- **#222 confirmed.** This helper is the slot-remove callee its next
  question pointed at.
- No earlier-packet verdict changed, and no bytes claimed by packets
  #183–#222 are re-claimed. All exhibits lie strictly inside the remove
  FDE; caller FDEs are cited by address only.

## Unresolved, stated not inferred

The global invariant of the slot chain (sorted list versus tree, and the
key order direction) is not settled by these bytes: the rotation block at
`0x63ad078` assigns the head's `+0x38` side by key comparison in a way
no plain BST reading explains. The semantic identity of the slot's second
word (`[slot+8]`) is unresolved: zeroed on insert-before (#219) and on
head removal with a `+0x38` side, incremented on after-head insert
(#219). Which of the three callers is #222's collect sibling is not
mapped here, and the purpose of the paired callee `0x63abcf0` is open.

## Next question

Decode the `0x63b0780..0x63b097f` caller FDE end to end: what it does
with its slot before and after the remove call, and why it immediately
calls `0x63abcf0` with the same slot.

## Verification

- Static verifier `tools/node115_lu_slotremove.py`: exit 0
  (5 excerpts, 184 bytes, 53 strict mnemonics, census
  3 E8 sites, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_slotremove.py`: 9/9.
- `make verify`: exit 0 (29 manifests, 471 entries).
- `make catalogue-check`: exit 0.
- `make test`: 77 files attempted, 1 failed — the single
  failure is the pre-existing test_node115_catalogue Errno 18
  cross-device-link error, identical on pristine checkouts,
  not a packet regression; this packet's file [36/77]
  passes 9/9.
- Target: node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis).
- No bytes claimed by packets #183–#222 are
  re-claimed; earlier bytes are cited by address
  only. No execution of the node binary at any
  point.

## Files (16)

- `research/work-items/RE-001-node115-lu-slotremove/README.md`
- `research/work-items/RE-001-node115-lu-slotremove/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-slotremove/records.json`
- `research/work-items/RE-001-node115-lu-slotremove/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-slotremove/rm_entry.hex`
- `research/work-items/RE-001-node115-lu-slotremove/rm_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotremove/rm_nonhead.hex`
- `research/work-items/RE-001-node115-lu-slotremove/rm_nonhead.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotremove/rm_signum.hex`
- `research/work-items/RE-001-node115-lu-slotremove/rm_signum.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotremove/rm_head.hex`
- `research/work-items/RE-001-node115-lu-slotremove/rm_head.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotremove/rm_relink.hex`
- `research/work-items/RE-001-node115-lu-slotremove/rm_relink.objdump.txt`
- `tools/node115_lu_slotremove.py`
- `tests/test_node115_lu_slotremove.py`
