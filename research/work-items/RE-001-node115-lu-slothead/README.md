# RE-001: the node #115 lu slot-head helper — what 0x63abd00 returns, and that it rewrites the chain

## Question

Packet #224's next question: decode `0x63abd00` end to end — what node
it returns for a slot, and whether it mutates the chain. This decides
whether the cache refresh in packet #224 is read-only, and what the
slot's cached key actually tracks.

## Answer (short)

`0x63abd00(slot)` takes one argument, the slot entry `T` (the 32-byte
entry #224's release helper operates on: `[T]` head, `[T+8]` second
word, `[T+0x10]`/`[T+0x18]` cached key). It **always returns the slot's
head node after restructuring** — `NULL` if and only if the slot is
empty. And it **does mutate the chain, extensively**: it is not
read-only. It zeroes `[slot+8]`, zeroes and rewrites `+0x28` pairs,
rebuilds the `+0x30` sibling chain through two rounds of adjacent-pair
max-selection, rewrites `+0x38` first-child links, and can change
`[slot]` itself. No node is freed, dropped, or unlinked: the node set
is preserved, only the link structure changes. It makes no calls at
all.

Consequence for #224: the cache refresh is **not** read-only, and the
cached key after refresh is the **new head's key** — which is either
the old head's key or the last second-round winner's key, whichever
the tail comparison selects. It is **not** the global maximum key:
for chains long enough to run two rounds, the tail compares only the
last second-round winner against the head; winners from earlier
positions in the second round are never compared against the head.

## The function

FDE `0x63abd00..0x63ac0cc` (972 bytes), two `ret` sites
(`0x63abf5a`, `0x63ac0c3`), zero `call` instructions. All control flow
is internal jumps; every jump target lies inside the FDE.

Node words (consistent with #219's slot-insert and #217's slot-claim):

- `+0x8` and `+0x20` = two-word sort key, compared with the
  `setb`/`sbb` signum idiom (first `+0x20`, then `+0x8` as tiebreak).
- `+0x28` = parent pointer (low half of the 16-byte link pair).
- `+0x30` = next-sibling pointer (high half of the link pair).
- `+0x38` = first-child pointer.

In other words the slot's `+0x30` chain is a sibling list, and this
function reshapes it toward a left-child/right-sibling tree.

## Entry

- `endbr64`; `head = [slot]`; if `head == NULL`, return `NULL`
  (`0x63ac0c0`: `rax = 0`, `ret`).
- Otherwise push callee-saved registers and store `[slot+8] = 0`
  (`movq $0, 0x8(%rdi)` at `0x63abd25`). This zeroing is
  unconditional and `[slot+8]` is never rewritten later, so on return
  `[slot+8] == 0` always.
- If `head+0x30 == NULL` (single-node chain), return `head`
  (`0x63abf4d` path). The `[slot+8]` zeroing has already happened on
  this path too.

## The two pairing rounds

Starting at the second node (`node2 = head+0x30`), the function pairs
adjacent non-overlapping nodes and keeps the larger key of each pair
(ties go to the later node: the `>=` branch makes the second node the
representative):

- Round 1 pairs `(node2, node3)`, `(node4, node5)`, and so on. The
  loser of each pair is attached as the winner's first child:
  `winner+0x38 = loser`, `loser+0x28 = winner`,
  `loser+0x30 = winner`'s old first child. Winners are chained via
  `+0x30`. A trailing unpaired node (odd chain length) is chained
  after the last winner.
- Round 2 runs only when round 1 yielded at least two winners (plus a
  possible trailing unpaired node): the same pairing runs over the
  winner chain. There is no third round — after round 2 the function
  goes to the tail regardless of how many winners remain.

Every processed node's `+0x28` pair is zeroed before it is rewritten,
so no stale link survives the pass.

## The tail

The last round-2 winner — or the round-1 winner if only one round
ran, or `node2` in the two-node case — is compared against `head`
with the same (`+0x20`, `+0x8`) signum idiom:

- Winner key `>=` head key: `[slot] = winner`, and `head` becomes the
  winner's first child (`head+0x28 = winner`,
  `head+0x30 = winner`'s old first child, `winner+0x38 = head`).
- Winner key `<` head key: `[slot]` stays `head`, and the winner
  becomes `head`'s first child (`winner+0x28 = head`,
  `winner+0x30 = head`'s old first child, `head+0x38 = winner`).

Either way the returned node equals `[slot]` on return. Short-chain
cases, all confirmed in the disassembly:

- 1 node: return `head`.
- 2 nodes: tail compare `node2` vs `head`.
- 3 nodes: round 1 over `(node2, node3)`, tail compare winner vs `head`.
- 4 nodes: round 1 winner plus trailing `node4`; round 2 over
  `(winner, node4)`; tail compare that winner vs `head`.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Helper `0x63abd00`: 6 direct E8, 0 E9, 0 LEA,
0 GOT. E8: `0x63b0912` (release helper, #224), `0x63b0bc7`,
`0x63b1131`, `0x63b1490`, `0x63b14ed` (all in FDE
`0x63b0980..0x63b15e9`, the FDE immediately after the release
helper), `0x63bca0f` (FDE `0x63bc730..0x63bcb12`). The
non-release callers' purposes are cited by address only, not decoded
here.

## Corrections to earlier packets

- **#224 confirmed.** The call site `0x63b0912` passes the slot alone
  (single argument, `rdi`); the refresh copies the returned node's
  key into the cache — and the returned node is the slot head after
  restructuring, so the cached key is the new head's key.
- **#224 refined.** The refresh is **not** read-only: `0x63abd00`
  rewrites `+0x28`/`+0x30`/`+0x38` links across the whole chain,
  zeroes `[slot+8]`, and can change `[slot]`. Any later traversal
  sees a different `+0x30` order than before the call, though the
  node set is unchanged.
- **#219 confirmed.** The node words (`+0x28` pair, `+0x30` link,
  `+0x38` word) and the (`+0x20`, `+0x8`) signum idiom are the same
  ones the slot-insert helper uses; here their roles resolve to
  parent / next-sibling / first-child.
- **#217/#219 note.** The slot second word `[slot+8]` is zeroed
  unconditionally on entry here; its semantic identity is still
  unresolved, but after this call it is always 0.
- No bytes claimed by packets #183–#224 are re-claimed. All exhibits
  lie strictly inside the `0x63abd00` FDE; caller FDEs are cited by
  address only.

## Unresolved, stated not inferred

The semantic identity of `[slot+8]` (why it is zeroed here, what it
counts between calls); why the restructuring stops after exactly two
pairing rounds instead of running to a single winner; the purposes of
the five non-release callers; whether later traversals consume the
produced tree shape (following `+0x38` children) or only the rebuilt
`+0x30` chain; what invariant the slot's cached key is meant to
maintain beyond "the head's key".

## Next question

Decode the FDE `0x63b0980..0x63b15e9` end to end: what it does with
its slot and nodes, why it calls the slot-head helper four times
(`0x63b0bc7`, `0x63b1131`, `0x63b1490`, `0x63b14ed`), and how its
slot relates to the allocator's pool slots.

## Verification

- Static verifier `tools/node115_lu_slothead.py`: exit 0
  (5 excerpts, 231 bytes, 64 strict mnemonics, census
  6 E8 sites, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_slothead.py`: 10/10.
- `make verify`: exit 0 (29 manifests, 471 entries).
- `make catalogue-check`: exit 0.
- `make test`: 77 files attempted, 1 failed — the single
  failure is the pre-existing test_node115_catalogue Errno 18
  cross-device-link error, identical on pristine checkouts,
  not a packet regression; this packet's file [36/77]
  passes 10/10.
- Target: node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis).
- No bytes claimed by packets #183–#224 are
  re-claimed; earlier bytes are cited by address
  only. No execution of the node binary at any
  point.

## Files (16)

- `research/work-items/RE-001-node115-lu-slothead/README.md`
- `research/work-items/RE-001-node115-lu-slothead/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-slothead/records.json`
- `research/work-items/RE-001-node115-lu-slothead/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-slothead/sh_entry.hex`
- `research/work-items/RE-001-node115-lu-slothead/sh_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-slothead/sh_cmp.hex`
- `research/work-items/RE-001-node115-lu-slothead/sh_cmp.objdump.txt`
- `research/work-items/RE-001-node115-lu-slothead/sh_splice.hex`
- `research/work-items/RE-001-node115-lu-slothead/sh_splice.objdump.txt`
- `research/work-items/RE-001-node115-lu-slothead/sh_loop.hex`
- `research/work-items/RE-001-node115-lu-slothead/sh_loop.objdump.txt`
- `research/work-items/RE-001-node115-lu-slothead/sh_tail.hex`
- `research/work-items/RE-001-node115-lu-slothead/sh_tail.objdump.txt`
- `tools/node115_lu_slothead.py`
- `tests/test_node115_lu_slothead.py`
