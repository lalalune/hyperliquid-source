# RE-001: the node #115 lu slot-claim helper — head, compare, splice, return

This packet answers packet #216's next question: what the `0x63ac480`
slot-claim helper does with a pool slot pointer, what its nonzero return
is, and how it detaches the block it returns.

## Answer in one paragraph

`0x63ac480(slot)` takes a 16-byte pool slot entry. If `[slot]` is zero
it returns zero. Otherwise it detaches one block from the slot's
intrusive chain — a sorted structure whose nodes carry a two-word key
at `+0x20`/`+0x8`, a 16-byte link pair at `+0x28`, a chain link at
`+0x30`, and a second link word at `+0x38` — stores the remainder head
back into `[slot]`, and returns the detached block pointer. The
allocator's scan passes each slot in `rdi`, tests the return, and on
nonzero jumps to its carve block at `0x636a97e` (#216's al_found). The
helper makes no calls at all: the whole detach is inline splice code,
with two `ret` sites (the NULL early return and the shared exit).

## Entry and exit contract

- Entry: `rdi` = slot pointer (a 16-byte entry in the pool slot array;
  the allocator steps `rbp` by `0x10` per entry and moves it to `rdi`).
- `[slot] == 0` → return `0` (`xor %eax,%eax; ret` at `0x63acb20`).
- Otherwise: `[slot+8]` is cleared to zero immediately, the chain is
  walked and re-spliced, `[slot]` is rewritten with the remainder head,
  and the detached block pointer is returned in `rax`.
- Single-node case, traced exactly: `[slot] = N`, `[N+0x30] = 0`,
  `[N+0x38] = 0` → `[slot] = 0`, return `N`. The slot is emptied and
  the node is fully detached.
- Shared exit (`0x63ac937`): `[slot] = rdx` (remainder head),
  `rax = rcx` (detached block), callee-saved registers restored, `ret`.

## How the detach works

- **Chain walk.** The walk follows `+0x30` links (`mov 0x30(%rdi),%rax`
  at `0x63ac5b6`); when a node's `+0x30` is zero the single-node path
  follows its `+0x38` word instead (`mov 0x10(%r10),%rax` at
  `0x63ac990`, where `r10 = node+0x28`).
- **Key comparison.** Each splice step compares two nodes
  lexicographically on their two-word key: first `+0x20`, then `+0x8`
  as tiebreak, via a `setb`/`sbb` signum idiom producing -1, 0, or +1
  (`sc_cmp`). A result of -1 takes the insert-before splice branch;
  any other result takes the append/rotate branch.
- **Splice.** Both branches rewrite link words with 16-byte `movups`
  pair stores into `+0x28` slots plus backlink writes (`sc_splice`:
  `[rcx+0x28] = (r14, [r14+0x38])`, `[r14+0x38] = rcx`, and
  `[[r14+0x38]+0x28] = rcx` when that word is nonzero).
- **Detach hygiene.** Nodes passed over have their `+0x28` pairs zeroed
  (`movups %xmm0,0x28(%rdx)` at `0x63ac4c2` and siblings) and their
  `+0x30` links cleared, so a detached block carries no stale linkage
  back into the slot's chain.
- **No calls.** The FDE contains zero `call` instructions: no
  contention helper, no allocator, no `__stack_chk_fail`. The
  `0x63bf680` contention path used by the allocator worker and the
  miss handler is never entered from here.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Slot-claim `0x63ac480`: 20 direct E8, 0 E9, 0 LEA,
0 GOT. Fifteen sites are the allocator worker's scan (FDE
`0x636a680..0x636aad8`): the 8-unrolled scan loop plus the Duff's-device
remainder dispatch and the tail call at `0x636aa33`. Five sites are in
three other FDEs: two in `0x6361320..0x63620da`, one in
`0x6362190..0x6362901`, two in `0x6364880..0x6365142` (purposes not
decoded here; cited by address only).

## Corrections to earlier packets

- **#216 confirmed and refined.** #216 said the scan calls the
  slot-claim helper per entry and a nonzero return means a found block.
  Confirmed exactly: the scan passes the slot pointer in `rdi`
  (`mov %rbp,%rdi` at `0x636a78f`, `rbp` stepping `0x10`), tests `rax`,
  and on nonzero jumps to the carve block at `0x636a97e`. Refined:
  the helper also rewrites `[slot]` with the remainder head and clears
  `[slot+8]` — the slot is not left stale after a claim — and the
  helper itself makes no calls.
- No bytes claimed by packets #183–#216 are re-claimed. All exhibits lie
  strictly inside the slot-claim FDE; the allocator scan and carve
  addresses are cited by address only.

## Unresolved, stated not inferred

The exact invariant of the slot's chain (binary search tree versus
sorted list, and which node of a multi-node chain is selected for
detach — the walk's selection rule across the merge loops); the roles
of the node words at `+0x0` and `+0x10`; the purposes of the five
non-allocator callers; what populates the chain for a fresh pool slot.

## Next question

Decode the `0x6369fe0` remainder helper end to end: what it does with
`(pool, block, aligned, aligned, requested)`, how it re-inserts the
remainder into the free list, and when it leaves the remainder out.

## Verification

- Static verifier `tools/node115_lu_slotclaim.py`: exit 0 (5 excerpts,
  119 bytes, 39 strict mnemonics, census 20 E8 sites, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_slotclaim.py`: 9/9.
- `make verify`: exit 0 (29 manifests, 471 entries).
- `make catalogue-check`: exit 0.
- `make test`: 77 files attempted, 1 failed — the single failure is the
  pre-existing test_node115_catalogue Errno 18 cross-device-link error,
  identical on pristine checkouts, not a packet regression; this
  packet's file passes 9/9.
- Target: node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), upstream main `8fd8db6` (fetch-confirmed
  unmoved before analysis).
- No bytes claimed by packets #183–#216 are re-claimed; earlier bytes
  are cited by address only. No execution of the node binary at any
  point.

## Files (16)

- `research/work-items/RE-001-node115-lu-slotclaim/README.md`
- `research/work-items/RE-001-node115-lu-slotclaim/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-slotclaim/records.json`
- `research/work-items/RE-001-node115-lu-slotclaim/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-slotclaim/sc_entry.hex`
- `research/work-items/RE-001-node115-lu-slotclaim/sc_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotclaim/sc_clear.hex`
- `research/work-items/RE-001-node115-lu-slotclaim/sc_clear.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotclaim/sc_cmp.hex`
- `research/work-items/RE-001-node115-lu-slotclaim/sc_cmp.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotclaim/sc_splice.hex`
- `research/work-items/RE-001-node115-lu-slotclaim/sc_splice.objdump.txt`
- `research/work-items/RE-001-node115-lu-slotclaim/sc_exit.hex`
- `research/work-items/RE-001-node115-lu-slotclaim/sc_exit.objdump.txt`
- `tools/node115_lu_slotclaim.py`
- `tests/test_node115_lu_slotclaim.py`
